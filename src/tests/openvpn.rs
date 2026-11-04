//! OpenVPN de bout en bout : serveur OpenVPN en mémoire (`openvpn::test_server`) devant les
//! serveurs SSH de test, et interopérabilité avec un vrai OpenVPN 2.6 (tools/openvpn-test).

use super::*;
use crate::model::{VpnKind, VpnProfile};
use crate::openvpn::data::Compression;
use crate::openvpn::link::OpenVpnLink;
use crate::openvpn::test_server::{self as ts, ControlWrap, ServerHandle, ServerOpts};
use crate::vpn::{Link, Transport};
use std::net::SocketAddr;

fn profile(name: &str, h: &ServerHandle) -> VpnProfile {
    let mut p = VpnProfile::default();
    p.name = name.into();
    p.kind = VpnKind::OpenVpn;
    p.openvpn = h.client_config();
    let (u, pw) = h.credentials();
    p.username = u;
    p.password = pw;
    p
}

/// UDP, tls-crypt, AES-256-GCM, certificat seul (profil A).
fn opts_udp(forward: SocketAddr, listen_port: u16) -> ServerOpts {
    ServerOpts { wrap: ControlWrap::TlsCrypt, listen_port, forward, ..Default::default() }
}

/// TCP, tls-auth SHA256, AES-256-CBC, comp-lzo, identifiant (type WatchGuard SSL, profil C).
fn opts_tcp(forward: SocketAddr, listen_port: u16) -> ServerOpts {
    ServerOpts {
        transport: Transport::Tcp,
        wrap: ControlWrap::TlsAuth { server_direction: Some(0) },
        cipher: "AES-256-CBC".into(),
        auth: "SHA256".into(),
        user_pass: Some(("test".into(), "secret".into())),
        compression: Compression::Lzo,
        listen_port,
        forward,
        ..Default::default()
    }
}

fn local(port: u16) -> SocketAddr {
    ([127, 0, 0, 1], port).into()
}

/// Serveur d'écho TCP local (relayé dans le tunnel par le serveur OpenVPN de test).
async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// Envoie `size` octets pseudo-aléatoires et vérifie leur écho exact.
async fn echo_roundtrip(p: &VpnProfile, host: &str, port: u16, size: usize) {
    let s = tokio::time::timeout(Duration::from_secs(30), crate::vpn::connect(p, host, port))
        .await
        .expect("connexion VPN trop longue")
        .unwrap_or_else(|e| panic!("connexion VPN : {e}"));
    let data: Vec<u8> = (0..size as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let (mut r, mut w) = tokio::io::split(s);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.flush().await.unwrap();
        w
    });
    let mut got = vec![0u8; size];
    tokio::time::timeout(Duration::from_secs(120), r.read_exact(&mut got)).await.expect("écho trop long").unwrap();
    let _w = writer.await.unwrap();
    assert!(got == data, "écho altéré ({size} octets)");
}

async fn ssh_through(p: VpnProfile, name: &'static str) {
    let mut h = host(name, 22);
    h.hostname = "10.8.0.1".into();
    h.password = "s".into();
    h.vpn = Some(p.id);
    let data = VaultData { hosts: vec![h.clone()], vpns: vec![p], ..Default::default() };
    let mut run = launch(data.chain(h.id).unwrap());
    let out = run.expect_output(&format!("WELCOME {name}")).await;
    assert!(out.contains("via le VPN"), "{out}");
    run.tx.send(Cmd::Data(b"ovpn".to_vec())).unwrap();
    run.expect_output("echo:ovpn").await;
    run.tx.send(Cmd::Close).unwrap();
    assert_eq!(run.finish().await, Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_over_openvpn_udp_tls_crypt_gcm() {
    let ssh = start(TestServer { password: "s".into(), name: "udp", ..Default::default() }).await;
    let srv = ts::start(opts_udp(local(ssh), 22)).await;
    ssh_through(profile("OVPN UDP", &srv), "udp").await;
    let st = srv.stats();
    assert!(st.ekm && st.data_v2_rx && st.cipher == "AES-256-GCM", "{st:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_over_openvpn_tcp_tls_auth_cbc_lzo_password() {
    let ssh = start(TestServer { password: "s".into(), name: "tcp", ..Default::default() }).await;
    let srv = ts::start(opts_tcp(local(ssh), 22)).await;
    ssh_through(profile("OVPN TCP", &srv), "tcp").await;
    let st = srv.stats();
    assert_eq!(st.username, "test");
    assert_eq!(st.cipher, "AES-256-CBC");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openvpn_wrong_password_is_reported_in_french() {
    let srv = ts::start(opts_tcp(local(1), 7)).await;
    let mut p = profile("OVPN mdp", &srv);
    p.password = "faux".into();
    let e = crate::vpn::connect(&p, "10.8.0.1", 7).await.err().expect("mot de passe faux accepté");
    assert!(e.contains("Identifiant ou mot de passe refusé"), "{e}");
    assert!(srv.stats().auth_failures >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openvpn_wrong_ca_is_a_certificate_error() {
    let srv = ts::start(opts_udp(local(1), 7)).await;
    let mut p = profile("OVPN CA", &srv);
    p.openvpn.ca = ts::Pki::generate("autre", "autre").ca_pem;
    let e = crate::vpn::connect(&p, "10.8.0.1", 7).await.err().expect("serveur d'une autre autorité accepté");
    assert!(e.contains("Certificat du serveur OpenVPN refusé") && e.contains("autorité de certification"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openvpn_large_echo_udp_and_tcp() {
    let echo = echo_server().await;
    let udp = ts::start(opts_udp(local(echo), 7)).await;
    echo_roundtrip(&profile("OVPN gros UDP", &udp), "10.8.0.1", 7, 1_500_000).await;
    let tcp = ts::start(opts_tcp(local(echo), 7)).await;
    echo_roundtrip(&profile("OVPN gros TCP", &tcp), "10.8.0.1", 7, 1_500_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openvpn_server_renegotiation_keeps_the_stream() {
    let echo = echo_server().await;
    for opts in [opts_udp(local(echo), 7), opts_tcp(local(echo), 7)] {
        let srv = ts::start(opts).await;
        let p = profile("OVPN reneg", &srv);
        // la même connexion reste ouverte pendant la renégociation (le tunnel vit avec elle)
        let mut s = crate::vpn::connect(&p, "10.8.0.1", 7).await.unwrap();
        let ping = async |s: &mut crate::vpn::VpnStream, n: usize| {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + n) as u8).collect();
            s.write_all(&data).await.unwrap();
            let mut got = vec![0; n];
            tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got)).await.expect("écho perdu").unwrap();
            assert!(got == data);
        };
        ping(&mut s, 20_000).await;
        srv.renegotiate();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while srv.stats().last_rx_key != Some(1) {
            assert!(tokio::time::Instant::now() < deadline, "{:?}", srv.stats());
            ping(&mut s, 1_000).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ping(&mut s, 200_000).await;
        let st = srv.stats();
        assert_eq!(st.keys_established, vec![0, 1], "{st:?}");
        assert_eq!(st.last_tx_key, Some(1), "{st:?}");
    }
}

/// Client et serveur reliés en mémoire, sans socket : renégociation à l'initiative du client.
#[test]
fn openvpn_client_renegotiation_in_memory() {
    for opts in [opts_udp(local(1), 7), opts_tcp(local(1), 7)] {
        let (mut server, h) = ts::link(opts);
        let cfg = h.client_config();
        let (u, pw) = h.credentials();
        let mut client = OpenVpnLink::new("mémoire", &cfg, &u, &pw).unwrap();
        let from = Some(local(1194));
        let pump = |client: &mut OpenVpnLink, server: &mut Box<dyn Link>| {
            for _ in 0..50 {
                let mut moved = false;
                while let Some(b) = client.poll_net() {
                    server.input(&b, from);
                    moved = true;
                }
                while let Some(b) = server.poll_net() {
                    client.input(&b, from);
                    moved = true;
                }
                if !moved {
                    client.tick();
                    server.tick();
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !client.established() {
            assert!(std::time::Instant::now() < deadline, "{:?} / {:?}", client.state(), h.stats());
            pump(&mut client, &mut server);
        }
        assert_eq!(client.tx_key_id(), Some(0));
        client.force_renegotiate();
        while client.tx_key_id() != Some(1) {
            assert!(std::time::Instant::now() < deadline, "{:?}", h.stats());
            pump(&mut client, &mut server);
        }
        // paquet IP minimal client → serveur sur la nouvelle clé
        let mut ip = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1];
        ip.resize(20, 0);
        client.send_ip(&ip);
        pump(&mut client, &mut server);
        assert_eq!(h.stats().last_rx_key, Some(1), "{:?}", h.stats());
    }
}

// ------------------------------------------------------------------ vrai serveur OpenVPN

/// Profil importé de tools/openvpn-test/out/<nom>.ovpn (serveurs lancés par run.ps1).
fn interop_profile(name: &str) -> VpnProfile {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/openvpn-test/out").join(format!("{name}.ovpn"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} : {e} (lancer tools/openvpn-test/run.ps1)", path.display()));
    let mut p = VpnProfile::default();
    p.name = format!("Docker {name}");
    p.kind = VpnKind::OpenVpn;
    p.openvpn = crate::openvpn::config::parse_ovpn(&text, path.parent()).unwrap_or_else(|e| panic!("{name}.ovpn : {e}"));
    if p.openvpn.auth_user_pass {
        p.username = "test".into();
        p.password = "secret".into();
    }
    crate::vpn::check(&p).unwrap();
    p
}

async fn interop(name: &str, tunnel_ip: &str) {
    let p = interop_profile(name);
    echo_roundtrip(&p, tunnel_ip, 7, 100_000).await;
    // deuxième connexion sur le même tunnel
    echo_roundtrip(&p, tunnel_ip, 7, 10_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "serveurs Docker de tools/openvpn-test"]
async fn openvpn_interop_a_udp_tls_crypt_gcm() {
    interop("A", "10.8.0.1").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "serveurs Docker de tools/openvpn-test"]
async fn openvpn_interop_b_tcp_tls_auth_lzo_password() {
    let _b = DOCKER_B.lock().await;
    interop("B", "10.9.0.1").await;
}

/// Les deux tests du serveur B utilisent le même certificat client et B n'a pas `duplicate-cn` :
/// en parallèle, la session acceptée fait tomber l'autre avant que AUTH_FAILED ne parte.
static DOCKER_B: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "serveurs Docker de tools/openvpn-test"]
async fn openvpn_interop_c_tcp_cbc_sha256() {
    interop("C", "10.10.0.1").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "serveurs Docker de tools/openvpn-test"]
async fn openvpn_interop_b_wrong_password() {
    let _b = DOCKER_B.lock().await;
    let mut p = interop_profile("B");
    p.password = "faux".into();
    let e = crate::vpn::connect(&p, "10.9.0.1", 7).await.err().expect("mot de passe faux accepté");
    assert!(e.contains("Identifiant ou mot de passe refusé"), "{e}");
}

// ------------------------------------------------------------------ réglages du profil

/// Échange en mémoire jusqu'à ce que `done` soit vrai (ou 10 s).
fn drive(client: &mut OpenVpnLink, server: &mut Box<dyn Link>, done: impl Fn(&OpenVpnLink) -> bool) {
    let from = Some(local(1194));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !done(client) {
        assert!(std::time::Instant::now() < deadline, "{:?}", client.state());
        let mut moved = false;
        while let Some(b) = client.poll_net() {
            server.input(&b, from);
            moved = true;
        }
        while let Some(b) = server.poll_net() {
            client.input(&b, from);
            moved = true;
        }
        if !moved {
            client.tick();
            server.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn up_info(client: &OpenVpnLink) -> crate::vpn::LinkInfo {
    match client.state() {
        crate::vpn::LinkState::Up(i) => i.clone(),
        s => panic!("{s:?}"),
    }
}

/// `compress stub-v2` du profil (non poussé), routes, `route-nopull`, `redirect-gateway` et
/// `tun-mtu` du profil.
#[test]
fn openvpn_profile_routes_mtu_and_stub_v2() {
    let mut opts = ServerOpts { compression: Compression::V2, ..opts_tcp(local(1), 7) };
    // serveur 2.4 / 2.5 : tun-mtu non poussé, celui du profil s'applique
    opts.push.retain(|o| !o.starts_with("tun-mtu"));
    let (mut server, h) = ts::link(opts.clone());
    let mut cfg = h.client_config();
    assert_eq!(cfg.compression, "compress stub-v2");
    cfg.routes = "172.20.0.0/16 fd00:1::/48".into();
    cfg.tun_mtu = 1400;
    let (u, pw) = h.credentials();
    let mut client = OpenVpnLink::new("mémoire", &cfg, &u, &pw).unwrap();
    drive(&mut client, &mut server, |c| c.established());
    let i = up_info(&client);
    assert_eq!(i.mtu, 1400);
    let net = |s: &str, p: u8| (s.parse::<std::net::IpAddr>().unwrap(), p);
    for r in [net("10.8.0.0", 24), net("192.168.100.0", 24), net("172.20.0.0", 16), net("fd00:1::", 48)] {
        assert!(i.routes.contains(&r), "{r:?} absent de {:?}", i.routes);
    }
    // cadrage stub-v2 : le serveur reçoit le paquet IP intact
    let ip = vec![0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1];
    client.send_ip(&ip);
    drive(&mut client, &mut server, |_| true);
    for _ in 0..20 {
        client.tick();
        while let Some(b) = client.poll_net() {
            server.input(&b, Some(local(1194)));
        }
    }
    assert_eq!(server.recv_ip().as_deref(), Some(&ip[..]), "{:?}", h.stats());

    // route-nopull : routes poussées ignorées, réseau du VPN et routes du profil gardés
    let (mut server, h) = ts::link(opts.clone());
    let mut cfg = h.client_config();
    cfg.routes = "172.20.0.0/16".into();
    cfg.route_nopull = true;
    let mut client = OpenVpnLink::new("mémoire", &cfg, &u, &pw).unwrap();
    drive(&mut client, &mut server, |c| c.established());
    let i = up_info(&client);
    assert!(i.routes.contains(&net("10.8.0.0", 24)) && i.routes.contains(&net("172.20.0.0", 16)), "{:?}", i.routes);
    assert!(!i.routes.contains(&net("192.168.100.0", 24)), "{:?}", i.routes);

    // redirect-gateway du profil : aucun hôte refusé
    let (mut server, h) = ts::link(opts);
    let mut cfg = h.client_config();
    cfg.redirect_gateway = true;
    let mut client = OpenVpnLink::new("mémoire", &cfg, &u, &pw).unwrap();
    drive(&mut client, &mut server, |c| c.established());
    assert!(up_info(&client).routes.is_empty());
}

/// Un chiffrement poussé hors de la liste du profil est refusé (« pushed cipher not allowed »).
#[test]
fn openvpn_pushed_cipher_must_be_offered() {
    let (mut server, h) = ts::link(ServerOpts {
        cipher: "AES-128-CBC".into(),
        push_cipher: false,
        push: vec!["ifconfig 10.8.0.2 255.255.255.0".into(), "topology subnet".into(), "cipher AES-128-CBC".into()],
        ..Default::default()
    });
    let mut cfg = h.client_config();
    cfg.data_ciphers = "AES-256-GCM".into();
    cfg.cipher.clear();
    let mut client = OpenVpnLink::new("mémoire", &cfg, "", "").unwrap();
    drive(&mut client, &mut server, |c| matches!(c.state(), crate::vpn::LinkState::Failed(_)));
    let crate::vpn::LinkState::Failed(e) = client.state() else { unreachable!() };
    assert!(e.contains("AES-128-CBC") && e.contains("autorisés"), "{e}");
}

/// Une réinitialisation serveur qui n'acquitte pas la nôtre (réponse tardive, rejouée ou
/// forgée) ne verrouille pas la session : la vraie passe ensuite.
#[test]
fn openvpn_stale_server_reset_is_ignored() {
    use crate::openvpn::packet::{ControlPacket, P_CONTROL_HARD_RESET_SERVER_V2};
    let (mut server, h) = ts::link(ServerOpts::default());
    let cfg = h.client_config();
    let mut client = OpenVpnLink::new("mémoire", &cfg, "", "").unwrap();
    for (acks, remote) in [(vec![0], Some([9u8; 8])), (vec![], None)] {
        let forged = ControlPacket {
            opcode: P_CONTROL_HARD_RESET_SERVER_V2,
            key_id: 0,
            session_id: [7; 8],
            acks,
            remote_session_id: remote,
            packet_id: Some(0),
            payload: Vec::new(),
        };
        assert!(!client.input(&forged.encode(), Some(local(1194))));
    }
    drive(&mut client, &mut server, |c| c.established());
}

/// `reneg-sec 0` et un `cipher` ancien (BF-CBC) dans le profil : accepté quand le serveur négocie.
#[test]
fn openvpn_legacy_cipher_line_and_reneg_sec() {
    let (mut server, h) = ts::link(ServerOpts::default());
    let mut cfg = h.client_config();
    cfg.cipher = "BF-CBC".into();
    cfg.reneg_sec = Some(0);
    cfg.ping = 5;
    cfg.ping_restart = 30;
    let mut p = VpnProfile::default();
    p.name = "x".into();
    p.kind = VpnKind::OpenVpn;
    p.openvpn = cfg.clone();
    // vérification à l'enregistrement : un repli inutilisable n'est pas une erreur, …
    crate::vpn::check(&p).unwrap();
    // … mais une autorité que webpki refuse l'est dès l'enregistrement
    p.openvpn.ca = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into();
    assert!(crate::vpn::check(&p).is_err());
    let mut client = OpenVpnLink::new("mémoire", &cfg, "", "").unwrap();
    drive(&mut client, &mut server, |c| c.established());
}
