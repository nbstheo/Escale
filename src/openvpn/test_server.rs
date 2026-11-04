//! Serveur OpenVPN en mémoire pour les tests de bout en bout (compilé seulement en test).
//!
//! Écrit indépendamment du client (`control`) à partir des seuls modules de format (`packet`,
//! `reliable`, `data`) et d'un `rustls::ServerConnection` : les deux côtés se vérifient ainsi
//! l'un l'autre. Le serveur répond à la réinitialisation, mène le TLS (certificat signé par une
//! autorité de test rcgen, certificat client facultatif ou exigé), l'échange key-method 2
//! (identifiant / mot de passe vérifiés si configurés), répond au `PUSH_REQUEST`, chiffre le
//! canal de données et sert de routeur : la pile smoltcp du moteur (`vpn::serve`) accepte les
//! connexions faites dans le tunnel sur `server_ip:listen_port` et les relaie vers `forward`.
//!
//! Comportement calqué sur OpenVPN 2.6 côté serveur :
//! - réinitialisation : `P_CONTROL_HARD_RESET_SERVER_V2` (packet-id 0) acquittant celle du client ;
//!   un HARD_RESET d'un autre identifiant de session remplace la session (reconnexion) ;
//! - key-method 2 serveur : `0u32 | 2 | random1 | random2 | options | "" | "" | ""` (identifiant,
//!   mot de passe et peer-info vides, longueur 0 sur 2 octets) ; la réponse est écrite après la
//!   lecture du message du client ;
//! - `PUSH_REPLY` à la demande (`PUSH_REQUEST`), ou aussitôt après key-method 2 si le client
//!   annonce `IV_PROTO_REQUEST_PUSH` ; `AUTH_FAILED` si l'identification ou la négociation du
//!   chiffrement échoue ;
//! - clés de données dérivées à l'envoi du `PUSH_REPLY` (PRF ou exportateur TLS si le client
//!   annonce `IV_PROTO_TLS_KEY_EXPORT` et que l'option `ekm` est active), puis à chaque
//!   renégociation dès l'échange key-method 2 ;
//! - renégociation : chaque côté envoie son `P_CONTROL_SOFT_RESET_V1` (packet-id 0) sur le nouveau
//!   key_id ; l'ancienne clé reste valable en réception 60 s ; l'émission passe sur la nouvelle
//!   clé quand tout le contrôle de celle-ci est acquitté ou qu'un paquet du client l'utilise.

#![allow(dead_code)]

use super::data::{self, ClientKeySource, Compression, DataChannel, DataCipher, Digest, Key2, ServerKeySource};
use super::packet::{self, AuthDigest, ControlPacket, DataHeader, TcpFramer, Wrap};
use super::reliable::{Reliable, ReliableConfig};
use crate::model::{OpenVpnConfig, OpenVpnProto};
use crate::vpn::{Link, LinkInfo, LinkState, Transport};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Bits de `IV_PROTO` (ssl.h d'OpenVPN).
pub(crate) const IV_PROTO_DATA_V2: u32 = 1 << 1;
pub(crate) const IV_PROTO_REQUEST_PUSH: u32 = 1 << 2;
pub(crate) const IV_PROTO_TLS_KEY_EXPORT: u32 = 1 << 3;
/// Préfixe des messages OCC sur le canal de données (occ.c), suivi de l'opcode OCC.
pub(crate) const OCC_MAGIC: [u8; 16] =
    [0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c];
pub(crate) const OCC_EXIT: u8 = 6;
/// Durée de vie de l'ancienne clé après une renégociation (`transition-window`).
const TRANSITION_WINDOW: Duration = Duration::from_secs(60);

// ------------------------------------------------------------------ réglages

/// Enveloppe du canal de contrôle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlWrap {
    None,
    /// `tls-auth` ; `server_direction` = `key-direction` du serveur (habituellement `Some(0)`,
    /// le client prend alors 1 ; `None` : bidirectionnel des deux côtés).
    TlsAuth { server_direction: Option<u8> },
    TlsCrypt,
}

/// Certificat client demandé pendant le TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientCert {
    /// Pas de CertificateRequest (identification par mot de passe seulement).
    None,
    /// Demandé, accepté s'il manque (vérifié s'il est fourni).
    Optional,
    Required,
}

/// Annonce de `key-derivation tls-ekm` (si le client annonce `IV_PROTO_TLS_KEY_EXPORT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ekm {
    /// Jamais : dérivation par la PRF d'OpenVPN.
    Off,
    /// `key-derivation tls-ekm` (serveurs 2.5 / clients 2.5).
    KeyDerivation,
    /// `protocol-flags … tls-ekm` (serveur 2.6 face à un client 2.6).
    ProtocolFlags,
}

/// Autorité, certificat serveur et certificat client de test (PEM).
#[derive(Clone)]
pub(crate) struct Pki {
    pub ca_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

impl Pki {
    /// Autorité « Escale Test CA », certificat serveur (CN = `server_cn`, serverAuth) et client
    /// (CN = `client_cn`, clientAuth), clés ECDSA P-256 (PKCS#8).
    pub fn generate(server_cn: &str, client_cn: &str) -> Self {
        use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.distinguished_name.push(DnType::CommonName, "Escale Test CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca, &ca_key);
        let leaf = |cn: &str, eku: ExtendedKeyUsagePurpose| {
            let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
            p.distinguished_name.push(DnType::CommonName, cn);
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
            p.extended_key_usages = vec![eku];
            let k = KeyPair::generate().unwrap();
            let c = p.signed_by(&k, &issuer).unwrap();
            (c.pem(), k.serialize_pem())
        };
        let (server_cert_pem, server_key_pem) = leaf(server_cn, ExtendedKeyUsagePurpose::ServerAuth);
        let (client_cert_pem, client_key_pem) = leaf(client_cn, ExtendedKeyUsagePurpose::ClientAuth);
        Self { ca_pem: ca_cert.pem(), server_cert_pem, server_key_pem, client_cert_pem, client_key_pem }
    }
}

/// Clé statique OpenVPN aléatoire (« OpenVPN Static key V1 », 256 octets), pour tls-auth / tls-crypt.
pub(crate) fn generate_static_key() -> String {
    let mut k = Zeroizing::new([0u8; packet::STATIC_KEY_LEN]);
    SystemRandom::new().fill(&mut k[..]).unwrap();
    let mut s = String::from("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n");
    for line in k.chunks(16) {
        for b in line {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('\n');
    }
    s.push_str("-----END OpenVPN Static key V1-----\n");
    s
}

/// Réglages du serveur de test.
#[derive(Clone)]
pub(crate) struct ServerOpts {
    pub transport: Transport,
    pub wrap: ControlWrap,
    /// Chiffrement du canal de données (poussé par `cipher` si `push_cipher`).
    pub cipher: String,
    /// `auth` : HMAC de tls-auth et du mode CBC ("" = SHA1).
    pub auth: String,
    /// Pousse `cipher …` (NCP) ; faux : serveur ancien, le client garde son `cipher`.
    pub push_cipher: bool,
    pub ekm: Ekm,
    /// `auth-user-pass` exigé : identifiant et mot de passe attendus.
    pub user_pass: Option<(String, String)>,
    pub client_cert: ClientCert,
    /// Cadrage de compression (`comp-lzo` : `Compression::Lzo`), jamais poussé : il vient du .ovpn.
    pub compression: Compression,
    /// `peer-id` poussé si le client annonce `IV_PROTO_DATA_V2` (`None` : jamais, P_DATA_V1).
    pub peer_id: Option<u32>,
    /// Options de base du `PUSH_REPLY` (`peer-id`, `cipher`, tls-ekm et `ping` sont ajoutés).
    pub push: Vec<String>,
    /// `ping N` / `ping-restart M` poussés ; le serveur envoie alors un ping après N s sans envoi.
    pub ping: Option<(u32, u32)>,
    /// `PUSH_REPLY` en deux messages (`push-continuation 2` puis `1`).
    pub split_push: bool,
    /// Pousse aussitôt après key-method 2 si le client annonce `IV_PROTO_REQUEST_PUSH`.
    pub request_push: bool,
    pub tls12_only: bool,
    /// Renégociation lancée par le serveur après cette durée (`reneg-sec`).
    pub reneg_after: Option<Duration>,
    pub server_cn: String,
    /// Adresse du serveur dans le tunnel (le client reçoit `push` : 10.8.0.2/24 par défaut).
    pub server_ip: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
    /// Port TCP écouté dans le tunnel.
    pub listen_port: u16,
    /// Service local vers lequel les connexions du tunnel sont relayées.
    pub forward: SocketAddr,
    /// PKI imposée (ex. pour une autorité différente côté client), générée sinon.
    pub pki: Option<Pki>,
    /// Clé statique imposée (PEM), générée sinon.
    pub static_key: Option<String>,
}

impl Default for ServerOpts {
    fn default() -> Self {
        Self {
            transport: Transport::Udp,
            wrap: ControlWrap::None,
            cipher: "AES-256-GCM".into(),
            auth: String::new(),
            push_cipher: true,
            ekm: Ekm::ProtocolFlags,
            user_pass: None,
            client_cert: ClientCert::Required,
            compression: Compression::None,
            peer_id: Some(0),
            push: [
                "route 192.168.100.0 255.255.255.0",
                "dhcp-option DNS 10.8.0.1",
                "dhcp-option DOMAIN escale.test",
                "route-gateway 10.8.0.1",
                "topology subnet",
                "ifconfig 10.8.0.2 255.255.255.0",
                "tun-mtu 1500",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ping: None,
            split_push: false,
            request_push: true,
            tls12_only: false,
            reneg_after: None,
            server_cn: "server".into(),
            server_ip: Ipv4Addr::new(10, 8, 0, 1),
            prefix: 24,
            mtu: 1500,
            listen_port: 7,
            forward: ([127, 0, 0, 1], 1).into(),
            pki: None,
            static_key: None,
        }
    }
}

// ------------------------------------------------------------------ état observable

/// Ce que le serveur a vu (pour les assertions des tests).
#[derive(Clone, Debug, Default)]
pub(crate) struct ServerStats {
    /// Sessions ouvertes (HARD_RESET d'un nouvel identifiant de session).
    pub hard_resets: u32,
    /// `PUSH_REPLY` envoyés.
    pub pushes: u32,
    pub auth_failures: u32,
    pub username: String,
    pub peer_info: String,
    /// Chaîne d'options key-method 2 du client.
    pub client_options: String,
    /// Version TLS négociée (« TLSv1_3 »…).
    pub tls_version: String,
    /// Clés de la dernière session dérivées par l'exportateur TLS.
    pub ekm: bool,
    /// peer-id poussé (P_DATA_V2), `None` : P_DATA_V1.
    pub peer_id: Option<u32>,
    pub cipher: String,
    /// key_id des clés de données mises en place, dans l'ordre.
    pub keys_established: Vec<u8>,
    /// Le client a envoyé au moins un P_DATA_V2.
    pub data_v2_rx: bool,
    /// key_id du dernier paquet de données reçu / envoyé.
    pub last_rx_key: Option<u8>,
    pub last_tx_key: Option<u8>,
    pub packets_in: u64,
    pub packets_out: u64,
    pub pings_in: u32,
    pub pings_out: u32,
    /// Fin annoncée par le client (OCC EXIT sur les données ou « EXIT » sur le contrôle).
    pub exit_notified: bool,
    /// Autres messages de contrôle du client (hors PUSH_REQUEST).
    pub control_messages: Vec<String>,
    pub errors: Vec<String>,
}

enum Ctl {
    Renegotiate,
    Restart(String),
    Kill,
}

#[derive(Default)]
struct Shared {
    stats: ServerStats,
    ctl: VecDeque<Ctl>,
    /// Plus rien n'est reçu ni envoyé (test de `ping-restart`).
    silent: bool,
}

fn lock(s: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serveur lancé : de quoi construire le profil client et piloter le serveur.
#[derive(Clone)]
pub(crate) struct ServerHandle {
    /// Port d'écoute sur 127.0.0.1 (UDP ou TCP selon `transport`), 0 pour `link()`.
    pub port: u16,
    pub transport: Transport,
    pub pki: Pki,
    /// Clé statique (PEM) de tls-auth / tls-crypt.
    pub static_key: String,
    pub wrap: ControlWrap,
    pub cipher: String,
    pub auth: String,
    pub user_pass: Option<(String, String)>,
    pub client_cert: ClientCert,
    pub compression: Compression,
    shared: Arc<Mutex<Shared>>,
}

impl ServerHandle {
    /// Profil client correspondant (127.0.0.1:port, CA, certificat client sauf `ClientCert::None`,
    /// clé statique et direction opposée, `cipher` en repli, `remote-cert-tls server`).
    pub fn client_config(&self) -> OpenVpnConfig {
        let with_cert = self.client_cert != ClientCert::None;
        let defaults = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"];
        OpenVpnConfig {
            remote: "127.0.0.1".into(),
            port: self.port,
            proto: match self.transport {
                Transport::Udp => OpenVpnProto::Udp,
                Transport::Tcp => OpenVpnProto::Tcp,
            },
            ca: self.pki.ca_pem.clone(),
            cert: if with_cert { self.pki.client_cert_pem.clone() } else { String::new() },
            key: if with_cert { self.pki.client_key_pem.clone() } else { String::new() },
            tls_auth: if matches!(self.wrap, ControlWrap::TlsAuth { .. }) { self.static_key.clone() } else { String::new() },
            key_direction: match self.wrap {
                ControlWrap::TlsAuth { server_direction: Some(0) } => "1".into(),
                ControlWrap::TlsAuth { server_direction: Some(_) } => "0".into(),
                _ => String::new(),
            },
            tls_crypt: if self.wrap == ControlWrap::TlsCrypt { self.static_key.clone() } else { String::new() },
            cipher: self.cipher.clone(),
            // chiffrement hors de la liste par défaut du client : il doit pouvoir le négocier
            data_ciphers: if defaults.iter().any(|d| d.eq_ignore_ascii_case(&self.cipher)) { String::new() } else { self.cipher.clone() },
            auth: self.auth.clone(),
            auth_user_pass: self.user_pass.is_some(),
            verify_x509_name: String::new(),
            remote_cert_tls: true,
            compression: match self.compression {
                Compression::None => String::new(),
                Compression::Lzo => "comp-lzo".into(),
                Compression::Swap => "compress".into(),
                Compression::V2 => "compress stub-v2".into(),
            },
            ..Default::default()
        }
    }

    /// (identifiant, mot de passe) attendus, vides sinon.
    pub fn credentials(&self) -> (String, String) {
        self.user_pass.clone().unwrap_or_default()
    }

    pub fn stats(&self) -> ServerStats {
        lock(&self.shared).stats.clone()
    }

    /// Renégociation lancée par le serveur (au prochain tour de minuterie).
    pub fn renegotiate(&self) {
        lock(&self.shared).ctl.push_back(Ctl::Renegotiate);
    }

    /// Envoie `RESTART` (ou `RESTART,<raison>`) sur le canal de contrôle.
    pub fn restart(&self, reason: &str) {
        lock(&self.shared).ctl.push_back(Ctl::Restart(reason.to_string()));
    }

    /// Oublie la session sans prévenir (le client doit refaire un HARD_RESET).
    pub fn kill_session(&self) {
        lock(&self.shared).ctl.push_back(Ctl::Kill);
    }

    /// Serveur muet : plus rien n'est reçu ni envoyé.
    pub fn set_silent(&self, silent: bool) {
        lock(&self.shared).silent = silent;
    }
}

/// Lance le serveur (pile smoltcp du moteur, `vpn::serve`) sur 127.0.0.1.
pub(crate) async fn start(opts: ServerOpts) -> ServerHandle {
    let (transport, listen_port, forward) = (opts.transport, opts.listen_port, opts.forward);
    let (link, mut handle) = link(opts);
    handle.port = crate::vpn::serve(link, transport, listen_port, forward).await;
    handle
}

/// Protocole serveur seul (sans E/S), pour piloter un client en mémoire.
pub(crate) fn link(mut opts: ServerOpts) -> (Box<dyn Link>, ServerHandle) {
    let pki = opts.pki.take().unwrap_or_else(|| Pki::generate(&opts.server_cn, "client"));
    let static_key = opts.static_key.take().unwrap_or_else(generate_static_key);
    let shared = Arc::new(Mutex::new(Shared::default()));
    let handle = ServerHandle {
        port: 0,
        transport: opts.transport,
        pki: pki.clone(),
        static_key: static_key.clone(),
        wrap: opts.wrap,
        cipher: opts.cipher.clone(),
        auth: opts.auth.clone(),
        user_pass: opts.user_pass.clone(),
        client_cert: opts.client_cert,
        compression: opts.compression,
        shared: shared.clone(),
    };
    (Box::new(ServerLink::new(opts, &pki, &static_key, shared)), handle)
}

fn tls_config(o: &ServerOpts, pki: &Pki) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] =
        if o.tls12_only { &[&rustls::version::TLS12] } else { rustls::ALL_VERSIONS };
    let b = rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions).unwrap();
    let b = match o.client_cert {
        ClientCert::None => b.with_no_client_auth(),
        req => {
            let mut roots = rustls::RootCertStore::empty();
            for c in CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()) {
                roots.add(c.unwrap()).unwrap();
            }
            let v = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
            let v = if req == ClientCert::Optional { v.allow_unauthenticated() } else { v };
            b.with_client_cert_verifier(v.build().unwrap())
        }
    };
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pki.server_cert_pem.as_bytes()).map(|c| c.unwrap()).collect();
    let key = PrivateKeyDer::from_pem_slice(pki.server_key_pem.as_bytes()).unwrap();
    Arc::new(b.with_single_cert(chain, key).unwrap())
}

// ------------------------------------------------------------------ key-method 2

/// Message key-method 2 du client.
pub(crate) struct ClientKm2 {
    pub source: ClientKeySource,
    pub options: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub peer_info: String,
}

/// Chaîne key-method 2 : longueur (2 octets, NUL compris) puis octets ; 0 = chaîne absente.
fn read_string(b: &[u8], pos: &mut usize) -> Result<Option<String>, ()> {
    let rest = &b[*pos..];
    if rest.len() < 2 {
        return Err(());
    }
    let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + n {
        return Err(());
    }
    *pos += 2 + n;
    let s = &rest[2..2 + n];
    let s = s.strip_suffix(&[0]).unwrap_or(s);
    Ok(Some(String::from_utf8_lossy(s).into_owned()))
}

/// Lit le message du client en tête de `b`. `Ok(None)` : incomplet. Les champs après les options
/// (identifiant, mot de passe, peer-info) sont facultatifs s'ils manquent entièrement.
pub(crate) fn parse_client_km2(b: &[u8]) -> Result<Option<(ClientKm2, usize)>, String> {
    let head = 4 + 1 + ClientKeySource::WIRE_LEN;
    if b.len() < head {
        return Ok(None);
    }
    if b[..4] != [0; 4] {
        return Err("key-method 2 : les 4 premiers octets doivent être nuls".into());
    }
    if b[4] & 0x0F != 2 {
        return Err(format!("key-method {} non pris en charge", b[4] & 0x0F));
    }
    let mut source = ClientKeySource { pre_master: Zeroizing::new([0; 48]), random1: [0; 32], random2: [0; 32] };
    source.pre_master.copy_from_slice(&b[5..53]);
    source.random1.copy_from_slice(&b[53..85]);
    source.random2.copy_from_slice(&b[85..117]);
    let mut pos = head;
    let Ok(options) = read_string(b, &mut pos) else { return Ok(None) };
    let opt = |pos: &mut usize| -> Result<Option<String>, ()> {
        if *pos == b.len() { Ok(None) } else { read_string(b, pos) }
    };
    let Ok(username) = opt(&mut pos) else { return Ok(None) };
    let Ok(password) = opt(&mut pos) else { return Ok(None) };
    let Ok(peer_info) = opt(&mut pos) else { return Ok(None) };
    Ok(Some((
        ClientKm2 {
            source,
            options: options.unwrap_or_default(),
            username: username.unwrap_or_default(),
            password: Zeroizing::new(password.unwrap_or_default()),
            peer_info: peer_info.unwrap_or_default(),
        },
        pos,
    )))
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&((s.len() + 1) as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// Message key-method 2 du serveur.
pub(crate) fn server_km2(src: &ServerKeySource, options: &str) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 0, 2];
    v.extend_from_slice(&src.to_wire());
    write_string(&mut v, options);
    // identifiant, mot de passe, peer-info : vides
    v.extend_from_slice(&[0; 6]);
    v
}

/// Valeur d'une clé `KEY=valeur` du peer-info.
fn peer_info_value<'a>(info: &'a str, key: &str) -> Option<&'a str> {
    info.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

// ------------------------------------------------------------------ sessions

struct KeyState {
    key_id: u8,
    rel: Reliable,
    tls: rustls::ServerConnection,
    /// Clair TLS reçu, pas encore traité.
    plain: Vec<u8>,
    tls_failed: bool,
    client_src: Option<ClientKeySource>,
    server_src: ServerKeySource,
    km2_done: bool,
    data: Option<DataChannel>,
    /// Le client a ses clés : on peut émettre avec celle-ci.
    tx_ready: bool,
    retire_at: Option<Instant>,
    born: Instant,
}

struct Session {
    client_sid: [u8; 8],
    server_sid: [u8; 8],
    wrap: Wrap,
    /// La plus récente en tête.
    keys: Vec<KeyState>,
    next_key_id: u8,
    iv_proto: u32,
    iv_ciphers: String,
    pushed: bool,
    auth_failed: bool,
    ekm: bool,
    peer_id: Option<u32>,
    last_data_tx: Instant,
}

fn next_key_id(k: u8) -> u8 {
    if k >= 7 { 1 } else { k + 1 }
}

fn unix_secs() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(1)
}

struct ServerLink {
    o: ServerOpts,
    tls_cfg: Arc<rustls::ServerConfig>,
    static_key: Zeroizing<Vec<u8>>,
    auth_digest: AuthDigest,
    digest: Digest,
    cipher: DataCipher,
    framer: TcpFramer,
    tcp_peer: Option<SocketAddr>,
    sess: Option<Session>,
    net: VecDeque<Vec<u8>>,
    ip: VecDeque<Vec<u8>>,
    state: LinkState,
    shared: Arc<Mutex<Shared>>,
    rng: SystemRandom,
}

impl ServerLink {
    fn new(o: ServerOpts, pki: &Pki, static_key: &str, shared: Arc<Mutex<Shared>>) -> Self {
        let static_key = if o.wrap == ControlWrap::None {
            Zeroizing::new(Vec::new())
        } else {
            packet::parse_static_key(static_key).unwrap()
        };
        let info = LinkInfo {
            addrs: vec![(IpAddr::V4(o.server_ip), o.prefix)],
            dns: Vec::new(),
            search: Vec::new(),
            routes: Vec::new(),
            mtu: o.mtu,
        };
        Self {
            tls_cfg: tls_config(&o, pki),
            auth_digest: AuthDigest::from_name(&o.auth).unwrap(),
            digest: Digest::from_name(if o.auth.trim().is_empty() { "SHA1" } else { &o.auth }).unwrap(),
            cipher: DataCipher::from_name(&o.cipher).unwrap(),
            static_key,
            framer: TcpFramer::new(),
            tcp_peer: None,
            sess: None,
            net: VecDeque::new(),
            ip: VecDeque::new(),
            state: LinkState::Up(info),
            shared,
            rng: SystemRandom::new(),
            o,
        }
    }

    fn error(&self, e: impl Into<String>) {
        lock(&self.shared).stats.errors.push(e.into());
    }

    fn fresh_wrap(&self) -> Wrap {
        match self.o.wrap {
            ControlWrap::None => Wrap::Plain,
            ControlWrap::TlsAuth { server_direction } => {
                Wrap::tls_auth(&self.static_key, server_direction, self.auth_digest).unwrap()
            }
            ControlWrap::TlsCrypt => Wrap::tls_crypt(&self.static_key, packet::Role::Server).unwrap(),
        }
    }

    fn new_key(&self, key_id: u8) -> KeyState {
        let mut r = [0u8; 64];
        let _ = self.rng.fill(&mut r);
        let mut server_src = ServerKeySource { random1: [0; 32], random2: [0; 32] };
        server_src.random1.copy_from_slice(&r[..32]);
        server_src.random2.copy_from_slice(&r[32..]);
        KeyState {
            key_id,
            rel: Reliable::new(ReliableConfig::default()),
            tls: rustls::ServerConnection::new(self.tls_cfg.clone()).unwrap(),
            plain: Vec::new(),
            tls_failed: false,
            client_src: None,
            server_src,
            km2_done: false,
            data: None,
            tx_ready: false,
            retire_at: None,
            born: Instant::now(),
        }
    }

    fn push_net(&mut self, pkt: Vec<u8>) {
        if lock(&self.shared).silent {
            return;
        }
        self.net.push_back(match self.o.transport {
            Transport::Tcp => packet::frame(&pkt),
            Transport::Udp => pkt,
        });
    }

    /// Un paquet complet du client. Vrai s'il est authentique.
    fn packet(&mut self, raw: &[u8]) -> bool {
        let Some((opcode, _)) = packet::peek_opcode(raw) else { return false };
        if packet::is_data(opcode) {
            return self.data_in(raw);
        }
        if !packet::is_control(opcode) || raw.len() < 9 {
            return false;
        }
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&raw[1..9]);
        let current = self.sess.as_ref().is_some_and(|s| s.client_sid == sid);
        if opcode == packet::P_CONTROL_HARD_RESET_CLIENT_V2 && !current {
            return self.hard_reset(raw);
        }
        if !current {
            return false;
        }
        let pkt = match self.sess.as_mut().map(|s| s.wrap.unwrap(raw)) {
            Some(Ok(p)) => p,
            Some(Err(e)) => {
                self.error(e);
                return false;
            }
            None => return false,
        };
        self.control(pkt);
        true
    }

    fn hard_reset(&mut self, raw: &[u8]) -> bool {
        let mut wrap = self.fresh_wrap();
        let pkt = match wrap.unwrap(raw) {
            Ok(p) => p,
            Err(e) => {
                self.error(e);
                return false;
            }
        };
        let mut server_sid = [0u8; 8];
        let _ = self.rng.fill(&mut server_sid);
        let mut key = self.new_key(0);
        key.rel.send(packet::P_CONTROL_HARD_RESET_SERVER_V2, &[]);
        self.sess = Some(Session {
            client_sid: pkt.session_id,
            server_sid,
            wrap,
            keys: vec![key],
            next_key_id: 1,
            iv_proto: 0,
            iv_ciphers: String::new(),
            pushed: false,
            auth_failed: false,
            ekm: false,
            peer_id: None,
            last_data_tx: Instant::now(),
        });
        lock(&self.shared).stats.hard_resets += 1;
        self.control(pkt);
        true
    }

    /// Paquet de contrôle authentifié de la session courante.
    fn control(&mut self, pkt: ControlPacket) {
        let Some(s) = self.sess.as_mut() else { return };
        if pkt.remote_session_id.is_some_and(|r| r != s.server_sid) {
            lock(&self.shared).stats.errors.push("paquet de contrôle pour une autre session serveur".into());
            return;
        }
        let known = s.keys.iter().any(|k| k.key_id == pkt.key_id);
        if !known {
            if pkt.opcode != packet::P_CONTROL_SOFT_RESET_V1 || pkt.key_id == 0 {
                return;
            }
            // renégociation lancée par le client : notre propre SOFT_RESET part aussi
            let mut k = self.new_key(pkt.key_id);
            k.rel.send(packet::P_CONTROL_SOFT_RESET_V1, &[]);
            let s = self.sess.as_mut().unwrap();
            s.next_key_id = next_key_id(pkt.key_id);
            s.keys.insert(0, k);
            s.keys.truncate(3);
        }
        let s = self.sess.as_mut().unwrap();
        let Some(i) = s.keys.iter().position(|k| k.key_id == pkt.key_id) else { return };
        s.keys[i].rel.on_acks(&pkt.acks);
        if pkt.opcode != packet::P_ACK_V1
            && let Some(id) = pkt.packet_id
        {
            s.keys[i].rel.on_packet(id, pkt.opcode, &pkt.payload);
        }
        self.tls_progress(i);
        self.flush_control();
    }

    /// Fait avancer le TLS de la clé `i` avec ce que la couche fiable a remis.
    fn tls_progress(&mut self, i: usize) {
        let Some(s) = self.sess.as_mut() else { return };
        let k = &mut s.keys[i];
        let mut err = None;
        while let Some((op, payload)) = k.rel.recv() {
            if op != packet::P_CONTROL_V1 || k.tls_failed {
                continue;
            }
            let mut rd = &payload[..];
            while !rd.is_empty() {
                match k.tls.read_tls(&mut rd) {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Err(e) = k.tls.process_new_packets() {
                            err = Some(format!("TLS : {e}"));
                            k.tls_failed = true;
                            break;
                        }
                    }
                    Err(e) => {
                        err = Some(format!("TLS : {e}"));
                        k.tls_failed = true;
                        break;
                    }
                }
            }
        }
        if !k.tls_failed {
            let mut buf = [0u8; 4096];
            loop {
                match k.tls.reader().read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => k.plain.extend_from_slice(&buf[..n]),
                }
            }
        }
        if let Some(e) = err {
            self.error(e);
        }
        self.messages(i);
        self.tls_out(i);
    }

    /// Envoie ce que rustls a produit sur le canal de contrôle de la clé `i`.
    fn tls_out(&mut self, i: usize) {
        let Some(s) = self.sess.as_mut() else { return };
        let k = &mut s.keys[i];
        let mut out = Vec::new();
        while k.tls.wants_write() {
            if k.tls.write_tls(&mut out).is_err() {
                break;
            }
        }
        if !out.is_empty() {
            k.rel.send(packet::P_CONTROL_V1, &out);
        }
    }

    /// Messages en clair : key-method 2, puis chaînes terminées par NUL.
    fn messages(&mut self, i: usize) {
        let Some(s) = self.sess.as_mut() else { return };
        if !s.keys[i].km2_done
            && !s.keys[i].tls.is_handshaking()
            && let Some(v) = s.keys[i].tls.protocol_version()
        {
            lock(&self.shared).stats.tls_version = format!("{v:?}");
        }
        if !s.keys[i].km2_done {
            let k = &mut s.keys[i];
            match parse_client_km2(&k.plain) {
                Ok(None) => return,
                Ok(Some((km, used))) => {
                    k.plain.drain(..used);
                    self.key_method(i, km);
                }
                Err(e) => {
                    k.plain.clear();
                    k.tls_failed = true;
                    self.error(e);
                    return;
                }
            }
        }
        loop {
            let Some(s) = self.sess.as_mut() else { return };
            let k = &mut s.keys[i];
            let Some(end) = k.plain.iter().position(|&b| b == 0) else { return };
            let msg: Vec<u8> = k.plain.drain(..=end).collect();
            let msg = String::from_utf8_lossy(&msg[..end]).into_owned();
            match msg.as_str() {
                "PUSH_REQUEST" => self.push_reply(i),
                "EXIT" => lock(&self.shared).stats.exit_notified = true,
                _ => lock(&self.shared).stats.control_messages.push(msg),
            }
        }
    }

    fn key_method(&mut self, i: usize, km: ClientKm2) {
        let o = &self.o;
        let s = self.sess.as_mut().unwrap();
        let initial = s.keys[i].key_id == 0 && !s.pushed;
        {
            let mut sh = lock(&self.shared);
            sh.stats.username = km.username.clone();
            sh.stats.client_options = km.options.clone();
            if initial {
                sh.stats.peer_info = km.peer_info.clone();
            }
        }
        if initial {
            s.iv_proto = peer_info_value(&km.peer_info, "IV_PROTO").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
            s.iv_ciphers = peer_info_value(&km.peer_info, "IV_CIPHERS").unwrap_or("").to_string();
            if let Some((u, p)) = &o.user_pass
                && (km.username != *u || *km.password != *p)
            {
                s.auth_failed = true;
                lock(&self.shared).stats.auth_failures += 1;
            }
        }
        let options = format!(
            "V4,dev-type tun,link-mtu 1549,tun-mtu {},proto {},cipher {},auth {},keysize 256,key-method 2,tls-server",
            o.mtu,
            if o.transport == Transport::Tcp { "TCPv4_SERVER" } else { "UDPv4" },
            self.cipher.name(),
            if self.cipher.is_aead() { "[null-digest]" } else { o.auth.as_str() },
        );
        let k = &mut s.keys[i];
        k.km2_done = true;
        k.client_src = Some(km.source);
        let reply = server_km2(&k.server_src, &options);
        let _ = k.tls.writer().write_all(&reply);
        if !initial {
            // renégociation : réglages de la session, clés tout de suite
            self.derive(i);
        } else if s.iv_proto & IV_PROTO_REQUEST_PUSH != 0 && o.request_push {
            self.push_reply(i);
        }
    }

    /// Met en place les clés de données de la clé `i`.
    fn derive(&mut self, i: usize) {
        let s = self.sess.as_mut().unwrap();
        let (csid, ssid, ekm) = (s.client_sid, s.server_sid, s.ekm);
        let k = &mut s.keys[i];
        if k.data.is_some() {
            return;
        }
        let key2 = if ekm {
            let mut out = Zeroizing::new([0u8; data::KEY2_LEN]);
            match k.tls.export_keying_material(&mut out[..], data::EKM_LABEL, None) {
                Ok(_) => Key2::from_bytes(&out[..]),
                Err(e) => Err(format!("exportateur TLS : {e}")),
            }
        } else {
            match &k.client_src {
                Some(c) => Ok(data::derive_key2_prf(c, &k.server_src, &csid, &ssid)),
                None => Err("key-method 2 du client absent".into()),
            }
        };
        let r = key2.and_then(|key2| DataChannel::new(self.cipher, self.digest, &key2, data::Role::Server));
        match r {
            Ok(d) => {
                k.data = Some(d);
                let mut sh = lock(&self.shared);
                sh.stats.keys_established.push(k.key_id);
                sh.stats.ekm = ekm;
            }
            Err(e) => self.error(e),
        }
    }

    fn push_reply(&mut self, i: usize) {
        let o = &self.o;
        let s = self.sess.as_mut().unwrap();
        let write = |k: &mut KeyState, m: &str| {
            let _ = k.tls.writer().write_all(m.as_bytes());
            let _ = k.tls.writer().write_all(&[0]);
        };
        if !s.pushed && !s.auth_failed && o.push_cipher && !s.iv_ciphers.is_empty() {
            let name = self.cipher.name();
            if !s.iv_ciphers.split(':').any(|c| c.trim().eq_ignore_ascii_case(name)) {
                s.auth_failed = true;
                lock(&self.shared).stats.auth_failures += 1;
                lock(&self.shared).stats.errors.push(format!("pas de chiffrement commun ({})", s.iv_ciphers));
            }
        }
        if s.auth_failed {
            write(&mut s.keys[i], "AUTH_FAILED");
            return;
        }
        if !s.pushed {
            s.peer_id = o.peer_id.filter(|_| s.iv_proto & IV_PROTO_DATA_V2 != 0);
            s.ekm = o.ekm != Ekm::Off && s.iv_proto & IV_PROTO_TLS_KEY_EXPORT != 0;
        }
        let mut opts = o.push.clone();
        if let Some((p, r)) = o.ping {
            opts.push(format!("ping {p}"));
            opts.push(format!("ping-restart {r}"));
        }
        if let Some(id) = s.peer_id {
            opts.push(format!("peer-id {id}"));
        }
        if o.push_cipher {
            opts.push(format!("cipher {}", self.cipher.name()));
        }
        if s.ekm {
            opts.push(match o.ekm {
                Ekm::KeyDerivation => "key-derivation tls-ekm".into(),
                _ => "protocol-flags cc-exit tls-ekm".into(),
            });
        }
        let k = &mut s.keys[i];
        if o.split_push && opts.len() >= 2 {
            let half = opts.len() / 2;
            write(k, &format!("PUSH_REPLY,{},push-continuation 2", opts[..half].join(",")));
            write(k, &format!("PUSH_REPLY,{},push-continuation 1", opts[half..].join(",")));
        } else {
            write(k, &format!("PUSH_REPLY,{}", opts.join(",")));
        }
        let first = !s.pushed;
        s.pushed = true;
        {
            let mut sh = lock(&self.shared);
            sh.stats.pushes += 1;
            if first {
                sh.stats.peer_id = s.peer_id;
                sh.stats.cipher = self.cipher.name().into();
            }
        }
        self.derive(i);
    }

    /// Émet les paquets de contrôle en attente (réémissions comprises) et les accusés seuls.
    fn flush_control(&mut self) {
        let now = Instant::now();
        let t = unix_secs();
        let mut out = Vec::new();
        let mut failed = None;
        if let Some(s) = self.sess.as_mut() {
            let (csid, ssid) = (s.client_sid, s.server_sid);
            for k in &mut s.keys {
                while let Some(o) = k.rel.poll_transmit(now) {
                    let p = ControlPacket {
                        opcode: o.opcode,
                        key_id: k.key_id,
                        session_id: ssid,
                        remote_session_id: Some(csid),
                        acks: o.acks,
                        packet_id: Some(o.packet_id),
                        payload: o.payload,
                    };
                    out.push(s.wrap.wrap(&p, t));
                }
                while let Some(acks) = k.rel.take_acks() {
                    let p = ControlPacket {
                        opcode: packet::P_ACK_V1,
                        key_id: k.key_id,
                        session_id: ssid,
                        remote_session_id: Some(csid),
                        acks,
                        packet_id: None,
                        payload: Vec::new(),
                    };
                    out.push(s.wrap.wrap(&p, t));
                }
                if k.data.is_some() && k.km2_done && k.rel.pending_count() == 0 {
                    k.tx_ready = true;
                }
                if let Some(e) = k.rel.failed() {
                    failed = Some(e);
                }
            }
        }
        for p in out {
            self.push_net(p);
        }
        if let Some(e) = failed {
            self.error(e);
            self.sess = None;
        }
        self.retire();
    }

    /// Dès qu'une clé plus récente émet, les anciennes ne servent plus qu'à recevoir un temps.
    fn retire(&mut self) {
        let Some(s) = self.sess.as_mut() else { return };
        let now = Instant::now();
        if let Some(i) = s.keys.iter().position(|k| k.tx_ready) {
            for k in &mut s.keys[i + 1..] {
                k.retire_at.get_or_insert(now + TRANSITION_WINDOW);
            }
        }
        s.keys.retain(|k| k.retire_at.is_none_or(|t| t > now));
    }

    fn data_in(&mut self, raw: &[u8]) -> bool {
        let Some(s) = self.sess.as_mut() else { return false };
        let Ok((hdr, body)) = DataHeader::parse(raw) else { return false };
        let header = &raw[..hdr.header_len()];
        if let (Some(want), Some(got)) = (s.peer_id, hdr.peer_id)
            && want != got
        {
            lock(&self.shared).stats.errors.push(format!("peer-id {got} au lieu de {want}"));
            return false;
        }
        let Some(k) = s.keys.iter_mut().find(|k| k.key_id == hdr.key_id && k.data.is_some()) else { return false };
        let plain = match k.data.as_mut().map(|d| d.decrypt(body, header)) {
            Some(Ok(p)) => p,
            Some(Err(e)) => {
                lock(&self.shared).stats.errors.push(e);
                return false;
            }
            None => return false,
        };
        k.tx_ready = true;
        let key_id = k.key_id;
        let plain = match self.o.compression.unframe(plain) {
            Ok(p) => p,
            Err(e) => {
                self.error(e);
                return true;
            }
        };
        let mut sh = lock(&self.shared);
        sh.stats.data_v2_rx |= hdr.peer_id.is_some();
        sh.stats.last_rx_key = Some(key_id);
        if data::is_ping(&plain) {
            sh.stats.pings_in += 1;
        } else if plain.len() > 16 && plain[..16] == OCC_MAGIC {
            if plain[16] == OCC_EXIT {
                sh.stats.exit_notified = true;
            }
        } else {
            sh.stats.packets_in += 1;
            drop(sh);
            self.ip.push_back(plain);
            return true;
        }
        drop(sh);
        self.retire();
        true
    }

    /// Chiffre un paquet (IP ou ping) avec la clé d'émission courante.
    fn data_out(&mut self, plain: &[u8]) -> bool {
        let Some(s) = self.sess.as_mut() else { return false };
        let peer_id = s.peer_id;
        let Some(k) = s.keys.iter_mut().find(|k| k.tx_ready && k.data.is_some()) else { return false };
        let key_id = k.key_id;
        let framed = self.o.compression.frame(plain.to_vec());
        let Some(Ok(pkt)) = k.data.as_mut().map(|d| d.encrypt(&framed, &data::data_header(key_id, peer_id))) else {
            return false;
        };
        s.last_data_tx = Instant::now();
        lock(&self.shared).stats.last_tx_key = Some(key_id);
        self.push_net(pkt);
        true
    }

    fn renegotiate(&mut self) {
        let Some(s) = self.sess.as_ref() else { return };
        if !s.pushed || s.keys.first().is_some_and(|k| k.data.is_none()) {
            return; // négociation déjà en cours
        }
        let id = s.next_key_id;
        let mut k = self.new_key(id);
        k.rel.send(packet::P_CONTROL_SOFT_RESET_V1, &[]);
        let s = self.sess.as_mut().unwrap();
        s.next_key_id = next_key_id(id);
        s.keys.insert(0, k);
        s.keys.truncate(3);
        self.flush_control();
    }

    fn restart(&mut self, reason: &str) {
        let Some(s) = self.sess.as_mut() else { return };
        let Some(i) = s.keys.iter().position(|k| k.km2_done) else { return };
        let msg = if reason.is_empty() { "RESTART".to_string() } else { format!("RESTART,{reason}") };
        let k = &mut s.keys[i];
        let _ = k.tls.writer().write_all(msg.as_bytes());
        let _ = k.tls.writer().write_all(&[0]);
        self.tls_out(i);
        self.flush_control();
    }
}

impl Link for ServerLink {
    fn input(&mut self, data: &[u8], from: Option<SocketAddr>) -> bool {
        if lock(&self.shared).silent {
            return false;
        }
        match self.o.transport {
            Transport::Udp => self.packet(data),
            Transport::Tcp => {
                // nouveau client TCP (le moteur remplace l'ancien) : flux repris de zéro
                if from.is_some() && from != self.tcp_peer {
                    self.tcp_peer = from;
                    self.framer = TcpFramer::new();
                }
                self.framer.push(data);
                let mut ok = false;
                loop {
                    match self.framer.next_packet() {
                        Ok(Some(p)) => ok |= self.packet(&p),
                        Ok(None) => break,
                        Err(e) => {
                            self.error(e);
                            self.framer = TcpFramer::new();
                            self.sess = None;
                            break;
                        }
                    }
                }
                ok
            }
        }
    }

    fn send_ip(&mut self, packet: &[u8]) {
        if self.data_out(packet) {
            lock(&self.shared).stats.packets_out += 1;
        }
    }

    fn tick(&mut self) {
        let ctl: Vec<Ctl> = lock(&self.shared).ctl.drain(..).collect();
        for c in ctl {
            match c {
                Ctl::Renegotiate => self.renegotiate(),
                Ctl::Restart(r) => self.restart(&r),
                Ctl::Kill => self.sess = None,
            }
        }
        let ping_due = match (self.o.ping, &self.sess) {
            (Some((ping, _)), Some(s)) => s.pushed && s.last_data_tx.elapsed() >= Duration::from_secs(ping as u64),
            _ => false,
        };
        if ping_due && self.data_out(&data::PING_MAGIC) {
            lock(&self.shared).stats.pings_out += 1;
        }
        let reneg_due = match (self.o.reneg_after, &self.sess) {
            (Some(after), Some(s)) => s.keys.first().is_some_and(|k| k.data.is_some() && k.born.elapsed() >= after),
            _ => false,
        };
        if reneg_due {
            self.renegotiate();
        }
        self.flush_control();
    }

    fn recv_ip(&mut self) -> Option<Vec<u8>> {
        self.ip.pop_front()
    }

    fn poll_net(&mut self) -> Option<Vec<u8>> {
        self.net.pop_front()
    }

    fn state(&self) -> &LinkState {
        &self.state
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Client OpenVPN minimal, écrit d'après le protocole et non d'après `control` : il ne sert
    /// qu'à éprouver le serveur.
    struct Cli {
        tcp: bool,
        sid: [u8; 8],
        server_sid: Option<[u8; 8]>,
        wrap: Wrap,
        keys: Vec<CliKey>,
        framer: TcpFramer,
        out: VecDeque<Vec<u8>>,
        cfg: Arc<rustls::ClientConfig>,
        user: (String, String),
        iv_proto: u32,
        ciphers: String,
        fallback: DataCipher,
        digest: Digest,
        comp: Compression,
        // résultats
        push_reply: String,
        auth_failed: bool,
        messages: Vec<String>,
        peer_id: Option<u32>,
        ekm: bool,
        cipher: Option<DataCipher>,
        ip: Vec<Vec<u8>>,
        pings: u32,
    }

    struct CliKey {
        key_id: u8,
        rel: Reliable,
        tls: rustls::ClientConnection,
        plain: Vec<u8>,
        src: ClientKeySource,
        km2_sent: bool,
        server_src: Option<ServerKeySource>,
        data: Option<DataChannel>,
    }

    impl Cli {
        fn new(h: &ServerHandle, iv_proto: u32, ciphers: &str) -> Self {
            let c = h.client_config();
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(c.ca.as_bytes()) {
                roots.add(cert.unwrap()).unwrap();
            }
            let b = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots);
            let cfg = if c.cert.is_empty() {
                b.with_no_client_auth()
            } else {
                let chain = CertificateDer::pem_slice_iter(c.cert.as_bytes()).map(|c| c.unwrap()).collect();
                b.with_client_auth_cert(chain, PrivateKeyDer::from_pem_slice(c.key.as_bytes()).unwrap()).unwrap()
            };
            let key = parse_static(&c);
            let wrap = if !c.tls_crypt.is_empty() {
                Wrap::tls_crypt(&key, packet::Role::Client).unwrap()
            } else if !c.tls_auth.is_empty() {
                Wrap::tls_auth(&key, c.key_direction.parse().ok(), AuthDigest::from_name(&c.auth).unwrap()).unwrap()
            } else {
                Wrap::Plain
            };
            let mut sid = [0u8; 8];
            SystemRandom::new().fill(&mut sid).unwrap();
            let mut cli = Self {
                tcp: c.proto == OpenVpnProto::Tcp,
                sid,
                server_sid: None,
                wrap,
                keys: Vec::new(),
                framer: TcpFramer::new(),
                out: VecDeque::new(),
                cfg: Arc::new(cfg),
                user: h.credentials(),
                iv_proto,
                ciphers: ciphers.into(),
                fallback: DataCipher::from_name(&c.cipher).unwrap(),
                digest: Digest::from_name(if c.auth.is_empty() { "SHA1" } else { &c.auth }).unwrap(),
                comp: h.compression,
                push_reply: String::new(),
                auth_failed: false,
                messages: Vec::new(),
                peer_id: None,
                ekm: false,
                cipher: None,
                ip: Vec::new(),
                pings: 0,
            };
            let mut k = cli.new_key(0);
            k.rel.send(packet::P_CONTROL_HARD_RESET_CLIENT_V2, &[]);
            cli.keys.push(k);
            cli.flush();
            cli
        }

        fn new_key(&self, key_id: u8) -> CliKey {
            CliKey {
                key_id,
                rel: Reliable::new(ReliableConfig::default()),
                tls: rustls::ClientConnection::new(self.cfg.clone(), "server".try_into().unwrap()).unwrap(),
                plain: Vec::new(),
                src: ClientKeySource::generate().unwrap(),
                km2_sent: false,
                server_src: None,
                data: None,
            }
        }

        fn send_raw(&mut self, p: Vec<u8>) {
            self.out.push_back(if self.tcp { packet::frame(&p) } else { p });
        }

        fn flush(&mut self) {
            let now = Instant::now();
            let t = unix_secs();
            let mut out = Vec::new();
            for k in &mut self.keys {
                // le TLS ne démarre qu'une fois la réinitialisation acquittée
                if k.rel.pending_count() == 0 || k.km2_sent || !k.tls.is_handshaking() {
                    let mut tls = Vec::new();
                    while k.tls.wants_write() {
                        k.tls.write_tls(&mut tls).unwrap();
                    }
                    if !tls.is_empty() {
                        k.rel.send(packet::P_CONTROL_V1, &tls);
                    }
                }
                while let Some(o) = k.rel.poll_transmit(now) {
                    let p = ControlPacket {
                        opcode: o.opcode,
                        key_id: k.key_id,
                        session_id: self.sid,
                        remote_session_id: self.server_sid,
                        acks: o.acks,
                        packet_id: Some(o.packet_id),
                        payload: o.payload,
                    };
                    out.push(self.wrap.wrap(&p, t));
                }
                while let Some(acks) = k.rel.take_acks() {
                    let p = ControlPacket {
                        opcode: packet::P_ACK_V1,
                        key_id: k.key_id,
                        session_id: self.sid,
                        remote_session_id: self.server_sid,
                        acks,
                        packet_id: None,
                        payload: Vec::new(),
                    };
                    out.push(self.wrap.wrap(&p, t));
                }
            }
            for p in out {
                self.send_raw(p);
            }
        }

        fn input(&mut self, data: &[u8]) {
            if self.tcp {
                self.framer.push(data);
                while let Some(p) = self.framer.next_packet().unwrap() {
                    self.packet(&p);
                }
            } else {
                self.packet(data);
            }
            self.flush();
        }

        fn packet(&mut self, raw: &[u8]) {
            let (op, _) = packet::peek_opcode(raw).unwrap();
            if packet::is_data(op) {
                let (hdr, body) = DataHeader::parse(raw).unwrap();
                let k = self.keys.iter_mut().find(|k| k.key_id == hdr.key_id).unwrap();
                let plain = k.data.as_mut().unwrap().decrypt(body, &raw[..hdr.header_len()]).unwrap();
                let plain = self.comp.unframe(plain).unwrap();
                if data::is_ping(&plain) {
                    self.pings += 1;
                } else {
                    self.ip.push(plain);
                }
                return;
            }
            let p = self.wrap.unwrap(raw).unwrap();
            if self.server_sid.is_none() {
                assert_eq!(p.opcode, packet::P_CONTROL_HARD_RESET_SERVER_V2);
                self.server_sid = Some(p.session_id);
            }
            assert_eq!(Some(p.session_id), self.server_sid);
            if let Some(r) = p.remote_session_id {
                assert_eq!(r, self.sid);
            }
            if !self.keys.iter().any(|k| k.key_id == p.key_id) {
                assert_eq!(p.opcode, packet::P_CONTROL_SOFT_RESET_V1);
                let mut k = self.new_key(p.key_id);
                k.rel.send(packet::P_CONTROL_SOFT_RESET_V1, &[]);
                self.keys.insert(0, k);
            }
            let i = self.keys.iter().position(|k| k.key_id == p.key_id).unwrap();
            let k = &mut self.keys[i];
            k.rel.on_acks(&p.acks);
            if let Some(id) = p.packet_id {
                k.rel.on_packet(id, p.opcode, &p.payload);
            }
            while let Some((op, payload)) = k.rel.recv() {
                if op == packet::P_CONTROL_V1 {
                    let mut rd = &payload[..];
                    while !rd.is_empty() {
                        k.tls.read_tls(&mut rd).unwrap();
                        k.tls.process_new_packets().unwrap();
                    }
                }
            }
            let mut buf = [0u8; 4096];
            while let Ok(n) = k.tls.reader().read(&mut buf) {
                if n == 0 {
                    break;
                }
                k.plain.extend_from_slice(&buf[..n]);
            }
            if !k.km2_sent && !k.tls.is_handshaking() {
                let mut m = vec![0, 0, 0, 0, 2];
                m.extend_from_slice(&k.src.to_wire());
                write_string(&mut m, "V4,dev-type tun,tls-client");
                write_string(&mut m, &self.user.0);
                write_string(&mut m, &self.user.1);
                let info = format!(
                    "IV_VER=2.6.0\nIV_PLAT=win\nIV_PROTO={}\nIV_NCP=2\nIV_CIPHERS={}\n",
                    self.iv_proto, self.ciphers
                );
                write_string(&mut m, &info);
                k.tls.writer().write_all(&m).unwrap();
                k.km2_sent = true;
            }
            self.client_messages(i);
        }

        fn client_messages(&mut self, i: usize) {
            let k = &mut self.keys[i];
            if k.server_src.is_none() {
                // 0u32 | 2 | 64 octets | options | 3 chaînes vides
                if k.plain.len() < 69 + 2 {
                    return;
                }
                assert_eq!(&k.plain[..5], &[0, 0, 0, 0, 2]);
                k.server_src = Some(ServerKeySource::from_wire(&k.plain[5..69]).unwrap());
                let mut pos = 69;
                let opts = read_string(&k.plain, &mut pos).unwrap().unwrap();
                assert!(opts.contains("tls-server"), "{opts}");
                assert_eq!(&k.plain[pos..pos + 6], &[0; 6]);
                k.plain.drain(..pos + 6);
                if k.key_id == 0 {
                    if self.iv_proto & IV_PROTO_REQUEST_PUSH == 0 {
                        k.tls.writer().write_all(b"PUSH_REQUEST\0").unwrap();
                    }
                } else {
                    let key2 = self.key2(i);
                    let c = self.cipher.unwrap();
                    self.keys[i].data = Some(DataChannel::new(c, self.digest, &key2, data::Role::Client).unwrap());
                }
            }
            loop {
                let k = &mut self.keys[i];
                let Some(end) = k.plain.iter().position(|&b| b == 0) else { return };
                let m: Vec<u8> = k.plain.drain(..=end).collect();
                let m = String::from_utf8(m[..end].to_vec()).unwrap();
                if let Some(rest) = m.strip_prefix("PUSH_REPLY,") {
                    if !self.push_reply.is_empty() {
                        self.push_reply.push(',');
                    }
                    self.push_reply.push_str(rest);
                    if rest.ends_with("push-continuation 2") {
                        continue;
                    }
                    self.apply_push();
                    let key2 = self.key2(i);
                    let c = self.cipher.unwrap();
                    self.keys[i].data = Some(DataChannel::new(c, self.digest, &key2, data::Role::Client).unwrap());
                } else if m.starts_with("AUTH_FAILED") {
                    self.auth_failed = true;
                } else {
                    self.messages.push(m);
                }
            }
        }

        fn apply_push(&mut self) {
            let mut cipher = self.fallback;
            for o in self.push_reply.split(',') {
                let w: Vec<&str> = o.split_whitespace().collect();
                match w.as_slice() {
                    ["peer-id", id] => self.peer_id = Some(id.parse().unwrap()),
                    ["cipher", c] => cipher = DataCipher::from_name(c).unwrap(),
                    ["key-derivation", "tls-ekm"] => self.ekm = true,
                    ["protocol-flags", flags @ ..] => self.ekm |= flags.contains(&"tls-ekm"),
                    _ => {}
                }
            }
            self.cipher = Some(cipher);
        }

        fn key2(&self, i: usize) -> Key2 {
            let k = &self.keys[i];
            if self.ekm {
                let mut out = [0u8; 256];
                k.tls.export_keying_material(&mut out, data::EKM_LABEL, None).unwrap();
                Key2::from_bytes(&out).unwrap()
            } else {
                data::derive_key2_prf(&k.src, k.server_src.as_ref().unwrap(), &self.sid, &self.server_sid.unwrap())
            }
        }

        /// Envoie des données sur la clé la plus récente qui en a.
        fn send_data(&mut self, plain: &[u8]) {
            let peer = self.peer_id;
            let k = self.keys.iter_mut().find(|k| k.data.is_some()).unwrap();
            let framed = self.comp.frame(plain.to_vec());
            let p = k.data.as_mut().unwrap().encrypt(&framed, &data::data_header(k.key_id, peer)).unwrap();
            self.send_raw(p);
        }

        fn up(&self) -> bool {
            self.keys.iter().any(|k| k.data.is_some())
        }
    }

    fn parse_static(c: &OpenVpnConfig) -> Zeroizing<Vec<u8>> {
        let t = if !c.tls_crypt.is_empty() { &c.tls_crypt } else { &c.tls_auth };
        if t.is_empty() { Zeroizing::new(Vec::new()) } else { packet::parse_static_key(t).unwrap() }
    }

    /// Échange les paquets entre les deux côtés jusqu'à épuisement. `chunk` : découpe du flux TCP.
    fn pump(srv: &mut dyn Link, cli: &mut Cli, chunk: usize) {
        let from: SocketAddr = ([127, 0, 0, 1], 50000).into();
        for _ in 0..200 {
            let mut moved = false;
            while let Some(b) = cli.out.pop_front() {
                moved = true;
                for c in b.chunks(chunk.max(1)) {
                    srv.input(c, Some(from));
                }
            }
            while let Some(b) = srv.poll_net() {
                moved = true;
                cli.input(&b);
            }
            if !moved {
                return;
            }
        }
        panic!("échange sans fin");
    }

    const ALL_PROTO: u32 = IV_PROTO_DATA_V2 | IV_PROTO_REQUEST_PUSH | IV_PROTO_TLS_KEY_EXPORT;
    const CIPHERS: &str = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";

    /// Paquet IP quelconque (le serveur ne l'interprète pas, smoltcp le fera).
    fn ip_packet(n: usize) -> Vec<u8> {
        let mut p = vec![0x45u8; n];
        for (i, b) in p.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        p
    }

    fn roundtrip(srv: &mut dyn Link, cli: &mut Cli, chunk: usize) {
        for n in [1usize, 20, 1400] {
            let p = ip_packet(n);
            cli.send_data(&p);
            pump(srv, cli, chunk);
            assert_eq!(srv.recv_ip().as_deref(), Some(&p[..]));
            srv.send_ip(&p);
            pump(srv, cli, chunk);
            assert_eq!(cli.ip.pop().as_deref(), Some(&p[..]));
        }
    }

    #[test]
    fn udp_tls_crypt_gcm_ekm_peer_id() {
        let (mut srv, h) = link(ServerOpts { wrap: ControlWrap::TlsCrypt, ..Default::default() });
        let mut cli = Cli::new(&h, ALL_PROTO, CIPHERS);
        pump(srv.as_mut(), &mut cli, usize::MAX);
        assert!(cli.up(), "{:?}", h.stats().errors);
        assert!(cli.push_reply.contains("ifconfig 10.8.0.2 255.255.255.0"), "{}", cli.push_reply);
        assert!(cli.push_reply.contains("cipher AES-256-GCM"));
        assert!(cli.ekm && cli.peer_id == Some(0));
        roundtrip(srv.as_mut(), &mut cli, usize::MAX);
        let s = h.stats();
        assert!(s.ekm && s.data_v2_rx && s.errors.is_empty(), "{s:?}");
        assert_eq!((s.hard_resets, s.pushes, s.keys_established.as_slice()), (1, 1, &[0u8][..]));
        assert!(s.peer_info.contains("IV_VER=2.6.0"));
        assert_eq!(s.tls_version, "TLSv1_3");
        // ping et fin annoncée
        cli.send_data(&data::PING_MAGIC);
        let mut exit = OCC_MAGIC.to_vec();
        exit.push(OCC_EXIT);
        cli.send_data(&exit);
        pump(srv.as_mut(), &mut cli, usize::MAX);
        let s = h.stats();
        assert_eq!(s.pings_in, 1);
        assert!(s.exit_notified && srv.recv_ip().is_none());
    }

    #[test]
    fn tcp_tls_auth_cbc_lzo_password_without_ekm() {
        let (mut srv, h) = link(ServerOpts {
            transport: Transport::Tcp,
            wrap: ControlWrap::TlsAuth { server_direction: Some(0) },
            cipher: "AES-256-CBC".into(),
            auth: "SHA256".into(),
            compression: Compression::Lzo,
            user_pass: Some(("test".into(), "secret".into())),
            ..Default::default()
        });
        assert_eq!(h.client_config().key_direction, "1");
        assert_eq!(h.client_config().data_ciphers, "AES-256-CBC");
        // client 2.4 : ni DATA_V2, ni REQUEST_PUSH, ni EKM
        let mut cli = Cli::new(&h, 0, "AES-256-GCM:AES-256-CBC");
        pump(srv.as_mut(), &mut cli, 3);
        assert!(cli.up(), "{:?}", h.stats().errors);
        assert!(!cli.ekm && cli.peer_id.is_none());
        roundtrip(srv.as_mut(), &mut cli, 5);
        let s = h.stats();
        assert_eq!(s.username, "test");
        assert!(!s.ekm && !s.data_v2_rx && s.peer_id.is_none() && s.errors.is_empty(), "{s:?}");
    }

    #[test]
    fn wrong_password_and_no_shared_cipher_get_auth_failed() {
        let (mut srv, h) = link(ServerOpts { user_pass: Some(("test".into(), "secret".into())), ..Default::default() });
        let mut cli = Cli::new(&h, ALL_PROTO, CIPHERS);
        cli.user.1 = "faux".into();
        pump(srv.as_mut(), &mut cli, usize::MAX);
        assert!(cli.auth_failed && !cli.up());
        assert_eq!(h.stats().auth_failures, 1);

        let (mut srv, h) = link(ServerOpts { cipher: "AES-128-CBC".into(), ..Default::default() });
        let mut cli = Cli::new(&h, IV_PROTO_DATA_V2, CIPHERS);
        pump(srv.as_mut(), &mut cli, usize::MAX);
        assert!(cli.auth_failed && !cli.up());
    }

    #[test]
    fn old_server_without_ncp_tls12_chacha_split_push() {
        // serveur sans `cipher` poussé : le client prend son `cipher` de repli
        let (mut srv, h) = link(ServerOpts {
            cipher: "CHACHA20-POLY1305".into(),
            push_cipher: false,
            tls12_only: true,
            split_push: true,
            ekm: Ekm::KeyDerivation,
            client_cert: ClientCert::Optional,
            wrap: ControlWrap::TlsAuth { server_direction: None },
            ..Default::default()
        });
        assert_eq!(h.client_config().key_direction, "");
        let mut cli = Cli::new(&h, IV_PROTO_TLS_KEY_EXPORT, CIPHERS);
        pump(srv.as_mut(), &mut cli, usize::MAX);
        assert!(cli.up(), "{:?}", h.stats().errors);
        assert!(!cli.push_reply.contains("cipher"));
        assert!(cli.push_reply.contains("key-derivation tls-ekm") && cli.ekm);
        assert!(cli.push_reply.contains("push-continuation 1"));
        roundtrip(srv.as_mut(), &mut cli, usize::MAX);
        assert_eq!(h.stats().tls_version, "TLSv1_2");
    }

    #[test]
    fn renegotiation_by_server_keeps_traffic_flowing() {
        for ekm in [true, false] {
            let (mut srv, h) = link(ServerOpts { wrap: ControlWrap::TlsCrypt, ..Default::default() });
            let proto = if ekm { ALL_PROTO } else { IV_PROTO_DATA_V2 };
            let mut cli = Cli::new(&h, proto, CIPHERS);
            pump(srv.as_mut(), &mut cli, usize::MAX);
            roundtrip(srv.as_mut(), &mut cli, usize::MAX);
            h.renegotiate();
            srv.tick();
            // l'ancienne clé fonctionne pendant la renégociation
            pump(srv.as_mut(), &mut cli, usize::MAX);
            assert_eq!(h.stats().keys_established, vec![0, 1], "{:?}", h.stats().errors);
            assert_eq!(cli.keys[0].key_id, 1);
            assert!(cli.keys[0].data.is_some());
            srv.tick();
            roundtrip(srv.as_mut(), &mut cli, usize::MAX);
            let s = h.stats();
            assert_eq!((s.last_rx_key, s.last_tx_key), (Some(1), Some(1)));
            // un paquet en retard sur l'ancienne clé passe encore
            let k0 = cli.keys.iter_mut().find(|k| k.key_id == 0).unwrap();
            let p = k0.data.as_mut().unwrap().encrypt(&ip_packet(30), &data::data_header(0, Some(0))).unwrap();
            assert!(srv.input(&p, None));
            assert_eq!(srv.recv_ip(), Some(ip_packet(30)));
            assert!(h.stats().errors.is_empty(), "{:?}", h.stats().errors);
        }
    }

    #[test]
    fn timers_send_pings_and_renegotiate() {
        let (mut srv, h) = link(ServerOpts { ping: Some((0, 10)), reneg_after: Some(Duration::ZERO), ..Default::default() });
        let mut cli = Cli::new(&h, ALL_PROTO, CIPHERS);
        pump(srv.as_mut(), &mut cli, usize::MAX);
        assert!(cli.push_reply.contains("ping 0,ping-restart 10"));
        roundtrip(srv.as_mut(), &mut cli, usize::MAX);
        srv.tick();
        pump(srv.as_mut(), &mut cli, usize::MAX);
        assert!(cli.pings >= 1 && h.stats().pings_out >= 1);
        srv.tick();
        pump(srv.as_mut(), &mut cli, usize::MAX);
        let s = h.stats();
        assert!(s.keys_established.len() >= 2 && s.keys_established[1] == 1, "{s:?}");
        roundtrip(srv.as_mut(), &mut cli, usize::MAX);
    }

    #[test]
    fn restart_message_and_reconnection_with_new_session() {
        let (mut srv, h) = link(ServerOpts::default());
        let mut cli = Cli::new(&h, ALL_PROTO, CIPHERS);
        pump(srv.as_mut(), &mut cli, usize::MAX);
        h.restart("serveur arrêté");
        srv.tick();
        pump(srv.as_mut(), &mut cli, usize::MAX);
        assert_eq!(cli.messages, vec!["RESTART,serveur arrêté".to_string()]);
        // nouveau client (nouvel identifiant de session) : la session est remplacée
        let mut cli2 = Cli::new(&h, ALL_PROTO, CIPHERS);
        pump(srv.as_mut(), &mut cli2, usize::MAX);
        assert!(cli2.up());
        roundtrip(srv.as_mut(), &mut cli2, usize::MAX);
        assert_eq!(h.stats().hard_resets, 2);
    }

    #[test]
    fn required_client_cert_and_wrong_static_key_are_refused() {
        let (mut srv, h) = link(ServerOpts::default());
        let mut cli = {
            let mut h2 = h.clone();
            h2.client_cert = ClientCert::None;
            Cli::new(&h2, ALL_PROTO, CIPHERS)
        };
        // le client ne présente pas de certificat : le serveur refuse le TLS
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pump(srv.as_mut(), &mut cli, usize::MAX)));
        assert!(r.is_err() || !cli.up());
        assert!(h.stats().errors.iter().any(|e| e.starts_with("TLS")), "{:?}", h.stats().errors);

        let (mut srv, h) = link(ServerOpts { wrap: ControlWrap::TlsCrypt, ..Default::default() });
        let mut h2 = h.clone();
        h2.static_key = generate_static_key();
        let mut cli = Cli::new(&h2, ALL_PROTO, CIPHERS);
        let p = cli.out.pop_front().unwrap();
        assert!(!srv.input(&p, None));
        assert!(srv.poll_net().is_none());
    }

    #[test]
    fn garbage_never_panics() {
        for wrap in [ControlWrap::None, ControlWrap::TlsAuth { server_direction: Some(0) }, ControlWrap::TlsCrypt] {
            for transport in [Transport::Udp, Transport::Tcp] {
                let (mut srv, h) = link(ServerOpts { wrap, transport, ..Default::default() });
                let mut cli = Cli::new(&h, ALL_PROTO, CIPHERS);
                pump(srv.as_mut(), &mut cli, usize::MAX);
                let mut seed = 0x1234_5678u32;
                let mut rnd = || {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed
                };
                for len in 0..300 {
                    let mut p: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
                    if let Some(b) = p.first_mut() {
                        *b = (*b & 7) | ((rnd() % 12) as u8) << 3;
                    }
                    srv.input(&p, None);
                    srv.tick();
                }
                // un paquet valide tronqué
                cli.send_data(&ip_packet(100));
                let p = cli.out.pop_front().unwrap();
                for n in 0..p.len() {
                    srv.input(&p[..n], None);
                }
                while srv.poll_net().is_some() {}
            }
        }
    }

    #[test]
    fn key_method_2_parsing() {
        let src = ClientKeySource::generate().unwrap();
        let mut m = vec![0, 0, 0, 0, 2];
        m.extend_from_slice(&src.to_wire());
        write_string(&mut m, "V4,dev-type tun");
        let head = m.len();
        write_string(&mut m, "théo");
        let after_user = m.len();
        write_string(&mut m, "mot de passe");
        let after_pass = m.len();
        write_string(&mut m, "IV_VER=2.6.0\nIV_PROTO=990\n");
        let (km, used) = parse_client_km2(&m).unwrap().unwrap();
        assert_eq!(used, m.len());
        assert_eq!((km.options.as_str(), km.username.as_str(), km.password.as_str()), ("V4,dev-type tun", "théo", "mot de passe"));
        assert_eq!(peer_info_value(&km.peer_info, "IV_PROTO"), Some("990"));
        assert_eq!(km.source.random2, src.random2);
        // incomplet : rien n'est lu (sauf aux frontières des champs facultatifs)
        for n in 0..m.len() {
            if ![head, after_user, after_pass].contains(&n) {
                assert!(parse_client_km2(&m[..n]).unwrap().is_none(), "{n}");
            }
        }
        // client ancien : options seules
        let (km, _) = parse_client_km2(&m[..head]).unwrap().unwrap();
        assert!(km.username.is_empty() && km.peer_info.is_empty());
        let mut bad = m.clone();
        bad[0] = 1;
        assert!(parse_client_km2(&bad).is_err());
        bad = m.clone();
        bad[4] = 1;
        assert!(parse_client_km2(&bad).is_err());
        let s = server_km2(&ServerKeySource { random1: [1; 32], random2: [2; 32] }, "V4");
        assert_eq!(s.len(), 5 + 64 + 2 + 3 + 6);
        assert_eq!(next_key_id(7), 1);
    }
}
