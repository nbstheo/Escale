//! Sessions SSH (russh) avec chaîne de rebonds via des canaux direct-tcpip.
//! La chaîne sert aussi de tunnel aux sessions RDP et VNC (`open_stream`).

use crate::model::{Auth, Host, VpnProfile};
use russh::client::{self, Handle};
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use zeroize::Zeroizing;

pub enum Cmd {
    Data(Vec<u8>),
    Resize(u32, u32),
    /// Ouvre un sous-système SFTP sur la connexion de la session.
    OpenSftp(oneshot::Sender<Result<SftpSession, String>>),
    /// Ajoute une clé publique (ligne OpenSSH) à `~/.ssh/authorized_keys` de la cible.
    InstallKey(String, oneshot::Sender<Result<(), String>>),
    Close,
}

pub enum Event {
    Status(String),
    Connected,
    Output(Vec<u8>),
    VerifyHostKey {
        host_id: Uuid,
        host_name: String,
        fingerprint: String,
        previous: Option<String>,
        reply: oneshot::Sender<bool>,
    },
    Closed(Option<String>),
}

/// Côté UI d'une session.
pub struct SessionHandle {
    pub tx: mpsc::UnboundedSender<Cmd>,
    pub rx: std::sync::mpsc::Receiver<Event>,
}

#[derive(Clone)]
pub(crate) struct Events {
    tx: std::sync::mpsc::Sender<Event>,
    ctx: eframe::egui::Context,
}

impl Events {
    pub(crate) fn new(ctx: eframe::egui::Context) -> (Self, std::sync::mpsc::Receiver<Event>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (Self { tx, ctx }, rx)
    }

    pub(crate) fn send(&self, e: Event) {
        let _ = self.tx.send(e);
        self.ctx.request_repaint();
    }

    pub(crate) fn repaint(&self) {
        self.ctx.request_repaint();
    }

    /// Demande à l'utilisateur de valider une empreinte inconnue ou changée (TOFU).
    pub(crate) async fn verify(&self, host: &Host, fingerprint: String) -> bool {
        if host.known_key.as_deref() == Some(fingerprint.as_str()) {
            return true;
        }
        let (reply, answer) = oneshot::channel();
        self.send(Event::VerifyHostKey {
            host_id: host.id,
            host_name: format!("{} ({}:{})", host.display_name(), host.hostname, host.port),
            fingerprint,
            previous: host.known_key.clone(),
            reply,
        });
        answer.await.unwrap_or(false)
    }
}

pub(crate) struct Client {
    host: Host,
    events: Events,
    /// Empreinte acceptée, reprise par l'appelant (reconnexion sans nouvelle question).
    accepted: Arc<std::sync::Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let ok = self.events.verify(&self.host, fp.clone()).await;
        if ok && let Ok(mut a) = self.accepted.lock() {
            *a = Some(fp);
        }
        Ok(ok)
    }
}

/// Adresse saisie -> (nom ou IP, port) : `[fd00::1]`, `[fd00::1]:3390`, `fd00::1`, `srv:3390`, `srv`.
/// Un port écrit dans l'adresse l'emporte sur celui de l'hôte.
pub(crate) fn endpoint(hostname: &str, port: u16) -> (String, u16) {
    let h = hostname.trim();
    if let Some(rest) = h.strip_prefix('[')
        && let Some((addr, tail)) = rest.split_once(']')
    {
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(port);
        return (addr.to_string(), port);
    }
    // un seul « : » : nom suivi d'un port (plusieurs : adresse IPv6 sans crochets)
    if let Some((name, p)) = h.split_once(':')
        && !p.contains(':')
        && let Ok(p) = p.parse()
    {
        return (name.to_string(), p);
    }
    (h.to_string(), port)
}

/// Connexion TCP directe, avec keepalive : une coupure silencieuse (veille, Wi-Fi perdu, NAT
/// expiré) finit par une erreur au lieu d'une session figée, sans gêner une session inactive.
pub(crate) async fn tcp_connect(hostname: &str, port: u16) -> Result<tokio::net::TcpStream, String> {
    let (name, port) = endpoint(hostname, port);
    let tcp = tokio::time::timeout(Duration::from_secs(20), tokio::net::TcpStream::connect((name.as_str(), port)))
        .await
        .map_err(|_| format!("Délai dépassé vers {name}"))?
        .map_err(|e| format!("{name} : {e}"))?;
    let _ = tcp.set_nodelay(true);
    let _ = socket2::SockRef::from(&tcp).set_tcp_keepalive(&keepalive());
    Ok(tcp)
}

/// Première connexion d'une chaîne : directe, ou à travers le VPN du premier hôte (`route_vpn`).
pub(crate) async fn dial(vpn: Option<&VpnProfile>, name: &str, port: u16) -> Result<Box<dyn Stream>, String> {
    match vpn {
        Some(v) => Ok(Box::new(crate::vpn::connect(v, name, port).await?)),
        None => Ok(Box::new(tcp_connect(name, port).await?)),
    }
}

/// « via le VPN « … » » pour les messages d'étape, si la connexion passe par un VPN.
fn via(vpn: Option<&VpnProfile>) -> String {
    vpn.map(|v| format!(" via le VPN « {} »", v.name)).unwrap_or_default()
}

/// Première sonde après 30 s sans échange, puis toutes les 5 s (10 sondes sous Windows) : une
/// session morte est détectée en un peu plus d'une minute.
fn keepalive() -> socket2::TcpKeepalive {
    socket2::TcpKeepalive::new().with_time(Duration::from_secs(30)).with_interval(Duration::from_secs(5))
}

pub fn spawn(
    rt: &tokio::runtime::Runtime,
    chain: Vec<Host>,
    cols: u32,
    rows: u32,
    ctx: eframe::egui::Context,
) -> SessionHandle {
    let (tx, cmd_rx) = mpsc::unbounded_channel();
    let (events, rx) = Events::new(ctx);
    let ev = events.clone();
    rt.spawn(async move {
        let res = isolated(run(chain, cols, rows, cmd_rx, ev)).await;
        events.send(Event::Closed(res.err()));
    });
    SessionHandle { tx, rx }
}

/// Exécute une session dans sa propre tâche : une panique interne la ferme avec un message
/// au lieu d'emporter Escale.
pub(crate) async fn isolated<F>(fut: F) -> Result<(), String>
where
    F: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(r) => r,
        Err(e) if e.is_panic() => Err("Erreur interne : la session a été interrompue (détails dans crash.log)".into()),
        Err(_) => Err("Session annulée".into()),
    }
}

#[cfg(test)]
pub(crate) fn test_events(tx: std::sync::mpsc::Sender<Event>) -> Events {
    Events { tx, ctx: eframe::egui::Context::default() }
}

#[cfg(test)]
pub(crate) async fn run_for_test(
    chain: Vec<Host>,
    cols: u32,
    rows: u32,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    events: Events,
) -> Result<(), String> {
    run(chain, cols, rows, cmd_rx, events).await
}

fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        nodelay: true,
        ..Default::default()
    })
}

async fn authenticate(h: &mut Handle<Client>, host: &Host) -> Result<(), String> {
    let who = format!("{}@{}", host.username, host.hostname);
    let mut ok = false;
    if host.auth == Auth::Key {
        let pass = (!host.passphrase.is_empty()).then_some(host.passphrase.as_str());
        let key = russh::keys::decode_secret_key(&host.private_key, pass)
            .map_err(|e| format!("Clé privée illisible pour {who} : {e}"))?;
        let hash = h.best_supported_rsa_hash().await.map_err(|e| e.to_string())?.flatten();
        ok = h
            .authenticate_publickey(&host.username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await
            .map_err(|e| e.to_string())?
            .success();
    }
    // Mot de passe : mode principal, ou repli si la clé est refusée et qu'un mot de passe est renseigné.
    if !ok && (host.auth == Auth::Password || !host.password.is_empty()) {
        ok = h
            .authenticate_password(&host.username, &host.password)
            .await
            .map_err(|e| e.to_string())?
            .success();
    }
    if ok { Ok(()) } else { Err(format!("Authentification refusée pour {who}")) }
}

/// Échec d'ouverture d'une chaîne : message, et vrai s'il est définitif (clé serveur ou
/// identifiants refusés) plutôt que dû au réseau.
pub(crate) type ChainError = (String, bool);

/// Connexions SSH successives : chaque hôte est joint à travers le précédent.
pub(crate) async fn connect_chain(chain: &[Host], events: &Events) -> Result<Vec<Handle<Client>>, String> {
    connect_chain_learning(&mut chain.to_vec(), events).await.map_err(|(e, _)| e)
}

/// Comme `connect_chain`, en mémorisant dans `chain` les empreintes acceptées en cours de route :
/// une nouvelle connexion avec la même chaîne (reconnexion RDP) ne repose pas la question.
pub(crate) async fn connect_chain_learning(chain: &mut [Host], events: &Events) -> Result<Vec<Handle<Client>>, ChainError> {
    let n = chain.len();
    let mut handles: Vec<Handle<Client>> = Vec::with_capacity(n);
    for (i, host) in chain.iter_mut().enumerate() {
        let step = if n > 1 { format!(" [{}/{}]", i + 1, n) } else { String::new() };
        let vpn = host.route_vpn.clone().filter(|_| handles.is_empty());
        events.send(Event::Status(format!("Connexion à {}{}{step}…", host.address(), via(vpn.as_deref()))));
        let accepted = Arc::new(std::sync::Mutex::new(None));
        let handler = Client { host: host.clone(), events: events.clone(), accepted: accepted.clone() };
        let (name, port) = endpoint(&host.hostname, host.port);
        let connect = async {
            match handles.last() {
                None => {
                    // keepalive TCP en plus de celui de SSH : rien ne reste suspendu à une socket morte
                    let tcp = dial(vpn.as_deref(), &name, port).await.map_err(|e| russh::Error::IO(std::io::Error::other(e)))?;
                    client::connect_stream(config(), tcp, handler).await
                }
                Some(prev) => {
                    let ch = prev.channel_open_direct_tcpip(name.clone(), port as u32, "127.0.0.1", 0).await?;
                    client::connect_stream(config(), ch.into_stream(), handler).await
                }
            }
        };
        let res = tokio::time::timeout(Duration::from_secs(20), connect).await;
        if let Some(fp) = accepted.lock().ok().and_then(|mut a| a.take()) {
            host.known_key = Some(fp);
        }
        let mut h = res.map_err(|_| (format!("Délai dépassé vers {}", host.hostname), false))?.map_err(|e| match e {
            russh::Error::UnknownKey => (format!("Clé serveur refusée pour {}", host.hostname), true),
            // message déjà formé par `tcp_connect`
            russh::Error::IO(e) if e.kind() == std::io::ErrorKind::Other && e.get_ref().is_some() => (e.to_string(), false),
            e => (format!("{} : {e}", host.hostname), false),
        })?;
        events.send(Event::Status(format!("Authentification sur {}{step}…", host.address())));
        // clé privée illisible ou identifiants refusés : inutile de réessayer
        authenticate(&mut h, host).await.map_err(|e| (e, true))?;
        handles.push(h);
    }
    Ok(handles)
}

pub(crate) async fn disconnect(handles: &[Handle<Client>]) {
    for h in handles.iter().rev() {
        let _ = h.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    }
}

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}

/// Flux TCP vers la cible (dernier élément de `chain`), à travers les rebonds SSH qui la précèdent.
/// Les connexions de rebond renvoyées doivent rester en vie aussi longtemps que le flux.
pub(crate) async fn open_stream(chain: &[Host], events: &Events) -> Result<(Box<dyn Stream>, Vec<Handle<Client>>), String> {
    open_stream_learning(&mut chain.to_vec(), events).await.map_err(|(e, _)| e)
}

/// `open_stream` qui mémorise dans `chain` les empreintes des rebonds acceptées (cf.
/// `connect_chain_learning`) et indique si l'échec est définitif.
pub(crate) async fn open_stream_learning(chain: &mut [Host], events: &Events) -> Result<(Box<dyn Stream>, Vec<Handle<Client>>), ChainError> {
    let (target, jumps) = chain.split_last_mut().ok_or(("Aucun hôte".to_string(), true))?;
    let handles = connect_chain_learning(jumps, events).await?;
    let vpn = target.route_vpn.clone().filter(|_| handles.is_empty());
    events.send(Event::Status(format!("Connexion à {}{}…", target.address(), via(vpn.as_deref()))));
    let stream: Box<dyn Stream> = match handles.last() {
        None => dial(vpn.as_deref(), &target.hostname, target.port).await.map_err(|e| (e, false))?,
        Some(last) => {
            let (name, port) = endpoint(&target.hostname, target.port);
            let ch = last
                .channel_open_direct_tcpip(name.clone(), port as u32, "127.0.0.1", 0)
                .await
                .map_err(|e| (format!("Tunnel vers {name}:{port} refusé : {e}"), false))?;
            Box::new(ch.into_stream())
        }
    };
    Ok((stream, handles))
}

async fn open_sftp(target: &Handle<Client>) -> Result<russh::Channel<client::Msg>, String> {
    let ch = target.channel_open_session().await.map_err(|e| format!("Canal SFTP : {e}"))?;
    ch.request_subsystem(true, "sftp").await.map_err(|e| format!("Sous-système SFTP : {e}"))?;
    Ok(ch)
}

/// Nouvelle clé ed25519 pour un hôte : (clé privée au format OpenSSH, ligne publique pour
/// `authorized_keys`). Le commentaire nomme cet ordinateur pour la reconnaître sur le serveur.
pub fn generate_key() -> Result<(Zeroizing<String>, String), String> {
    let seed = Zeroizing::new(crate::vault::random::<32>());
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    let pc: String = std::env::var("COMPUTERNAME")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    key.set_comment(if pc.is_empty() { "escale".to_string() } else { format!("escale@{pc}") });
    let private = key.to_openssh(LineEnding::LF).map_err(|e| format!("Clé générée illisible : {e}"))?;
    let public = key.public_key().to_openssh().map_err(|e| format!("Clé générée illisible : {e}"))?;
    Ok((private, public))
}

/// Script `sh` qui ajoute `line` à `~/.ssh/authorized_keys` (une seule fois), avec les droits
/// exigés par sshd. `line` ne contient que base64, espaces et commentaire filtré : pas d'apostrophe.
fn authorized_keys_script(line: &str) -> String {
    format!(
        r#"set -e
        umask 077
        mkdir -p "$HOME/.ssh"
        chmod 700 "$HOME/.ssh"
        f="$HOME/.ssh/authorized_keys"
        touch "$f"
        chmod 600 "$f"
        if ! grep -qxF '{line}' "$f"; then
            if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi
            printf '%s\n' '{line}' >> "$f"
        fi
        "#
    )
}

/// Exécute le script d'ajout de clé avec `sh` (lu sur l'entrée standard : indépendant du shell
/// de connexion de l'utilisateur, fish, zsh…).
async fn install_key(mut ch: russh::Channel<client::Msg>, line: &str) -> Result<(), String> {
    if line.contains(['\'', '\n', '\r']) {
        return Err("Clé publique invalide".into());
    }
    ch.exec(true, "sh").await.map_err(|e| format!("Exécution de sh : {e}"))?;
    ch.data(authorized_keys_script(line).as_bytes()).await.map_err(|e| e.to_string())?;
    ch.eof().await.map_err(|e| e.to_string())?;
    let mut stderr = Vec::new();
    let mut status = None;
    while let Some(msg) = ch.wait().await {
        match msg {
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Failure => return Err("Le serveur refuse l'exécution de commandes".into()),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    match status {
        Some(0) => Ok(()),
        Some(code) => {
            let msg = String::from_utf8_lossy(&stderr).trim().to_string();
            Err(if msg.is_empty() { format!("Échec de l'ajout de la clé (code {code})") } else { msg })
        }
        None => Err("Le serveur n'a pas confirmé l'ajout de la clé".into()),
    }
}

async fn run(
    chain: Vec<Host>,
    cols: u32,
    rows: u32,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    events: Events,
) -> Result<(), String> {
    let handles = connect_chain(&chain, &events).await?;
    let target = handles.last().ok_or("Aucun hôte")?;
    let ch = target.channel_open_session().await.map_err(|e| e.to_string())?;
    ch.request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
        .await
        .map_err(|e| e.to_string())?;
    ch.request_shell(false).await.map_err(|e| e.to_string())?;
    events.send(Event::Connected);

    let (mut rd, wr) = ch.split();
    let mut exit: Option<String> = None;
    loop {
        tokio::select! {
            msg = rd.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    events.send(Event::Output(data.to_vec()));
                }
                Some(ChannelMsg::ExitStatus { exit_status }) if exit_status != 0 => {
                    exit = Some(format!("Code de sortie {exit_status}"));
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                _ => {}
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Data(d)) => { let _ = wr.data(&d[..]).await; }
                Some(Cmd::Resize(c, r)) => { let _ = wr.window_change(c, r, 0, 0).await; }
                Some(Cmd::OpenSftp(reply)) => match open_sftp(target).await {
                    // l'initialisation SFTP attend le serveur : hors de la boucle du terminal
                    Ok(ch) => {
                        tokio::spawn(async move {
                            let r = SftpSession::new(ch.into_stream()).await.map_err(|e| format!("SFTP : {e}"));
                            let _ = reply.send(r);
                        });
                    }
                    Err(e) => { let _ = reply.send(Err(e)); }
                },
                Some(Cmd::InstallKey(line, reply)) => match target.channel_open_session().await {
                    // canal séparé : le terminal reste utilisable pendant l'installation
                    Ok(ch) => {
                        tokio::spawn(async move {
                            let r = tokio::time::timeout(Duration::from_secs(20), install_key(ch, &line))
                                .await
                                .unwrap_or_else(|_| Err("Le serveur ne répond pas".into()));
                            let _ = reply.send(r);
                        });
                    }
                    Err(e) => { let _ = reply.send(Err(format!("Canal : {e}"))); }
                },
                Some(Cmd::Close) | None => break,
            },
        }
    }
    let _ = wr.close().await;
    disconnect(&handles).await;
    match exit {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_with_brackets_or_port() {
        assert_eq!(endpoint("srv.corp.local", 3389), ("srv.corp.local".into(), 3389));
        assert_eq!(endpoint(" srv:3390 ", 3389), ("srv".into(), 3390));
        assert_eq!(endpoint("[fd00::1]", 22), ("fd00::1".into(), 22));
        assert_eq!(endpoint("[fd00::1]:2222", 22), ("fd00::1".into(), 2222));
        assert_eq!(endpoint("fd00::1", 22), ("fd00::1".into(), 22));
        assert_eq!(endpoint("10.0.0.5", 5900), ("10.0.0.5".into(), 5900));
        // port illisible : l'adresse est laissée telle quelle
        assert_eq!(endpoint("srv:abc", 22), ("srv:abc".into(), 22));
    }

    #[tokio::test]
    async fn direct_stream_to_bracketed_ipv6_with_keepalive() {
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        // IPv4 : keepalive activé sur la socket
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let tcp = tcp_connect(&format!("127.0.0.1:{port}"), 1).await.unwrap();
        assert!(socket2::SockRef::from(&tcp).keepalive().unwrap(), "keepalive TCP");
        // IPv6 entre crochets, comme on l'écrit dans une URL
        let Ok(l6) = tokio::net::TcpListener::bind("[::1]:0").await else { return };
        let mut host = Host::default();
        host.hostname = "[::1]".into();
        host.port = l6.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { l6.accept().await.map(|_| ()) });
        let r = open_stream(&[host], &events).await;
        assert!(r.is_ok(), "{:?}", r.err());
        accept.await.unwrap().unwrap();
    }
}
