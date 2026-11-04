//! VPN propres à Escale : le tunnel tourne dans l'application (WireGuard en espace utilisateur avec
//! boringtun, pile TCP/IP smoltcp), sans carte réseau ni droits administrateur. Seules les
//! connexions d'Escale l'empruntent : le reste du PC n'en voit rien.
//!
//! Un tunnel est partagé par toutes les sessions ouvertes avec le même profil et s'arrête avec la
//! dernière. Il ne sert qu'à la première connexion TCP d'une chaîne (cf. `ssh::dial`) : la suite
//! (rebonds SSH, RDP, VNC) passe à l'intérieur comme sur un réseau ordinaire.

use crate::model::{VpnKind, VpnProfile, WireGuardConfig};
use base64::Engine as _;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use sha2::Digest;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{dns, tcp};
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Données en attente dans chaque sens d'une connexion (au-delà, l'émetteur attend).
const PIPE_MAX: usize = 256 * 1024;
/// Tampons TCP de smoltcp (fenêtre annoncée au serveur).
const TCP_BUF: usize = 256 * 1024;
const DEFAULT_MTU: u16 = 1420;
/// Tampons des sockets UDP (Windows en donne 64 Kio par défaut).
const UDP_BUF: usize = 4 * 1024 * 1024;
/// Délai pour établir la session WireGuard (boringtun renvoie l'initiation toutes les 5 s).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Délai d'ouverture d'une connexion TCP dans le tunnel (inférieur à celui de la chaîne SSH).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Minuteries WireGuard (renégociation, keepalive).
const TIMER_TICK: Duration = Duration::from_millis(250);

// ------------------------------------------------------------------ fichier .conf

/// Ajoute une valeur à une liste séparée par des virgules (`Address`, `DNS`, `AllowedIPs` répétés).
fn append(list: &mut String, v: &str) {
    if !list.is_empty() {
        list.push_str(", ");
    }
    list.push_str(v);
}

/// Lit un fichier WireGuard (`wg-quick`). Seul le premier `[Peer]` est utilisé ; les directives
/// propres à `wg-quick` (PostUp, Table…) sont ignorées.
pub fn parse_wireguard(text: &str) -> Result<WireGuardConfig, String> {
    let mut c = WireGuardConfig::default();
    let mut section = String::new();
    let mut peers = 0;
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[') {
            section = s.trim_end_matches(']').trim().to_ascii_lowercase();
            if section == "peer" {
                peers += 1;
            }
            continue;
        }
        // une clé base64 se termine par « = » : seul le premier sépare le nom de la valeur
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (section.as_str(), k.as_str()) {
            ("interface", "privatekey") => c.private_key = v.to_string(),
            ("interface", "address") => append(&mut c.address, v),
            ("interface", "dns") => append(&mut c.dns, v),
            ("interface", "mtu") => c.mtu = v.parse().map_err(|_| format!("MTU invalide : {v}"))?,
            ("peer", _) if peers > 1 => {}
            ("peer", "publickey") => c.peer_public_key = v.to_string(),
            ("peer", "presharedkey") => c.preshared_key = v.to_string(),
            ("peer", "endpoint") => c.endpoint = v.to_string(),
            ("peer", "allowedips") => append(&mut c.allowed_ips, v),
            ("peer", "persistentkeepalive") if v.eq_ignore_ascii_case("off") => c.keepalive = 0,
            ("peer", "persistentkeepalive") => c.keepalive = v.parse().map_err(|_| format!("PersistentKeepalive invalide : {v}"))?,
            _ => {}
        }
    }
    if peers == 0 {
        return Err("Aucune section [Peer] : ce fichier n'est pas une configuration WireGuard".into());
    }
    if c.private_key.is_empty() {
        return Err("Clé privée (PrivateKey) absente du fichier".into());
    }
    Ok(c)
}

// ------------------------------------------------------------------ vérification

fn key(s: &str, what: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let b = Zeroizing::new(
        base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|_| format!("{what} : texte base64 invalide"))?,
    );
    let k: [u8; 32] = b.as_slice().try_into().map_err(|_| format!("{what} : 32 octets attendus"))?;
    Ok(Zeroizing::new(k))
}

/// Éléments d'une liste « a, b c » (virgules, espaces ou retours à la ligne).
fn items(s: &str) -> impl Iterator<Item = &str> {
    s.split([',', ' ', '\n', '\r', '\t']).map(str::trim).filter(|x| !x.is_empty())
}

/// `10.0.0.2/24`, `fd00::2` (préfixe complet par défaut).
fn cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (a, p) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let ip: IpAddr = a.trim().parse().map_err(|_| format!("Adresse invalide : {s}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let p = match p {
        Some(p) => p.trim().parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(|| format!("Préfixe invalide : {s}"))?,
        None => max,
    };
    Ok((ip, p))
}

fn in_net(ip: IpAddr, (net, p): (IpAddr, u8)) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let m = u32::MAX.checked_shl(32 - p as u32).unwrap_or(0);
            u32::from(a) & m == u32::from(n) & m
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let m = u128::MAX.checked_shl(128 - p as u32).unwrap_or(0);
            u128::from(a) & m == u128::from(n) & m
        }
        _ => false,
    }
}

/// Réglages WireGuard vérifiés, prêts pour le tunnel.
struct WgParams {
    secret: StaticSecret,
    peer: PublicKey,
    psk: Option<[u8; 32]>,
    keepalive: Option<u16>,
    addrs: Vec<(IpAddr, u8)>,
    dns: Vec<IpAddr>,
    /// Domaines de recherche (noms non IP de la ligne `DNS`).
    search: Vec<String>,
    allowed: Vec<(IpAddr, u8)>,
    mtu: u16,
    endpoint: (String, u16),
}

fn wireguard_params(c: &WireGuardConfig) -> Result<WgParams, String> {
    let secret = StaticSecret::from(*key(&c.private_key, "Clé privée")?);
    let peer = PublicKey::from(*key(&c.peer_public_key, "Clé publique du serveur")?);
    let psk = if c.preshared_key.trim().is_empty() { None } else { Some(*key(&c.preshared_key, "Clé partagée")?) };
    let addrs = items(&c.address).map(cidr).collect::<Result<Vec<_>, _>>()?;
    if addrs.is_empty() {
        return Err("Adresse de ce poste dans le VPN (Address) manquante".into());
    }
    let (mut dns, mut search) = (Vec::new(), Vec::new());
    for d in items(&c.dns) {
        match d.parse::<IpAddr>() {
            Ok(ip) => dns.push(ip),
            Err(_) => search.push(d.trim_matches('.').to_string()),
        }
    }
    let allowed = items(&c.allowed_ips).map(cidr).collect::<Result<Vec<_>, _>>()?;
    if c.endpoint.trim().is_empty() {
        return Err("Adresse du serveur VPN (Endpoint) manquante".into());
    }
    let endpoint = crate::ssh::endpoint(&c.endpoint, 51820);
    if endpoint.0.is_empty() {
        return Err("Adresse du serveur VPN (Endpoint) invalide".into());
    }
    let mtu = if c.mtu == 0 { DEFAULT_MTU } else { c.mtu };
    if !(576..=9000).contains(&mtu) {
        return Err(format!("MTU hors limites : {mtu} (576 à 9000)"));
    }
    let keepalive = (c.keepalive > 0).then_some(c.keepalive);
    Ok(WgParams { secret, peer, psk, keepalive, addrs, dns, search, allowed, mtu, endpoint })
}

/// Vérifie un profil avant de l'enregistrer.
pub fn check(p: &VpnProfile) -> Result<(), String> {
    if p.name.trim().is_empty() {
        return Err("Le nom du profil est obligatoire.".into());
    }
    match p.kind {
        VpnKind::WireGuard => wireguard_params(&p.wireguard).map(|_| ()),
        VpnKind::OpenVpn => crate::openvpn::check(p),
    }
}

/// Clé publique correspondant à la clé privée (à communiquer à l'administrateur du VPN).
pub fn public_key(private_key: &str) -> Option<String> {
    let k = key(private_key, "").ok()?;
    let public = PublicKey::from(&StaticSecret::from(*k));
    Some(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

/// Nouvelle clé privée WireGuard (base64).
pub fn generate_private_key() -> String {
    let seed = Zeroizing::new(crate::vault::random::<32>());
    let secret = StaticSecret::from(*seed);
    base64::engine::general_purpose::STANDARD.encode(secret.to_bytes())
}

// ------------------------------------------------------------------ connexions

/// État d'une connexion TCP, partagé entre le flux (côté session) et le tunnel.
#[derive(Default)]
struct PipeState {
    /// Reçu du serveur, pas encore lu par la session.
    rx: VecDeque<u8>,
    /// Écrit par la session, pas encore confié à smoltcp.
    tx: VecDeque<u8>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// Le serveur a fini d'envoyer.
    eof: bool,
    /// Plus d'écriture possible (fermeture par le serveur).
    write_closed: bool,
    /// La session a fermé son sens d'écriture.
    shutdown: bool,
}

struct Pipe {
    state: Mutex<PipeState>,
    /// Réveille la tâche du tunnel.
    wake: Arc<Notify>,
}

impl Pipe {
    fn lock(&self) -> std::sync::MutexGuard<'_, PipeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Flux TCP vers un hôte, à travers le tunnel. Le garde en vie tant qu'il existe.
pub(crate) struct VpnStream {
    pipe: Arc<Pipe>,
    _tunnel: Option<Arc<Tunnel>>,
}

impl Drop for VpnStream {
    fn drop(&mut self) {
        self.pipe.wake.notify_one();
    }
}

impl AsyncRead for VpnStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut st = self.pipe.lock();
        if !st.rx.is_empty() {
            let n = buf.remaining().min(st.rx.len());
            let (a, b) = st.rx.as_slices();
            let k = a.len().min(n);
            buf.put_slice(&a[..k]);
            buf.put_slice(&b[..n - k]);
            st.rx.drain(..n);
            drop(st);
            // place libérée : le tunnel peut reprendre la lecture
            self.pipe.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if st.eof {
            return Poll::Ready(Ok(()));
        }
        st.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for VpnStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut st = self.pipe.lock();
        if st.write_closed || st.shutdown {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "Connexion fermée par le serveur")));
        }
        let room = PIPE_MAX.saturating_sub(st.tx.len());
        if room == 0 {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(data.len());
        st.tx.extend(&data[..n]);
        drop(st);
        self.pipe.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.pipe.lock().shutdown = true;
        self.pipe.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ------------------------------------------------------------------ protocoles

/// Réglages réseau du tunnel : connus d'emblée (WireGuard) ou appris du serveur (OpenVPN,
/// `PUSH_REPLY`).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LinkInfo {
    /// Adresses de ce poste dans le VPN.
    pub addrs: Vec<(IpAddr, u8)>,
    pub dns: Vec<IpAddr>,
    /// Domaines de recherche DNS (le premier complète les noms courts).
    pub search: Vec<String>,
    /// Réseaux joignables par le tunnel (vide : tous, ex. `redirect-gateway`).
    pub routes: Vec<(IpAddr, u8)>,
    pub mtu: u16,
}

/// État d'un protocole VPN, relu par le tunnel après chaque événement.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum LinkState {
    /// Négociation en cours, avec un texte affichable (« Négociation TLS… »).
    Connecting(String),
    /// Tunnel utilisable : l'interface est configurée avec ces réglages.
    Up(LinkInfo),
    /// Arrêt définitif (message en français) : le tunnel s'arrête et les connexions échouent.
    Failed(String),
}

/// Protocole VPN sans entrées-sorties : le tunnel lui confie ce qu'il reçoit du serveur et les
/// paquets IP de smoltcp, et envoie ce qu'il produit. Le découpage du flux TCP (longueur sur
/// 2 octets d'OpenVPN) est à la charge du protocole.
pub(crate) trait Link: Send {
    /// Données reçues du serveur : un datagramme (UDP) ou un morceau du flux (TCP). Renvoie vrai
    /// si elles sont authentiques (le serveur de test UDP apprend ainsi l'adresse du client).
    fn input(&mut self, data: &[u8], from: Option<SocketAddr>) -> bool;
    /// Paquet IP produit par smoltcp, à chiffrer pour le serveur.
    fn send_ip(&mut self, packet: &[u8]);
    /// Appelée toutes les `TIMER_TICK` : renégociation, keepalive, délais.
    fn tick(&mut self);
    /// Prochain paquet IP déchiffré, pour smoltcp.
    fn recv_ip(&mut self) -> Option<Vec<u8>>;
    /// Prochaines données pour le serveur (un datagramme, ou des octets du flux TCP).
    fn poll_net(&mut self) -> Option<Vec<u8>>;
    fn state(&self) -> &LinkState;
    /// Le canal de données fonctionne (WireGuard : une négociation a abouti). Tant que ce n'est
    /// pas le cas, les connexions en attente échouent au bout du délai de négociation.
    fn established(&self) -> bool {
        matches!(self.state(), LinkState::Up(_))
    }
}

/// Transport vers le serveur VPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    /// Flux TCP (OpenVPN sur 443, WatchGuard SSL) : octets bruts, découpés par le protocole.
    Tcp,
}

/// Délai de négociation conseillé pour OpenVPN (TLS, authentification, `PUSH_REPLY`).
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Protocole prêt à démarrer, avec ses réglages de transport.
pub(crate) struct LinkSetup {
    pub link: Box<dyn Link>,
    pub transport: Transport,
    /// Serveur VPN (nom ou adresse, port).
    pub server: (String, u16),
    /// Délai pour que le tunnel devienne utilisable (connexion TCP comprise).
    pub handshake_timeout: Duration,
    /// Erreur donnée si le serveur ne répond pas dans ce délai.
    pub unreachable: String,
    /// Nom des réseaux autorisés dans les messages (« AllowedIPs », « routes du serveur »).
    pub routes_hint: &'static str,
}

/// Seul point de construction des protocoles (un bras par type de VPN).
pub(crate) fn start_link(p: &VpnProfile) -> Result<LinkSetup, String> {
    match p.kind {
        VpnKind::WireGuard => {
            let w = wireguard_params(&p.wireguard)?;
            Ok(LinkSetup {
                server: w.endpoint.clone(),
                transport: Transport::Udp,
                handshake_timeout: HANDSHAKE_TIMEOUT,
                unreachable: format!(
                    "Le serveur VPN « {} » ne répond pas : vérifiez son adresse, le port UDP et les clés",
                    p.name
                ),
                routes_hint: "AllowedIPs",
                link: Box::new(WgLink::new(&w, &p.name, false)),
            })
        }
        VpnKind::OpenVpn => {
            let link = crate::openvpn::link::OpenVpnLink::new(&p.name, &p.openvpn, &p.username, &p.password)?;
            Ok(LinkSetup {
                transport: if link.is_tcp() { Transport::Tcp } else { Transport::Udp },
                server: crate::openvpn::link::server(&p.openvpn),
                handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
                unreachable: format!(
                    "Le serveur OpenVPN « {} » ne répond pas : vérifiez l'adresse, le port, UDP/TCP et la clé tls-auth/tls-crypt (key-direction)",
                    p.name
                ),
                routes_hint: "routes du serveur",
                link: Box::new(link),
            })
        }
    }
}

/// WireGuard (boringtun) : réglages connus d'emblée, la négociation suit en arrière-plan.
struct WgLink {
    name: String,
    tunn: Box<Tunn>,
    out: Vec<u8>,
    net: VecDeque<Vec<u8>>,
    ip: VecDeque<Vec<u8>>,
    state: LinkState,
    /// Serveur de test : la session n'expire pas, il attend un client.
    server: bool,
    /// Session établie au moins une fois.
    established: bool,
}

impl WgLink {
    fn new(p: &WgParams, name: &str, server: bool) -> Self {
        let index = u32::from_le_bytes(crate::vault::random::<4>()) >> 8;
        let tunn = Box::new(Tunn::new(p.secret.clone(), p.peer, p.psk, p.keepalive, index, None));
        let info = LinkInfo {
            addrs: p.addrs.clone(),
            dns: p.dns.clone(),
            search: p.search.clone(),
            routes: p.allowed.clone(),
            mtu: p.mtu,
        };
        let mut l = Self {
            name: name.to_string(),
            tunn,
            out: vec![0; 65_600],
            net: VecDeque::new(),
            ip: VecDeque::new(),
            state: LinkState::Up(info),
            server,
            established: server,
        };
        // négociation lancée tout de suite : la première connexion n'attend pas un tour de minuterie
        if !server && let TunnResult::WriteToNetwork(b) = l.tunn.format_handshake_initiation(&mut l.out, false) {
            l.net.push_back(b.to_vec());
        }
        l
    }
}

impl Link for WgLink {
    fn input(&mut self, data: &[u8], from: Option<SocketAddr>) -> bool {
        let ok = match self.tunn.decapsulate(from.map(|a| a.ip()), data, &mut self.out) {
            TunnResult::WriteToNetwork(b) => {
                self.net.push_back(b.to_vec());
                // paquets mis en attente pendant la négociation
                while let TunnResult::WriteToNetwork(b) = self.tunn.decapsulate(None, &[], &mut self.out) {
                    self.net.push_back(b.to_vec());
                }
                true
            }
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                self.ip.push_back(p.to_vec());
                true
            }
            TunnResult::Done | TunnResult::Err(_) => false,
        };
        if self.tunn.stats().0.is_some() {
            self.established = true;
        }
        ok
    }

    fn send_ip(&mut self, packet: &[u8]) {
        if let TunnResult::WriteToNetwork(b) = self.tunn.encapsulate(packet, &mut self.out) {
            self.net.push_back(b.to_vec());
        }
    }

    fn tick(&mut self) {
        match self.tunn.update_timers(&mut self.out) {
            TunnResult::WriteToNetwork(b) => self.net.push_back(b.to_vec()),
            TunnResult::Err(WireGuardError::ConnectionExpired) if !self.server => {
                self.state = LinkState::Failed(format!("Le serveur VPN « {} » ne répond plus", self.name));
            }
            _ => {}
        }
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

    fn established(&self) -> bool {
        self.established
    }
}

// ------------------------------------------------------------------ tunnels partagés

enum Cmd {
    Connect { ip: IpAddr, port: u16, reply: oneshot::Sender<Result<Arc<Pipe>, String>> },
    Resolve { name: String, reply: oneshot::Sender<Result<Vec<IpAddr>, String>> },
}

impl Cmd {
    fn fail(self, e: &str) {
        match self {
            Cmd::Connect { reply, .. } => {
                let _ = reply.send(Err(e.to_string()));
            }
            Cmd::Resolve { reply, .. } => {
                let _ = reply.send(Err(e.to_string()));
            }
        }
    }
}

/// Tunnel en cours : la tâche s'arrête quand la dernière référence disparaît.
pub(crate) struct Tunnel {
    cmd: mpsc::UnboundedSender<Cmd>,
    /// Erreur qui a arrêté le tunnel, pour l'expliquer aux connexions en attente.
    fatal: Arc<Mutex<Option<String>>>,
    name: String,
    /// État du protocole, publié par la tâche du tunnel.
    state: watch::Receiver<LinkState>,
    routes_hint: &'static str,
}

impl Tunnel {
    fn stopped(&self) -> String {
        self.fatal
            .lock()
            .ok()
            .and_then(|f| f.clone())
            .unwrap_or_else(|| format!("Le tunnel VPN « {} » s'est arrêté", self.name))
    }

    /// Attend que le tunnel soit utilisable ; `status` reçoit chaque étape de la négociation.
    async fn up(&self, status: &mut (impl FnMut(&str) + Send)) -> Result<LinkInfo, String> {
        let mut rx = self.state.clone();
        let mut last = String::new();
        loop {
            let st = rx.borrow_and_update().clone();
            match st {
                LinkState::Up(info) => return Ok(info),
                LinkState::Failed(e) => return Err(e),
                LinkState::Connecting(s) if s != last => {
                    status(&s);
                    last = s;
                }
                LinkState::Connecting(_) => {}
            }
            if rx.changed().await.is_err() {
                // tâche arrêtée : son dernier état explique pourquoi
                return match &*rx.borrow() {
                    LinkState::Failed(e) => Err(e.clone()),
                    _ => Err(self.stopped()),
                };
            }
        }
    }
}

/// Exécuteur des tunnels, indépendant de celui des sessions (une session RDP a le sien, arrêté
/// avec elle, alors que le tunnel peut servir à d'autres onglets).
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("escale-vpn")
            .enable_all()
            .build()
            .expect("runtime VPN")
    })
}

/// Tunnels ouverts : (profil, empreinte de sa configuration). Aucun secret n'est conservé ici.
static TUNNELS: Mutex<Vec<(Uuid, [u8; 32], Weak<Tunnel>)>> = Mutex::new(Vec::new());

fn fingerprint(p: &VpnProfile) -> [u8; 32] {
    let json = Zeroizing::new(serde_json::to_vec(p).unwrap_or_default());
    sha2::Sha256::digest(&*json).into()
}

/// Tunnel du profil : celui déjà ouvert (même configuration), sinon un nouveau.
fn tunnel(p: &VpnProfile) -> Result<Arc<Tunnel>, String> {
    let fp = fingerprint(p);
    let mut list = TUNNELS.lock().unwrap_or_else(|e| e.into_inner());
    list.retain(|(_, _, w)| w.strong_count() > 0);
    if let Some(t) = list.iter().find(|(id, f, _)| *id == p.id && *f == fp).and_then(|(.., w)| w.upgrade())
        && !t.cmd.is_closed()
    {
        return Ok(t);
    }
    let setup = start_link(p).map_err(|e| format!("VPN « {} » : {e}", p.name))?;
    let t = launch(&p.name, setup);
    // ancienne configuration du même profil : ses sessions gardent leur tunnel jusqu'à leur fermeture
    list.retain(|(id, ..)| *id != p.id);
    list.push((p.id, fp, Arc::downgrade(&t)));
    Ok(t)
}

/// Démarre la tâche d'un tunnel.
fn launch(name: &str, setup: LinkSetup) -> Arc<Tunnel> {
    let (tx, rx) = mpsc::unbounded_channel();
    let (state_tx, state_rx) = watch::channel(LinkState::Connecting("Connexion au serveur VPN…".into()));
    let fatal = Arc::new(Mutex::new(None));
    let t = Arc::new(Tunnel {
        cmd: tx,
        fatal: fatal.clone(),
        name: name.to_string(),
        state: state_rx,
        routes_hint: setup.routes_hint,
    });
    runtime().spawn(run(setup, name.to_string(), rx, state_tx, fatal));
    t
}

/// Connexion TCP à `host:port` à travers le VPN du profil. Un nom est résolu par les DNS du VPN
/// s'il en a (avec ses domaines de recherche), sinon par ceux de cet ordinateur.
pub(crate) async fn connect(p: &VpnProfile, host: &str, port: u16) -> Result<VpnStream, String> {
    connect_with_status(p, host, port, |_| {}).await
}

/// Comme `connect`, en signalant les étapes de la négociation (« Négociation TLS… »).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn connect_with_status(
    p: &VpnProfile,
    host: &str,
    port: u16,
    status: impl FnMut(&str) + Send,
) -> Result<VpnStream, String> {
    let t = tunnel(p)?;
    open(t, host, port, status).await
}

async fn open(t: Arc<Tunnel>, host: &str, port: u16, mut status: impl FnMut(&str) + Send) -> Result<VpnStream, String> {
    let info = t.up(&mut status).await?;
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => resolve(&t, &info, host, port).await?,
    };
    if !info.routes.is_empty() && !info.routes.iter().any(|n| in_net(ip, *n)) {
        return Err(format!("{host} ({ip}) n'est pas dans les réseaux du VPN « {} » ({})", t.name, t.routes_hint));
    }
    let (reply, rx) = oneshot::channel();
    t.cmd.send(Cmd::Connect { ip, port, reply }).map_err(|_| t.stopped())?;
    let pipe = rx.await.map_err(|_| t.stopped())??;
    Ok(VpnStream { pipe, _tunnel: Some(t) })
}

async fn resolve(t: &Tunnel, info: &LinkInfo, host: &str, port: u16) -> Result<IpAddr, String> {
    if !info.dns.is_empty() {
        // nom court (« srv01 ») : complété par le premier domaine de recherche du VPN
        let name = match info.search.first() {
            Some(d) if !host.contains('.') => format!("{host}.{d}"),
            _ => host.to_string(),
        };
        let (reply, rx) = oneshot::channel();
        t.cmd.send(Cmd::Resolve { name, reply }).map_err(|_| t.stopped())?;
        if let Ok(Ok(ips)) = rx.await
            && let Some(ip) = ips.first()
        {
            return Ok(*ip);
        }
    }
    // nom public (ou DNS du VPN muet) : résolution par cet ordinateur
    let mut addrs = tokio::net::lookup_host((host, port)).await.map_err(|_| format!("Nom introuvable : {host}"))?;
    addrs.next().map(|a| a.ip()).ok_or_else(|| format!("Nom introuvable : {host}"))
}

// ------------------------------------------------------------------ interface smoltcp

/// Interface IP virtuelle : paquets reçus du tunnel / à chiffrer pour le serveur.
struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _t: smoltcp::time::Instant) -> Option<(RxTok, TxTok<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _t: smoltcp::time::Instant) -> Option<TxTok<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

// ------------------------------------------------------------------ transport réseau

/// Liaison avec le serveur VPN (ou, pour le serveur de test, avec le client).
enum Net {
    /// Envoi par une copie non bloquante de la socket, réception par tokio.
    Udp { send: std::net::UdpSocket, recv: tokio::net::UdpSocket, peer: Option<SocketAddr> },
    /// `listener` : serveur de test, qui accepte un client à la fois.
    Tcp { stream: Option<tokio::net::TcpStream>, wbuf: VecDeque<u8>, listener: Option<tokio::net::TcpListener> },
}

enum NetEv {
    Data(usize, Option<SocketAddr>),
    Closed(String),
    Nothing,
}

impl Net {
    fn send(&mut self, b: &[u8]) {
        match self {
            // tampon d'envoi plein : paquet perdu, TCP le renverra
            Net::Udp { send, peer: Some(peer), .. } => {
                let _ = send.send_to(b, *peer);
            }
            Net::Tcp { stream: Some(s), wbuf, .. } => {
                let mut b = b;
                if wbuf.is_empty()
                    && let Ok(n) = s.try_write(b)
                {
                    b = &b[n..];
                }
                // le reste part dès que la socket le permet (cf. `event`)
                wbuf.extend(b);
            }
            _ => {}
        }
    }

    /// Attend des données (ou de la place pour écrire ce qui est en attente sur TCP).
    async fn event(&mut self, buf: &mut [u8]) -> NetEv {
        match self {
            Net::Udp { recv, .. } => match recv.recv_from(buf).await {
                Ok((n, from)) => NetEv::Data(n, Some(from)),
                // Windows signale un port injoignable (ICMP) comme une erreur de réception : ignorée
                Err(_) => NetEv::Nothing,
            },
            Net::Tcp { stream: Some(s), wbuf, .. } => {
                tokio::select! {
                    r = s.readable() => match r.and_then(|_| s.try_read(buf)) {
                        Ok(0) => NetEv::Closed("connexion fermée".into()),
                        Ok(n) => NetEv::Data(n, s.peer_addr().ok()),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => NetEv::Nothing,
                        Err(e) => NetEv::Closed(e.to_string()),
                    },
                    r = s.writable(), if !wbuf.is_empty() => {
                        if let Err(e) = r {
                            return NetEv::Closed(e.to_string());
                        }
                        while !wbuf.is_empty() {
                            match s.try_write(wbuf.as_slices().0) {
                                Ok(0) => break,
                                Ok(n) => {
                                    wbuf.drain(..n);
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(e) => return NetEv::Closed(e.to_string()),
                            }
                        }
                        NetEv::Nothing
                    }
                }
            }
            Net::Tcp { stream: stream @ None, wbuf, listener: Some(l) } => {
                if let Ok((s, _)) = l.accept().await {
                    let _ = s.set_nodelay(true);
                    *stream = Some(s);
                    wbuf.clear();
                }
                NetEv::Nothing
            }
            Net::Tcp { stream: None, listener: None, .. } => std::future::pending().await,
        }
    }

    /// Données déjà arrivées, sans attendre (rafales).
    fn try_recv(&mut self, buf: &mut [u8]) -> Option<(usize, Option<SocketAddr>)> {
        match self {
            Net::Udp { recv, .. } => recv.try_recv_from(buf).ok().map(|(n, from)| (n, Some(from))),
            Net::Tcp { stream: Some(s), .. } => match s.try_read(buf) {
                Ok(n) if n > 0 => Some((n, None)),
                _ => None,
            },
            Net::Tcp { stream: None, .. } => None,
        }
    }
}

/// Socket UDP vers le serveur : envoi par une copie non bloquante, réception par tokio.
async fn udp_socket(bind: SocketAddr) -> Result<(std::net::UdpSocket, tokio::net::UdpSocket), String> {
    let err = |e: io::Error| format!("Socket UDP : {e}");
    let s = socket2::Socket::new(socket2::Domain::for_address(bind), socket2::Type::DGRAM, Some(socket2::Protocol::UDP)).map_err(err)?;
    // tampons larges : une fenêtre TCP entière part d'un coup, sans perte de paquets en rafale
    let _ = s.set_send_buffer_size(UDP_BUF);
    let _ = s.set_recv_buffer_size(UDP_BUF);
    s.bind(&bind.into()).map_err(err)?;
    let s: std::net::UdpSocket = s.into();
    s.set_nonblocking(true).map_err(err)?;
    let send = s.try_clone().map_err(|e| format!("Socket UDP : {e}"))?;
    let recv = tokio::net::UdpSocket::from_std(s).map_err(|e| format!("Socket UDP : {e}"))?;
    Ok((send, recv))
}

/// Résout le serveur et ouvre le transport.
async fn open_net(transport: Transport, (host, port): &(String, u16), timeout: Duration, name: &str) -> Result<Net, String> {
    let server = tokio::net::lookup_host((host.as_str(), *port))
        .await
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| format!("Serveur VPN introuvable : {host}"))?;
    match transport {
        Transport::Udp => {
            let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
            let (send, recv) = udp_socket(bind).await?;
            Ok(Net::Udp { send, recv, peer: Some(server) })
        }
        Transport::Tcp => {
            let s = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(server))
                .await
                .map_err(|_| format!("Le serveur VPN « {name} » ne répond pas ({host}:{port} en TCP)"))?
                .map_err(|e| format!("Serveur VPN « {name} » injoignable ({host}:{port} en TCP) : {e}"))?;
            let _ = s.set_nodelay(true);
            Ok(Net::Tcp { stream: Some(s), wbuf: VecDeque::new(), listener: None })
        }
    }
}

// ------------------------------------------------------------------ tâche du tunnel

struct Conn {
    handle: SocketHandle,
    pipe: Arc<Pipe>,
    /// Réponse à la demande d'ouverture, tant que la connexion n'est pas établie.
    reply: Option<oneshot::Sender<Result<Arc<Pipe>, String>>>,
    deadline: Instant,
    target: String,
    /// FIN envoyé (fermeture côté session).
    fin: bool,
}

struct Query {
    handle: dns::QueryHandle,
    reply: oneshot::Sender<Result<Vec<IpAddr>, String>>,
    deadline: Instant,
}

struct Engine {
    name: String,
    link: Box<dyn Link>,
    net: Net,
    iface: Interface,
    dev: Dev,
    sockets: SocketSet<'static>,
    conns: Vec<Conn>,
    dns: Option<SocketHandle>,
    /// Serveurs de la socket `dns`.
    dns_servers: Vec<IpAddr>,
    queries: Vec<Query>,
    /// Demandes reçues avant que le tunnel soit utilisable.
    held: Vec<Cmd>,
    /// Interface configurée et protocole prêt.
    up: bool,
    /// Dernier état publié pour les connexions en attente.
    published: LinkState,
    state_tx: watch::Sender<LinkState>,
    /// Début de la négociation en cours.
    connecting_since: Instant,
    handshake_timeout: Duration,
    unreachable: String,
    next_port: u16,
    /// Connexions acceptées sur ce port (serveur de test).
    listen: Option<(u16, SocketHandle, mpsc::UnboundedSender<VpnStream>)>,
    fatal: Option<String>,
    wake: Arc<Notify>,
}

fn now() -> smoltcp::time::Instant {
    smoltcp::time::Instant::now()
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUF]), tcp::SocketBuffer::new(vec![0; TCP_BUF]));
    // sessions interactives : pas d'attente de regroupement ; une coupure finit par une erreur
    s.set_nagle_enabled(false);
    s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(90)));
    s
}

fn interface(dev: &mut Dev) -> Interface {
    let mut cfg = Config::new(HardwareAddress::Ip);
    cfg.random_seed = u64::from_le_bytes(crate::vault::random::<8>());
    Interface::new(cfg, dev, now())
}

impl Engine {
    /// Interface sans adresse : elle est configurée quand le protocole est prêt (`configure`).
    fn new(name: String, link: Box<dyn Link>, net: Net, wake: Arc<Notify>, state_tx: watch::Sender<LinkState>) -> Self {
        let mut dev = Dev { rx: VecDeque::new(), tx: VecDeque::new(), mtu: DEFAULT_MTU as usize };
        let iface = interface(&mut dev);
        let published = state_tx.borrow().clone();
        Self {
            name,
            link,
            net,
            iface,
            dev,
            sockets: SocketSet::new(Vec::new()),
            conns: Vec::new(),
            dns: None,
            dns_servers: Vec::new(),
            queries: Vec::new(),
            held: Vec::new(),
            up: false,
            published,
            state_tx,
            connecting_since: Instant::now(),
            handshake_timeout: HANDSHAKE_TIMEOUT,
            unreachable: String::new(),
            next_port: 49152 + (u16::from_le_bytes(crate::vault::random::<2>()) % 16000),
            listen: None,
            fatal: None,
            wake,
        }
    }

    /// Applique les réglages du protocole (adresses, routes, DNS, MTU).
    fn configure(&mut self, info: &LinkInfo) {
        // smoltcp lit le MTU à la création de l'interface : elle est recréée (les sockets n'en
        // dépendent pas)
        self.dev.mtu = info.mtu.max(576) as usize;
        self.iface = interface(&mut self.dev);
        let valid = |(ip, p): &&(IpAddr, u8)| *p <= if ip.is_ipv4() { 32 } else { 128 };
        self.iface.update_ip_addrs(|a| {
            for (ip, prefix) in info.addrs.iter().filter(valid) {
                let _ = a.push(IpCidr::new(IpAddress::from(*ip), *prefix));
            }
        });
        // tout ce qui n'est pas sur le réseau local part dans le tunnel
        if let Some(IpAddr::V4(v4)) = info.addrs.iter().map(|a| a.0).find(IpAddr::is_ipv4) {
            let _ = self.iface.routes_mut().add_default_ipv4_route(v4);
        }
        if let Some(IpAddr::V6(v6)) = info.addrs.iter().map(|a| a.0).find(IpAddr::is_ipv6) {
            let _ = self.iface.routes_mut().add_default_ipv6_route(v6);
        }
        if info.dns != self.dns_servers {
            if let Some(h) = self.dns.take() {
                for q in self.queries.drain(..) {
                    let _ = q.reply.send(Err("DNS du VPN modifié".into()));
                }
                self.sockets.remove(h);
            }
            self.dns = (!info.dns.is_empty()).then(|| {
                let servers: Vec<IpAddress> = info.dns.iter().take(4).map(|ip| IpAddress::from(*ip)).collect();
                self.sockets.add(dns::Socket::new(&servers, Vec::new()))
            });
            self.dns_servers = info.dns.clone();
        }
    }

    /// Relit l'état du protocole : configuration de l'interface, publication, délai de négociation.
    fn check_state(&mut self) {
        if self.link.state() != &self.published {
            let st = self.link.state().clone();
            match &st {
                LinkState::Up(info) => {
                    self.configure(info);
                    self.up = true;
                    for c in std::mem::take(&mut self.held) {
                        self.command(c);
                    }
                }
                LinkState::Connecting(_) => {
                    // renégociation complète (reconnexion) : nouveau délai
                    if self.up {
                        self.connecting_since = Instant::now();
                    }
                    self.up = false;
                }
                LinkState::Failed(e) => self.fatal = Some(e.clone()),
            }
            self.state_tx.send_replace(st.clone());
            self.published = st;
        }
        if !self.up
            && self.listen.is_none()
            && self.fatal.is_none()
            && matches!(self.published, LinkState::Connecting(_))
            && Instant::now() >= self.connecting_since + self.handshake_timeout
        {
            self.fatal = Some(self.unreachable.clone());
        }
    }

    /// Données reçues du serveur VPN.
    fn receive(&mut self, data: &[u8], from: Option<SocketAddr>) {
        // client : le socket UDP n'est pas connecté, seuls les datagrammes du serveur comptent
        if self.listen.is_none()
            && let (Net::Udp { peer: Some(p), .. }, Some(f)) = (&self.net, from)
            && (f.ip().to_canonical() != p.ip().to_canonical() || f.port() != p.port())
        {
            return;
        }
        let ok = self.link.input(data, from);
        if ok && self.listen.is_some() && let Net::Udp { peer, .. } = &mut self.net {
            *peer = from.or(*peer);
        }
        self.link_io();
    }

    /// Ce que le protocole a produit : paquets IP pour smoltcp, données pour le serveur.
    fn link_io(&mut self) {
        while let Some(p) = self.link.recv_ip() {
            self.dev.rx.push_back(p);
        }
        while let Some(b) = self.link.poll_net() {
            self.net.send(&b);
        }
    }

    fn timers(&mut self) {
        self.link.tick();
        self.link_io();
    }

    /// Paquets produits par smoltcp : chiffrés et envoyés au serveur.
    fn flush(&mut self) {
        while let Some(pkt) = self.dev.tx.pop_front() {
            self.link.send_ip(&pkt);
        }
        self.link_io();
    }

    fn poll(&mut self) {
        self.iface.poll(now(), &mut self.dev, &mut self.sockets);
    }

    fn command(&mut self, cmd: Cmd) {
        if !self.up {
            self.held.push(cmd);
            return;
        }
        match cmd {
            Cmd::Connect { ip, port, reply } => {
                let target = match ip {
                    IpAddr::V6(_) => format!("[{ip}]:{port}"),
                    IpAddr::V4(_) => format!("{ip}:{port}"),
                };
                let mut s = tcp_socket();
                let local = self.local_port();
                if s.connect(self.iface.context(), (IpAddress::from(ip), port), local).is_err() {
                    let v = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
                    let _ = reply.send(Err(format!("Le VPN « {} » n'a pas d'adresse {v} pour joindre {target}", self.name)));
                    return;
                }
                let handle = self.sockets.add(s);
                let pipe = Arc::new(Pipe { state: Mutex::new(PipeState::default()), wake: self.wake.clone() });
                let deadline = Instant::now() + CONNECT_TIMEOUT;
                self.conns.push(Conn { handle, pipe, reply: Some(reply), deadline, target, fin: false });
            }
            Cmd::Resolve { name, reply } => {
                let Some(h) = self.dns else {
                    let _ = reply.send(Err("Aucun DNS".into()));
                    return;
                };
                let v6_only = !self.iface.ip_addrs().iter().any(|a| matches!(a.address(), IpAddress::Ipv4(_)));
                let kind = if v6_only { DnsQueryType::Aaaa } else { DnsQueryType::A };
                let cx = self.iface.context();
                match self.sockets.get_mut::<dns::Socket>(h).start_query(cx, &name, kind) {
                    Ok(handle) => self.queries.push(Query { handle, reply, deadline: Instant::now() + DNS_TIMEOUT }),
                    Err(e) => {
                        let _ = reply.send(Err(format!("{e:?}")));
                    }
                }
            }
        }
    }

    fn local_port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 65000 { 49152 } else { self.next_port + 1 };
        self.next_port
    }

    /// Fait passer les données entre les flux des sessions et les sockets smoltcp.
    fn pump(&mut self) {
        let now = Instant::now();
        let handshake_late = !self.link.established() && now >= self.connecting_since + self.handshake_timeout;
        let mut i = 0;
        while i < self.conns.len() {
            let c = &mut self.conns[i];
            let s = self.sockets.get_mut::<tcp::Socket>(c.handle);
            if c.reply.is_some() {
                let err = match s.state() {
                    tcp::State::Established | tcp::State::CloseWait => {
                        let reply = c.reply.take().expect("réponse");
                        if reply.send(Ok(c.pipe.clone())).is_err() {
                            // demande abandonnée (onglet fermé)
                            s.abort();
                        }
                        i += 1;
                        continue;
                    }
                    tcp::State::Closed => Some(format!("Connexion refusée par {} (via le VPN « {} »)", c.target, self.name)),
                    _ if handshake_late => Some(self.unreachable.clone()),
                    _ if now >= c.deadline => Some(format!("Délai dépassé vers {} (via le VPN « {} »)", c.target, self.name)),
                    _ => None,
                };
                match err {
                    Some(e) => {
                        let _ = c.reply.take().expect("réponse").send(Err(e));
                        s.abort();
                        self.sockets.remove(c.handle);
                        self.conns.swap_remove(i);
                    }
                    None => i += 1,
                }
                continue;
            }

            // flux abandonné par la session : fermeture propre après envoi de ce qui reste
            let gone = Arc::strong_count(&c.pipe) == 1;
            let mut st = c.pipe.lock();
            let mut wrote = false;
            while s.can_send() && !st.tx.is_empty() {
                let n = s.send_slice(st.tx.as_slices().0).unwrap_or(0);
                if n == 0 {
                    break;
                }
                st.tx.drain(..n);
                wrote = true;
            }
            if wrote && let Some(w) = st.write_waker.take() {
                w.wake();
            }
            if (st.shutdown || gone) && st.tx.is_empty() && !c.fin {
                s.close();
                c.fin = true;
            }
            let mut got = false;
            while s.can_recv() && (gone || st.rx.len() < PIPE_MAX) {
                let room = if gone { usize::MAX } else { PIPE_MAX - st.rx.len() };
                let n = s
                    .recv(|b| {
                        let n = b.len().min(room);
                        if !gone {
                            st.rx.extend(&b[..n]);
                        }
                        (n, n)
                    })
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                got = true;
            }
            if !s.may_recv() && !s.can_recv() && !st.eof {
                st.eof = true;
                got = true;
            }
            if !s.may_send() && !st.write_closed && !c.fin {
                st.write_closed = true;
                if let Some(w) = st.write_waker.take() {
                    w.wake();
                }
            }
            if got && let Some(w) = st.read_waker.take() {
                w.wake();
            }
            drop(st);
            let done = matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait)
                || (gone && c.fin && matches!(s.state(), tcp::State::FinWait2 | tcp::State::Closing | tcp::State::LastAck));
            if gone && done {
                self.sockets.remove(c.handle);
                self.conns.swap_remove(i);
            } else {
                i += 1;
            }
        }

        if let Some(h) = self.dns {
            let dns = self.sockets.get_mut::<dns::Socket>(h);
            let mut k = 0;
            while k < self.queries.len() {
                let q = &self.queries[k];
                let res = match dns.get_query_result(q.handle) {
                    Ok(ips) => Some(Ok(ips.iter().map(|a| IpAddr::from(*a)).collect())),
                    Err(dns::GetQueryResultError::Failed) => Some(Err("Nom introuvable".to_string())),
                    Err(dns::GetQueryResultError::Pending) if now >= q.deadline => {
                        dns.cancel_query(q.handle);
                        Some(Err("DNS du VPN muet".to_string()))
                    }
                    Err(dns::GetQueryResultError::Pending) => None,
                };
                match res {
                    Some(r) => {
                        let _ = self.queries.swap_remove(k).reply.send(r);
                    }
                    None => k += 1,
                }
            }
        }

        if let Some((port, h, accepted)) = &mut self.listen {
            let s = self.sockets.get_mut::<tcp::Socket>(*h);
            if !matches!(s.state(), tcp::State::Listen | tcp::State::SynReceived) {
                let pipe = Arc::new(Pipe { state: Mutex::new(PipeState::default()), wake: self.wake.clone() });
                let _ = accepted.send(VpnStream { pipe: pipe.clone(), _tunnel: None });
                let target = "client".to_string();
                self.conns.push(Conn { handle: *h, pipe, reply: None, deadline: now, target, fin: false });
                let mut s = tcp_socket();
                let _ = s.listen(*port);
                *h = self.sockets.add(s);
            }
        }
    }

    /// Prochaine échéance de smoltcp (retransmission, keepalive…).
    fn delay(&mut self) -> Duration {
        let d = self.iface.poll_delay(now(), &self.sockets).map(|d| Duration::from_micros(d.total_micros()));
        d.unwrap_or(TIMER_TICK).min(TIMER_TICK)
    }

    fn fail_all(&mut self, e: &str) {
        for c in &mut self.conns {
            match c.reply.take() {
                Some(r) => {
                    let _ = r.send(Err(e.to_string()));
                }
                None => {
                    let mut st = c.pipe.lock();
                    st.eof = true;
                    st.write_closed = true;
                    for w in [st.read_waker.take(), st.write_waker.take()].into_iter().flatten() {
                        w.wake();
                    }
                }
            }
        }
        for q in self.queries.drain(..) {
            let _ = q.reply.send(Err(e.to_string()));
        }
        for c in self.held.drain(..) {
            c.fail(e);
        }
    }
}

enum Wake {
    Cmd(Option<Cmd>),
    Net(NetEv),
    Other,
}

/// Arrêt sur erreur : l'erreur est notée avant la fin de la tâche, pour les connexions en attente.
fn stop(fatal: &Mutex<Option<String>>, state: &watch::Sender<LinkState>, msg: String) {
    if let Ok(mut f) = fatal.lock() {
        *f = Some(msg.clone());
    }
    state.send_replace(LinkState::Failed(msg));
}

async fn run(
    setup: LinkSetup,
    name: String,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    state_tx: watch::Sender<LinkState>,
    fatal: Arc<Mutex<Option<String>>>,
) {
    let LinkSetup { link, transport, server, handshake_timeout, unreachable, .. } = setup;
    let started = Instant::now();
    let net = match open_net(transport, &server, handshake_timeout, &name).await {
        Ok(n) => n,
        Err(msg) => return stop(&fatal, &state_tx, msg),
    };
    let wake = Arc::new(Notify::new());
    let mut e = Engine::new(name, link, net, wake.clone(), state_tx);
    // la connexion TCP au serveur compte dans le délai de négociation
    e.connecting_since = started;
    e.handshake_timeout = handshake_timeout;
    e.unreachable = unreachable;
    if let Err(msg) = event_loop(&mut e, &wake, &mut cmd_rx).await {
        e.fail_all(&msg);
        stop(&fatal, &e.state_tx, msg);
    }
}

async fn event_loop(e: &mut Engine, wake: &Notify, cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>) -> Result<(), String> {
    let mut inbuf = vec![0u8; 65_600];
    let mut last_timers = Instant::now();
    loop {
        e.check_state();
        e.poll();
        e.pump();
        e.poll();
        e.flush();
        e.check_state();
        if let Some(f) = e.fatal.take() {
            return Err(f);
        }
        let delay = e.delay();
        let ev = tokio::select! {
            c = cmd_rx.recv() => Wake::Cmd(c),
            r = e.net.event(&mut inbuf) => Wake::Net(r),
            _ = wake.notified() => Wake::Other,
            _ = tokio::time::sleep(delay) => Wake::Other,
        };
        match ev {
            // plus aucune session ni demande : le tunnel se ferme
            Wake::Cmd(None) if e.listen.is_none() => return Ok(()),
            Wake::Cmd(None) => {}
            Wake::Cmd(Some(c)) => e.command(c),
            Wake::Net(NetEv::Data(n, from)) => {
                e.receive(&inbuf[..n], from);
                // rafale : on vide ce qui est déjà arrivé avant de repasser par smoltcp
                for _ in 0..64 {
                    match e.net.try_recv(&mut inbuf) {
                        Some((n, from)) => e.receive(&inbuf[..n], from),
                        None => break,
                    }
                }
            }
            Wake::Net(NetEv::Closed(why)) if e.listen.is_none() => {
                return Err(format!("Le serveur VPN « {} » a coupé la connexion ({why})", e.name));
            }
            // serveur de test : le client suivant prendra la place
            Wake::Net(NetEv::Closed(_)) => {
                if let Net::Tcp { stream, wbuf, .. } = &mut e.net {
                    *stream = None;
                    wbuf.clear();
                }
            }
            Wake::Net(NetEv::Nothing) | Wake::Other => {}
        }
        if last_timers.elapsed() >= TIMER_TICK {
            last_timers = Instant::now();
            e.timers();
        }
    }
}

// ------------------------------------------------------------------ serveur de test

/// Côté serveur d'un tunnel en mémoire, avec un protocole quelconque : accepte les connexions TCP
/// faites dans le tunnel sur `listen_port` et les relaie vers `forward`. Renvoie le port (UDP ou
/// TCP) d'écoute sur 127.0.0.1. En TCP, un client à la fois (le suivant remplace le précédent).
#[cfg(test)]
pub(crate) async fn serve(link: Box<dyn Link>, transport: Transport, listen_port: u16, forward: SocketAddr) -> u16 {
    let (net, port) = match transport {
        Transport::Udp => {
            let (send, recv) = udp_socket(([127, 0, 0, 1], 0).into()).await.unwrap();
            let port = recv.local_addr().unwrap().port();
            (Net::Udp { send, recv, peer: None }, port)
        }
        Transport::Tcp => {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = l.local_addr().unwrap().port();
            (Net::Tcp { stream: None, wbuf: VecDeque::new(), listener: Some(l) }, port)
        }
    };
    let wake = Arc::new(Notify::new());
    let (state_tx, _) = watch::channel(LinkState::Connecting(String::new()));
    let mut e = Engine::new("test".into(), link, net, wake.clone(), state_tx);
    let mut s = tcp_socket();
    s.listen(listen_port).unwrap();
    let h = e.sockets.add(s);
    let (tx, mut accepted) = mpsc::unbounded_channel();
    e.listen = Some((listen_port, h, tx));
    tokio::spawn(async move {
        while let Some(mut stream) = accepted.recv().await {
            tokio::spawn(async move {
                if let Ok(mut tcp) = tokio::net::TcpStream::connect(forward).await {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                }
            });
        }
    });
    tokio::spawn(async move {
        let (_keep, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
        let _ = event_loop(&mut e, &wake, &mut cmd_rx).await;
    });
    port
}

/// Serveur WireGuard minimal en mémoire (cf. `serve`). Renvoie son port UDP.
#[cfg(test)]
pub(crate) async fn test_server(server_key: &str, client_public: &str, address: &str, listen_port: u16, forward: SocketAddr) -> u16 {
    let c = WireGuardConfig {
        private_key: server_key.into(),
        address: address.into(),
        peer_public_key: client_public.into(),
        endpoint: "127.0.0.1:1".into(),
        ..Default::default()
    };
    let p = wireguard_params(&c).unwrap();
    serve(Box::new(WgLink::new(&p, "test", true)), Transport::Udp, listen_port, forward).await
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CONF: &str = "\u{feff}[Interface]
# poste de test
PrivateKey = 81XpVNy/290KDNrujvfebhFB8TNoSXOqwt7iv8T6BbU=
Address = 10.66.0.2/32
Address = fd00::2/128
DNS = 10.66.0.1, corp.local
MTU = 1380
PostUp = iptables -A FORWARD

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
Endpoint = vpn.exemple.fr:51821
AllowedIPs = 10.66.0.0/24, 192.168.1.0/24
PersistentKeepalive = 25

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
AllowedIPs = 10.99.0.0/16
";

    #[test]
    fn wireguard_file_is_read_and_checked() {
        let c = parse_wireguard(CONF).unwrap();
        assert_eq!(c.private_key, "81XpVNy/290KDNrujvfebhFB8TNoSXOqwt7iv8T6BbU=");
        assert_eq!(c.address, "10.66.0.2/32, fd00::2/128");
        assert_eq!(c.dns, "10.66.0.1, corp.local");
        assert_eq!(c.mtu, 1380);
        assert_eq!(c.peer_public_key, "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
        assert_eq!(c.endpoint, "vpn.exemple.fr:51821");
        // second [Peer] ignoré
        assert_eq!(c.allowed_ips, "10.66.0.0/24, 192.168.1.0/24");
        assert_eq!(c.keepalive, 25);
        let p = wireguard_params(&c).unwrap();
        assert_eq!(p.dns, ["10.66.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(p.search, ["corp.local"]);
        assert_eq!(p.endpoint, ("vpn.exemple.fr".into(), 51821));
        assert!(p.psk.is_some());

        let mut profile = VpnProfile::default();
        profile.name = "Client A".into();
        profile.wireguard = c.clone();
        assert!(check(&profile).is_ok());
        let mut unnamed = profile.clone();
        unnamed.name = " ".into();
        assert!(check(&unnamed).is_err());
        let mut bad = c.clone();
        bad.peer_public_key = "abc".into();
        assert!(wireguard_params(&bad).err().unwrap().contains("Clé publique"));
        let mut bad = c.clone();
        bad.address = "10.66.0.300/32".into();
        assert!(wireguard_params(&bad).is_err());
        let mut bad = c;
        bad.endpoint.clear();
        assert!(wireguard_params(&bad).err().unwrap().contains("Endpoint"));

        assert!(parse_wireguard("[Interface]\nPrivateKey = x\n").unwrap_err().contains("[Peer]"));
        assert!(parse_wireguard("bonjour").is_err());
    }

    #[test]
    fn networks_and_keys() {
        let net = cidr("10.66.0.0/24").unwrap();
        assert!(in_net("10.66.0.200".parse().unwrap(), net));
        assert!(!in_net("10.67.0.1".parse().unwrap(), net));
        assert!(in_net("8.8.8.8".parse().unwrap(), cidr("0.0.0.0/0").unwrap()));
        assert!(in_net("fd00::5".parse().unwrap(), cidr("fd00::/64").unwrap()));
        assert!(!in_net("fd00::5".parse().unwrap(), net));
        assert_eq!(cidr("10.0.0.1").unwrap().1, 32);
        assert!(cidr("10.0.0.1/33").is_err());

        let k = generate_private_key();
        let public = public_key(&k).unwrap();
        assert_eq!(public.len(), 44);
        assert_ne!(public, k);
        assert!(public_key("pas une clé").is_none());
    }

    fn client(server_port: u16, client_key: &str, server_public: &str) -> VpnProfile {
        let mut p = VpnProfile::default();
        p.name = "Test".into();
        p.wireguard = WireGuardConfig {
            private_key: client_key.into(),
            address: "10.66.0.2/32".into(),
            peer_public_key: server_public.into(),
            endpoint: format!("127.0.0.1:{server_port}"),
            allowed_ips: "10.66.0.0/24".into(),
            ..Default::default()
        };
        p
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_through_the_tunnel_shared_then_closed() {
        // service TCP « derrière » le VPN : met en majuscules
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let svc = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n].to_ascii_uppercase()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let (sk, ck) = (generate_private_key(), generate_private_key());
        let port = test_server(&sk, &public_key(&ck).unwrap(), "10.66.0.1/24", 22, svc).await;
        let profile = client(port, &ck, &public_key(&sk).unwrap());

        let mut a = connect(&profile, "10.66.0.1", 22).await.unwrap();
        a.write_all(b"bonjour").await.unwrap();
        let mut out = [0u8; 7];
        a.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"BONJOUR");

        // gros transfert (plusieurs fenêtres TCP, paquets découpés au MTU)
        let big: Vec<u8> = (0..1_500_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(a);
        let expect = big.to_ascii_uppercase();
        let writer = tokio::spawn(async move {
            wr.write_all(&big).await.unwrap();
            wr
        });
        let mut got = vec![0u8; expect.len()];
        tokio::time::timeout(Duration::from_secs(30), rd.read_exact(&mut got)).await.unwrap().unwrap();
        assert!(got == expect, "données altérées");
        let wr = writer.await.unwrap();

        // deuxième connexion : même tunnel
        let b = connect(&profile, "10.66.0.1", 22).await.unwrap();
        assert!(Arc::ptr_eq(a_tunnel(&b), &tunnel(&profile).unwrap()));
        drop(rd.unsplit(wr));
        drop(b);
        // dernière connexion fermée : le tunnel s'arrête
        let deadline = Instant::now() + Duration::from_secs(5);
        while TUNNELS.lock().unwrap().iter().any(|(id, _, w)| *id == profile.id && w.strong_count() > 0) {
            assert!(Instant::now() < deadline, "tunnel toujours ouvert");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // hors des AllowedIPs, port fermé
        let e = connect(&profile, "10.99.0.1", 22).await.err().unwrap();
        assert!(e.contains("AllowedIPs"), "{e}");
        let e = connect(&profile, "10.66.0.1", 23).await.err().unwrap();
        assert!(e.contains("refusée") || e.contains("Délai"), "{e}");
    }

    fn a_tunnel(s: &VpnStream) -> &Arc<Tunnel> {
        s._tunnel.as_ref().unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_server_key_is_reported() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let svc = l.local_addr().unwrap();
        let (sk, ck) = (generate_private_key(), generate_private_key());
        let port = test_server(&sk, &public_key(&ck).unwrap(), "10.66.0.1/24", 22, svc).await;
        // clé publique d'un autre serveur : la négociation n'aboutit jamais
        let profile = client(port, &ck, &public_key(&generate_private_key()).unwrap());
        let started = Instant::now();
        let e = connect(&profile, "10.66.0.1", 22).await.err().unwrap();
        assert!(e.contains("ne répond pas"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(14));
    }

    // ---------------------------------------------------------------- protocole factice

    /// Protocole de test : aucune cryptographie, négociation « H » → « W » (réponse du serveur au
    /// troisième tour de minuterie), paquets IP préfixés par « D ». En TCP, chaque message est
    /// précédé de sa longueur sur 2 octets, comme OpenVPN.
    struct FakeLink {
        tcp: bool,
        server: bool,
        /// Le serveur refuse le client (« N »).
        refuse: bool,
        rbuf: Vec<u8>,
        net: VecDeque<Vec<u8>>,
        ip: VecDeque<Vec<u8>>,
        state: LinkState,
        welcome_in: Option<u32>,
    }

    fn fake_info(addr: &str, mtu: u16) -> LinkInfo {
        LinkInfo { addrs: vec![cidr(addr).unwrap()], dns: vec![], search: vec![], routes: vec![cidr("10.77.0.0/24").unwrap()], mtu }
    }

    impl FakeLink {
        fn new(tcp: bool, server: bool, refuse: bool) -> Self {
            let state =
                if server { LinkState::Up(fake_info("10.77.0.1/24", 1400)) } else { LinkState::Connecting("Négociation…".into()) };
            let mut l = Self { tcp, server, refuse, rbuf: vec![], net: VecDeque::new(), ip: VecDeque::new(), state, welcome_in: None };
            if !server {
                l.push(b'H', &[]);
            }
            l
        }

        fn push(&mut self, kind: u8, payload: &[u8]) {
            let mut m = Vec::with_capacity(payload.len() + 3);
            if self.tcp {
                m.extend(((payload.len() + 1) as u16).to_be_bytes());
            }
            m.push(kind);
            m.extend(payload);
            self.net.push_back(m);
        }

        fn message(&mut self, m: &[u8]) -> bool {
            match (m.first(), self.server) {
                (Some(b'H'), true) if self.refuse => self.push(b'N', &[]),
                (Some(b'H'), true) => self.welcome_in = Some(2),
                (Some(b'W'), false) => self.state = LinkState::Up(fake_info("10.77.0.2/24", 1300)),
                (Some(b'N'), false) => self.state = LinkState::Failed("Accès refusé par le serveur".into()),
                (Some(b'D'), _) => self.ip.push_back(m[1..].to_vec()),
                _ => return false,
            }
            true
        }
    }

    impl Link for FakeLink {
        fn input(&mut self, data: &[u8], _from: Option<SocketAddr>) -> bool {
            if !self.tcp {
                return self.message(data);
            }
            self.rbuf.extend_from_slice(data);
            let mut ok = true;
            while self.rbuf.len() >= 2 {
                let n = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]) as usize;
                if self.rbuf.len() < 2 + n {
                    break;
                }
                let m: Vec<u8> = self.rbuf.drain(..2 + n).skip(2).collect();
                ok &= self.message(&m);
            }
            ok
        }
        fn send_ip(&mut self, packet: &[u8]) {
            if matches!(self.state, LinkState::Up(_)) {
                self.push(b'D', packet);
            }
        }
        fn tick(&mut self) {
            match self.welcome_in {
                Some(0) => {
                    self.welcome_in = None;
                    self.push(b'W', &[]);
                }
                Some(n) => self.welcome_in = Some(n - 1),
                None => {}
            }
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

    fn fake_client(tcp: bool, port: u16, timeout: Duration) -> Arc<Tunnel> {
        let transport = if tcp { Transport::Tcp } else { Transport::Udp };
        launch(
            "Factice",
            LinkSetup {
                link: Box::new(FakeLink::new(tcp, false, false)),
                transport,
                server: ("127.0.0.1".into(), port),
                handshake_timeout: timeout,
                unreachable: "Serveur factice muet".into(),
                routes_hint: "routes du serveur",
            },
        )
    }

    async fn upper_service() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let svc = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n].to_ascii_uppercase()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        svc
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deferred_configuration_over_tcp_and_udp() {
        let svc = upper_service().await;
        for tcp in [true, false] {
            let transport = if tcp { Transport::Tcp } else { Transport::Udp };
            let port = serve(Box::new(FakeLink::new(tcp, true, false)), transport, 22, svc).await;
            let t = fake_client(tcp, port, Duration::from_secs(10));
            // la connexion attend la fin de la négociation (adresse inconnue jusque-là)
            let mut steps = Vec::new();
            let mut a = open(t.clone(), "10.77.0.1", 22, |s: &str| steps.push(s.to_string())).await.unwrap();
            assert!(steps.iter().any(|s| s == "Négociation…"), "{steps:?}");
            assert!(matches!(&*t.state.borrow(), LinkState::Up(i) if i.mtu == 1300));
            a.write_all(b"bonjour").await.unwrap();
            let mut out = [0u8; 7];
            a.read_exact(&mut out).await.unwrap();
            assert_eq!(&out, b"BONJOUR");

            // gros transfert : flux TCP découpé n'importe où, paquets au MTU appris
            let big: Vec<u8> = (0..400_000u32).map(|i| b'a' + (i % 26) as u8).collect();
            let expect = big.to_ascii_uppercase();
            let (mut rd, mut wr) = tokio::io::split(a);
            let writer = tokio::spawn(async move { wr.write_all(&big).await.unwrap() });
            let mut got = vec![0u8; expect.len()];
            tokio::time::timeout(Duration::from_secs(30), rd.read_exact(&mut got)).await.unwrap().unwrap();
            assert!(got == expect, "données altérées (tcp={tcp})");
            writer.await.unwrap();

            // routes appliquées une fois le tunnel prêt
            let e = open(t.clone(), "10.78.0.1", 22, |_: &str| {}).await.err().unwrap();
            assert!(e.contains("routes du serveur"), "{e}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn link_failure_and_silence_are_reported() {
        let svc = upper_service().await;
        let port = serve(Box::new(FakeLink::new(true, true, true)), Transport::Tcp, 22, svc).await;
        let t = fake_client(true, port, Duration::from_secs(10));
        let e = open(t.clone(), "10.77.0.1", 22, |_: &str| {}).await.err().unwrap();
        assert_eq!(e, "Accès refusé par le serveur");
        // le tunnel s'est arrêté : les demandes suivantes reçoivent la même explication
        let e = open(t, "10.77.0.1", 22, |_: &str| {}).await.err().unwrap();
        assert_eq!(e, "Accès refusé par le serveur");

        // serveur muet (UDP) : délai de négociation propre au protocole
        let mute = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let started = Instant::now();
        let t = fake_client(false, mute.local_addr().unwrap().port(), Duration::from_secs(1));
        let e = open(t, "10.77.0.1", 22, |_: &str| {}).await.err().unwrap();
        assert_eq!(e, "Serveur factice muet");
        assert!(started.elapsed() < Duration::from_secs(3));

        // port TCP fermé
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let t = fake_client(true, port, Duration::from_secs(5));
        let e = open(t, "10.77.0.1", 22, |_: &str| {}).await.err().unwrap();
        assert!(e.contains("injoignable") || e.contains("ne répond pas"), "{e}");
    }
}
