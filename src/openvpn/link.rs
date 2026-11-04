//! Lien OpenVPN pour le tunnel en mémoire de `vpn` : découpage du flux TCP, aiguillage contrôle /
//! données, chiffrement du canal de données (P_DATA_V2 si le serveur attribue un peer-id),
//! cadrage de compression, ping et ping-restart, réglages réseau tirés du PUSH_REPLY.
//!
//! En UDP, une session perdue après avoir fonctionné (RESTART, ping-restart, renégociation ratée)
//! est rouverte sur place : le tunnel repasse en `Connecting` et les connexions TCP ouvertes à
//! l'intérieur survivent si le serveur redonne la même adresse. En TCP, le transport ne peut pas
//! être rouvert par le lien : la session échoue et le prochain `connect` refait un tunnel.

use super::control::{ClientSetup, ControlSession, Event, Negotiated, PushOptions, Topology, mask_prefix};
use super::data::{self, Compression, DataChannel, DataCipher, Digest, Role};
use super::packet::{self, DataHeader, TcpFramer};
use crate::model::OpenVpnConfig;
use crate::vpn::{Link, LinkInfo, LinkState};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Durée de vie de l'ancienne clé après une renégociation (`transition-window`).
const TRANSITION: Duration = Duration::from_secs(60);
/// Ping envoyé après ce délai sans émission, si le serveur n'en pousse pas d'autre.
const DEFAULT_PING: Duration = Duration::from_secs(10);
/// Silence du serveur au-delà duquel la session est tenue pour perdue, si ni le serveur ni le
/// profil n'indiquent de `ping-restart` : un tunnel mort n'est pas gardé indéfiniment.
const DEFAULT_PING_RESTART: Duration = Duration::from_secs(120);
const DEFAULT_TUN_MTU: u16 = 1500;
/// Taille visée d'un datagramme chiffré (en-têtes IP et UDP compris) : comme `mssfix`, les
/// paquets de smoltcp (et le MSS annoncé) restent assez petits pour ne pas être fragmentés.
const UDP_TARGET: usize = 1450;
/// En-tête des messages OCC du canal de données (occ.c) ; `OCC_EXIT` = le pair s'en va.
const OCC_MAGIC: [u8; 16] = [0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c];
const OCC_EXIT: u8 = 6;
/// Pause avant de rouvrir une session UDP perdue.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// Reconnexion recommencée si le serveur reste muet ce délai.
const RECONNECT_STALL: Duration = Duration::from_secs(5);

/// Serveur d'un profil (nom ou adresse, port ; 1194 par défaut).
pub(crate) fn server(cfg: &OpenVpnConfig) -> (String, u16) {
    (cfg.remote.trim().to_string(), if cfg.port == 0 { 1194 } else { cfg.port })
}

/// Clé du canal de données (une par `key_id` : en service, ou ancienne en fin de vie).
struct DataKey {
    key_id: u8,
    chan: DataChannel,
    expires: Option<Instant>,
}

/// Client OpenVPN branché sur le tunnel en mémoire (cf. `vpn::Link`).
pub(crate) struct OpenVpnLink {
    name: String,
    setup: Arc<ClientSetup>,
    control: ControlSession,
    framer: TcpFramer,
    state: LinkState,
    keys: Vec<DataKey>,
    tx_key: Option<u8>,
    cipher: Option<(DataCipher, Digest)>,
    peer_id: Option<u32>,
    compression: Compression,
    ping: Duration,
    ping_restart: Option<Duration>,
    /// `ping-restart` par défaut, mis en service au premier ping reçu du serveur.
    ping_restart_default: Option<Duration>,
    /// `ping-exit` : silence du serveur = arrêt, sans reconnexion.
    ping_exit: bool,
    last_rx: Instant,
    last_tx: Instant,
    net: VecDeque<Vec<u8>>,
    ip: VecDeque<Vec<u8>>,
    /// Le tunnel a fonctionné au moins une fois (une reconnexion a un sens).
    ever_up: bool,
    /// Reconnexion UDP programmée.
    reconnect_at: Option<Instant>,
}

impl OpenVpnLink {
    /// Prépare la connexion d'un profil ; la réinitialisation part au premier `poll_net`.
    pub(crate) fn new(name: &str, cfg: &OpenVpnConfig, username: &str, password: &str) -> Result<Self, String> {
        let setup = Arc::new(ClientSetup::new(cfg, username, password)?);
        let now = Instant::now();
        let control = ControlSession::new(setup.clone(), now)?;
        let mut l = Self {
            name: name.to_string(),
            compression: setup.compression,
            setup,
            control,
            framer: TcpFramer::new(),
            state: LinkState::Connecting("Connexion au serveur OpenVPN…".into()),
            keys: Vec::new(),
            tx_key: None,
            cipher: None,
            peer_id: None,
            ping: DEFAULT_PING,
            ping_restart: None,
            ping_restart_default: None,
            ping_exit: false,
            last_rx: now,
            last_tx: now,
            net: VecDeque::new(),
            ip: VecDeque::new(),
            ever_up: false,
            reconnect_at: None,
        };
        l.pump(now);
        Ok(l)
    }

    /// Transport du profil (`proto tcp`).
    pub(crate) fn is_tcp(&self) -> bool {
        self.setup.tcp
    }

    /// Clé d'émission en service (tests de renégociation).
    #[cfg(test)]
    pub(crate) fn tx_key_id(&self) -> Option<u8> {
        self.tx_key
    }

    /// Renégociation à l'initiative du client (tests).
    #[cfg(test)]
    pub(crate) fn force_renegotiate(&mut self) {
        let now = Instant::now();
        self.control.renegotiate(now);
        self.pump(now);
    }

    fn push_net(&mut self, pkt: Vec<u8>) {
        self.net.push_back(if self.setup.tcp { packet::frame(&pkt) } else { pkt });
    }

    /// Un paquet OpenVPN complet (datagramme ou paquet extrait du flux TCP).
    fn packet(&mut self, raw: &[u8], now: Instant) -> bool {
        let Some((op, key_id)) = packet::peek_opcode(raw) else { return false };
        let ok = if packet::is_data(op) {
            self.data_in(raw, key_id)
        } else if packet::is_control(op) {
            self.control.input(raw, now)
        } else {
            false
        };
        if ok {
            self.last_rx = now;
        }
        ok
    }

    fn data_in(&mut self, raw: &[u8], key_id: u8) -> bool {
        let Some(k) = self.keys.iter_mut().find(|k| k.key_id == key_id) else { return false };
        let Ok((_, body)) = DataHeader::parse(raw) else { return false };
        let header = &raw[..raw.len() - body.len()];
        let Ok(plain) = k.chan.decrypt(body, header) else { return false };
        // authentique : un paquet compressé (refusé) ne fait que tomber
        let Ok(p) = self.compression.unframe(plain) else { return true };
        if data::is_ping(&p) {
            if let Some(d) = self.ping_restart_default.take() {
                self.ping_restart = Some(d.max(self.ping * 2));
            }
        } else if p.len() > OCC_MAGIC.len() && p[..OCC_MAGIC.len()] == OCC_MAGIC {
            if p[OCC_MAGIC.len()] == OCC_EXIT {
                self.lost("Le serveur OpenVPN a mis fin à la session".into(), true);
            }
        } else if matches!(p.first().map(|b| b >> 4), Some(4 | 6)) {
            self.ip.push_back(p);
        }
        true
    }

    /// Chiffre et envoie un paquet sur la clé en service.
    fn send_data(&mut self, plain: Vec<u8>, now: Instant) {
        let Some(id) = self.tx_key else { return };
        let Some(k) = self.keys.iter_mut().find(|k| k.key_id == id) else { return };
        let framed = self.compression.frame(plain);
        let hdr = data::data_header(id, self.peer_id);
        let res = k.chan.encrypt(&framed, &hdr);
        let reneg = k.chan.should_renegotiate();
        match res {
            Ok(p) => {
                self.push_net(p);
                self.last_tx = now;
            }
            Err(_) => self.control.renegotiate(now),
        }
        if reneg {
            self.control.renegotiate(now);
        }
    }

    /// Lit ce que la session de contrôle a produit : paquets à envoyer, événements.
    fn pump(&mut self, now: Instant) {
        loop {
            while let Some(p) = self.control.poll_net() {
                self.push_net(p);
            }
            let Some(ev) = self.control.poll_event() else { break };
            match ev {
                Event::Status(s) => {
                    if matches!(self.state, LinkState::Connecting(_)) {
                        let s = if self.ever_up { format!("Reconnexion — {s}") } else { s };
                        self.state = LinkState::Connecting(s);
                    }
                }
                Event::Ready(n) => {
                    if let Err(e) = self.ready(*n, now) {
                        self.lost(e, false);
                    }
                }
                Event::Rekey { key_id, key2 } => {
                    let Some((cipher, digest)) = self.cipher else { continue };
                    match DataChannel::new(cipher, digest, &key2, Role::Client) {
                        Ok(chan) => {
                            let old = self.tx_key.replace(key_id);
                            for k in self.keys.iter_mut().filter(|k| Some(k.key_id) == old) {
                                k.expires = Some(now + TRANSITION);
                            }
                            self.keys.retain(|k| k.key_id != key_id);
                            self.keys.push(DataKey { key_id, chan, expires: None });
                        }
                        Err(e) => self.lost(e, true),
                    }
                }
                Event::Failed { message, retry } => self.lost(message, retry),
            }
        }
    }

    /// Première clé prête : canal de données, réglages réseau.
    fn ready(&mut self, n: Negotiated, now: Instant) -> Result<(), String> {
        let chan = DataChannel::new(n.cipher, n.digest, &n.key2, Role::Client)?;
        let o = &n.options;
        self.keys = vec![DataKey { key_id: n.key_id, chan, expires: None }];
        self.tx_key = Some(n.key_id);
        self.cipher = Some((n.cipher, n.digest));
        self.peer_id = o.peer_id;
        self.compression = o.compression.unwrap_or(self.setup.compression);
        // options poussées, sinon celles du profil (`keepalive`, `ping`, `ping-restart`)
        let secs = |p: u32| Duration::from_secs(p as u64);
        self.ping = o.ping.or(self.setup.ping).filter(|p| *p > 0).map_or(DEFAULT_PING, secs);
        self.ping_exit = o.ping_restart.is_none_or(|p| p == 0) && o.ping_exit.is_some_and(|p| p > 0);
        let restart = match (o.ping_restart, o.ping_exit) {
            (Some(p), _) if p > 0 => Some(p),
            (_, Some(p)) if p > 0 => Some(p),
            _ => self.setup.ping_restart,
        };
        self.ping_restart = restart.map(secs);
        // sans réglage : délai prudent, armé au premier ping du serveur (un serveur qui ne pinge
        // jamais n'est pas tenu pour perdu sur un simple silence, comme avec OpenVPN)
        self.ping_restart_default = restart.is_none().then_some(DEFAULT_PING_RESTART);
        let overhead = (if self.peer_id.is_some() { 4 } else { 1 })
            + n.cipher.overhead(n.digest)
            + usize::from(self.compression != Compression::None);
        let mtu = data_mtu(o.tun_mtu.or(self.setup.tun_mtu), self.setup.tcp, overhead);
        let info = if self.setup.route_nopull {
            // route-nopull : routes (et redirect-gateway) poussées ignorées, le réseau du VPN reste
            let own = PushOptions { routes: Vec::new(), route_gateway: None, redirect_gateway: false, ..o.clone() };
            profile_routes(link_info(&own, mtu)?, &self.setup)
        } else {
            profile_routes(link_info(o, mtu)?, &self.setup)
        };
        self.state = LinkState::Up(info);
        self.ever_up = true;
        self.last_rx = now;
        Ok(())
    }

    /// Session perdue : reconnexion sur place (UDP, après un premier succès) ou échec.
    fn lost(&mut self, message: String, retry: bool) {
        if matches!(self.state, LinkState::Failed(_)) {
            return;
        }
        self.keys.clear();
        self.tx_key = None;
        if retry && self.ever_up && !self.setup.tcp {
            // le serveur qui redémarre a besoin d'un instant (connect-retry d'OpenVPN)
            self.reconnect_at = Some(Instant::now() + RECONNECT_DELAY);
            self.state = LinkState::Connecting(format!("Reconnexion au serveur OpenVPN… ({message})"));
        } else {
            self.state = LinkState::Failed(format!("VPN « {} » : {message}", self.name));
        }
    }

    /// Nouvelle session de contrôle (reconnexion UDP).
    fn reconnect(&mut self, now: Instant) {
        self.reconnect_at = None;
        match ControlSession::new(self.setup.clone(), now) {
            Ok(c) => {
                self.control = c;
                self.last_rx = now;
                self.pump(now);
            }
            Err(e) => self.state = LinkState::Failed(format!("VPN « {} » : {e}", self.name)),
        }
    }
}

impl Link for OpenVpnLink {
    fn input(&mut self, data: &[u8], _from: Option<SocketAddr>) -> bool {
        if matches!(self.state, LinkState::Failed(_)) {
            return false;
        }
        let now = Instant::now();
        let mut ok = false;
        if self.setup.tcp {
            self.framer.push(data);
            loop {
                match self.framer.next_packet() {
                    Ok(Some(p)) => ok |= self.packet(&p, now),
                    Ok(None) => break,
                    Err(e) => {
                        self.lost(e, false);
                        break;
                    }
                }
            }
        } else {
            ok = self.packet(data, now);
        }
        self.pump(now);
        ok
    }

    fn send_ip(&mut self, packet: &[u8]) {
        if matches!(self.state, LinkState::Up(_)) {
            self.send_data(packet.to_vec(), Instant::now());
        }
    }

    fn tick(&mut self) {
        if matches!(self.state, LinkState::Failed(_)) {
            return;
        }
        let now = Instant::now();
        if self.reconnect_at.is_some_and(|t| now >= t) {
            self.reconnect(now);
        }
        self.control.tick(now);
        self.pump(now);
        if !matches!(self.state, LinkState::Up(_)) {
            // reconnexion sans réponse (ancien processus serveur, session oubliée) : on recommence
            if self.ever_up
                && !self.setup.tcp
                && self.reconnect_at.is_none()
                && now.saturating_duration_since(self.last_rx) >= RECONNECT_STALL
            {
                self.reconnect_at = Some(now);
            }
            return;
        }
        self.keys.retain(|k| k.expires.is_none_or(|t| now < t));
        if let Some(limit) = self.ping_restart
            && now.saturating_duration_since(self.last_rx) >= limit
        {
            let msg = format!("Le serveur OpenVPN ne répond plus (aucun paquet depuis {} s)", limit.as_secs());
            self.lost(msg, !self.ping_exit);
            self.pump(now);
            return;
        }
        if now.saturating_duration_since(self.last_tx) >= self.ping {
            self.send_data(data::PING_MAGIC.to_vec(), now);
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

/// MTU de l'interface smoltcp : `tun-mtu` poussé (1500 par défaut), réduit en UDP pour que le
/// datagramme chiffré tienne dans `UDP_TARGET` (équivalent de `mssfix`).
fn data_mtu(tun_mtu: Option<u16>, tcp: bool, overhead: usize) -> u16 {
    let tun = tun_mtu.filter(|m| *m >= 576).unwrap_or(DEFAULT_TUN_MTU);
    if tcp {
        return tun;
    }
    let fit = UDP_TARGET.saturating_sub(20 + 8 + overhead).max(576);
    tun.min(fit.min(u16::MAX as usize) as u16)
}

fn net4(a: Ipv4Addr, p: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::from(a) & u32::MAX.checked_shl(32 - p as u32).unwrap_or(0)))
}

fn net6(a: Ipv6Addr, p: u8) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(u128::from(a) & u128::MAX.checked_shl(128 - p as u32).unwrap_or(0)))
}

/// Ajoute les routes du profil (`route`, `route-ipv6`) à celles du serveur ; `redirect-gateway`
/// dans le profil = tout passe. Liste vide = aucun hôte refusé.
fn profile_routes(mut info: LinkInfo, setup: &ClientSetup) -> LinkInfo {
    // routes vides = déjà « tout » (redirect-gateway poussé) : rien à ajouter
    if setup.redirect_gateway || info.routes.is_empty() {
        info.routes.clear();
        return info;
    }
    for r in &setup.routes {
        if !info.routes.contains(r) {
            info.routes.push(*r);
        }
    }
    info
}

/// Réglages de l'interface à partir des options poussées : adresses (`ifconfig` selon la
/// topologie), réseaux joignables (réseau du VPN, `route`, tout si `redirect-gateway`), DNS.
pub(crate) fn link_info(o: &PushOptions, mtu: u16) -> Result<LinkInfo, String> {
    let (mut addrs, mut routes) = (Vec::new(), Vec::new());
    if let Some((local, second)) = o.ifconfig {
        // topology subnet : « adresse masque » ; net30 / p2p : « adresse adresse-distante »
        let subnet = match o.topology {
            Some(Topology::Subnet) => true,
            Some(_) => false,
            None => u32::from(second) >> 24 == 255 && mask_prefix(second).is_some(),
        };
        if subnet {
            let p = mask_prefix(second).ok_or_else(|| format!("Masque réseau poussé par le serveur OpenVPN invalide : {second}"))?;
            addrs.push((IpAddr::V4(local), p));
            routes.push((net4(local, p), p));
        } else {
            addrs.push((IpAddr::V4(local), 32));
            routes.push((IpAddr::V4(second), 32));
        }
    }
    if let Some((a, p)) = o.ifconfig_ipv6 {
        addrs.push((IpAddr::V6(a), p));
        routes.push((net6(a, p), p));
    }
    if addrs.is_empty() {
        return Err("Le serveur OpenVPN n'a attribué aucune adresse (ifconfig absent du PUSH_REPLY)".into());
    }
    if let Some(gw) = o.route_gateway {
        routes.push((IpAddr::V4(gw), 32));
    }
    routes.extend(o.routes.iter().copied());
    let mut uniq = Vec::new();
    for r in routes {
        if !uniq.contains(&r) {
            uniq.push(r);
        }
    }
    if o.redirect_gateway {
        uniq.clear();
    }
    Ok(LinkInfo { addrs, dns: o.dns.clone(), search: o.domains.clone(), routes: uniq, mtu })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openvpn::control::parse_push_reply;

    fn opts(body: &str) -> PushOptions {
        let mut o = PushOptions::default();
        parse_push_reply(body, &mut o).unwrap();
        o
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn link_info_from_push() {
        let o = opts(
            "route 192.168.100.0 255.255.255.0,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN escale.test,\
             route-gateway 10.8.0.1,topology subnet,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,tun-mtu 1500",
        );
        let i = link_info(&o, 1400).unwrap();
        assert_eq!(i.addrs, vec![(ip("10.8.0.2"), 24)]);
        assert_eq!(i.routes, vec![(ip("10.8.0.0"), 24), (ip("10.8.0.1"), 32), (ip("192.168.100.0"), 24)]);
        assert_eq!(i.dns, vec![ip("10.8.0.1")]);
        assert_eq!(i.search, vec!["escale.test".to_string()]);
        assert_eq!(i.mtu, 1400);

        // net30 (défaut d'OpenVPN 2.4) : adresse /32, la distante sert de passerelle
        let i = link_info(&opts("ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.1"), 1500).unwrap();
        assert_eq!(i.addrs, vec![(ip("10.8.0.6"), 32)]);
        assert_eq!(i.routes, vec![(ip("10.8.0.5"), 32), (ip("10.8.0.1"), 32)]);
        // sans topology : un masque reste reconnu
        let i = link_info(&opts("ifconfig 10.9.0.2 255.255.0.0"), 1500).unwrap();
        assert_eq!(i.addrs, vec![(ip("10.9.0.2"), 16)]);
        // p2p explicite, IPv6, redirect-gateway = tout
        let i = link_info(&opts("topology p2p,ifconfig 10.0.0.2 10.0.0.1,ifconfig-ipv6 fd00::2/64 fd00::1,redirect-gateway def1"), 1500)
            .unwrap();
        assert_eq!(i.addrs, vec![(ip("10.0.0.2"), 32), (ip("fd00::2"), 64)]);
        assert!(i.routes.is_empty());
        assert!(link_info(&opts("route 10.0.0.0 255.0.0.0"), 1500).is_err());
        assert!(link_info(&opts("topology subnet,ifconfig 10.0.0.2 255.0.255.0"), 1500).is_err());
    }

    #[test]
    fn mtu_fits_udp() {
        assert_eq!(data_mtu(None, true, 40), 1500);
        assert_eq!(data_mtu(Some(1400), true, 40), 1400);
        assert_eq!(data_mtu(None, false, 4 + 20 + 1), 1450 - 28 - 25);
        assert_eq!(data_mtu(Some(1200), false, 25), 1200);
        assert_eq!(data_mtu(Some(100), false, 25), 1397);
    }
}
