//! Couche de fiabilité du canal de contrôle OpenVPN (`reliable.c` côté OpenVPN), sans E/S : les
//! paquets de contrôle (réinitialisations, `P_CONTROL_V1` portant le TLS) sont numérotés, gardés
//! jusqu'à leur acquittement et réémis avec un délai qui double ; à la réception, ils sont remis
//! dans l'ordre, les doublons écartés (mais acquittés quand même).
//!
//! Une instance par session de clé (`key_id`) : les numéros de paquet partent de 0 dans chaque sens.
//! L'horloge est fournie par l'appelant (`std::time::Instant`), ce qui rend les tests déterministes.
//!
//! Utilisation, après chaque événement (paquet reçu, données à envoyer, minuterie) :
//! 1. `on_acks` puis `on_packet` pour chaque paquet reçu, `send` pour les données à émettre ;
//! 2. `poll_transmit(now)` jusqu'à `None` (paquets de contrôle, avec acquittements embarqués) ;
//! 3. `take_acks()` jusqu'à `None` (acquittements restants, à envoyer en `P_ACK_V1`) ;
//! 4. `recv()` jusqu'à `None` (charges utiles reçues, dans l'ordre) ;
//! 5. `failed()` ; réveil suivant à `next_deadline(now)`.
//!
//! Le découpage en fragments ne conserve pas les frontières de message : la suite des charges
//! utiles `P_CONTROL_V1` reçues forme le flux d'octets TLS, à donner tel quel à rustls.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Acquittements au plus par paquet (`RELIABLE_ACK_SIZE` d'OpenVPN : au-delà, le pair rejette).
pub const MAX_ACKS_LIMIT: usize = 8;

/// Réglages de la couche de fiabilité.
#[derive(Clone, Debug)]
pub struct ReliableConfig {
    /// Octets de charge utile au plus par paquet de contrôle (hors en-têtes OpenVPN/UDP/IP).
    pub max_payload: usize,
    /// Fenêtre : paquets émis au-delà du plus ancien non acquitté (et paquets acceptés en avance).
    pub window: u32,
    /// Acquittements embarqués au plus par paquet (1 à `MAX_ACKS_LIMIT`).
    pub max_acks: usize,
    /// Premier délai de réémission, doublé ensuite jusqu'à `max_timeout`.
    pub initial_timeout: Duration,
    pub max_timeout: Duration,
    /// Abandon si un paquet n'est toujours pas acquitté ce délai après sa première émission.
    pub give_up: Duration,
}

impl Default for ReliableConfig {
    fn default() -> Self {
        Self {
            max_payload: 1250,
            window: 8,
            max_acks: 4,
            initial_timeout: Duration::from_secs(2),
            max_timeout: Duration::from_secs(16),
            give_up: Duration::from_secs(60),
        }
    }
}

/// Paquet de contrôle à émettre : l'appelant ajoute l'en-tête (opcode/key_id, session, HMAC…).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub packet_id: u32,
    pub opcode: u8,
    pub payload: Vec<u8>,
    /// Numéros à acquitter dans ce paquet (liste d'ACK de l'en-tête).
    pub acks: Vec<u32>,
}

/// Fragment en attente d'acquittement.
struct Pending {
    id: u32,
    opcode: u8,
    payload: Vec<u8>,
    acked: bool,
    /// Première émission (pour l'abandon), `None` tant qu'il n'est pas parti.
    first_tx: Option<Instant>,
    /// Prochaine (ré)émission, `None` : à émettre tout de suite (jamais parti).
    next_tx: Option<Instant>,
    timeout: Duration,
}

/// Acquittements en attente gardés au plus (au-delà, les plus anciens sont oubliés : le pair
/// réémettra et sera réacquitté).
const ACK_BACKLOG: usize = 64;

pub struct Reliable {
    cfg: ReliableConfig,
    // --- émission
    next_id: u32,
    /// Fragments numérotés, du plus ancien non acquitté au plus récent.
    pending: VecDeque<Pending>,
    // --- réception
    /// Prochain numéro attendu (tout ce qui précède a été remis).
    expected: u32,
    /// Paquets arrivés en avance, dans la fenêtre.
    ahead: BTreeMap<u32, (u8, Vec<u8>)>,
    delivered: VecDeque<(u8, Vec<u8>)>,
    acks: VecDeque<u32>,
    error: Option<String>,
}

impl Reliable {
    pub fn new(mut cfg: ReliableConfig) -> Self {
        cfg.max_payload = cfg.max_payload.max(1);
        cfg.window = cfg.window.clamp(1, 1 << 16);
        cfg.max_acks = cfg.max_acks.clamp(1, MAX_ACKS_LIMIT);
        cfg.max_timeout = cfg.max_timeout.max(cfg.initial_timeout);
        Self {
            cfg,
            next_id: 0,
            pending: VecDeque::new(),
            expected: 0,
            ahead: BTreeMap::new(),
            delivered: VecDeque::new(),
            acks: VecDeque::new(),
            error: None,
        }
    }

    pub fn config(&self) -> &ReliableConfig {
        &self.cfg
    }

    /// Met un message en file, découpé en fragments de `max_payload` octets au plus. Un message
    /// vide (réinitialisation) donne un paquet sans charge utile.
    pub fn send(&mut self, opcode: u8, data: &[u8]) {
        let push = |s: &mut Self, chunk: &[u8]| {
            s.pending.push_back(Pending {
                id: s.next_id,
                opcode,
                payload: chunk.to_vec(),
                acked: false,
                first_tx: None,
                next_tx: None,
                timeout: s.cfg.initial_timeout,
            });
            s.next_id = s.next_id.wrapping_add(1);
        };
        if data.is_empty() {
            push(self, &[]);
        } else {
            let n = self.cfg.max_payload;
            for chunk in data.chunks(n) {
                push(self, chunk);
            }
        }
    }

    /// Paquet reçu (après vérification de l'en-tête par l'appelant). Renvoie `true` s'il doit être
    /// acquitté (nouveau ou doublon), `false` s'il est hors fenêtre et ignoré.
    pub fn on_packet(&mut self, packet_id: u32, opcode: u8, payload: &[u8]) -> bool {
        let d = packet_id.wrapping_sub(self.expected);
        if d >= self.cfg.window {
            if d > u32::MAX / 2 {
                // déjà remis : notre acquittement s'est perdu, on le renvoie
                self.queue_ack(packet_id);
                return true;
            }
            return false; // trop en avance : le pair le réémettra
        }
        self.queue_ack(packet_id);
        self.ahead.entry(packet_id).or_insert_with(|| (opcode, payload.to_vec()));
        while let Some(p) = self.ahead.remove(&self.expected) {
            self.delivered.push_back(p);
            self.expected = self.expected.wrapping_add(1);
        }
        true
    }

    /// Acquittements reçus du pair (liste d'ACK d'un paquet de contrôle ou d'un `P_ACK_V1`).
    pub fn on_acks(&mut self, ids: &[u32]) {
        for &id in ids {
            // un numéro jamais émis ne peut pas être acquitté : ignoré
            if let Some(p) = self.pending.iter_mut().find(|p| p.id == id && p.first_tx.is_some()) {
                p.acked = true;
                p.payload = Vec::new();
            }
        }
        while self.pending.front().is_some_and(|p| p.acked) {
            self.pending.pop_front();
        }
    }

    /// Prochain paquet de contrôle à émettre (nouveau ou réémission échue), avec les acquittements
    /// en attente embarqués. À appeler jusqu'à `None`.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Outgoing> {
        if self.check_give_up(now) {
            return None;
        }
        let window = self.cfg.window as usize;
        let p = self
            .pending
            .iter_mut()
            .take(window)
            .find(|p| !p.acked && p.next_tx.is_none_or(|t| t <= now))?;
        if p.first_tx.is_none() {
            p.first_tx = Some(now);
        } else {
            p.timeout = (p.timeout * 2).min(self.cfg.max_timeout);
        }
        // première émission : délai initial ; ensuite il double à chaque réémission
        p.next_tx = Some(now + p.timeout);
        let (packet_id, opcode, payload) = (p.id, p.opcode, p.payload.clone());
        let n = self.acks.len().min(self.cfg.max_acks);
        let acks = self.acks.drain(..n).collect();
        Some(Outgoing { packet_id, opcode, payload, acks })
    }

    /// Acquittements restant à envoyer seuls (`P_ACK_V1`), `max_acks` au plus par appel. À appeler
    /// après `poll_transmit`, jusqu'à `None`.
    pub fn take_acks(&mut self) -> Option<Vec<u32>> {
        if self.acks.is_empty() {
            return None;
        }
        let n = self.acks.len().min(self.cfg.max_acks);
        Some(self.acks.drain(..n).collect())
    }

    /// Prochaine charge utile reçue, dans l'ordre des numéros.
    pub fn recv(&mut self) -> Option<(u8, Vec<u8>)> {
        self.delivered.pop_front()
    }

    /// Instant où rappeler `poll_transmit` : `now` s'il y a déjà quelque chose à émettre
    /// (fragment neuf dans la fenêtre ou acquittement en attente), `None` si rien n'est en vol.
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if self.error.is_some() {
            return None;
        }
        if !self.acks.is_empty() {
            return Some(now);
        }
        let mut best: Option<Instant> = None;
        for p in self.pending.iter().take(self.cfg.window as usize).filter(|p| !p.acked) {
            let t = match (p.next_tx, p.first_tx) {
                (Some(t), Some(first)) => t.min(first + self.cfg.give_up),
                _ => now,
            };
            best = Some(best.map_or(t, |b| b.min(t)));
        }
        best
    }

    /// Erreur définitive (paquet jamais acquitté) : la session doit être abandonnée.
    pub fn failed(&self) -> Option<String> {
        self.error.clone()
    }

    /// Plus rien en attente d'acquittement ni à émettre.
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty() && self.acks.is_empty()
    }

    /// Fragments en file (émis non acquittés et pas encore émis).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Acquittements gardés en attente d'émission (le plus ancien est oublié au-delà de la limite).
    fn queue_ack(&mut self, id: u32) {
        if self.acks.contains(&id) {
            return;
        }
        if self.acks.len() >= ACK_BACKLOG {
            self.acks.pop_front();
        }
        self.acks.push_back(id);
    }

    fn check_give_up(&mut self, now: Instant) -> bool {
        if self.error.is_some() {
            return true;
        }
        let give_up = self.cfg.give_up;
        let late = self.pending.iter().find(|p| {
            !p.acked && p.first_tx.is_some_and(|t| now.saturating_duration_since(t) >= give_up)
        });
        if let Some(p) = late {
            self.error = Some(format!(
                "Le serveur OpenVPN ne répond plus (paquet de contrôle {} non acquitté après {} s)",
                p.id,
                give_up.as_secs()
            ));
            return true;
        }
        false
    }

    #[cfg(test)]
    fn with_start(cfg: ReliableConfig, send_id: u32, recv_id: u32) -> Self {
        let mut r = Self::new(cfg);
        r.next_id = send_id;
        r.expected = recv_id;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTRL: u8 = 4;

    fn cfg() -> ReliableConfig {
        ReliableConfig { max_payload: 100, ..Default::default() }
    }

    fn drain(r: &mut Reliable, now: Instant) -> Vec<Outgoing> {
        std::iter::from_fn(|| r.poll_transmit(now)).collect()
    }

    #[test]
    fn fragmentation_and_ids() {
        let now = Instant::now();
        let mut r = Reliable::new(cfg());
        r.send(7, &[]);
        r.send(CTRL, &[1u8; 250]);
        let out = drain(&mut r, now);
        assert_eq!(out.len(), 4);
        assert_eq!(out.iter().map(|o| o.packet_id).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(out[0].opcode, 7);
        assert!(out[0].payload.is_empty());
        assert_eq!(out.iter().map(|o| o.payload.len()).collect::<Vec<_>>(), [0, 100, 100, 50]);
    }

    #[test]
    fn window_limits_in_flight() {
        let now = Instant::now();
        let mut r = Reliable::new(cfg());
        r.send(CTRL, &[0u8; 2000]); // 20 fragments
        assert_eq!(drain(&mut r, now).len(), 8);
        // acquitter le 1 ne fait pas avancer la fenêtre (le 0 manque)
        r.on_acks(&[1]);
        assert!(r.poll_transmit(now).is_none());
        r.on_acks(&[0]);
        let out = drain(&mut r, now);
        assert_eq!(out.iter().map(|o| o.packet_id).collect::<Vec<_>>(), [8, 9]);
        // les numéros jamais émis (10..20) ne comptent pas
        r.on_acks(&(0..20).collect::<Vec<_>>());
        let out = drain(&mut r, now);
        assert_eq!(out.iter().map(|o| o.packet_id).collect::<Vec<_>>(), (10..18).collect::<Vec<_>>());
        r.on_acks(&(0..20).collect::<Vec<_>>());
        assert_eq!(drain(&mut r, now).len(), 2);
        r.on_acks(&(0..20).collect::<Vec<_>>());
        assert!(r.is_idle());
        assert_eq!(r.next_deadline(now), None);
    }

    #[test]
    fn retransmit_backoff_and_give_up() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut r = Reliable::new(cfg());
        r.send(CTRL, b"hello");
        assert_eq!(r.next_deadline(t0), Some(t0));
        assert!(r.poll_transmit(t0).is_some());
        assert_eq!(r.next_deadline(t0), Some(t0 + s(2)));
        assert!(r.poll_transmit(t0 + s(1)).is_none());
        let mut t = t0;
        let mut gaps = Vec::new();
        let mut last = t0;
        while t < t0 + s(70) {
            t += Duration::from_millis(250);
            if let Some(o) = r.poll_transmit(t) {
                assert_eq!(o.payload, b"hello");
                gaps.push((t - last).as_secs());
                last = t;
            }
            if r.failed().is_some() {
                break;
            }
        }
        assert_eq!(gaps, [2, 4, 8, 16, 16]); // 2+4+8+16+16 = 46 ; 46+16 > 60 : abandon à 60 s
        assert!(r.failed().is_some());
        assert_eq!(t, t0 + s(60));
        assert!(r.poll_transmit(t + s(100)).is_none());
        assert_eq!(r.next_deadline(t), None);
    }

    #[test]
    fn ack_stops_retransmit() {
        let t0 = Instant::now();
        let mut r = Reliable::new(cfg());
        r.send(CTRL, b"x");
        let o = r.poll_transmit(t0).unwrap();
        r.on_acks(&[o.packet_id, 99]);
        assert!(r.poll_transmit(t0 + Duration::from_secs(100)).is_none());
        assert!(r.failed().is_none());
    }

    #[test]
    fn receive_reorder_duplicates_window() {
        let mut r = Reliable::new(cfg());
        assert!(r.on_packet(2, CTRL, b"c"));
        assert!(r.on_packet(1, CTRL, b"b"));
        assert!(r.recv().is_none());
        assert!(r.on_packet(0, CTRL, b"a"));
        let got: Vec<_> = std::iter::from_fn(|| r.recv()).map(|(_, p)| p).collect();
        assert_eq!(got, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        // doublon déjà remis : acquitté, pas remis
        assert!(r.on_packet(1, CTRL, b"b"));
        assert!(r.recv().is_none());
        // hors fenêtre (3 + 8 = 11) : ignoré, pas acquitté
        let _ = std::iter::from_fn(|| r.take_acks()).count();
        assert!(!r.on_packet(11, CTRL, b"z"));
        assert!(r.take_acks().is_none());
        // limite haute de la fenêtre acceptée
        assert!(r.on_packet(10, CTRL, b"k"));
        // doublon en avance : gardé une fois
        assert!(r.on_packet(10, CTRL, b"k2"));
        assert_eq!(r.take_acks(), Some(vec![10]));
        for i in 3..10 {
            r.on_packet(i, CTRL, &[i as u8]);
        }
        let got: Vec<_> = std::iter::from_fn(|| r.recv()).map(|(_, p)| p).collect();
        assert_eq!(got.len(), 8);
        assert_eq!(got[7], b"k");
    }

    #[test]
    fn piggyback_and_standalone_acks() {
        let now = Instant::now();
        let mut r = Reliable::new(cfg());
        for i in 0..6 {
            r.on_packet(i, CTRL, b"");
        }
        r.send(CTRL, b"data");
        let o = r.poll_transmit(now).unwrap();
        assert_eq!(o.acks, [0, 1, 2, 3]);
        assert_eq!(r.take_acks(), Some(vec![4, 5]));
        assert!(r.take_acks().is_none());
        // configurable, borné à 8
        let mut r = Reliable::new(ReliableConfig { max_acks: 50, window: 64, ..cfg() });
        for i in 0..20 {
            r.on_packet(i, CTRL, b"");
        }
        assert_eq!(r.take_acks().unwrap().len(), 8);
        assert_eq!(r.next_deadline(now), Some(now));
    }

    #[test]
    fn packet_id_wraparound() {
        let now = Instant::now();
        let mut a = Reliable::with_start(cfg(), u32::MAX - 2, 0);
        let mut b = Reliable::with_start(cfg(), 0, u32::MAX - 2);
        a.send(CTRL, &[5u8; 500]);
        let out = drain(&mut a, now);
        assert_eq!(out[3].packet_id, 0);
        for o in out.iter().rev() {
            assert!(b.on_packet(o.packet_id, o.opcode, &o.payload));
        }
        assert_eq!(std::iter::from_fn(|| b.recv()).count(), 5);
        // u32::MAX - 2 est maintenant « déjà remis »
        assert!(b.on_packet(u32::MAX - 2, CTRL, b""));
        assert!(b.recv().is_none());
        a.on_acks(&out.iter().map(|o| o.packet_id).collect::<Vec<_>>());
        assert!(a.is_idle());
    }

    /// Générateur pseudo-aléatoire déterministe (xorshift).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn chance(&mut self, pct: u64) -> bool {
            self.next() % 100 < pct
        }
    }

    /// Paquet en transit : contrôle (avec ACK embarqués) ou ACK seul.
    #[derive(Clone)]
    enum Wire {
        Ctrl(Outgoing),
        Ack(Vec<u32>),
    }

    /// Canal simulé : perte, réordonnancement (retard aléatoire), duplication.
    fn transfer(seed: u64, loss: u64, size: usize, give_up: Duration) {
        let mut rng = Rng(seed);
        let t0 = Instant::now();
        let data_a: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();
        let data_b: Vec<u8> = (0..size).map(|i| (i * 13 + 1) as u8).collect();
        let c = ReliableConfig { give_up, ..Default::default() };
        let mut peers = [Reliable::new(c.clone()), Reliable::new(c)];
        peers[0].send(CTRL, &data_a);
        peers[1].send(CTRL, &data_b);
        let mut got: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        // (instant d'arrivée, destinataire, paquet)
        let mut wire: Vec<(Duration, usize, Wire)> = Vec::new();
        let mut now = Duration::ZERO;
        let step = Duration::from_millis(10);
        let mut sent = 0usize;
        while got[0].len() < size || got[1].len() < size || !peers[0].is_idle() || !peers[1].is_idle() {
            assert!(now < Duration::from_secs(36000), "transfert bloqué");
            let at = t0 + now;
            // livraison des paquets arrivés
            let mut i = 0;
            while i < wire.len() {
                if wire[i].0 <= now {
                    let (_, dst, w) = wire.swap_remove(i);
                    let p = &mut peers[dst];
                    match w {
                        Wire::Ctrl(o) => {
                            p.on_acks(&o.acks);
                            p.on_packet(o.packet_id, o.opcode, &o.payload);
                        }
                        Wire::Ack(a) => p.on_acks(&a),
                    }
                } else {
                    i += 1;
                }
            }
            for side in 0..2 {
                let p = &mut peers[side];
                let mut outs: Vec<Wire> = std::iter::from_fn(|| p.poll_transmit(at)).map(Wire::Ctrl).collect();
                outs.extend(std::iter::from_fn(|| p.take_acks()).map(Wire::Ack));
                while let Some((op, d)) = p.recv() {
                    assert_eq!(op, CTRL);
                    got[side].extend_from_slice(&d);
                }
                assert!(p.failed().is_none(), "{:?}", p.failed());
                for w in outs {
                    sent += 1;
                    if rng.chance(loss) {
                        continue;
                    }
                    let delay = Duration::from_millis(20 + rng.next() % 300);
                    if rng.chance(5) {
                        wire.push((now + delay * 2, 1 - side, w.clone()));
                    }
                    wire.push((now + delay, 1 - side, w));
                }
            }
            now += step;
        }
        assert!(got[1] == data_a, "données A altérées");
        assert!(got[0] == data_b, "données B altérées");
        assert!(sent > 2 * size / 1250);
    }

    #[test]
    fn lossy_channel_200k() {
        // forte perte : l'abandon est repoussé pour ne pas dépendre du hasard
        transfer(0x9E37_79B9_7F4A_7C15, 20, 200 * 1024, Duration::from_secs(3600));
        // réglages par défaut, perte modérée
        transfer(7, 5, 200 * 1024, Duration::from_secs(60));
    }

    #[test]
    fn lossy_channel_various_seeds() {
        for seed in 1..6u64 {
            transfer(seed * 0x2545_F491_4F6C_DD1D, 35, 40 * 1024, Duration::from_secs(3600));
        }
        transfer(42, 0, 200 * 1024, Duration::from_secs(60));
    }
}
