//! Format des paquets OpenVPN (sans E/S) : octet opcode/key_id, paquets de contrôle (accusés,
//! numéro de message), enveloppes `tls-auth` / `tls-crypt` (v1) avec anti-rejeu, en-têtes du canal
//! de données (P_DATA_V1 / P_DATA_V2) et découpage du flux TCP (longueur sur 2 octets).
//!
//! Disposition sur le fil (cf. ssl_pkt.c, reliable.c, tls_crypt.c d'OpenVPN) :
//!
//! ```text
//! octet 0          : opcode (5 bits de poids fort) | key_id (3 bits de poids faible)
//!
//! contrôle, clair  : op | session_id(8) | n_acks(1) | acks(4·n, BE) | [remote_session_id(8) si n>0]
//!                    | [message_packet_id(4, BE), absent pour P_ACK_V1] | charge (TLS)
//! tls-auth         : op | session_id(8) | HMAC(L) | packet_id(4) | net_time(4) | n_acks | …
//!                    HMAC = HMAC(packet_id | net_time | op | session_id | n_acks | … | charge)
//! tls-crypt (v1)   : op | session_id(8) | packet_id(4) | net_time(4) | tag(32) | chiffré(n_acks | …)
//!                    tag = HMAC-SHA256(op | session_id | packet_id | net_time | clair)
//!                    chiffré = AES-256-CTR(clé, IV = tag[0..16], clair)
//!
//! données V1       : op | …                     (1 octet d'en-tête)
//! données V2       : op | peer_id(3, BE) | …    (4 octets d'en-tête, données AEAD authentifiées)
//!
//! TCP              : longueur(2, BE) | paquet, répété
//! ```
//!
//! Clé statique (256 octets, fichier « OpenVPN Static key V1 ») : deux emplacements de 128 octets,
//! chacun `chiffrement(64) | hmac(64)`. Emplacement utilisé à l'émission / à la réception :
//! direction absente → 0 / 0 ; `key-direction 0` → 0 / 1 ; `key-direction 1` → 1 / 0.
//! `tls-crypt` impose la direction : serveur = 0, client = 1.

use ring::hmac;
use zeroize::Zeroizing;

// ------------------------------------------------------------------ opcodes

pub const P_CONTROL_HARD_RESET_CLIENT_V1: u8 = 1;
pub const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
pub const P_CONTROL_SOFT_RESET_V1: u8 = 3;
pub const P_CONTROL_V1: u8 = 4;
pub const P_ACK_V1: u8 = 5;
pub const P_DATA_V1: u8 = 6;
pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
pub const P_DATA_V2: u8 = 9;
pub const P_CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;
pub const P_CONTROL_WKC_V1: u8 = 11;

pub const OPCODE_SHIFT: u8 = 3;
pub const KEY_ID_MASK: u8 = 0x07;
/// Accusés au plus par paquet (RELIABLE_ACK_SIZE) : OpenVPN rejette au-delà.
pub const MAX_ACKS: usize = 8;
/// Taille de la clé statique `tls-auth` / `tls-crypt`.
pub const STATIC_KEY_LEN: usize = 256;
/// peer-id « non attribué » de P_DATA_V2.
pub const PEER_ID_UNDEF: u32 = 0x00FF_FFFF;
/// Fenêtre anti-rejeu du packet-id de l'enveloppe (replay-window 64 par défaut).
const REPLAY_WINDOW: u32 = 64;
const TLS_CRYPT_TAG: usize = 32;

/// Octet d'en-tête : opcode sur 5 bits, key_id sur 3 bits.
pub fn op_byte(opcode: u8, key_id: u8) -> u8 {
    (opcode << OPCODE_SHIFT) | (key_id & KEY_ID_MASK)
}

/// (opcode, key_id) d'un octet d'en-tête.
pub fn split_op(b: u8) -> (u8, u8) {
    (b >> OPCODE_SHIFT, b & KEY_ID_MASK)
}

/// (opcode, key_id) du premier octet d'un paquet reçu, s'il y en a un.
pub fn peek_opcode(raw: &[u8]) -> Option<(u8, u8)> {
    raw.first().map(|&b| split_op(b))
}

/// Opcode du canal de contrôle (y compris P_ACK_V1) ?
pub fn is_control(opcode: u8) -> bool {
    matches!(
        opcode,
        P_CONTROL_HARD_RESET_CLIENT_V1
            | P_CONTROL_HARD_RESET_SERVER_V1
            | P_CONTROL_SOFT_RESET_V1
            | P_CONTROL_V1
            | P_ACK_V1
            | P_CONTROL_HARD_RESET_CLIENT_V2
            | P_CONTROL_HARD_RESET_SERVER_V2
            | P_CONTROL_HARD_RESET_CLIENT_V3
            | P_CONTROL_WKC_V1
    )
}

/// Opcode du canal de données ?
pub fn is_data(opcode: u8) -> bool {
    opcode == P_DATA_V1 || opcode == P_DATA_V2
}

// ------------------------------------------------------------------ lecture

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("paquet OpenVPN tronqué".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn id8(&mut self) -> Result<[u8; 8], String> {
        let mut s = [0u8; 8];
        s.copy_from_slice(self.take(8)?);
        Ok(s)
    }
}

// ------------------------------------------------------------------ paquet de contrôle

/// Paquet du canal de contrôle, une fois l'enveloppe retirée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPacket {
    pub opcode: u8,
    pub key_id: u8,
    /// Identifiant de session de l'émetteur.
    pub session_id: [u8; 8],
    /// Numéros de message acquittés (au plus `MAX_ACKS`).
    pub acks: Vec<u32>,
    /// Session du destinataire : présente sur le fil seulement s'il y a des accusés (à l'encodage,
    /// des zéros sont écrits si elle manque alors que `acks` n'est pas vide).
    pub remote_session_id: Option<[u8; 8]>,
    /// Numéro de message fiable ; `None` pour P_ACK_V1 (ignoré à l'encodage pour cet opcode).
    pub packet_id: Option<u32>,
    /// Charge : enregistrements TLS (ou TLV de négociation anticipée sur un HARD_RESET).
    pub payload: Vec<u8>,
}

impl ControlPacket {
    /// Forme claire (sans enveloppe) : `op | session_id | corps`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + 1 + self.acks.len() * 4 + 12 + self.payload.len());
        out.push(op_byte(self.opcode, self.key_id));
        out.extend_from_slice(&self.session_id);
        self.encode_body(&mut out);
        out
    }

    /// Lit la forme claire.
    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut r = Reader(raw);
        let op = r.u8()?;
        let sid = r.id8()?;
        Self::decode_body(op, sid, r.0)
    }

    /// Corps commun à toutes les enveloppes : accusés, numéro de message, charge. Les accusés
    /// au-delà de `MAX_ACKS` ne sont pas écrits (l'appelant doit les garder pour le paquet suivant).
    fn encode_body(&self, out: &mut Vec<u8>) {
        let acks = &self.acks[..self.acks.len().min(MAX_ACKS)];
        out.push(acks.len() as u8);
        for a in acks {
            out.extend_from_slice(&a.to_be_bytes());
        }
        if !acks.is_empty() {
            out.extend_from_slice(&self.remote_session_id.unwrap_or([0; 8]));
        }
        if self.opcode != P_ACK_V1 {
            out.extend_from_slice(&self.packet_id.unwrap_or(0).to_be_bytes());
        }
        out.extend_from_slice(&self.payload);
    }

    fn decode_body(op: u8, session_id: [u8; 8], body: &[u8]) -> Result<Self, String> {
        let (opcode, key_id) = split_op(op);
        if !is_control(opcode) {
            return Err(format!("opcode OpenVPN inattendu sur le canal de contrôle : {opcode}"));
        }
        let mut r = Reader(body);
        let n = r.u8()? as usize;
        if n > MAX_ACKS {
            return Err(format!("trop d'accusés dans un paquet OpenVPN : {n}"));
        }
        let mut acks = Vec::with_capacity(n);
        for _ in 0..n {
            acks.push(r.u32()?);
        }
        let remote_session_id = if n > 0 { Some(r.id8()?) } else { None };
        let packet_id = if opcode == P_ACK_V1 { None } else { Some(r.u32()?) };
        if opcode == P_ACK_V1 && !r.0.is_empty() {
            return Err("P_ACK_V1 OpenVPN avec une charge".into());
        }
        Ok(Self {
            opcode,
            key_id,
            session_id,
            acks,
            remote_session_id,
            packet_id,
            payload: r.0.to_vec(),
        })
    }
}

// ------------------------------------------------------------------ packet-id de l'enveloppe

/// Compteur d'émission (forme longue : identifiant + date, fixée au premier envoi).
#[derive(Default)]
struct PidSend {
    id: u32,
    time: u32,
}

impl PidSend {
    fn next(&mut self, now: u32) -> (u32, u32) {
        if self.time == 0 {
            self.time = now.max(1);
        } else if self.id == u32::MAX {
            // Compteur épuisé : nouvelle époque, strictement plus récente (packet_id_send_update).
            self.time = now.max(self.time.saturating_add(1));
            self.id = 0;
        }
        self.id += 1;
        (self.id, self.time)
    }
}

/// Fenêtre glissante anti-rejeu (identifiant, date) du packet-id de l'enveloppe.
#[derive(Default)]
struct ReplayWindow {
    init: bool,
    time: u32,
    max: u32,
    /// Bit i = identifiant `max - i` déjà vu.
    seen: u64,
}

impl ReplayWindow {
    fn check(&self, id: u32, time: u32) -> Result<(), String> {
        if id == 0 {
            return Err("packet-id OpenVPN nul".into());
        }
        if !self.init || time > self.time || (time == self.time && id > self.max) {
            return Ok(());
        }
        if time < self.time {
            return Err("paquet OpenVPN rejoué (date ancienne)".into());
        }
        let back = self.max - id;
        if back >= REPLAY_WINDOW || self.seen & (1u64 << back) != 0 {
            return Err("paquet OpenVPN rejoué".into());
        }
        Ok(())
    }

    /// À appeler après `check` réussi et l'authentification du paquet.
    fn accept(&mut self, id: u32, time: u32) {
        if !self.init || time > self.time {
            *self = Self { init: true, time, max: id, seen: 1 };
        } else if id > self.max {
            let shift = id - self.max;
            self.seen = if shift >= 64 { 0 } else { self.seen << shift } | 1;
            self.max = id;
        } else {
            self.seen |= 1u64 << (self.max - id);
        }
    }
}

// ------------------------------------------------------------------ enveloppes

/// Côté de la connexion (détermine les clés de `tls-crypt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Condensé HMAC de `tls-auth` (option `auth`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthDigest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthDigest {
    /// Nom OpenVPN (`auth SHA256`…) ; vide = SHA1, la valeur par défaut d'OpenVPN.
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "" | "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA384" => Ok(Self::Sha384),
            "SHA512" => Ok(Self::Sha512),
            other => Err(format!("condensé « auth » OpenVPN non pris en charge : {other}")),
        }
    }

    /// Taille du condensé (et de la clé HMAC).
    pub fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// Lit une clé statique OpenVPN (« -----BEGIN OpenVPN Static key V1----- », 256 octets en
/// hexadécimal). Les lignes de commentaire (`#`) et les espaces sont ignorés.
pub fn parse_static_key(text: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN OpenVPN Static key V1-----";
    const END: &str = "-----END OpenVPN Static key V1-----";
    let start = text.find(BEGIN).ok_or("clé statique OpenVPN : en-tête BEGIN absent")?;
    let rest = &text[start + BEGIN.len()..];
    let end = rest.find(END).ok_or("clé statique OpenVPN : ligne END absente")?;
    let hex = Zeroizing::new(
        rest[..end]
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .flat_map(|l| l.chars())
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );
    if hex.len() != STATIC_KEY_LEN * 2 {
        return Err(format!(
            "clé statique OpenVPN : {} octets au lieu de {STATIC_KEY_LEN}",
            hex.len() / 2
        ));
    }
    let mut key = Zeroizing::new(Vec::with_capacity(STATIC_KEY_LEN));
    for pair in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(pair).map_err(|_| "clé statique OpenVPN invalide")?;
        key.push(u8::from_str_radix(s, 16).map_err(|_| "clé statique OpenVPN : hexadécimal invalide")?);
    }
    Ok(key)
}

/// Partie chiffrement (64 octets) de l'emplacement `slot` de la clé statique.
fn cipher_part(key: &[u8], slot: usize) -> &[u8] {
    &key[slot * 128..slot * 128 + 64]
}

/// Partie HMAC (64 octets) de l'emplacement `slot`.
fn hmac_part(key: &[u8], slot: usize) -> &[u8] {
    &key[slot * 128 + 64..slot * 128 + 128]
}

/// Emplacements (émission, réception) selon `key-direction`.
fn slots(key_direction: Option<u8>) -> Result<(usize, usize), String> {
    match key_direction {
        None => Ok((0, 0)),
        Some(0) => Ok((0, 1)),
        Some(1) => Ok((1, 0)),
        Some(d) => Err(format!("key-direction OpenVPN invalide : {d} (0 ou 1 attendu)")),
    }
}

fn check_key_len(key: &[u8]) -> Result<(), String> {
    if key.len() != STATIC_KEY_LEN {
        return Err(format!(
            "clé statique OpenVPN : {} octets au lieu de {STATIC_KEY_LEN}",
            key.len()
        ));
    }
    Ok(())
}

/// `tls-auth` : HMAC sur chaque paquet de contrôle.
pub struct TlsAuth {
    digest: AuthDigest,
    tx_key: hmac::Key,
    rx_key: hmac::Key,
    tx: PidSend,
    rx: ReplayWindow,
}

/// `tls-crypt` v1 : AES-256-CTR + HMAC-SHA256 (IV synthétique) sur chaque paquet de contrôle.
pub struct TlsCrypt {
    tx_cipher: Zeroizing<[u8; 32]>,
    rx_cipher: Zeroizing<[u8; 32]>,
    tx_hmac: hmac::Key,
    rx_hmac: hmac::Key,
    tx: PidSend,
    rx: ReplayWindow,
}

/// Enveloppe du canal de contrôle. Un `Wrap` par session TLS : son anti-rejeu et son compteur
/// repartent de zéro avec une nouvelle session (nouvel identifiant de session).
pub enum Wrap {
    Plain,
    TlsAuth(TlsAuth),
    TlsCrypt(TlsCrypt),
}

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

fn ctr_apply(key: &[u8; 32], iv: &[u8], data: &mut [u8]) {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    // Tailles fixes (32 et 16 octets) : `new_from_slices` ne peut pas échouer ici.
    if let Ok(mut c) = Aes256Ctr::new_from_slices(key, iv) {
        c.apply_keystream(data);
    }
}

impl Wrap {
    /// `tls-auth` avec la clé statique de 256 octets. `key_direction` : `None` (bidirectionnel),
    /// `Some(0)` (habituellement le serveur) ou `Some(1)` (habituellement le client). Le rôle ne
    /// compte pas ici : le serveur de test prend simplement la direction opposée.
    pub fn tls_auth(static_key: &[u8], key_direction: Option<u8>, digest: AuthDigest) -> Result<Self, String> {
        check_key_len(static_key)?;
        let (tx, rx) = slots(key_direction)?;
        let alg = digest.algorithm();
        let n = digest.size();
        Ok(Self::TlsAuth(TlsAuth {
            digest,
            tx_key: hmac::Key::new(alg, &hmac_part(static_key, tx)[..n]),
            rx_key: hmac::Key::new(alg, &hmac_part(static_key, rx)[..n]),
            tx: PidSend::default(),
            rx: ReplayWindow::default(),
        }))
    }

    /// `tls-crypt` v1. Directions imposées par OpenVPN : serveur = `key-direction 0`,
    /// client = `key-direction 1`.
    pub fn tls_crypt(static_key: &[u8], role: Role) -> Result<Self, String> {
        check_key_len(static_key)?;
        let (tx, rx) = slots(Some(match role {
            Role::Server => 0,
            Role::Client => 1,
        }))?;
        let key32 = |slot: usize| {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&cipher_part(static_key, slot)[..32]);
            k
        };
        Ok(Self::TlsCrypt(TlsCrypt {
            tx_cipher: key32(tx),
            rx_cipher: key32(rx),
            tx_hmac: hmac::Key::new(hmac::HMAC_SHA256, &hmac_part(static_key, tx)[..32]),
            rx_hmac: hmac::Key::new(hmac::HMAC_SHA256, &hmac_part(static_key, rx)[..32]),
            tx: PidSend::default(),
            rx: ReplayWindow::default(),
        }))
    }

    /// Octets ajoutés par l'enveloppe à la forme claire.
    pub fn overhead(&self) -> usize {
        match self {
            Self::Plain => 0,
            Self::TlsAuth(a) => a.digest.size() + 8,
            Self::TlsCrypt(_) => 8 + TLS_CRYPT_TAG,
        }
    }

    /// Paquet prêt à envoyer (sans le préfixe de longueur TCP). `now_secs` : date Unix en secondes
    /// (net_time du packet-id, figée au premier envoi).
    pub fn wrap(&mut self, pkt: &ControlPacket, now_secs: u32) -> Vec<u8> {
        let op = op_byte(pkt.opcode, pkt.key_id);
        match self {
            Self::Plain => pkt.encode(),
            Self::TlsAuth(a) => {
                let (id, time) = a.tx.next(now_secs);
                // Données authentifiées : packet_id | net_time | op | session_id | corps.
                let mut auth = Vec::with_capacity(9 + 8 + 64 + pkt.payload.len());
                auth.extend_from_slice(&id.to_be_bytes());
                auth.extend_from_slice(&time.to_be_bytes());
                auth.push(op);
                auth.extend_from_slice(&pkt.session_id);
                pkt.encode_body(&mut auth);
                let tag = hmac::sign(&a.tx_key, &auth);
                let mut out = Vec::with_capacity(auth.len() + tag.as_ref().len());
                out.push(op);
                out.extend_from_slice(&pkt.session_id);
                out.extend_from_slice(tag.as_ref());
                out.extend_from_slice(&auth[..8]);
                out.extend_from_slice(&auth[17..]);
                out
            }
            Self::TlsCrypt(c) => {
                let (id, time) = c.tx.next(now_secs);
                let mut out = Vec::with_capacity(17 + TLS_CRYPT_TAG + 64 + pkt.payload.len());
                out.push(op);
                out.extend_from_slice(&pkt.session_id);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&time.to_be_bytes());
                let mut body = Zeroizing::new(Vec::with_capacity(64 + pkt.payload.len()));
                pkt.encode_body(&mut body);
                let mut ctx = hmac::Context::with_key(&c.tx_hmac);
                ctx.update(&out);
                ctx.update(&body);
                let tag = ctx.sign();
                let tag = tag.as_ref();
                ctr_apply(&c.tx_cipher, &tag[..16], &mut body);
                out.extend_from_slice(tag);
                out.extend_from_slice(&body);
                out
            }
        }
    }

    /// Vérifie, déchiffre et lit un paquet de contrôle reçu (sans le préfixe de longueur TCP).
    /// Le packet-id de l'enveloppe n'est enregistré qu'une fois le paquet authentifié et lu.
    pub fn unwrap(&mut self, raw: &[u8]) -> Result<ControlPacket, String> {
        match self {
            Self::Plain => ControlPacket::decode(raw),
            Self::TlsAuth(a) => {
                let mut r = Reader(raw);
                let op = r.u8()?;
                let sid = r.id8()?;
                let tag = r.take(a.digest.size())?;
                let id = r.u32()?;
                let time = r.u32()?;
                let body = r.0;
                let mut auth = Vec::with_capacity(17 + body.len());
                auth.extend_from_slice(&raw[9 + tag.len()..17 + tag.len()]);
                auth.push(op);
                auth.extend_from_slice(&sid);
                auth.extend_from_slice(body);
                hmac::verify(&a.rx_key, &auth, tag)
                    .map_err(|_| "paquet OpenVPN refusé : HMAC tls-auth invalide (clé ou key-direction ?)")?;
                a.rx.check(id, time)?;
                let pkt = ControlPacket::decode_body(op, sid, body)?;
                a.rx.accept(id, time);
                Ok(pkt)
            }
            Self::TlsCrypt(c) => {
                let mut r = Reader(raw);
                let op = r.u8()?;
                let sid = r.id8()?;
                let id = r.u32()?;
                let time = r.u32()?;
                let tag = r.take(TLS_CRYPT_TAG)?;
                let mut body = Zeroizing::new(r.0.to_vec());
                ctr_apply(&c.rx_cipher, &tag[..16], &mut body);
                let mut ctx = hmac::Context::with_key(&c.rx_hmac);
                ctx.update(&raw[..17]);
                ctx.update(&body);
                let expect = ctx.sign();
                // Comparaison en temps constant.
                if !constant_eq(expect.as_ref(), tag) {
                    return Err("paquet OpenVPN refusé : authentification tls-crypt invalide (mauvaise clé ?)".into());
                }
                c.rx.check(id, time)?;
                let pkt = ControlPacket::decode_body(op, sid, &body)?;
                c.rx.accept(id, time);
                Ok(pkt)
            }
        }
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ------------------------------------------------------------------ canal de données

/// En-tête d'un paquet de données : P_DATA_V1 (1 octet) ou P_DATA_V2 (1 octet + peer-id sur 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataHeader {
    pub key_id: u8,
    /// `Some` = P_DATA_V2 (24 bits, `PEER_ID_UNDEF` si non attribué).
    pub peer_id: Option<u32>,
}

impl DataHeader {
    /// Taille de l'en-tête (1 ou 4 octets). En V2, ces 4 octets font partie des données
    /// authentifiées AEAD ; en V1, l'octet d'en-tête n'est pas authentifié.
    pub fn header_len(&self) -> usize {
        if self.peer_id.is_some() { 4 } else { 1 }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self.peer_id {
            None => vec![op_byte(P_DATA_V1, self.key_id)],
            Some(p) => {
                let p = (p & 0x00FF_FFFF).to_be_bytes();
                vec![op_byte(P_DATA_V2, self.key_id), p[1], p[2], p[3]]
            }
        }
    }

    /// Sépare l'en-tête du reste (packet-id, données chiffrées…).
    pub fn parse(raw: &[u8]) -> Result<(Self, &[u8]), String> {
        let (&b, rest) = raw.split_first().ok_or("paquet OpenVPN vide")?;
        let (opcode, key_id) = split_op(b);
        match opcode {
            P_DATA_V1 => Ok((Self { key_id, peer_id: None }, rest)),
            P_DATA_V2 => {
                if rest.len() < 3 {
                    return Err("paquet de données OpenVPN tronqué".into());
                }
                let peer = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]);
                Ok((Self { key_id, peer_id: Some(peer) }, &rest[3..]))
            }
            _ => Err(format!("opcode OpenVPN inattendu sur le canal de données : {opcode}")),
        }
    }
}

// ------------------------------------------------------------------ TCP

/// Préfixe un paquet de sa longueur (2 octets, gros-boutiste) pour le transport TCP. Un paquet
/// de plus de 65 535 octets est tronqué (n'arrive pas : l'appelant reste sous le MTU).
pub fn frame(pkt: &[u8]) -> Vec<u8> {
    let pkt = &pkt[..pkt.len().min(u16::MAX as usize)];
    let mut out = Vec::with_capacity(2 + pkt.len());
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.extend_from_slice(pkt);
    out
}

/// Recompose les paquets d'un flux TCP reçu par morceaux quelconques.
#[derive(Default)]
pub struct TcpFramer {
    buf: Vec<u8>,
    pos: usize,
}

impl TcpFramer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajoute des octets reçus.
    pub fn push(&mut self, data: &[u8]) {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Paquet complet suivant, `None` s'il en manque une partie. Une longueur nulle est une
    /// erreur de flux (OpenVPN coupe alors la connexion).
    pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>, String> {
        let avail = &self.buf[self.pos..];
        if avail.len() < 2 {
            return Ok(None);
        }
        let n = u16::from_be_bytes([avail[0], avail[1]]) as usize;
        if n == 0 {
            return Err("flux TCP OpenVPN invalide (paquet de longueur nulle)".into());
        }
        if avail.len() < 2 + n {
            return Ok(None);
        }
        let pkt = avail[2..2 + n].to_vec();
        self.pos += 2 + n;
        Ok(Some(pkt))
    }

    /// Octets reçus pas encore rendus.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        (0..STATIC_KEY_LEN).map(|i| (i as u8).wrapping_mul(7).wrapping_add(3)).collect()
    }

    fn sample(opcode: u8, acks: Vec<u32>, pid: Option<u32>) -> ControlPacket {
        ControlPacket {
            opcode,
            key_id: 2,
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            remote_session_id: if acks.is_empty() { None } else { Some([9; 8]) },
            acks,
            packet_id: pid,
            payload: if opcode == P_ACK_V1 { vec![] } else { b"\x16\x03\x01hello".to_vec() },
        }
    }

    fn all_samples() -> Vec<ControlPacket> {
        vec![
            sample(P_CONTROL_HARD_RESET_CLIENT_V2, vec![], Some(0)),
            sample(P_CONTROL_HARD_RESET_SERVER_V2, vec![0], Some(0)),
            sample(P_CONTROL_V1, vec![1, 2, 3], Some(7)),
            sample(P_ACK_V1, vec![4], None),
            sample(P_CONTROL_SOFT_RESET_V1, vec![], Some(0)),
        ]
    }

    #[test]
    fn op_byte_packing() {
        assert_eq!(op_byte(P_CONTROL_HARD_RESET_CLIENT_V2, 0), 0x38);
        assert_eq!(op_byte(P_CONTROL_HARD_RESET_SERVER_V2, 0), 0x40);
        assert_eq!(op_byte(P_DATA_V2, 1), 0x49);
        assert_eq!(split_op(0x49), (P_DATA_V2, 1));
        assert_eq!(split_op(op_byte(P_CONTROL_V1, 7)), (P_CONTROL_V1, 7));
    }

    #[test]
    fn plain_layout_exact() {
        let p = sample(P_CONTROL_V1, vec![0x01020304], Some(0x0A0B0C0D));
        let e = p.encode();
        let mut want = vec![0x22, 1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 2, 3, 4];
        want.extend([9; 8]);
        want.extend([0x0A, 0x0B, 0x0C, 0x0D]);
        want.extend(b"\x16\x03\x01hello");
        assert_eq!(e, want);
        // Reset client classique : 0x38 | sid | 0 accusé | pid 0.
        let r = sample(P_CONTROL_HARD_RESET_CLIENT_V2, vec![], Some(0));
        assert_eq!(&r.encode()[..14], &[0x3A, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0]);
        // ACK : pas de packet-id.
        let a = sample(P_ACK_V1, vec![5], None);
        assert_eq!(a.encode().len(), 1 + 8 + 1 + 4 + 8);
    }

    #[test]
    fn plain_roundtrip_and_malformed() {
        for p in all_samples() {
            assert_eq!(ControlPacket::decode(&p.encode()).unwrap(), p);
        }
        let e = sample(P_CONTROL_V1, vec![1, 2], Some(3)).encode();
        for n in 0..19 {
            assert!(ControlPacket::decode(&e[..n]).is_err(), "tronqué à {n}");
        }
        // Trop d'accusés.
        let mut bad = e.clone();
        bad[9] = 9;
        assert!(ControlPacket::decode(&bad).is_err());
        // Opcode de données.
        let mut bad = e.clone();
        bad[0] = op_byte(P_DATA_V1, 0);
        assert!(ControlPacket::decode(&bad).is_err());
        // ACK avec charge.
        let mut a = sample(P_ACK_V1, vec![1], None).encode();
        a.push(0);
        assert!(ControlPacket::decode(&a).is_err());
        // Aucun octet ne fait paniquer.
        for len in 0..40 {
            for seed in 0..50u8 {
                let v: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed)).collect();
                let _ = ControlPacket::decode(&v);
            }
        }
    }

    #[test]
    fn acks_truncated_to_max() {
        let p = sample(P_CONTROL_V1, (0..12).collect(), Some(1));
        let d = ControlPacket::decode(&p.encode()).unwrap();
        assert_eq!(d.acks, (0..8).collect::<Vec<_>>());
    }

    fn pairs() -> Vec<(Wrap, Wrap)> {
        let k = key();
        let mut v = vec![(Wrap::Plain, Wrap::Plain)];
        for d in [AuthDigest::Sha1, AuthDigest::Sha256, AuthDigest::Sha512] {
            v.push((Wrap::tls_auth(&k, Some(1), d).unwrap(), Wrap::tls_auth(&k, Some(0), d).unwrap()));
            v.push((Wrap::tls_auth(&k, None, d).unwrap(), Wrap::tls_auth(&k, None, d).unwrap()));
        }
        v.push((Wrap::tls_crypt(&k, Role::Client).unwrap(), Wrap::tls_crypt(&k, Role::Server).unwrap()));
        v
    }

    #[test]
    fn wrap_roundtrip_both_ways() {
        for (mut c, mut s) in pairs() {
            for p in all_samples() {
                let w = c.wrap(&p, 1_700_000_000);
                assert_eq!(w.len(), p.encode().len() + c.overhead());
                assert_eq!(s.unwrap(&w).unwrap(), p);
                let w = s.wrap(&p, 1_700_000_001);
                assert_eq!(c.unwrap(&w).unwrap(), p);
            }
        }
    }

    #[test]
    fn tls_auth_layout_exact() {
        let k = key();
        let mut c = Wrap::tls_auth(&k, Some(1), AuthDigest::Sha256).unwrap();
        let p = sample(P_CONTROL_HARD_RESET_CLIENT_V2, vec![], Some(0));
        let w = c.wrap(&p, 0x11223344);
        assert_eq!(&w[..9], &p.encode()[..9]);
        assert_eq!(&w[41..49], &[0, 0, 0, 1, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&w[49..], &p.encode()[9..]);
        // HMAC = HMAC-SHA256(clé hmac de l'emplacement 1) sur pid|time|op|sid|corps.
        let mut auth = w[41..49].to_vec();
        auth.extend_from_slice(&w[..9]);
        auth.extend_from_slice(&w[49..]);
        let kk = hmac::Key::new(hmac::HMAC_SHA256, &k[192..224]);
        assert_eq!(hmac::sign(&kk, &auth).as_ref(), &w[9..41]);
        // Le packet-id progresse, la date reste celle du premier envoi.
        let w2 = c.wrap(&p, 0x55667788);
        assert_eq!(&w2[41..49], &[0, 0, 0, 2, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn tls_crypt_layout_exact() {
        let k = key();
        let mut c = Wrap::tls_crypt(&k, Role::Client).unwrap();
        let p = sample(P_CONTROL_V1, vec![3], Some(4));
        let w = c.wrap(&p, 0x01020304);
        let plain = p.encode();
        assert_eq!(&w[..9], &plain[..9]);
        assert_eq!(&w[9..17], &[0, 0, 0, 1, 1, 2, 3, 4]);
        let tag = &w[17..49];
        // Client : émission avec l'emplacement 1 (direction inverse).
        let mut auth = w[..17].to_vec();
        auth.extend_from_slice(&plain[9..]);
        let hk = hmac::Key::new(hmac::HMAC_SHA256, &k[192..224]);
        assert_eq!(hmac::sign(&hk, &auth).as_ref(), tag);
        let mut body = w[49..].to_vec();
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&k[128..160]);
        ctr_apply(&ck, &tag[..16], &mut body);
        assert_eq!(body, &plain[9..]);
        assert_ne!(&w[49..], &plain[9..]);
    }

    #[test]
    fn ctr_is_full_128bit_be_counter() {
        // Compteur sur 128 bits gros-boutiste (comme AES-256-CTR d'OpenSSL) : la retenue traverse
        // les 64 bits de poids faible.
        let key = [7u8; 32];
        let iv = [0xFFu8; 16];
        let mut a = vec![0u8; 32];
        ctr_apply(&key, &iv, &mut a);
        let mut b = vec![0u8; 16];
        ctr_apply(&key, &[0u8; 16], &mut b);
        assert_eq!(&a[16..], &b[..]);
    }

    #[test]
    fn tamper_detection() {
        for (mut c, mut s) in pairs().into_iter().skip(1) {
            let p = sample(P_CONTROL_V1, vec![1], Some(2));
            let w = c.wrap(&p, 100);
            for i in 0..w.len() {
                let mut t = w.clone();
                t[i] ^= 0x01;
                assert!(s.unwrap(&t).is_err(), "octet {i} modifié accepté");
            }
            for n in 0..w.len() {
                assert!(s.unwrap(&w[..n]).is_err());
            }
            // Toujours accepté intact (les échecs n'ont pas consommé le packet-id).
            assert_eq!(s.unwrap(&w).unwrap(), p);
        }
    }

    #[test]
    fn wrong_direction_or_key_rejected() {
        let k = key();
        let p = sample(P_CONTROL_V1, vec![], Some(1));
        // Même direction des deux côtés.
        let w = Wrap::tls_auth(&k, Some(1), AuthDigest::Sha1).unwrap().wrap(&p, 1);
        assert!(Wrap::tls_auth(&k, Some(1), AuthDigest::Sha1).unwrap().unwrap(&w).is_err());
        assert!(Wrap::tls_auth(&k, None, AuthDigest::Sha1).unwrap().unwrap(&w).is_err());
        // Mauvais condensé.
        assert!(Wrap::tls_auth(&k, Some(0), AuthDigest::Sha256).unwrap().unwrap(&w).is_err());
        // tls-crypt : deux clients.
        let w = Wrap::tls_crypt(&k, Role::Client).unwrap().wrap(&p, 1);
        assert!(Wrap::tls_crypt(&k, Role::Client).unwrap().unwrap(&w).is_err());
        let mut k2 = k.clone();
        k2[192] ^= 1; // clé HMAC client → serveur
        assert!(Wrap::tls_crypt(&k2, Role::Server).unwrap().unwrap(&w).is_err());
        assert!(Wrap::tls_crypt(&k[..255], Role::Server).is_err());
        assert!(Wrap::tls_auth(&k, Some(2), AuthDigest::Sha1).is_err());
    }

    #[test]
    fn replay_rejection() {
        for (mut c, mut s) in pairs().into_iter().skip(1) {
            let p = sample(P_CONTROL_V1, vec![], Some(1));
            let ws: Vec<_> = (0..100).map(|_| c.wrap(&p, 50)).collect();
            assert!(s.unwrap(&ws[5]).is_ok());
            assert!(s.unwrap(&ws[5]).is_err(), "rejeu accepté");
            // Désordre dans la fenêtre accepté, une seule fois.
            assert!(s.unwrap(&ws[2]).is_ok());
            assert!(s.unwrap(&ws[2]).is_err());
            assert!(s.unwrap(&ws[90]).is_ok());
            // Hors fenêtre (90 - 10 >= 64).
            assert!(s.unwrap(&ws[10]).is_err());
            assert!(s.unwrap(&ws[60]).is_ok());
            assert!(s.unwrap(&ws[99]).is_ok());
        }
    }

    #[test]
    fn replay_window_time() {
        let mut w = ReplayWindow::default();
        assert!(w.check(0, 5).is_err());
        w.check(10, 5).unwrap();
        w.accept(10, 5);
        // Nouvelle époque : remise à zéro.
        w.check(1, 6).unwrap();
        w.accept(1, 6);
        assert!(w.check(11, 5).is_err());
        assert!(w.check(1, 6).is_err());
        w.check(200, 6).unwrap();
        w.accept(200, 6);
        assert!(w.check(1, 6).is_err());
        assert!(w.check(137, 6).is_ok());
        assert!(w.check(136, 6).is_err());
    }

    #[test]
    fn static_key_parse() {
        let k = key();
        let mut text = String::from("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n");
        for line in k.chunks(16) {
            for b in line {
                text.push_str(&format!("{b:02x}"));
            }
            text.push_str("\r\n");
        }
        text.push_str("-----END OpenVPN Static key V1-----\n");
        assert_eq!(&parse_static_key(&text).unwrap()[..], &k[..]);
        assert!(parse_static_key("rien").is_err());
        assert!(parse_static_key(&text.replacen("-----
", "-----
zz", 1)).is_err());
        let short = text.replacen(&format!("{:02x}", k[0]), "", 1);
        assert!(parse_static_key(&short).is_err());
    }

    #[test]
    fn digest_names() {
        assert_eq!(AuthDigest::from_name("").unwrap(), AuthDigest::Sha1);
        assert_eq!(AuthDigest::from_name("sha256").unwrap(), AuthDigest::Sha256);
        assert_eq!(AuthDigest::from_name("SHA-512").unwrap(), AuthDigest::Sha512);
        assert!(AuthDigest::from_name("MD5").is_err());
    }

    #[test]
    fn data_headers() {
        let v1 = DataHeader { key_id: 3, peer_id: None };
        assert_eq!(v1.encode(), vec![0x33]);
        let v2 = DataHeader { key_id: 1, peer_id: Some(0x0A0B0C) };
        assert_eq!(v2.encode(), vec![0x49, 0x0A, 0x0B, 0x0C]);
        let mut raw = v2.encode();
        raw.extend([1, 2, 3]);
        let (h, rest) = DataHeader::parse(&raw).unwrap();
        assert_eq!((h, rest), (v2, &[1u8, 2, 3][..]));
        assert_eq!(DataHeader::parse(&[0x33, 9]).unwrap(), (v1, &[9u8][..]));
        assert!(DataHeader::parse(&[]).is_err());
        assert!(DataHeader::parse(&[0x49, 0, 0]).is_err());
        assert!(DataHeader::parse(&[0x20]).is_err());
        assert_eq!(DataHeader { key_id: 0, peer_id: Some(PEER_ID_UNDEF) }.encode(), vec![0x48, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn tcp_framing() {
        let pkts: Vec<Vec<u8>> = (1..40).map(|n| (0..n * 7).map(|i| i as u8).collect()).collect();
        let stream: Vec<u8> = pkts.iter().flat_map(|p| frame(p)).collect();
        for chunk in [1, 2, 3, 7, 100, stream.len()] {
            let mut f = TcpFramer::new();
            let mut got = vec![];
            for c in stream.chunks(chunk) {
                f.push(c);
                while let Some(p) = f.next_packet().unwrap() {
                    got.push(p);
                }
            }
            assert_eq!(got, pkts);
            assert_eq!(f.pending(), 0);
        }
        let mut f = TcpFramer::new();
        f.push(&[0, 0, 1]);
        assert!(f.next_packet().is_err());
        assert_eq!(frame(&[0xAB; 3]), vec![0, 3, 0xAB, 0xAB, 0xAB]);
    }
}
