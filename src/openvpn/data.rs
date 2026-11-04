//! Canal de données OpenVPN : matériel de clés (key-method 2, PRF TLS 1.0 ou exportateur TLS),
//! chiffrement des paquets P_DATA_V1/V2 (AEAD ou CBC + HMAC), protection anti-rejeu, ping et
//! cadrage de compression. Aucun accès réseau : on transforme des octets en octets.
//!
//! Formats (OpenVPN 2.4–2.6, mode TLS, packet-id court de 4 octets) :
//! - AEAD (GCM, ChaCha20-Poly1305) : `en-tête | packet_id(4) | tag(16) | chiffré`, nonce =
//!   `packet_id || IV implicite` (8 premiers octets de l'emplacement HMAC de la clé), données
//!   associées = en-tête P_DATA_V2 (4 octets, absent en V1) + packet_id ;
//! - CBC : `en-tête | HMAC(IV | chiffré) | IV(16) | chiffré`, le chiffré couvrant
//!   `packet_id(4) | données` complété en PKCS#7. L'en-tête n'est pas authentifié.
//!
//! Sens des clés : le bloc `key2` contient deux clés ; le client chiffre avec `keys[0]` et
//! déchiffre avec `keys[1]`, le serveur l'inverse (KEY_DIRECTION_NORMAL / INVERSE d'OpenVPN).

use hmac::{Hmac, KeyInit, Mac};
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

/// Code d'opération des paquets de données (5 bits de poids fort du premier octet).
const P_DATA_V1: u8 = 6;
const P_DATA_V2: u8 = 9;
/// Au-delà, il faut renégocier avant que le compteur ne boucle (même seuil qu'OpenVPN).
const PACKET_ID_RENEGOTIATE: u32 = 0xFF00_0000;
const TAG_LEN: usize = 16;
/// Taille du bloc `key2` : deux clés de (chiffrement 64 + HMAC 64) octets.
pub const KEY2_LEN: usize = 256;
/// Étiquette de l'exportateur TLS (RFC 5705) quand `key-derivation tls-ekm` est poussé.
pub const EKM_LABEL: &[u8] = b"EXPORTER-OpenVPN-datakeys";

// ------------------------------------------------------------------ key-method 2

/// Aléas envoyés par le client dans le message key-method 2.
pub struct ClientKeySource {
    pub pre_master: Zeroizing<[u8; 48]>,
    pub random1: [u8; 32],
    pub random2: [u8; 32],
}

/// Aléas renvoyés par le serveur (pas de pre-master côté serveur).
#[derive(Clone)]
pub struct ServerKeySource {
    pub random1: [u8; 32],
    pub random2: [u8; 32],
}

impl ClientKeySource {
    pub const WIRE_LEN: usize = 48 + 32 + 32;

    pub fn generate() -> Result<Self, String> {
        let rng = SystemRandom::new();
        let mut k = Self { pre_master: Zeroizing::new([0; 48]), random1: [0; 32], random2: [0; 32] };
        rng.fill(&mut k.pre_master[..])
            .and_then(|_| rng.fill(&mut k.random1))
            .and_then(|_| rng.fill(&mut k.random2))
            .map_err(|_| "Générateur aléatoire indisponible".to_string())?;
        Ok(k)
    }

    /// `pre_master | random1 | random2`, tel qu'écrit dans le message key-method 2.
    pub fn to_wire(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(Self::WIRE_LEN));
        v.extend_from_slice(&self.pre_master[..]);
        v.extend_from_slice(&self.random1);
        v.extend_from_slice(&self.random2);
        v
    }
}

impl ServerKeySource {
    pub const WIRE_LEN: usize = 32 + 32;

    /// Lit `random1 | random2` (les 64 premiers octets de `b`).
    pub fn from_wire(b: &[u8]) -> Result<Self, String> {
        if b.len() < Self::WIRE_LEN {
            return Err("Message key-method 2 du serveur tronqué".into());
        }
        let mut s = Self { random1: [0; 32], random2: [0; 32] };
        s.random1.copy_from_slice(&b[..32]);
        s.random2.copy_from_slice(&b[32..64]);
        Ok(s)
    }

    pub fn to_wire(&self) -> Vec<u8> {
        [&self.random1[..], &self.random2[..]].concat()
    }
}

/// P_hash de la RFC 2246 (§5), ajouté par XOR dans `out`.
fn p_hash_xor<M: Mac + KeyInit + Clone>(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let Ok(base) = <M as KeyInit>::new_from_slice(secret) else { return };
    let mut a = {
        let mut m = base.clone();
        m.update(seed);
        Zeroizing::new(m.finalize().into_bytes().to_vec())
    };
    let mut pos = 0;
    while pos < out.len() {
        let mut m = base.clone();
        m.update(&a);
        m.update(seed);
        let block = Zeroizing::new(m.finalize().into_bytes().to_vec());
        for (o, b) in out[pos..].iter_mut().zip(block.iter()) {
            *o ^= b;
        }
        pos += block.len();
        let mut m = base.clone();
        m.update(&a);
        *a = m.finalize().into_bytes().to_vec();
    }
}

/// PRF de TLS 1.0 : P_MD5(S1, étiquette | graine) XOR P_SHA1(S2, étiquette | graine), S1 et S2
/// étant les deux moitiés du secret (qui se chevauchent d'un octet si sa longueur est impaire).
pub fn tls1_prf(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let half = secret.len().div_ceil(2);
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];
    let ls = Zeroizing::new([label, seed].concat());
    out.fill(0);
    p_hash_xor::<Hmac<md5::Md5>>(s1, &ls, out);
    p_hash_xor::<Hmac<sha1::Sha1>>(s2, &ls, out);
}

/// Bloc `key2` brut (256 octets), effacé à la destruction.
pub struct Key2(Zeroizing<[u8; KEY2_LEN]>);

impl Key2 {
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != KEY2_LEN {
            return Err(format!("Matériel de clés OpenVPN de {} octets au lieu de {KEY2_LEN}", b.len()));
        }
        let mut k = Zeroizing::new([0; KEY2_LEN]);
        k.copy_from_slice(b);
        Ok(Self(k))
    }

    pub fn as_bytes(&self) -> &[u8; KEY2_LEN] {
        &self.0
    }

    /// Clé `i` (0 ou 1) : 64 octets de chiffrement puis 64 de HMAC.
    pub fn key(&self, i: usize) -> DataKey {
        let base = (i & 1) * 128;
        let mut k = DataKey { cipher: Zeroizing::new([0; 64]), hmac: Zeroizing::new([0; 64]) };
        k.cipher.copy_from_slice(&self.0[base..base + 64]);
        k.hmac.copy_from_slice(&self.0[base + 64..base + 128]);
        k
    }
}

/// Dérivation key-method 2 par la PRF d'OpenVPN (sans `key-derivation tls-ekm`) :
/// master = PRF(pre_master, "OpenVPN master secret", c.random1 | s.random1) sur 48 octets, puis
/// key2 = PRF(master, "OpenVPN key expansion", c.random2 | s.random2 | sid client | sid serveur).
pub fn derive_key2_prf(
    client: &ClientKeySource,
    server: &ServerKeySource,
    client_sid: &[u8; 8],
    server_sid: &[u8; 8],
) -> Key2 {
    let mut master = Zeroizing::new([0u8; 48]);
    let seed = [&client.random1[..], &server.random1[..]].concat();
    tls1_prf(&client.pre_master[..], b"OpenVPN master secret", &seed, &mut master[..]);
    let seed = [&client.random2[..], &server.random2[..], &client_sid[..], &server_sid[..]].concat();
    let mut k = Zeroizing::new([0u8; KEY2_LEN]);
    tls1_prf(&master[..], b"OpenVPN key expansion", &seed, &mut k[..]);
    Key2(k)
}

/// Dérivation par l'exportateur TLS : `ekm` = 256 octets exportés avec [`EKM_LABEL`], sans
/// contexte (rustls : `export_keying_material(buf, EKM_LABEL, None)`), utilisés tels quels.
pub fn key2_from_ekm(ekm: &[u8]) -> Result<Key2, String> {
    Key2::from_bytes(ekm)
}

/// Une clé directionnelle (`struct key` d'OpenVPN).
pub struct DataKey {
    pub cipher: Zeroizing<[u8; 64]>,
    pub hmac: Zeroizing<[u8; 64]>,
}

/// Côté de la connexion, qui fixe le sens des clés.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    /// (clé d'émission, clé de réception) dans `key2`.
    pub fn key_indices(self) -> (usize, usize) {
        match self {
            Role::Client => (0, 1),
            Role::Server => (1, 0),
        }
    }
}

// ------------------------------------------------------------------ algorithmes

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DataCipher {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    Aes128Cbc,
    Aes256Cbc,
}

impl DataCipher {
    /// Nom OpenVPN (`--cipher`, `--data-ciphers`, poussé par `cipher`), sans tenir compte de la casse.
    pub fn from_name(name: &str) -> Result<Self, String> {
        Ok(match name.trim().to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Self::Aes128Gcm,
            "AES-192-GCM" => Self::Aes192Gcm,
            "AES-256-GCM" => Self::Aes256Gcm,
            "CHACHA20-POLY1305" => Self::Chacha20Poly1305,
            "AES-128-CBC" => Self::Aes128Cbc,
            "AES-256-CBC" => Self::Aes256Cbc,
            "NONE" => return Err("Le chiffrement « none » n'est pas pris en charge".into()),
            _ => return Err(format!("Chiffrement OpenVPN non pris en charge : {name}")),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes192Gcm => "AES-192-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Chacha20Poly1305 => "CHACHA20-POLY1305",
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
        }
    }

    pub fn is_aead(self) -> bool {
        !matches!(self, Self::Aes128Cbc | Self::Aes256Cbc)
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Cbc => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm | Self::Aes256Cbc | Self::Chacha20Poly1305 => 32,
        }
    }

    /// Surcoût maximal d'un paquet chiffré (hors en-tête), pour le calcul de MTU.
    pub fn overhead(self, digest: Digest) -> usize {
        if self.is_aead() { 4 + TAG_LEN } else { digest.len() + 16 + 4 + 16 }
    }
}

/// Condensat HMAC du mode CBC (`--auth`), ignoré en AEAD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Digest {
    Sha1,
    Sha256,
    Sha512,
}

impl Digest {
    pub fn from_name(name: &str) -> Result<Self, String> {
        Ok(match name.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Self::Sha1,
            "SHA256" => Self::Sha256,
            "SHA512" => Self::Sha512,
            _ => return Err(format!("Condensat OpenVPN non pris en charge : {name}")),
        })
    }

    pub fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// HMAC de la concaténation de `parts`, avec une clé de `self.len()` octets.
    pub fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let Ok(mut m) = <M as KeyInit>::new_from_slice(key) else { return Vec::new() };
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }
        match self {
            Self::Sha1 => run::<Hmac<sha1::Sha1>>(key, parts),
            Self::Sha256 => run::<Hmac<sha2::Sha256>>(key, parts),
            Self::Sha512 => run::<Hmac<sha2::Sha512>>(key, parts),
        }
    }

    /// Vérifie un HMAC en temps constant.
    pub fn verify(self, key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
        fn run<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
            let Ok(mut m) = <M as KeyInit>::new_from_slice(key) else { return false };
            for p in parts {
                m.update(p);
            }
            m.verify_slice(tag).is_ok()
        }
        match self {
            Self::Sha1 => run::<Hmac<sha1::Sha1>>(key, parts, tag),
            Self::Sha256 => run::<Hmac<sha2::Sha256>>(key, parts, tag),
            Self::Sha512 => run::<Hmac<sha2::Sha512>>(key, parts, tag),
        }
    }
}

// ------------------------------------------------------------------ GCM logiciel (AES-192)

/// Multiplication dans GF(2^128) selon la convention de GCM, sans branchement sur les données.
fn gf_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xE1 << 120;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        z ^= v & 0u128.wrapping_sub((x >> (127 - i)) & 1);
        v = (v >> 1) ^ (R & 0u128.wrapping_sub(v & 1));
    }
    z
}

fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut y = 0u128;
    for data in [aad, ct] {
        for chunk in data.chunks(16) {
            let mut b = [0u8; 16];
            b[..chunk.len()].copy_from_slice(chunk);
            y = gf_mul(y ^ u128::from_be_bytes(b), h);
        }
    }
    let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
    gf_mul(y ^ lens, h)
}

/// GCM (nonce de 96 bits) au-dessus d'un chiffrement par bloc fourni par `enc`. Chiffre ou
/// déchiffre `data` sur place (CTR) et renvoie le tag calculé sur le chiffré.
fn soft_gcm(enc: &dyn Fn(&mut [u8; 16]), nonce: &[u8; 12], aad: &[u8], data: &mut [u8], encrypt: bool) -> [u8; 16] {
    let mut h = [0u8; 16];
    enc(&mut h);
    let h = u128::from_be_bytes(h);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let ctr_apply = |data: &mut [u8]| {
        for (i, chunk) in data.chunks_mut(16).enumerate() {
            let mut ks = j0;
            ks[12..].copy_from_slice(&(2u32.wrapping_add(i as u32)).to_be_bytes());
            enc(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
        }
    };
    let s = if encrypt {
        ctr_apply(data);
        ghash(h, aad, data)
    } else {
        let s = ghash(h, aad, data);
        ctr_apply(data);
        s
    };
    let mut ek = j0;
    enc(&mut ek);
    (u128::from_be_bytes(ek) ^ s).to_be_bytes()
}

fn aes192_block(c: &aes::Aes192) -> impl Fn(&mut [u8; 16]) + '_ {
    use aes::cipher::BlockCipherEncrypt;
    move |b: &mut [u8; 16]| {
        let mut blk = aes::Block::from(*b);
        c.encrypt_block(&mut blk);
        b.copy_from_slice(&blk);
    }
}

// ------------------------------------------------------------------ anti-rejeu

/// Fenêtre glissante de 64 packet-id (`--replay-window 64` d'OpenVPN, sans fenêtre de temps).
#[derive(Default, Clone)]
pub struct ReplayWindow {
    highest: u32,
    bitmap: u64,
}

impl ReplayWindow {
    /// Accepte `id` s'il est nouveau et pas trop ancien, et le mémorise.
    pub fn check_and_update(&mut self, id: u32) -> Result<(), String> {
        if id == 0 {
            return Err("Paquet OpenVPN avec un packet-id nul".into());
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = id;
            return Ok(());
        }
        let diff = self.highest - id;
        if diff >= 64 {
            return Err("Paquet OpenVPN trop ancien (hors fenêtre anti-rejeu)".into());
        }
        if self.bitmap & (1u64 << diff) != 0 {
            return Err("Paquet OpenVPN rejoué".into());
        }
        self.bitmap |= 1u64 << diff;
        Ok(())
    }

    pub fn highest(&self) -> u32 {
        self.highest
    }
}

// ------------------------------------------------------------------ canal de données

enum Engine {
    Ring(aead::LessSafeKey),
    Aes192Gcm(Box<aes::Aes192>),
    Cbc,
}

/// Une direction du canal (clé d'émission ou de réception).
struct Half {
    engine: Engine,
    /// Clé de chiffrement (CBC uniquement ; vide sinon).
    cipher_key: Zeroizing<Vec<u8>>,
    /// IV implicite (AEAD) ou clé HMAC (CBC).
    hmac_key: Zeroizing<Vec<u8>>,
}

impl Half {
    fn new(cipher: DataCipher, digest: Digest, key: &DataKey) -> Result<Self, String> {
        let k = &key.cipher[..cipher.key_len()];
        let bad = |_| "Clé de données OpenVPN invalide".to_string();
        let ring_key = |alg: &'static aead::Algorithm| -> Result<Engine, String> {
            Ok(Engine::Ring(aead::LessSafeKey::new(aead::UnboundKey::new(alg, k).map_err(bad)?)))
        };
        let (engine, cipher_key, hmac_key) = match cipher {
            DataCipher::Aes128Gcm => (ring_key(&aead::AES_128_GCM)?, Vec::new(), key.hmac[..8].to_vec()),
            DataCipher::Aes256Gcm => (ring_key(&aead::AES_256_GCM)?, Vec::new(), key.hmac[..8].to_vec()),
            DataCipher::Chacha20Poly1305 => {
                (ring_key(&aead::CHACHA20_POLY1305)?, Vec::new(), key.hmac[..8].to_vec())
            }
            DataCipher::Aes192Gcm => {
                let c = <aes::Aes192 as aes::cipher::KeyInit>::new_from_slice(k)
                    .map_err(|_| "Clé de données OpenVPN invalide".to_string())?;
                (Engine::Aes192Gcm(Box::new(c)), Vec::new(), key.hmac[..8].to_vec())
            }
            DataCipher::Aes128Cbc | DataCipher::Aes256Cbc => {
                (Engine::Cbc, k.to_vec(), key.hmac[..digest.len()].to_vec())
            }
        };
        Ok(Self { engine, cipher_key: Zeroizing::new(cipher_key), hmac_key: Zeroizing::new(hmac_key) })
    }

    fn nonce(&self, pid: &[u8; 4]) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(pid);
        n[4..].copy_from_slice(&self.hmac_key[..8]);
        n
    }
}

/// Canal de données d'une session de clés (un `key_id`).
pub struct DataChannel {
    cipher: DataCipher,
    digest: Digest,
    tx: Half,
    rx: Half,
    /// Dernier packet-id émis (le premier envoyé vaut 1).
    tx_pid: u32,
    replay: ReplayWindow,
    rng: SystemRandom,
}

/// L'en-tête est-il celui d'un P_DATA_V2 (opcode + peer-id, authentifié en AEAD) ?
fn is_v2(header: &[u8]) -> bool {
    header.len() == 4 && header[0] >> 3 == P_DATA_V2
}

impl DataChannel {
    /// `digest` ne sert qu'en CBC. `role` fixe le sens des clés de `key2`.
    pub fn new(cipher: DataCipher, digest: Digest, key2: &Key2, role: Role) -> Result<Self, String> {
        let (out, inn) = role.key_indices();
        Ok(Self {
            cipher,
            digest,
            tx: Half::new(cipher, digest, &key2.key(out))?,
            rx: Half::new(cipher, digest, &key2.key(inn))?,
            tx_pid: 0,
            replay: ReplayWindow::default(),
            rng: SystemRandom::new(),
        })
    }

    pub fn cipher(&self) -> DataCipher {
        self.cipher
    }

    /// Vrai quand le compteur d'émission approche de sa limite : il faut renégocier.
    pub fn should_renegotiate(&self) -> bool {
        self.tx_pid >= PACKET_ID_RENEGOTIATE
    }

    /// Chiffre `plaintext` et renvoie le paquet complet `header | corps`. `header` est l'en-tête
    /// P_DATA déjà construit : 1 octet (V1, `6 << 3 | key_id`) ou 4 octets (V2, `9 << 3 | key_id`
    /// puis peer-id sur 3 octets). Refuse si le packet-id bouclerait.
    pub fn encrypt(&mut self, plaintext: &[u8], header: &[u8]) -> Result<Vec<u8>, String> {
        let pid = self.tx_pid.checked_add(1).ok_or("Compteur de paquets OpenVPN épuisé : renégociation nécessaire")?;
        let pid_b = pid.to_be_bytes();
        let mut out = Vec::with_capacity(header.len() + plaintext.len() + 64);
        out.extend_from_slice(header);
        match &self.tx.engine {
            Engine::Ring(key) => {
                let aad = [if is_v2(header) { header } else { &[] }, &pid_b[..]].concat();
                let mut buf = plaintext.to_vec();
                let tag = key
                    .seal_in_place_separate_tag(
                        aead::Nonce::assume_unique_for_key(self.tx.nonce(&pid_b)),
                        aead::Aad::from(&aad),
                        &mut buf,
                    )
                    .map_err(|_| "Échec du chiffrement OpenVPN".to_string())?;
                out.extend_from_slice(&pid_b);
                out.extend_from_slice(tag.as_ref());
                out.extend_from_slice(&buf);
                buf.zeroize();
            }
            Engine::Aes192Gcm(c) => {
                let aad = [if is_v2(header) { header } else { &[] }, &pid_b[..]].concat();
                let mut buf = plaintext.to_vec();
                let tag = soft_gcm(&aes192_block(c), &self.tx.nonce(&pid_b), &aad, &mut buf, true);
                out.extend_from_slice(&pid_b);
                out.extend_from_slice(&tag);
                out.extend_from_slice(&buf);
            }
            Engine::Cbc => {
                use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
                let mut iv = [0u8; 16];
                self.rng.fill(&mut iv).map_err(|_| "Générateur aléatoire indisponible".to_string())?;
                let n = 4 + plaintext.len();
                let mut buf = Zeroizing::new(vec![0u8; (n / 16 + 1) * 16]);
                buf[..4].copy_from_slice(&pid_b);
                buf[4..n].copy_from_slice(plaintext);
                let key = &self.tx.cipher_key[..];
                let bad = |_| "Échec du chiffrement OpenVPN".to_string();
                let ct = match self.cipher {
                    DataCipher::Aes128Cbc => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &iv)
                        .map_err(|_| "Clé de données OpenVPN invalide".to_string())?
                        .encrypt_padded::<Pkcs7>(&mut buf, n)
                        .map_err(bad)?
                        .to_vec(),
                    _ => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv)
                        .map_err(|_| "Clé de données OpenVPN invalide".to_string())?
                        .encrypt_padded::<Pkcs7>(&mut buf, n)
                        .map_err(bad)?
                        .to_vec(),
                };
                out.extend_from_slice(&self.digest.hmac(&self.tx.hmac_key, &[&iv, &ct]));
                out.extend_from_slice(&iv);
                out.extend_from_slice(&ct);
            }
        }
        self.tx_pid = pid;
        Ok(out)
    }

    /// Déchiffre `body` (le paquet sans son en-tête `header`), vérifie l'authenticité puis le
    /// packet-id (fenêtre anti-rejeu, mise à jour seulement si le paquet est authentique).
    pub fn decrypt(&mut self, body: &[u8], header: &[u8]) -> Result<Vec<u8>, String> {
        let auth_err = || "Paquet OpenVPN non authentique (clé ou chiffrement incorrect)".to_string();
        let (pid, plain) = match &self.rx.engine {
            Engine::Ring(_) | Engine::Aes192Gcm(_) => {
                if body.len() < 4 + TAG_LEN {
                    return Err("Paquet OpenVPN tronqué".into());
                }
                let mut pid_b = [0u8; 4];
                pid_b.copy_from_slice(&body[..4]);
                let tag = &body[4..4 + TAG_LEN];
                let ct = &body[4 + TAG_LEN..];
                let aad = [if is_v2(header) { header } else { &[] }, &pid_b[..]].concat();
                let nonce = self.rx.nonce(&pid_b);
                let plain = match &self.rx.engine {
                    Engine::Ring(key) => {
                        let mut buf = [ct, tag].concat();
                        let n = key
                            .open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(&aad), &mut buf)
                            .map_err(|_| auth_err())?
                            .len();
                        buf.truncate(n);
                        buf
                    }
                    Engine::Aes192Gcm(c) => {
                        let mut buf = ct.to_vec();
                        let calc = soft_gcm(&aes192_block(c), &nonce, &aad, &mut buf, false);
                        if calc.iter().zip(tag).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
                            buf.zeroize();
                            return Err(auth_err());
                        }
                        buf
                    }
                    Engine::Cbc => return Err(auth_err()),
                };
                (u32::from_be_bytes(pid_b), plain)
            }
            Engine::Cbc => {
                use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
                let hl = self.digest.len();
                if body.len() < hl + 16 + 16 || (body.len() - hl) % 16 != 0 {
                    return Err("Paquet OpenVPN tronqué ou mal aligné".into());
                }
                let (mac, rest) = body.split_at(hl);
                let (iv, ct) = rest.split_at(16);
                if !self.digest.verify(&self.rx.hmac_key, &[iv, ct], mac) {
                    return Err(auth_err());
                }
                let key = &self.rx.cipher_key[..];
                let mut buf = ct.to_vec();
                let bad = |_| "Bourrage CBC OpenVPN invalide".to_string();
                let n = match self.cipher {
                    DataCipher::Aes128Cbc => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                        .map_err(|_| "Clé de données OpenVPN invalide".to_string())?
                        .decrypt_padded::<Pkcs7>(&mut buf)
                        .map_err(bad)?
                        .len(),
                    _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                        .map_err(|_| "Clé de données OpenVPN invalide".to_string())?
                        .decrypt_padded::<Pkcs7>(&mut buf)
                        .map_err(bad)?
                        .len(),
                };
                if n < 4 {
                    buf.zeroize();
                    return Err("Paquet OpenVPN tronqué".into());
                }
                let pid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let plain = buf[4..n].to_vec();
                buf.zeroize();
                (pid, plain)
            }
        };
        self.replay.check_and_update(pid)?;
        Ok(plain)
    }
}

/// En-tête P_DATA_V1 (1 octet) ou P_DATA_V2 (4 octets) pour `key_id` et un éventuel peer-id.
pub fn data_header(key_id: u8, peer_id: Option<u32>) -> Vec<u8> {
    match peer_id {
        Some(p) => {
            let p = p & 0x00FF_FFFF;
            vec![P_DATA_V2 << 3 | (key_id & 7), (p >> 16) as u8, (p >> 8) as u8, p as u8]
        }
        None => vec![P_DATA_V1 << 3 | (key_id & 7)],
    }
}

// ------------------------------------------------------------------ ping

/// Contenu d'un ping OpenVPN (keepalive), envoyé comme un paquet de données ordinaire.
pub const PING_MAGIC: [u8; 16] =
    [0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48];

/// Le paquet déchiffré (après décompression) est-il un ping ?
pub fn is_ping(plain: &[u8]) -> bool {
    plain == PING_MAGIC
}

// ------------------------------------------------------------------ compression

const NO_COMPRESS_BYTE: u8 = 0xFA;
const NO_COMPRESS_BYTE_SWAP: u8 = 0xFB;
const COMP_ALGV2_INDICATOR_BYTE: u8 = 0x50;
const COMP_ALGV2_UNCOMPRESSED: u8 = 0x00;

/// Cadrage de compression en vigueur. Escale ne compresse jamais : il ajoute seulement l'octet
/// « non compressé » attendu par le serveur et refuse les paquets réellement compressés.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Compression {
    /// Pas de compression négociée : rien n'est ajouté.
    #[default]
    None,
    /// `comp-lzo` (quelle que soit sa valeur), `compress lzo` : préfixe 0xFA.
    Lzo,
    /// `compress`, `compress stub`, `compress lz4` : 0xFB en tête, le premier octet passant à la fin.
    Swap,
    /// `compress stub-v2`, `compress lz4-v2` : rien, sauf si le paquet commence par 0x50 (0x50 0x00).
    V2,
}

impl Compression {
    /// Interprète `comp-lzo [arg]` ou `compress [arg]` (fichier .ovpn ou options poussées).
    pub fn from_directive(name: &str, arg: Option<&str>) -> Result<Self, String> {
        let arg = arg.map(|a| a.trim().to_ascii_lowercase());
        match (name, arg.as_deref()) {
            ("comp-lzo", _) => Ok(Self::Lzo),
            ("compress", None | Some("") | Some("stub") | Some("lz4")) => Ok(Self::Swap),
            ("compress", Some("lzo")) => Ok(Self::Lzo),
            ("compress", Some("stub-v2") | Some("lz4-v2")) => Ok(Self::V2),
            ("compress", Some(a)) => Err(format!("Compression OpenVPN non prise en charge : {a}")),
            _ => Err(format!("Directive de compression inconnue : {name}")),
        }
    }

    /// Prépare un paquet IP avant chiffrement (pings compris).
    pub fn frame(self, mut p: Vec<u8>) -> Vec<u8> {
        match self {
            Self::None => p,
            Self::Lzo => {
                p.insert(0, NO_COMPRESS_BYTE);
                p
            }
            Self::Swap => {
                if let Some(&first) = p.first() {
                    p.push(first);
                    p[0] = NO_COMPRESS_BYTE_SWAP;
                }
                p
            }
            Self::V2 => {
                if p.first() == Some(&COMP_ALGV2_INDICATOR_BYTE) {
                    p.splice(0..0, [COMP_ALGV2_INDICATOR_BYTE, COMP_ALGV2_UNCOMPRESSED]);
                }
                p
            }
        }
    }

    /// Retire le cadrage d'un paquet déchiffré ; refuse les paquets compressés.
    pub fn unframe(self, mut p: Vec<u8>) -> Result<Vec<u8>, String> {
        let compressed = || Err("Paquet OpenVPN compressé : la compression n'est pas prise en charge".to_string());
        match self {
            Self::None => Ok(p),
            Self::Lzo => match p.first() {
                None => Ok(p),
                Some(&NO_COMPRESS_BYTE) => {
                    p.remove(0);
                    Ok(p)
                }
                Some(_) => compressed(),
            },
            Self::Swap => match p.first() {
                None => Ok(p),
                Some(&NO_COMPRESS_BYTE_SWAP) => {
                    let Some(last) = p.pop() else { return Ok(p) };
                    if p.is_empty() {
                        // Paquet réduit à l'octet de cadrage : rien à restituer.
                        return Ok(p);
                    }
                    p[0] = last;
                    Ok(p)
                }
                Some(_) => compressed(),
            },
            Self::V2 => match p.first() {
                Some(&COMP_ALGV2_INDICATOR_BYTE) => match p.get(1) {
                    Some(&COMP_ALGV2_UNCOMPRESSED) => {
                        p.drain(..2);
                        Ok(p)
                    }
                    _ => compressed(),
                },
                _ => Ok(p),
            },
        }
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC de la RFC 2104 écrit à la main (indépendant de la caisse `hmac`).
    fn hmac_ref(hash: fn(&[u8]) -> Vec<u8>, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let h = hash(key);
            k[..h.len()].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).chain(msg.iter().copied()).collect();
        let inner = hash(&ipad);
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).chain(inner).collect();
        hash(&opad)
    }
    fn md5h(d: &[u8]) -> Vec<u8> {
        use md5::Digest as _;
        md5::Md5::digest(d).to_vec()
    }
    fn sha1h(d: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, d).as_ref().to_vec()
    }
    fn p_hash_ref(hash: fn(&[u8]) -> Vec<u8>, secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut a = hmac_ref(hash, secret, seed);
        while out.len() < len {
            out.extend(hmac_ref(hash, secret, &[&a[..], seed].concat()));
            a = hmac_ref(hash, secret, &a);
        }
        out.truncate(len);
        out
    }
    /// PRF de la RFC 2246 §5, écrite indépendamment.
    fn prf_ref(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let ls = [label, seed].concat();
        let half = (secret.len() + 1) / 2;
        let a = p_hash_ref(md5h, &secret[..half], &ls, len);
        let b = p_hash_ref(sha1h, &secret[secret.len() - half..], &ls, len);
        a.iter().zip(b).map(|(x, y)| x ^ y).collect()
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    #[test]
    fn prf_matches_reference() {
        for (slen, olen) in [(48, 48), (48, 256), (47, 100), (1, 17), (0, 5), (100, 1)] {
            let secret = pattern(slen, 3);
            let seed = pattern(64, 9);
            let mut out = vec![0u8; olen];
            tls1_prf(&secret, b"OpenVPN master secret", &seed, &mut out);
            assert_eq!(out, prf_ref(&secret, b"OpenVPN master secret", &seed, olen), "{slen}/{olen}");
        }
    }

    #[test]
    fn key_expansion_matches_reference() {
        let c = ClientKeySource {
            pre_master: Zeroizing::new(pattern(48, 1).try_into().unwrap()),
            random1: pattern(32, 2).try_into().unwrap(),
            random2: pattern(32, 4).try_into().unwrap(),
        };
        let s = ServerKeySource { random1: pattern(32, 5).try_into().unwrap(), random2: pattern(32, 6).try_into().unwrap() };
        let csid = [1, 2, 3, 4, 5, 6, 7, 8];
        let ssid = [9, 10, 11, 12, 13, 14, 15, 16];
        let k = derive_key2_prf(&c, &s, &csid, &ssid);
        let master = prf_ref(&c.pre_master[..], b"OpenVPN master secret", &[c.random1, s.random1].concat(), 48);
        let seed = [&c.random2[..], &s.random2, &csid, &ssid].concat();
        let exp = prf_ref(&master, b"OpenVPN key expansion", &seed, 256);
        assert_eq!(&k.as_bytes()[..], &exp[..]);
        // Découpage key2 : clé 0 = [0..64] chiffrement, [64..128] HMAC ; clé 1 ensuite.
        assert_eq!(&k.key(0).cipher[..], &exp[..64]);
        assert_eq!(&k.key(0).hmac[..], &exp[64..128]);
        assert_eq!(&k.key(1).cipher[..], &exp[128..192]);
        assert_eq!(&k.key(1).hmac[..], &exp[192..]);
        assert_eq!(ServerKeySource::from_wire(&s.to_wire()).unwrap().random2, s.random2);
        assert_eq!(c.to_wire().len(), ClientKeySource::WIRE_LEN);
        assert!(ServerKeySource::from_wire(&[0; 10]).is_err());
    }

    #[test]
    fn soft_gcm_matches_ring() {
        use aes::cipher::{BlockCipherEncrypt, KeyInit as _};
        let key = pattern(16, 7);
        let c = aes::Aes128::new_from_slice(&key).unwrap();
        let enc = |b: &mut [u8; 16]| {
            let mut blk = aes::Block::from(*b);
            c.encrypt_block(&mut blk);
            b.copy_from_slice(&blk);
        };
        let rk = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        for len in [0, 1, 15, 16, 17, 100, 1500] {
            let nonce: [u8; 12] = pattern(12, len as u8).try_into().unwrap();
            let aad = pattern(len % 9, 1);
            let pt = pattern(len, 42);
            let mut a = pt.clone();
            let tag = soft_gcm(&enc, &nonce, &aad, &mut a, true);
            let mut b = pt.clone();
            let rtag = rk
                .seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(&aad), &mut b)
                .unwrap();
            assert_eq!(a, b, "{len}");
            assert_eq!(&tag[..], rtag.as_ref(), "{len}");
            let tag2 = soft_gcm(&enc, &nonce, &aad, &mut a, false);
            assert_eq!(a, pt);
            assert_eq!(tag, tag2);
        }
    }

    /// Vecteur de test 10 de la spécification GCM (AES-192, IV 96 bits).
    #[test]
    fn soft_gcm_aes192_vector() {
        fn hx(s: &str) -> Vec<u8> {
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
        }
        use aes::cipher::KeyInit as _;
        let c = aes::Aes192::new_from_slice(&hx("feffe9928665731c6d6a8f9467308308feffe9928665731c")).unwrap();
        let nonce: [u8; 12] = hx("cafebabefacedbaddecaf888").try_into().unwrap();
        let aad = hx("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut pt = hx("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let tag = soft_gcm(&aes192_block(&c), &nonce, &aad, &mut pt, true);
        assert_eq!(pt, hx("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710"));
        assert_eq!(tag.to_vec(), hx("2519498e80f1478f37ba55bd6d27618c"));
    }

    const ALL: [DataCipher; 6] = [
        DataCipher::Aes128Gcm,
        DataCipher::Aes192Gcm,
        DataCipher::Aes256Gcm,
        DataCipher::Chacha20Poly1305,
        DataCipher::Aes128Cbc,
        DataCipher::Aes256Cbc,
    ];

    fn pair(c: DataCipher, d: Digest) -> (DataChannel, DataChannel) {
        let k = key2_from_ekm(&pattern(256, 77)).unwrap();
        (DataChannel::new(c, d, &k, Role::Client).unwrap(), DataChannel::new(c, d, &k, Role::Server).unwrap())
    }

    #[test]
    fn roundtrip_all_ciphers() {
        for c in ALL {
            assert_eq!(DataCipher::from_name(&c.name().to_lowercase()).unwrap(), c);
            for d in [Digest::Sha1, Digest::Sha256, Digest::Sha512] {
                for hdr in [data_header(1, None), data_header(2, Some(0x123456))] {
                    let (mut cl, mut sv) = pair(c, d);
                    for len in [0usize, 1, 11, 12, 16, 100, 1400] {
                        let pt = pattern(len, len as u8);
                        let pkt = cl.encrypt(&pt, &hdr).unwrap();
                        assert_eq!(&pkt[..hdr.len()], &hdr[..]);
                        assert!(pkt.len() - hdr.len() - len <= c.overhead(d), "{c:?} {len}");
                        assert_eq!(sv.decrypt(&pkt[hdr.len()..], &hdr).unwrap(), pt, "{c:?} {d:?} {len}");
                        let back = sv.encrypt(&pt, &hdr).unwrap();
                        assert_eq!(cl.decrypt(&back[hdr.len()..], &hdr).unwrap(), pt);
                        // Le client ne peut pas relire son propre paquet (clés directionnelles).
                        let mut cl2 = pair(c, d).0;
                        assert!(cl2.decrypt(&pkt[hdr.len()..], &hdr).is_err(), "{c:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn aead_layout() {
        let (mut cl, _) = pair(DataCipher::Aes256Gcm, Digest::Sha1);
        let hdr = data_header(0, Some(7));
        let pkt = cl.encrypt(b"abc", &hdr).unwrap();
        assert_eq!(pkt.len(), 4 + 4 + 16 + 3);
        assert_eq!(&pkt[4..8], &[0, 0, 0, 1]);
        let pkt = cl.encrypt(b"abc", &hdr).unwrap();
        assert_eq!(&pkt[4..8], &[0, 0, 0, 2]);
        // Recalcul indépendant avec ring : nonce = pid | hmac[0..8] de la clé 0, AAD = en-tête + pid.
        let k = key2_from_ekm(&pattern(256, 77)).unwrap();
        let k0 = k.key(0);
        let rk = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &k0.cipher[..32]).unwrap());
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&pkt[4..8]);
        nonce[4..].copy_from_slice(&k0.hmac[..8]);
        let mut buf = [&pkt[24..], &pkt[8..24]].concat();
        let aad = [&hdr[..], &pkt[4..8]].concat();
        let pt = rk.open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(&aad), &mut buf).unwrap();
        assert_eq!(pt, b"abc");
        assert_eq!(data_header(3, Some(0xABCDEF)), vec![0x4B, 0xAB, 0xCD, 0xEF]);
        assert_eq!(data_header(3, None), vec![0x33]);
    }

    #[test]
    fn cbc_layout() {
        let (mut cl, _) = pair(DataCipher::Aes128Cbc, Digest::Sha256);
        let hdr = data_header(0, None);
        let pkt = cl.encrypt(b"hello", &hdr).unwrap();
        let body = &pkt[1..];
        assert_eq!(body.len(), 32 + 16 + 16);
        let k0 = key2_from_ekm(&pattern(256, 77)).unwrap().key(0);
        assert_eq!(&body[..32], &Digest::Sha256.hmac(&k0.hmac[..32], &[&body[32..]])[..]);
        use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
        let mut buf = body[48..].to_vec();
        let pt = cbc::Decryptor::<aes::Aes128>::new_from_slices(&k0.cipher[..16], &body[32..48])
            .unwrap()
            .decrypt_padded::<Pkcs7>(&mut buf)
            .unwrap();
        assert_eq!(pt, b"\0\0\0\x01hello");
    }

    #[test]
    fn tamper_and_replay_rejected() {
        for c in ALL {
            let (mut cl, mut sv) = pair(c, Digest::Sha256);
            let hdr = data_header(0, Some(1));
            let pkt = cl.encrypt(b"payload data", &hdr).unwrap();
            for i in 0..pkt.len() - hdr.len() {
                let mut t = pkt[hdr.len()..].to_vec();
                t[i] ^= 0x01;
                assert!(sv.decrypt(&t, &hdr).is_err(), "{c:?} octet {i}");
            }
            if c.is_aead() {
                // L'en-tête V2 (peer-id) est authentifié en AEAD.
                assert!(sv.decrypt(&pkt[hdr.len()..], &data_header(0, Some(2))).is_err());
            }
            assert!(sv.decrypt(&[], &hdr).is_err());
            assert!(sv.decrypt(&pkt[hdr.len()..pkt.len() - 1], &hdr).is_err());
            assert!(sv.decrypt(&pkt[hdr.len()..], &hdr).is_ok());
            assert!(sv.decrypt(&pkt[hdr.len()..], &hdr).is_err(), "rejeu {c:?}");
        }
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_update(0).is_err());
        assert!(w.check_and_update(5).is_ok());
        assert!(w.check_and_update(3).is_ok());
        assert!(w.check_and_update(3).is_err());
        assert!(w.check_and_update(5).is_err());
        assert!(w.check_and_update(68).is_ok());
        assert!(w.check_and_update(6).is_ok()); // écart 62 : encore dans la fenêtre
        assert!(w.check_and_update(5).is_err()); // écart 63 : déjà vu
        assert!(w.check_and_update(4).is_err()); // écart 64 : trop ancien
        assert!(w.check_and_update(1000).is_ok());
        assert!(w.check_and_update(999).is_ok());
        assert!(w.check_and_update(u32::MAX).is_ok());
        assert!(w.check_and_update(u32::MAX).is_err());
    }

    #[test]
    fn packet_id_wrap_refused() {
        let (mut cl, mut sv) = pair(DataCipher::Aes128Gcm, Digest::Sha1);
        cl.tx_pid = u32::MAX - 1;
        assert!(cl.should_renegotiate());
        let hdr = data_header(0, None);
        let p = cl.encrypt(b"x", &hdr).unwrap();
        assert_eq!(sv.decrypt(&p[1..], &hdr).unwrap(), b"x");
        assert!(cl.encrypt(b"x", &hdr).is_err());
    }

    #[test]
    fn names() {
        assert!(DataCipher::from_name("none").is_err());
        assert!(DataCipher::from_name("BF-CBC").is_err());
        assert_eq!(Digest::from_name("sha256").unwrap(), Digest::Sha256);
        assert_eq!(Digest::from_name("SHA-512").unwrap(), Digest::Sha512);
        assert!(Digest::from_name("MD5").is_err());
        assert!(key2_from_ekm(&[0; 255]).is_err());
    }

    #[test]
    fn ping_and_compression() {
        assert!(is_ping(&PING_MAGIC));
        assert!(!is_ping(&PING_MAGIC[..15]));
        let ip = vec![0x45, 1, 2, 3];
        for c in [Compression::None, Compression::Lzo, Compression::Swap, Compression::V2] {
            for p in [ip.clone(), vec![], vec![0x50, 9], PING_MAGIC.to_vec()] {
                assert_eq!(c.unframe(c.frame(p.clone())).unwrap(), p, "{c:?}");
            }
        }
        assert_eq!(Compression::Lzo.frame(ip.clone()), vec![0xFA, 0x45, 1, 2, 3]);
        assert_eq!(Compression::Swap.frame(ip.clone()), vec![0xFB, 1, 2, 3, 0x45]);
        assert_eq!(Compression::V2.frame(ip.clone()), ip);
        assert_eq!(Compression::V2.frame(vec![0x50, 1]), vec![0x50, 0, 0x50, 1]);
        assert!(Compression::Lzo.unframe(vec![0x66, 1]).is_err());
        assert!(Compression::Swap.unframe(vec![0x69, 1]).is_err());
        assert!(Compression::V2.unframe(vec![0x50, 1, 2]).is_err());
        assert!(Compression::V2.unframe(vec![0x50]).is_err());
        assert_eq!(Compression::from_directive("comp-lzo", Some("no")).unwrap(), Compression::Lzo);
        assert_eq!(Compression::from_directive("compress", None).unwrap(), Compression::Swap);
        assert_eq!(Compression::from_directive("compress", Some("stub-v2")).unwrap(), Compression::V2);
        assert!(Compression::from_directive("compress", Some("zstd")).is_err());
    }
}
