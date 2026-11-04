//! Session de contrôle OpenVPN côté client, sans E/S : réinitialisation (HARD_RESET v2, numéros de
//! session), couche de fiabilité, TLS (rustls piloté sur des tampons), échange key-method 2
//! (aléas, chaîne d'options, identifiant / mot de passe, peer-info), PUSH_REQUEST / PUSH_REPLY,
//! négociation du chiffrement, dérivation des clés (PRF TLS 1.0 ou exportateur TLS) et
//! renégociation (SOFT_RESET, à l'initiative du serveur ou du client, nouveau `key_id`).
//!
//! L'appelant (`link`) lui confie les paquets de contrôle reçus (sans préfixe TCP), l'appelle
//! régulièrement (`tick`), envoie ce que rend `poll_net` et lit les événements (`poll_event`) :
//! clés prêtes, options poussées, erreurs. Le canal de données reste à la charge de l'appelant.
//!
//! Vérification du serveur : chaîne de certificats signée par l'autorité du profil (`ca`)
//! uniquement, sans contrôle de nom d'hôte (un serveur OpenVPN n'en a pas) ; `remote-cert-tls
//! server` (usage étendu serverAuth ou nsCertType server) et `verify-x509-name` si demandés.

use super::config::{self, X509NameType};
use super::data::{self, ClientKeySource, Compression, DataCipher, Digest, Key2, ServerKeySource};
use super::packet::{
    self, AuthDigest, ControlPacket, P_ACK_V1, P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_HARD_RESET_SERVER_V2,
    P_CONTROL_SOFT_RESET_V1, P_CONTROL_V1, Wrap,
};
use super::reliable::{Reliable, ReliableConfig};
use crate::model::{OpenVpnConfig, OpenVpnProto};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConnection, Resumption};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

/// Taille d'un paquet de contrôle (`tls-mtu` d'OpenVPN 2.6) : en-têtes et enveloppe compris.
const TLS_MTU: usize = 1250;
/// En-tête d'un paquet de contrôle hors enveloppe : op, session, accusés (4 au plus), numéro.
const CONTROL_HEADER: usize = 1 + 8 + 1 + 4 * 4 + 8 + 4;
/// Délai pour achever une négociation de clé (`hand-window`).
const HAND_WINDOW: Duration = Duration::from_secs(60);
/// Réémission de PUSH_REQUEST tant que le serveur n'a pas répondu.
const PUSH_RETRY: Duration = Duration::from_secs(2);
/// Durée de vie d'une clé (`reneg-sec` par défaut).
const RENEG_SEC: u32 = 3600;
/// Le serveur renégocie normalement le premier : le client ne le fait qu'avec une minute de
/// retard, pour éviter deux renégociations croisées.
const RENEG_DELAY: Duration = Duration::from_secs(60);
/// Octets TLS reçus en attente au plus (avant la session TLS, ou entre deux traitements).
const MAX_TLS_IN: usize = 64 * 1024;
/// Message texte du canal de contrôle au plus (PUSH_REPLY compris).
const MAX_TEXT: usize = 64 * 1024;
/// Version annoncée au serveur (IV_VER) : décide des options qu'il pousse.
const IV_VER: &str = "2.6.12";
/// IV_PROTO : DATA_V2 (2) | REQUEST_PUSH (4) | TLS_KEY_EXPORT (8). Pas de cc-exit, dyn-tls-crypt
/// ni AUTH_PENDING : non gérés.
const IV_PROTO: u32 = 2 | 4 | 8;
/// Chiffrements proposés quand le profil n'a pas de `data-ciphers` (défaut d'OpenVPN 2.6).
const DEFAULT_CIPHERS: [DataCipher; 3] = [DataCipher::Aes256Gcm, DataCipher::Aes128Gcm, DataCipher::Chacha20Poly1305];

// ------------------------------------------------------------------ réglages du client

/// Enveloppe du canal de contrôle choisie par le profil.
enum WrapKind {
    Plain,
    TlsAuth { key: Zeroizing<Vec<u8>>, direction: Option<u8>, digest: AuthDigest },
    TlsCrypt { key: Zeroizing<Vec<u8>> },
}

/// Réglages vérifiés d'un profil OpenVPN, partagés par les sessions successives (reconnexions).
pub struct ClientSetup {
    tls: Arc<ClientConfig>,
    /// Dernier refus du vérificateur de certificat, en clair (plus parlant que l'erreur rustls).
    verify_error: Arc<Mutex<Option<String>>>,
    wrap: WrapKind,
    /// Identifiant et mot de passe (`auth-user-pass`), `None` sinon.
    credentials: Option<(Zeroizing<String>, Zeroizing<String>)>,
    /// `cipher` du profil : utilisé si le serveur n'en pousse pas (serveur sans négociation).
    fallback: Option<DataCipher>,
    /// Chiffrements proposés (IV_CIPHERS) : un chiffrement poussé hors de cette liste est refusé.
    offered: Vec<DataCipher>,
    /// Renégociation à l'initiative du client (`reneg-sec` + une minute), `None` = jamais.
    reneg: Option<Duration>,
    digest: Digest,
    /// Cadrage de compression du profil (`comp-lzo` / `compress`), remplacé par une option poussée.
    pub compression: Compression,
    pub tcp: bool,
    /// `ping` / `ping-restart` / `tun-mtu` du profil (secondes ; une option poussée l'emporte).
    pub ping: Option<u32>,
    pub ping_restart: Option<u32>,
    pub tun_mtu: Option<u16>,
    /// Routes du profil (`route`, `route-ipv6`), ajoutées à celles du serveur.
    pub routes: Vec<(IpAddr, u8)>,
    /// `redirect-gateway` du profil : tout passe par le VPN.
    pub redirect_gateway: bool,
    /// `route-nopull` : routes poussées ignorées.
    pub route_nopull: bool,
    options_string: String,
    peer_info: String,
}

impl ClientSetup {
    /// Prépare un profil : certificats, clés, enveloppe, chiffrements. Les erreurs sont en français.
    pub fn new(cfg: &OpenVpnConfig, username: &str, password: &str) -> Result<Self, String> {
        config::check(cfg, username, password)?;
        let tcp = cfg.proto == OpenVpnProto::Tcp;

        // --- TLS
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(cfg.ca.as_bytes()) {
            let c = c.map_err(|e| format!("Autorité de certification (ca) illisible : {e}"))?;
            roots.add(c).map_err(|e| format!("Autorité de certification (ca) refusée : {e}"))?;
        }
        if roots.is_empty() {
            return Err("Autorité de certification (ca) absente du profil".into());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verify_error = Arc::new(Mutex::new(None));
        let verifier = Arc::new(OvpnVerifier {
            roots,
            algs: provider.signature_verification_algorithms,
            remote_cert_tls: cfg.remote_cert_tls,
            x509_name: config::x509_name(cfg),
            error: verify_error.clone(),
        });
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| format!("Configuration TLS impossible : {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let mut tls = if cfg.cert.trim().is_empty() {
            builder.with_no_client_auth()
        } else {
            let chain = CertificateDer::pem_slice_iter(cfg.cert.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Certificat client (cert) illisible : {e}"))?;
            let key = PrivateKeyDer::from_pem_slice(cfg.key.as_bytes())
                .map_err(|e| format!("Clé privée client (key) illisible : {e}"))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| format!("Certificat ou clé client inutilisable : {e}"))?
        };
        // un serveur OpenVPN n'a pas de nom : ni SNI ni reprise de session (OpenVPN la désactive)
        tls.enable_sni = false;
        tls.resumption = Resumption::disabled();

        // --- enveloppe
        let direction = match cfg.key_direction.trim() {
            "" => None,
            "0" => Some(0),
            "1" => Some(1),
            d => return Err(format!("key-direction invalide : {d} (0 ou 1)")),
        };
        let wrap = if !cfg.tls_crypt.trim().is_empty() {
            WrapKind::TlsCrypt { key: packet::parse_static_key(&cfg.tls_crypt).map_err(|e| format!("tls-crypt : {e}"))? }
        } else if !cfg.tls_auth.trim().is_empty() {
            WrapKind::TlsAuth {
                key: packet::parse_static_key(&cfg.tls_auth).map_err(|e| format!("tls-auth : {e}"))?,
                direction,
                digest: AuthDigest::from_name(&cfg.auth)?,
            }
        } else {
            WrapKind::Plain
        };

        // --- canal de données
        let mut ciphers = Vec::new();
        for name in cfg.data_ciphers.split(':').map(str::trim).filter(|n| !n.is_empty()) {
            let name = name.trim_start_matches('?');
            if let Ok(c) = DataCipher::from_name(name)
                && !ciphers.contains(&c)
            {
                ciphers.push(c);
            }
        }
        if ciphers.is_empty() {
            ciphers.extend(DEFAULT_CIPHERS);
        }
        // un `cipher` que le client ne sait pas jouer (BF-CBC…) n'est qu'un repli inutilisable :
        // le serveur qui négocie (NCP) poussera un chiffrement de la liste
        let fallback = DataCipher::from_name(cfg.cipher.trim()).ok();
        // comme OpenVPN 2.5 : le `cipher` du profil est aussi proposé (serveurs WatchGuard en CBC)
        if let Some(f) = fallback
            && !ciphers.contains(&f)
        {
            ciphers.push(f);
        }
        let auth = cfg.auth.trim();
        let digest = Digest::from_name(if auth.is_empty() { "SHA1" } else { auth })?;
        let compression = config::compression(cfg)?;

        let credentials = cfg.auth_user_pass.then(|| {
            (Zeroizing::new(username.trim().to_string()), Zeroizing::new(password.to_string()))
        });
        let options_string = options_string(tcp, compression, fallback.unwrap_or(ciphers[0]), digest, &wrap, direction);
        let peer_info = peer_info(&ciphers, compression);
        let reneg = match cfg.reneg_sec.unwrap_or(RENEG_SEC) {
            0 => None,
            n => Some(Duration::from_secs(n as u64) + RENEG_DELAY),
        };
        let nonzero = |v: u32| (v > 0).then_some(v);
        Ok(Self {
            tls: Arc::new(tls),
            verify_error,
            wrap,
            credentials,
            fallback,
            offered: ciphers,
            reneg,
            digest,
            compression,
            tcp,
            ping: nonzero(cfg.ping),
            ping_restart: nonzero(cfg.ping_restart),
            tun_mtu: (cfg.tun_mtu >= 576).then_some(cfg.tun_mtu),
            routes: config::profile_routes(cfg)?,
            redirect_gateway: cfg.redirect_gateway,
            route_nopull: cfg.route_nopull,
            options_string,
            peer_info,
        })
    }

    fn new_wrap(&self) -> Result<Wrap, String> {
        match &self.wrap {
            WrapKind::Plain => Ok(Wrap::Plain),
            WrapKind::TlsAuth { key, direction, digest } => Wrap::tls_auth(key, *direction, *digest),
            WrapKind::TlsCrypt { key } => Wrap::tls_crypt(key, packet::Role::Client),
        }
    }

    /// Chiffrement du canal de données : celui poussé par le serveur, sinon le `cipher` du profil.
    fn negotiate(&self, o: &PushOptions) -> Result<(DataCipher, Digest), String> {
        let cipher = match &o.cipher {
            Some(c) => {
                let cipher = DataCipher::from_name(c)
                    .map_err(|_| format!("Le serveur OpenVPN impose le chiffrement « {c} », non pris en charge par Escale"))?;
                // comme OpenVPN 2.5+ : « pushed cipher not allowed »
                if !self.offered.contains(&cipher) {
                    let names: Vec<&str> = self.offered.iter().map(|c| c.name()).collect();
                    return Err(format!(
                        "Le serveur OpenVPN impose le chiffrement « {} », absent de ceux autorisés par le profil ({})",
                        cipher.name(),
                        names.join(", ")
                    ));
                }
                cipher
            }
            None => self.fallback.ok_or(
                "Le serveur OpenVPN n'a pas négocié de chiffrement et le profil n'indique pas de « cipher » \
                 (l'ancien défaut BF-CBC n'est pas pris en charge)",
            )?,
        };
        let digest = match &o.auth {
            Some(a) => Digest::from_name(a)
                .map_err(|_| format!("Le serveur OpenVPN impose le condensé « auth {a} », non pris en charge"))?,
            None => self.digest,
        };
        Ok((cipher, digest))
    }
}

/// Chaîne d'options (contrôle de cohérence d'OpenVPN, simple avertissement côté serveur).
fn options_string(
    tcp: bool,
    compression: Compression,
    cipher: DataCipher,
    digest: Digest,
    wrap: &WrapKind,
    direction: Option<u8>,
) -> String {
    let mut s = String::from("V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto ");
    s.push_str(if tcp { "TCPv4_CLIENT" } else { "UDPv4" });
    match compression {
        Compression::None => {}
        Compression::Lzo => s.push_str(",comp-lzo"),
        Compression::Swap | Compression::V2 => s.push_str(",compress"),
    }
    if let WrapKind::TlsAuth { .. } = wrap
        && let Some(d) = direction
    {
        s.push_str(&format!(",keydir {d}"));
    }
    let auth = match digest {
        Digest::Sha1 => "SHA1",
        Digest::Sha256 => "SHA256",
        Digest::Sha512 => "SHA512",
    };
    s.push_str(&format!(",cipher {},auth {},keysize {}", cipher.name(), auth, cipher.key_len() * 8));
    if let WrapKind::TlsAuth { .. } = wrap {
        s.push_str(",tls-auth");
    }
    s.push_str(",key-method 2,tls-client");
    s
}

/// Informations sur le client (`push-peer-info`) : version, protocoles, chiffrements.
fn peer_info(ciphers: &[DataCipher], compression: Compression) -> String {
    let names: Vec<&str> = ciphers.iter().map(|c| c.name()).collect();
    // tests : sans exportateur TLS annoncé, le serveur garde la PRF d'OpenVPN
    let proto = if cfg!(test) && std::env::var_os("OVPN_NO_EKM").is_some() { IV_PROTO & !8 } else { IV_PROTO };
    let mut s = format!(
        "IV_VER={IV_VER}\nIV_PLAT=win\nIV_PROTO={proto}\nIV_NCP=2\nIV_CIPHERS={}\n",
        names.join(":")
    );
    // Escale ne compresse jamais : il le dit pour que le serveur n'envoie rien de compressé
    if compression == Compression::Lzo {
        s.push_str("IV_LZO_STUB=1\n");
    }
    s.push_str("IV_COMP_STUB=1\nIV_COMP_STUBv2=1\n");
    s.push_str(concat!("IV_GUI_VER=Escale_", env!("CARGO_PKG_VERSION"), "\n"));
    s
}

// ------------------------------------------------------------------ vérification du serveur

#[derive(Debug)]
struct OvpnVerifier {
    roots: RootCertStore,
    algs: WebPkiSupportedAlgorithms,
    remote_cert_tls: bool,
    x509_name: Option<(X509NameType, String)>,
    error: Arc<Mutex<Option<String>>>,
}

impl OvpnVerifier {
    fn refuse(&self, msg: String) -> rustls::Error {
        *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.clone());
        rustls::Error::General(msg)
    }
}

/// Message clair pour une erreur de vérification de chaîne.
fn chain_error(e: &rustls::Error) -> String {
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            CertificateError::UnknownIssuer => {
                "il n'est pas signé par l'autorité de certification (ca) du profil".to_string()
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => "il a expiré".into(),
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "il n'est pas encore valide (horloge du PC ?)".into()
            }
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
                "son usage étendu ne permet pas de l'utiliser comme serveur".into()
            }
            CertificateError::BadSignature => {
                "sa signature est invalide (autorité de certification (ca) du profil différente de celle du serveur ?)"
                    .into()
            }
            CertificateError::UnsupportedSignatureAlgorithmContext { .. } => {
                "son algorithme de signature n'est pas pris en charge (SHA-1, MD5 ?)".into()
            }
            other => format!("{other:?}"),
        },
        other => other.to_string(),
    }
}

impl ServerCertVerifier for OvpnVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fail = |why: String| self.refuse(format!("Certificat du serveur OpenVPN refusé : {why}"));
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity).map_err(|e| fail(chain_error(&e)))?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(&parsed, &self.roots, intermediates, now, self.algs.all)
            .map_err(|e| fail(chain_error(&e)))?;
        let info = cert_info(end_entity.as_ref()).ok_or_else(|| fail("certificat illisible".into()))?;
        if self.remote_cert_tls && !info.server_usage() {
            return Err(fail(
                "ce n'est pas un certificat de serveur (remote-cert-tls server : usage étendu serverAuth absent)".into(),
            ));
        }
        if let Some((kind, name)) = &self.x509_name {
            let cn = info.cn.as_deref().unwrap_or("");
            let ok = match kind {
                X509NameType::Subject => info.subject == *name,
                X509NameType::Name => cn == name,
                X509NameType::NamePrefix => cn.starts_with(name.as_str()),
            };
            if !ok {
                return Err(fail(format!(
                    "son nom « {} » ne correspond pas à verify-x509-name « {name} »",
                    if *kind == X509NameType::Subject { info.subject.as_str() } else { cn }
                )));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

// ------------------------------------------------------------------ lecture de certificat (DER)

/// Élément DER : (étiquette, contenu, suite). Étiquettes sur un octet, longueur sur 4 octets au plus.
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, r) = b.split_first()?;
    let (&l0, mut r) = r.split_first()?;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || r.len() < n {
            return None;
        }
        let l = r[..n].iter().fold(0usize, |a, &x| a << 8 | x as usize);
        r = &r[n..];
        l
    };
    if r.len() < len {
        return None;
    }
    Some((tag, &r[..len], &r[len..]))
}

const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_NS_CERT_TYPE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// Ce qu'OpenVPN vérifie dans le certificat du serveur.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// Sujet au format d'OpenVPN (`C=FR, O=Exemple, CN=serveur`), dans l'ordre du certificat.
    pub subject: String,
    pub cn: Option<String>,
    /// Usage étendu (EKU) présent, et s'il contient serverAuth.
    pub eku: Option<bool>,
    /// nsCertType « SSL server ».
    pub ns_server: bool,
}

impl CertInfo {
    /// `remote-cert-tls server` (ou `ns-cert-type server`).
    pub fn server_usage(&self) -> bool {
        self.eku == Some(true) || self.ns_server
    }
}

fn oid_name(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x2a] => "GN",
        [0x55, 0x04, 0x04] => "SN",
        [0x55, 0x04, 0x0c] => "title",
        [0x55, 0x04, 0x29] => "name",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01] => "UID",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        _ => return None,
    })
}

/// OID en notation pointée (attributs inconnus).
fn oid_dotted(oid: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for &b in oid {
        v = v.saturating_mul(128) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = (v / 40).min(2);
                parts.push(first);
                parts.push(v - first * 40);
            } else {
                parts.push(v);
            }
            v = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

fn der_text(tag: u8, v: &[u8]) -> String {
    match tag {
        // BMPString (UTF-16 BE)
        0x1e => {
            let u: Vec<u16> = v.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16_lossy(&u)
        }
        // T61String : Latin-1 en pratique
        0x14 => v.iter().map(|&b| b as char).collect(),
        // UniversalString (UTF-32 BE)
        0x1c => v
            .as_chunks::<4>()
            .0
            .iter()
            .filter_map(|c| char::from_u32(u32::from_be_bytes(*c)))
            .collect(),
        _ => String::from_utf8_lossy(v).into_owned(),
    }
}

/// Sujet, CN, usage étendu et nsCertType d'un certificat X.509 (DER). `None` si illisible.
pub fn cert_info(cert: &[u8]) -> Option<CertInfo> {
    let (0x30, cert, _) = der(cert)? else { return None };
    let (0x30, tbs, _) = der(cert)? else { return None };
    let mut r = tbs;
    if r.first() == Some(&0xa0) {
        r = der(r)?.2; // version
    }
    for _ in 0..4 {
        r = der(r)?.2; // numéro de série, algorithme, émetteur, validité
    }
    let (0x30, subject, r) = der(r)? else { return None };
    let mut r = der(r)?.2; // clé publique
    let mut info = CertInfo::default();

    let mut parts = Vec::new();
    let mut rdns = subject;
    while !rdns.is_empty() {
        let (_, set, rest) = der(rdns)?;
        rdns = rest;
        let mut atvs = set;
        let mut rdn = Vec::new();
        while !atvs.is_empty() {
            let (_, atv, rest) = der(atvs)?;
            atvs = rest;
            let (0x06, oid, rest) = der(atv)? else { return None };
            let (tag, value, _) = der(rest)?;
            let text = der_text(tag, value);
            if oid == OID_CN {
                info.cn = Some(text.clone());
            }
            let name = oid_name(oid).map(str::to_string).unwrap_or_else(|| oid_dotted(oid));
            rdn.push(format!("{name}={text}"));
        }
        parts.push(rdn.join(" + "));
    }
    info.subject = parts.join(", ");

    while !r.is_empty() {
        let (tag, content, rest) = der(r)?;
        r = rest;
        if tag != 0xa3 {
            continue;
        }
        let (0x30, mut exts, _) = der(content)? else { return None };
        while !exts.is_empty() {
            let (_, ext, rest) = der(exts)?;
            exts = rest;
            let (0x06, oid, mut e) = der(ext)? else { return None };
            if e.first() == Some(&0x01) {
                e = der(e)?.2; // critique
            }
            let (0x04, value, _) = der(e)? else { continue };
            if oid == OID_EKU {
                let (0x30, mut list, _) = der(value)? else { continue };
                let mut server = false;
                while !list.is_empty() {
                    let (_, o, rest) = der(list)?;
                    list = rest;
                    server |= o == OID_SERVER_AUTH;
                }
                info.eku = Some(server);
            } else if oid == OID_NS_CERT_TYPE
                && let Some((0x03, bits, _)) = der(value)
            {
                // BIT STRING : octet des bits inutilisés, puis bit 1 = « SSL server »
                info.ns_server = bits.get(1).is_some_and(|b| b & 0x40 != 0);
            }
        }
    }
    Some(info)
}

// ------------------------------------------------------------------ key-method 2

fn write_string(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&((b.len() + 1).min(u16::MAX as usize) as u16).to_be_bytes());
    out.extend_from_slice(b);
    out.push(0);
}

/// Message key-method 2 du client : `0(4) | 2 | aléas(112) | options | identifiant | mot de passe
/// | peer-info`, chaînes préfixées de leur longueur (zéro final compris) ; chaînes vides si pas
/// d'identifiant.
pub fn km2_client_message(
    src: &ClientKeySource,
    options: &str,
    credentials: Option<(&str, &str)>,
    peer_info: &str,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(256 + options.len() + peer_info.len()));
    out.extend_from_slice(&[0, 0, 0, 0, 2]);
    out.extend_from_slice(&src.to_wire());
    write_string(&mut out, options);
    match credentials {
        Some((u, p)) => {
            write_string(&mut out, u);
            write_string(&mut out, p);
        }
        None => out.extend_from_slice(&[0, 0, 0, 0]),
    }
    write_string(&mut out, peer_info);
    out
}

/// Réponse key-method 2 du serveur (sans les chaînes vides qui suivent ses options).
#[derive(Clone)]
pub struct ServerKm2 {
    pub src: ServerKeySource,
    pub options: String,
}

/// Lit la réponse key-method 2 au début de `b` : `Ok(None)` s'il manque des octets, sinon le
/// message et le nombre d'octets lus.
pub fn parse_server_km2(b: &[u8]) -> Result<Option<(ServerKm2, usize)>, String> {
    const HEAD: usize = 4 + 1 + ServerKeySource::WIRE_LEN;
    if b.len() < HEAD + 2 {
        return Ok(None);
    }
    if b[..4] != [0, 0, 0, 0] || b[4] & 0x0f != 2 {
        return Err("Réponse OpenVPN inattendue (key-method 2 attendu) : serveur trop ancien ?".into());
    }
    let src = ServerKeySource::from_wire(&b[5..HEAD])?;
    let n = u16::from_be_bytes([b[HEAD], b[HEAD + 1]]) as usize;
    if b.len() < HEAD + 2 + n {
        return Ok(None);
    }
    let raw = &b[HEAD + 2..HEAD + 2 + n];
    let options = String::from_utf8_lossy(raw.strip_suffix(&[0]).unwrap_or(raw)).into_owned();
    Ok(Some((ServerKm2 { src, options }, HEAD + 2 + n)))
}

// ------------------------------------------------------------------ options poussées

/// `topology` poussée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    Net30,
    P2p,
    Subnet,
}

/// Options utiles d'un PUSH_REPLY (le reste est ignoré).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PushOptions {
    /// `ifconfig` : adresse locale, puis masque (topology subnet) ou adresse distante (net30/p2p).
    pub ifconfig: Option<(Ipv4Addr, Ipv4Addr)>,
    pub ifconfig_ipv6: Option<(Ipv6Addr, u8)>,
    pub topology: Option<Topology>,
    /// `route` / `route-ipv6` passant par le VPN (réseau, préfixe).
    pub routes: Vec<(IpAddr, u8)>,
    pub route_gateway: Option<Ipv4Addr>,
    /// `redirect-gateway` / `redirect-private` avec def1… : tout passe par le VPN.
    pub redirect_gateway: bool,
    pub dns: Vec<IpAddr>,
    /// `dhcp-option DOMAIN` / `DOMAIN-SEARCH` / `ADAPTER_DOMAIN_SUFFIX`.
    pub domains: Vec<String>,
    pub peer_id: Option<u32>,
    pub cipher: Option<String>,
    pub auth: Option<String>,
    pub ping: Option<u32>,
    pub ping_restart: Option<u32>,
    /// `ping-exit` : comme ping-restart, mais sans reconnexion.
    pub ping_exit: Option<u32>,
    /// `key-derivation tls-ekm` ou `protocol-flags … tls-ekm`.
    pub tls_ekm: bool,
    pub tun_mtu: Option<u16>,
    /// `comp-lzo` / `compress` poussés (cadrage seulement : Escale ne compresse jamais).
    pub compression: Option<Compression>,
}

/// Masque réseau → préfixe (`None` si les bits ne sont pas contigus).
pub fn mask_prefix(m: Ipv4Addr) -> Option<u8> {
    let v = u32::from(m);
    let p = v.leading_ones();
    (v.checked_shl(p).unwrap_or(0) == 0).then_some(p as u8)
}

fn ipv6_cidr(s: &str) -> Option<(Ipv6Addr, u8)> {
    let (a, p) = s.split_once('/').unwrap_or((s, "128"));
    let p: u8 = p.parse().ok().filter(|p| *p <= 128)?;
    Some((a.parse().ok()?, p))
}

/// Ajoute au résultat les options d'un message `PUSH_REPLY,…` (sans le préfixe). Renvoie vrai si
/// d'autres morceaux suivent (`push-continuation 2`).
pub fn parse_push_reply(body: &str, o: &mut PushOptions) -> Result<bool, String> {
    let mut more = false;
    for opt in body.split(',') {
        let words: Vec<&str> = opt.split_whitespace().map(|w| w.trim_matches(|c| c == '"' || c == '\'')).collect();
        let Some((&name, args)) = words.split_first() else { continue };
        let arg = |i: usize| args.get(i).copied();
        match name {
            "ifconfig" => {
                if let (Some(Ok(a)), Some(Ok(b))) = (arg(0).map(str::parse), arg(1).map(str::parse)) {
                    o.ifconfig = Some((a, b));
                }
            }
            "ifconfig-ipv6" => o.ifconfig_ipv6 = arg(0).and_then(ipv6_cidr),
            "topology" => {
                o.topology = match arg(0) {
                    Some("subnet") => Some(Topology::Subnet),
                    Some("p2p") => Some(Topology::P2p),
                    Some("net30") => Some(Topology::Net30),
                    _ => o.topology,
                }
            }
            "route" => {
                // « route réseau [masque] [passerelle] [métrique] » ; net_gateway = hors VPN
                if arg(2) == Some("net_gateway") {
                    continue;
                }
                let Some(Ok(net)) = arg(0).map(str::parse::<Ipv4Addr>) else { continue };
                let prefix = match arg(1) {
                    None | Some("default") => Some(32),
                    Some(m) => m.parse().ok().and_then(mask_prefix),
                };
                if let Some(p) = prefix {
                    let net = Ipv4Addr::from(u32::from(net) & u32::MAX.checked_shl(32 - p as u32).unwrap_or(0));
                    o.routes.push((IpAddr::V4(net), p));
                }
            }
            "route-ipv6" => {
                if arg(1) == Some("net_gateway") {
                    continue;
                }
                if let Some((net, p)) = arg(0).and_then(ipv6_cidr) {
                    o.routes.push((IpAddr::V6(net), p));
                }
            }
            "route-gateway" => o.route_gateway = arg(0).and_then(|a| a.parse().ok()),
            "redirect-gateway" | "redirect-private" => {
                // « redirect-gateway !ipv4 ipv6 » ne détourne que l'IPv6 : tout reste plus simple
                // à traiter comme « tout passe par le VPN » côté Escale (seules ses connexions y vont)
                o.redirect_gateway = true;
            }
            "dhcp-option" => match (arg(0).map(str::to_ascii_uppercase).as_deref(), arg(1)) {
                (Some("DNS" | "DNS6"), Some(a)) => {
                    if let Ok(ip) = a.parse::<IpAddr>()
                        && !o.dns.contains(&ip)
                    {
                        o.dns.push(ip);
                    }
                }
                (Some("DOMAIN" | "DOMAIN-SEARCH" | "ADAPTER_DOMAIN_SUFFIX"), Some(d)) => {
                    let d = d.trim_matches('.').to_string();
                    if !d.is_empty() && !o.domains.contains(&d) {
                        o.domains.push(d);
                    }
                }
                _ => {}
            },
            "peer-id" => o.peer_id = arg(0).and_then(|a| a.parse().ok()).filter(|p| *p < packet::PEER_ID_UNDEF),
            "cipher" => o.cipher = arg(0).map(str::to_string),
            "auth" => o.auth = arg(0).map(str::to_string),
            "ping" => o.ping = arg(0).and_then(|a| a.parse().ok()),
            "ping-restart" => o.ping_restart = arg(0).and_then(|a| a.parse().ok()),
            "ping-exit" => o.ping_exit = arg(0).and_then(|a| a.parse().ok()),
            "key-derivation" => o.tls_ekm |= arg(0) == Some("tls-ekm"),
            "protocol-flags" => o.tls_ekm |= args.contains(&"tls-ekm"),
            "tun-mtu" => o.tun_mtu = arg(0).and_then(|a| a.parse().ok()),
            "comp-lzo" | "compress" => o.compression = Some(Compression::from_directive(name, arg(0))?),
            "push-continuation" => more = arg(0) == Some("2"),
            _ => {}
        }
    }
    Ok(more)
}

// ------------------------------------------------------------------ session

/// Ce que la session apprend, à lire par `poll_event`.
pub enum Event {
    /// Texte d'état pour l'interface (« Négociation TLS… »).
    Status(String),
    /// Première clé prête : options poussées et chiffrement négocié.
    Ready(Box<Negotiated>),
    /// Nouvelle clé après renégociation (même chiffrement) : l'émission passe sur `key_id`.
    Rekey { key_id: u8, key2: Box<Key2> },
    /// Session perdue. `retry` : une reconnexion peut réussir (RESTART, délai, renégociation
    /// ratée) ; faux pour un refus définitif (identification, certificat, chiffrement).
    Failed { message: String, retry: bool },
}

/// Résultat de la négociation initiale.
pub struct Negotiated {
    pub key_id: u8,
    pub key2: Key2,
    pub cipher: DataCipher,
    pub digest: Digest,
    pub options: PushOptions,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Réinitialisation envoyée, en attente d'accusé (et de la réponse du serveur).
    Reset,
    /// Négociation TLS, puis échange key-method 2.
    Tls,
    /// Réponse key-method 2 reçue : messages texte (PUSH_REPLY…).
    Active,
}

/// Une session de clé (`key_state` d'OpenVPN) : sa propre couche fiable et sa session TLS.
struct KeyState {
    key_id: u8,
    rel: Reliable,
    tls: Option<ClientConnection>,
    phase: Phase,
    started: Instant,
    client_src: Option<ClientKeySource>,
    server: Option<ServerKm2>,
    km2_sent: bool,
    /// Octets TLS reçus avant la création de la session TLS.
    tls_in: Vec<u8>,
    /// Clair reçu du serveur, pas encore interprété.
    plain: Zeroizing<Vec<u8>>,
    /// Chaînes vides suivant les options du serveur (identifiant, mot de passe, peer-info).
    skip_strings: u8,
    /// Fin de vie (ancienne clé après renégociation).
    expires: Option<Instant>,
}

impl KeyState {
    fn new(key_id: u8, reset_opcode: u8, max_payload: usize, now: Instant) -> Self {
        let mut rel = Reliable::new(ReliableConfig { max_payload, ..Default::default() });
        rel.send(reset_opcode, &[]);
        Self {
            key_id,
            rel,
            tls: None,
            phase: Phase::Reset,
            started: now,
            client_src: None,
            server: None,
            km2_sent: false,
            tls_in: Vec::new(),
            plain: Zeroizing::new(Vec::new()),
            skip_strings: 0,
            expires: None,
        }
    }
}

/// Erreur interne : définitive ou non.
struct Fail {
    message: String,
    retry: bool,
}

impl Fail {
    fn fatal(m: impl Into<String>) -> Self {
        Self { message: m.into(), retry: false }
    }
    fn retry(m: impl Into<String>) -> Self {
        Self { message: m.into(), retry: true }
    }
}

/// Session de contrôle d'un client OpenVPN (une par connexion au serveur).
pub struct ControlSession {
    setup: Arc<ClientSetup>,
    sid: [u8; 8],
    remote_sid: Option<[u8; 8]>,
    wrap: Wrap,
    max_payload: usize,
    keys: Vec<KeyState>,
    /// Clé du canal de données en service.
    active: Option<u8>,
    /// Dernier key_id attribué (1 à 7 après la clé initiale 0).
    last_key_id: u8,
    /// Options poussées en cours d'assemblage (`push-continuation`).
    push: PushOptions,
    negotiated: Option<(DataCipher, bool)>,
    push_next: Option<Instant>,
    reneg_at: Option<Instant>,
    out: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    dead: bool,
}

fn net_time() -> u32 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(1)
}

impl ControlSession {
    /// Nouvelle session : la réinitialisation (HARD_RESET_CLIENT_V2) part au premier `poll_net`.
    pub fn new(setup: Arc<ClientSetup>, now: Instant) -> Result<Self, String> {
        let mut sid = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut sid)
            .map_err(|_| "Générateur aléatoire indisponible".to_string())?;
        let wrap = setup.new_wrap()?;
        let max_payload = TLS_MTU - CONTROL_HEADER - wrap.overhead();
        let mut s = Self {
            setup,
            sid,
            remote_sid: None,
            wrap,
            max_payload,
            keys: vec![KeyState::new(0, P_CONTROL_HARD_RESET_CLIENT_V2, max_payload, now)],
            active: None,
            last_key_id: 0,
            push: PushOptions::default(),
            negotiated: None,
            push_next: None,
            reneg_at: None,
            out: VecDeque::new(),
            events: VecDeque::new(),
            dead: false,
        };
        s.events.push_back(Event::Status("Connexion au serveur OpenVPN…".into()));
        s.flush(now);
        Ok(s)
    }

    /// Notre identifiant de session.
    pub fn session_id(&self) -> [u8; 8] {
        self.sid
    }

    /// Paquet de contrôle prêt à envoyer (sans préfixe de longueur TCP).
    pub fn poll_net(&mut self) -> Option<Vec<u8>> {
        self.out.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// La session a échoué (un `Event::Failed` a été émis) : plus rien ne sort.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    fn fail(&mut self, f: Fail) {
        if !self.dead {
            self.dead = true;
            self.out.clear();
            self.events.push_back(Event::Failed { message: f.message, retry: f.retry });
        }
    }

    /// Paquet de contrôle reçu (opcode de contrôle, sans préfixe TCP). Renvoie vrai s'il est
    /// authentique et appartient à cette session.
    pub fn input(&mut self, raw: &[u8], now: Instant) -> bool {
        if self.dead {
            return false;
        }
        let Ok(pkt) = self.wrap.unwrap(raw) else { return false };
        // la réinitialisation du serveur doit acquitter la nôtre (notre session y est nommée) avant
        // que sa session soit retenue : une réponse tardive à une tentative précédente, rejouée ou
        // forgée ne verrouille pas la session sur un mauvais identifiant
        if pkt.remote_session_id.is_some_and(|r| r != self.sid) {
            return false;
        }
        match self.remote_sid {
            None if pkt.opcode == P_CONTROL_HARD_RESET_SERVER_V2 && pkt.key_id == 0 => {
                if pkt.remote_session_id != Some(self.sid) {
                    return false;
                }
                self.remote_sid = Some(pkt.session_id);
                self.events.push_back(Event::Status("Négociation TLS…".into()));
            }
            Some(r) if r == pkt.session_id => {}
            _ => return false,
        }
        let idx = match self.keys.iter().position(|k| k.key_id == pkt.key_id) {
            Some(i) => i,
            None if pkt.opcode == P_CONTROL_SOFT_RESET_V1 && self.active.is_some() && pkt.key_id != 0 => {
                // renégociation demandée par le serveur : nouvelle clé, en réponse à la sienne
                self.keys.retain(|k| Some(k.key_id) == self.active);
                self.keys.push(KeyState::new(pkt.key_id, P_CONTROL_SOFT_RESET_V1, self.max_payload, now));
                self.last_key_id = pkt.key_id;
                self.keys.len() - 1
            }
            None => return true,
        };
        let ks = &mut self.keys[idx];
        ks.rel.on_acks(&pkt.acks);
        if pkt.opcode != P_ACK_V1 {
            ks.rel.on_packet(pkt.packet_id.unwrap_or(0), pkt.opcode, &pkt.payload);
        }
        while let Some((op, payload)) = ks.rel.recv() {
            if op == P_CONTROL_V1 {
                ks.tls_in.extend_from_slice(&payload);
            }
        }
        // pair qui envoie du TLS sans jamais acquitter notre réinitialisation : mémoire bornée
        if ks.tls_in.len() > MAX_TLS_IN {
            self.fail(Fail::retry("Canal de contrôle OpenVPN : trop de données TLS en attente"));
            return true;
        }
        if let Err(f) = self.process(idx, now) {
            self.fail(f);
            return true;
        }
        self.flush(now);
        true
    }

    /// Minuteries : réémissions, PUSH_REQUEST, délais de négociation, renégociation.
    pub fn tick(&mut self, now: Instant) {
        if self.dead {
            return;
        }
        if let Err(f) = self.timers(now) {
            self.fail(f);
            return;
        }
        self.flush(now);
    }

    /// Demande une renégociation (compteur de paquets bientôt épuisé, `reneg-sec`).
    pub fn renegotiate(&mut self, now: Instant) {
        if self.dead || self.active.is_none() || self.keys.iter().any(|k| k.phase != Phase::Active) {
            return;
        }
        let key_id = if self.last_key_id >= 7 { 1 } else { self.last_key_id + 1 };
        self.last_key_id = key_id;
        self.keys.retain(|k| Some(k.key_id) == self.active);
        self.keys.push(KeyState::new(key_id, P_CONTROL_SOFT_RESET_V1, self.max_payload, now));
        self.flush(now);
    }

    fn timers(&mut self, now: Instant) -> Result<(), Fail> {
        // anciennes clés arrivées en fin de vie
        let active = self.active;
        self.keys.retain(|k| Some(k.key_id) == active || k.expires.is_none_or(|t| now < t));
        for i in 0..self.keys.len() {
            let ks = &self.keys[i];
            if ks.phase != Phase::Active && now.saturating_duration_since(ks.started) >= HAND_WINDOW {
                return Err(if self.active.is_some() {
                    Fail::retry("La renégociation des clés OpenVPN n'a pas abouti")
                } else {
                    Fail::retry("La négociation avec le serveur OpenVPN n'a pas abouti dans le délai")
                });
            }
            self.process(i, now)?;
        }
        if self.active.is_none()
            && self.push_next.is_some_and(|t| now >= t)
            && let Some(i) = self.keys.iter().position(|k| k.key_id == 0 && k.phase == Phase::Active)
        {
            self.send_text(i, "PUSH_REQUEST")?;
            self.push_next = Some(now + PUSH_RETRY);
        }
        if self.reneg_at.is_some_and(|t| now >= t) {
            self.reneg_at = self.setup.reneg.map(|d| now + d);
            self.renegotiate(now);
        }
        Ok(())
    }

    /// Fait avancer une session de clé : démarrage TLS, octets TLS, key-method 2, messages texte.
    fn process(&mut self, idx: usize, now: Instant) -> Result<(), Fail> {
        let setup = self.setup.clone();
        let ks = &mut self.keys[idx];
        if let Some(e) = ks.rel.failed() {
            return Err(Fail::retry(e));
        }
        // notre réinitialisation est acquittée et la session du serveur connue : TLS démarre
        if ks.phase == Phase::Reset && self.remote_sid.is_some() && ks.rel.pending_count() == 0 {
            let name = ServerName::try_from("openvpn.server")
                .map_err(|_| Fail::fatal("Nom TLS invalide"))?;
            let tls = ClientConnection::new(setup.tls.clone(), name)
                .map_err(|e| Fail::fatal(format!("Session TLS impossible : {e}")))?;
            ks.tls = Some(tls);
            ks.phase = Phase::Tls;
        }
        let Some(tls) = ks.tls.as_mut() else { return Ok(()) };

        // octets TLS reçus
        let input = std::mem::take(&mut ks.tls_in);
        let mut rd = &input[..];
        let mut buf = Zeroizing::new([0u8; 4096]);
        loop {
            if !rd.is_empty() {
                match tls.read_tls(&mut rd) {
                    Ok(_) => {}
                    Err(e) => return Err(Fail::retry(format!("Canal de contrôle OpenVPN : {e}"))),
                }
            }
            if let Err(e) = tls.process_new_packets() {
                // l'alerte part quand même vers le serveur
                let mut alert = Vec::new();
                while tls.wants_write() && tls.write_tls(&mut alert).is_ok_and(|n| n > 0) {}
                if !alert.is_empty() {
                    ks.rel.send(P_CONTROL_V1, &alert);
                }
                let verify = setup.verify_error.lock().unwrap_or_else(|e| e.into_inner()).take();
                return Err(Fail::fatal(verify.unwrap_or_else(|| tls_error(&e))));
            }
            loop {
                match tls.reader().read(&mut buf[..]) {
                    Ok(0) => return Err(Fail::retry("Le serveur OpenVPN a fermé la session TLS")),
                    Ok(n) => ks.plain.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            if rd.is_empty() {
                break;
            }
        }

        // TLS établi : envoi des aléas, des options et de l'identifiant
        if !tls.is_handshaking() && !ks.km2_sent {
            let src = ClientKeySource::generate().map_err(Fail::fatal)?;
            let creds = setup.credentials.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
            let msg = km2_client_message(&src, &setup.options_string, creds, &setup.peer_info);
            tls.writer()
                .write_all(&msg)
                .map_err(|e| Fail::retry(format!("Canal de contrôle OpenVPN : {e}")))?;
            ks.client_src = Some(src);
            ks.km2_sent = true;
            if ks.key_id == 0 && self.active.is_none() {
                self.events.push_back(Event::Status("Authentification…".into()));
            }
        }
        let mut out = Vec::new();
        while tls.wants_write() {
            match tls.write_tls(&mut out) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(Fail::retry(format!("Canal de contrôle OpenVPN : {e}"))),
            }
        }
        if !out.is_empty() {
            ks.rel.send(P_CONTROL_V1, &out);
        }
        self.read_plain(idx, now)
    }

    /// Interprète le clair reçu : réponse key-method 2, puis messages texte terminés par un zéro.
    fn read_plain(&mut self, idx: usize, now: Instant) -> Result<(), Fail> {
        let ks = &mut self.keys[idx];
        if ks.server.is_none() {
            let Some((km2, n)) = parse_server_km2(&ks.plain).map_err(Fail::fatal)? else { return Ok(()) };
            ks.plain.drain(..n);
            ks.server = Some(km2);
            ks.skip_strings = 3;
            ks.phase = Phase::Active;
            if self.active.is_none() {
                // clé initiale : les options (et la dérivation des clés) arrivent par PUSH_REPLY
                self.events.push_back(Event::Status("Configuration…".into()));
                self.send_text(idx, "PUSH_REQUEST")?;
                self.push_next = Some(now + PUSH_RETRY);
            } else {
                let (_, ekm) = self.negotiated.ok_or_else(|| Fail::retry("Renégociation OpenVPN inattendue"))?;
                let key2 = self.derive(idx, ekm)?;
                let ks = &mut self.keys[idx];
                let key_id = ks.key_id;
                let old = self.active.replace(key_id);
                for k in self.keys.iter_mut().filter(|k| Some(k.key_id) == old) {
                    k.expires = Some(now + HAND_WINDOW);
                }
                self.reneg_at = self.setup.reneg.map(|d| now + d);
                self.events.push_back(Event::Rekey { key_id, key2: Box::new(key2) });
            }
        }
        loop {
            let ks = &mut self.keys[idx];
            // chaînes vides qui suivent les options du serveur (un message texte commence par une lettre)
            while ks.skip_strings > 0 {
                match ks.plain.first() {
                    None => return Ok(()),
                    Some(&b) if b >= 0x10 => ks.skip_strings = 0,
                    Some(_) => {
                        if ks.plain.len() < 2 {
                            return Ok(());
                        }
                        let n = u16::from_be_bytes([ks.plain[0], ks.plain[1]]) as usize;
                        if ks.plain.len() < 2 + n {
                            return Ok(());
                        }
                        ks.plain.drain(..2 + n);
                        ks.skip_strings -= 1;
                    }
                }
            }
            let Some(end) = ks.plain.iter().position(|&b| b == 0) else {
                if ks.plain.len() > MAX_TEXT {
                    return Err(Fail::retry("Message du serveur OpenVPN trop long"));
                }
                return Ok(());
            };
            let msg = Zeroizing::new(String::from_utf8_lossy(&ks.plain[..end]).into_owned());
            ks.plain.drain(..=end);
            self.on_text(idx, msg.trim())?;
        }
    }

    /// Message texte du serveur (PUSH_REPLY, AUTH_FAILED, RESTART…).
    fn on_text(&mut self, idx: usize, msg: &str) -> Result<(), Fail> {
        let (cmd, rest) = msg.split_once(',').unwrap_or((msg, ""));
        match cmd {
            "" => Ok(()),
            "PUSH_REPLY" => {
                if self.active.is_some() {
                    return Ok(()); // réponse en double (PUSH_REQUEST réémis)
                }
                let more = parse_push_reply(rest, &mut self.push).map_err(Fail::fatal)?;
                if more {
                    return Ok(());
                }
                let options = std::mem::take(&mut self.push);
                let (cipher, digest) = self.setup.negotiate(&options).map_err(Fail::fatal)?;
                let key2 = self.derive(idx, options.tls_ekm)?;
                let key_id = self.keys[idx].key_id;
                self.active = Some(key_id);
                self.negotiated = Some((cipher, options.tls_ekm));
                self.push_next = None;
                self.reneg_at = self.setup.reneg.map(|d| self.keys[idx].started + d);
                self.events.push_back(Event::Ready(Box::new(Negotiated { key_id, key2, cipher, digest, options })));
                Ok(())
            }
            "AUTH_FAILED" => {
                let reason = rest.trim();
                let detail = if reason.is_empty() { String::new() } else { format!(" ({reason})") };
                Err(Fail::fatal(if reason.starts_with("CRV1") {
                    "Le serveur OpenVPN demande une réponse à un défi (challenge/response) : non pris en charge par Escale"
                        .to_string()
                } else if self.setup.credentials.is_some() {
                    format!("Identifiant ou mot de passe refusé par le serveur OpenVPN{detail}")
                } else {
                    format!(
                        "Le serveur OpenVPN a refusé la connexion{detail} : demande-t-il un identifiant (auth-user-pass) ?"
                    )
                }))
            }
            "AUTH_PENDING" => Err(Fail::fatal(
                "Le serveur OpenVPN demande une authentification supplémentaire (AUTH_PENDING : page web, code à usage \
                 unique…) : non prise en charge par Escale",
            )),
            "RESTART" => Err(Fail::retry(format!(
                "Le serveur OpenVPN a demandé une reconnexion{}",
                if rest.trim().is_empty() { String::new() } else { format!(" ({})", rest.trim()) }
            ))),
            "HALT" | "EXIT" => Err(Fail::retry("Le serveur OpenVPN a mis fin à la session")),
            _ => Ok(()), // INFO, INFO_PRE…
        }
    }

    /// Clés du canal de données de la session `idx` : exportateur TLS ou PRF d'OpenVPN.
    fn derive(&mut self, idx: usize, ekm: bool) -> Result<Key2, Fail> {
        let remote = self.remote_sid.unwrap_or_default();
        let ks = &mut self.keys[idx];
        let bad = || Fail::retry("Échange de clés OpenVPN incomplet");
        if ekm {
            let tls = ks.tls.as_ref().ok_or_else(bad)?;
            let out = tls
                .export_keying_material(Zeroizing::new([0u8; data::KEY2_LEN]), data::EKM_LABEL, None)
                .map_err(|e| Fail::retry(format!("Export des clés TLS impossible : {e}")))?;
            ks.client_src = None;
            data::key2_from_ekm(&out[..]).map_err(Fail::retry)
        } else {
            let client = ks.client_src.take().ok_or_else(bad)?;
            let server = ks.server.as_ref().ok_or_else(bad)?;
            Ok(data::derive_key2_prf(&client, &server.src, &self.sid, &remote))
        }
    }

    /// Envoie un message texte (terminé par un zéro) sur la session TLS `idx`.
    fn send_text(&mut self, idx: usize, msg: &str) -> Result<(), Fail> {
        let ks = &mut self.keys[idx];
        let Some(tls) = ks.tls.as_mut() else { return Ok(()) };
        let mut m = msg.as_bytes().to_vec();
        m.push(0);
        tls.writer().write_all(&m).map_err(|e| Fail::retry(format!("Canal de contrôle OpenVPN : {e}")))?;
        let mut out = Vec::new();
        while tls.wants_write() {
            match tls.write_tls(&mut out) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(Fail::retry(format!("Canal de contrôle OpenVPN : {e}"))),
            }
        }
        if !out.is_empty() {
            ks.rel.send(P_CONTROL_V1, &out);
        }
        Ok(())
    }

    /// Paquets de contrôle à émettre (nouveaux, réémissions, accusés seuls).
    fn flush(&mut self, now: Instant) {
        let mut failed = None;
        for ks in &mut self.keys {
            while let Some(o) = ks.rel.poll_transmit(now) {
                let pkt = ControlPacket {
                    opcode: o.opcode,
                    key_id: ks.key_id,
                    session_id: self.sid,
                    remote_session_id: (!o.acks.is_empty()).then_some(self.remote_sid.unwrap_or_default()),
                    acks: o.acks,
                    packet_id: Some(o.packet_id),
                    payload: o.payload,
                };
                self.out.push_back(self.wrap.wrap(&pkt, net_time()));
            }
            while let Some(acks) = ks.rel.take_acks() {
                let pkt = ControlPacket {
                    opcode: P_ACK_V1,
                    key_id: ks.key_id,
                    session_id: self.sid,
                    acks,
                    remote_session_id: Some(self.remote_sid.unwrap_or_default()),
                    packet_id: None,
                    payload: Vec::new(),
                };
                self.out.push_back(self.wrap.wrap(&pkt, net_time()));
            }
            if failed.is_none() {
                failed = ks.rel.failed();
            }
        }
        if let Some(e) = failed {
            self.fail(Fail::retry(e));
        }
    }
}

/// Erreur TLS en clair (alerte du serveur, protocole…).
fn tls_error(e: &rustls::Error) -> String {
    use rustls::AlertDescription as A;
    match e {
        rustls::Error::AlertReceived(a) => match a {
            A::BadCertificate | A::CertificateUnknown | A::UnknownCA | A::CertificateRequired | A::AccessDenied => {
                format!("Le serveur OpenVPN a refusé le certificat client ({a:?})")
            }
            A::HandshakeFailure | A::ProtocolVersion | A::InsufficientSecurity => format!(
                "Négociation TLS refusée par le serveur OpenVPN ({a:?}) : versions ou suites de chiffrement \
                 incompatibles (TLS 1.2 minimum, suites ECDHE)"
            ),
            other => format!("Le serveur OpenVPN a interrompu la négociation TLS ({other:?})"),
        },
        rustls::Error::PeerIncompatible(p) => {
            format!("Serveur OpenVPN incompatible (TLS 1.2 minimum, suites ECDHE) : {p:?}")
        }
        other => format!("Négociation TLS avec le serveur OpenVPN impossible : {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_prefixes() {
        assert_eq!(mask_prefix("255.255.255.0".parse().unwrap()), Some(24));
        assert_eq!(mask_prefix("255.255.255.255".parse().unwrap()), Some(32));
        assert_eq!(mask_prefix("0.0.0.0".parse().unwrap()), Some(0));
        assert_eq!(mask_prefix("255.0.255.0".parse().unwrap()), None);
        assert_eq!(mask_prefix("10.8.0.5".parse().unwrap()), None);
    }

    #[test]
    fn push_reply_is_parsed() {
        // PUSH_REPLY réel du serveur de test A (OpenVPN 2.6.20)
        let body = "route 192.168.100.0 255.255.255.0,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN escale.test,\
                    route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.8.0.2 255.255.255.0,\
                    peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500";
        let mut o = PushOptions::default();
        assert!(!parse_push_reply(body, &mut o).unwrap());
        assert_eq!(o.routes, vec![("192.168.100.0".parse().unwrap(), 24)]);
        assert_eq!(o.dns, vec!["10.8.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(o.domains, vec!["escale.test".to_string()]);
        assert_eq!(o.route_gateway, Some("10.8.0.1".parse().unwrap()));
        assert_eq!(o.topology, Some(Topology::Subnet));
        assert_eq!((o.ping, o.ping_restart), (Some(10), Some(60)));
        assert_eq!(o.ifconfig, Some(("10.8.0.2".parse().unwrap(), "255.255.255.0".parse().unwrap())));
        assert_eq!(o.peer_id, Some(0));
        assert_eq!(o.cipher.as_deref(), Some("AES-256-GCM"));
        assert!(o.tls_ekm);
        assert_eq!(o.tun_mtu, Some(1500));
        assert!(!o.redirect_gateway);
        assert_eq!(o.compression, None);

        // morceaux successifs, IPv6, routes hors VPN, compression
        let mut o = PushOptions::default();
        assert!(
            parse_push_reply("route 10.1.2.3 255.255.0.0,route 1.2.3.4 255.255.255.255 net_gateway,push-continuation 2", &mut o)
                .unwrap()
        );
        assert!(
            !parse_push_reply(
                "ifconfig-ipv6 fd00::1000/64 fd00::1,route-ipv6 2001:db8::/32,dhcp-option DNS6 fd00::1,\
                 redirect-gateway def1 bypass-dhcp,comp-lzo no,key-derivation tls-ekm,peer-id 16777215,\
                 ifconfig 10.8.0.6 10.8.0.5,push-continuation 1",
                &mut o
            )
            .unwrap()
        );
        assert_eq!(o.routes, vec![("10.1.0.0".parse().unwrap(), 16), ("2001:db8::".parse().unwrap(), 32)]);
        assert_eq!(o.ifconfig_ipv6, Some(("fd00::1000".parse().unwrap(), 64)));
        assert_eq!(o.dns, vec!["fd00::1".parse::<IpAddr>().unwrap()]);
        assert!(o.redirect_gateway && o.tls_ekm);
        assert_eq!(o.compression, Some(Compression::Lzo));
        assert_eq!(o.peer_id, None, "PEER_ID_UNDEF = pas de peer-id");
        assert_eq!(o.ifconfig, Some(("10.8.0.6".parse().unwrap(), "10.8.0.5".parse().unwrap())));

        let mut o = PushOptions::default();
        assert!(parse_push_reply("compress lz4-v2x", &mut o).is_err());
        assert!(parse_push_reply("compress stub-v2,,  ,route,ifconfig x y,route-gateway", &mut o).is_ok());
        assert_eq!(o.compression, Some(Compression::V2));
    }

    #[test]
    fn km2_messages() {
        let src = ClientKeySource::generate().unwrap();
        let m = km2_client_message(&src, "V4,tls-client", Some(("théo", "s3cret")), "IV_VER=2.6.12\n");
        assert_eq!(&m[..5], &[0, 0, 0, 0, 2]);
        assert_eq!(&m[5..5 + 112], &src.to_wire()[..]);
        let mut r = &m[117..];
        let mut strings = Vec::new();
        while !r.is_empty() {
            let n = u16::from_be_bytes([r[0], r[1]]) as usize;
            strings.push(r[2..2 + n].to_vec());
            r = &r[2 + n..];
        }
        assert_eq!(
            strings,
            vec![b"V4,tls-client\0".to_vec(), "théo\0".as_bytes().to_vec(), b"s3cret\0".to_vec(), b"IV_VER=2.6.12\n\0".to_vec()]
        );
        // sans identifiant : deux chaînes vides (longueur 0, sans zéro final)
        let m = km2_client_message(&src, "o", None, "p");
        assert_eq!(&m[117..], &[0, 2, b'o', 0, 0, 0, 0, 0, 0, 2, b'p', 0]);

        // réponse du serveur, suivie de ses chaînes vides puis d'un message texte
        let server = ServerKeySource { random1: [7; 32], random2: [9; 32] };
        let mut b = vec![0, 0, 0, 0, 2];
        b.extend_from_slice(&server.to_wire());
        b.extend_from_slice(&[0, 4, b'V', b'4', b',', 0]);
        for cut in 0..b.len() {
            assert!(parse_server_km2(&b[..cut]).unwrap().is_none(), "{cut}");
        }
        let (km2, n) = parse_server_km2(&b).unwrap().unwrap();
        assert_eq!((km2.options.as_str(), n), ("V4,", b.len()));
        assert_eq!(km2.src.random2, [9; 32]);
        b[4] = 1;
        assert!(parse_server_km2(&b).is_err());
    }

    fn ca(cn: &str) -> (rcgen::CertificateParams, rcgen::KeyPair) {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        (p, rcgen::KeyPair::generate().unwrap())
    }

    fn leaf(cn: &str, eku: &[rcgen::ExtendedKeyUsagePurpose], issuer: &rcgen::Issuer<'_, &rcgen::KeyPair>) -> CertificateDer<'static> {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CountryName, "FR");
        p.distinguished_name.push(rcgen::DnType::OrganizationName, "Escale");
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.extended_key_usages = eku.to_vec();
        let k = rcgen::KeyPair::generate().unwrap();
        p.signed_by(&k, issuer).unwrap().der().clone()
    }

    #[test]
    fn server_certificate_checks() {
        use rcgen::ExtendedKeyUsagePurpose as E;
        let (cap, cak) = ca("Escale CA");
        let ca_cert = cap.self_signed(&cak).unwrap();
        let issuer = rcgen::Issuer::from_params(&cap, &cak);
        let server = leaf("vpn-server", &[E::ServerAuth], &issuer);
        let client = leaf("client1", &[E::ClientAuth], &issuer);
        let plain = leaf("plain", &[], &issuer);

        let info = cert_info(server.as_ref()).unwrap();
        assert_eq!(info.subject, "C=FR, O=Escale, CN=vpn-server");
        assert_eq!(info.cn.as_deref(), Some("vpn-server"));
        assert!(info.server_usage());
        assert_eq!(cert_info(client.as_ref()).unwrap().eku, Some(false));
        assert_eq!(cert_info(plain.as_ref()).unwrap().eku, None);
        assert!(cert_info(&server.as_ref()[..50]).is_none());
        for cut in 0..server.as_ref().len() {
            let _ = cert_info(&server.as_ref()[..cut]);
        }

        let verifier = |rct: bool, name: Option<(X509NameType, &str)>| {
            let mut roots = RootCertStore::empty();
            roots.add(ca_cert.der().clone()).unwrap();
            OvpnVerifier {
                roots,
                algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
                remote_cert_tls: rct,
                x509_name: name.map(|(k, n)| (k, n.to_string())),
                error: Arc::new(Mutex::new(None)),
            }
        };
        let name = ServerName::try_from("openvpn.server").unwrap();
        let check = |v: &OvpnVerifier, c: &CertificateDer<'_>| {
            let r = v.verify_server_cert(c, &[], &name, &[], UnixTime::now());
            r.map(|_| ()).map_err(|_| v.error.lock().unwrap().take().unwrap_or_default())
        };
        assert!(check(&verifier(true, None), &server).is_ok());
        assert!(check(&verifier(false, None), &plain).is_ok());
        let e = check(&verifier(true, None), &plain).unwrap_err();
        assert!(e.contains("remote-cert-tls"), "{e}");
        // un certificat client présenté par le « serveur » : refusé même sans remote-cert-tls (webpki)
        assert!(check(&verifier(false, None), &client).is_err());
        assert!(check(&verifier(true, Some((X509NameType::Name, "vpn-server"))), &server).is_ok());
        assert!(check(&verifier(true, Some((X509NameType::NamePrefix, "vpn-"))), &server).is_ok());
        assert!(check(&verifier(true, Some((X509NameType::Subject, "C=FR, O=Escale, CN=vpn-server"))), &server).is_ok());
        let e = check(&verifier(true, Some((X509NameType::Name, "vpn"))), &server).unwrap_err();
        assert!(e.contains("verify-x509-name"), "{e}");
        // autre autorité
        let (op, ok) = ca("Autre CA");
        let other = rcgen::Issuer::from_params(&op, &ok);
        let foreign = leaf("vpn-server", &[E::ServerAuth], &other);
        let e = check(&verifier(false, None), &foreign).unwrap_err();
        assert!(e.contains("autorité"), "{e}");
    }

    #[test]
    fn oid_dotted_names() {
        assert_eq!(oid_dotted(&[0x55, 0x04, 0x03]), "2.5.4.3");
        assert_eq!(oid_dotted(OID_NS_CERT_TYPE), "2.16.840.1.113730.1.1");
    }
}
