//! Fichier `.ovpn` : lecture et vérification.
//!
//! Seules les options utiles au client sont retenues ; les options locales (persist-tun, nobind,
//! verb, resolv-retry…) sont ignorées. Les modes que le client ne sait pas jouer (clé statique,
//! tls-crypt-v2, dev tap, pkcs12, proxy…) sont refusés avec un message explicite plutôt que
//! d'échouer plus tard à la connexion.

use super::data::Compression;
use crate::model::{OpenVpnConfig, OpenVpnProto};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Chiffrements du canal de données pris en charge (noms OpenVPN, majuscules).
pub const DATA_CIPHERS: &[&str] = &[
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
    "AES-128-CBC",
    "AES-256-CBC",
];

/// Condensés `auth` pris en charge.
pub const AUTH_DIGESTS: &[&str] = &["SHA1", "SHA256", "SHA512"];

/// Taille maximale d'un fichier référencé (`ca`, `cert`…) : un PEM dépasse rarement quelques Ko.
const MAX_FILE: u64 = 1 << 20;

/// Nom canonique d'un chiffrement pris en charge (insensible à la casse), `None` sinon.
pub fn normalize_cipher(name: &str) -> Option<&'static str> {
    let n = name.trim();
    DATA_CIPHERS.iter().copied().find(|c| c.eq_ignore_ascii_case(n))
}

/// Nom canonique d'un condensé pris en charge (`sha256`, `SHA-256` → `SHA256`), `None` sinon.
pub fn normalize_auth(name: &str) -> Option<&'static str> {
    let n: String = name.trim().chars().filter(|c| *c != '-').collect();
    AUTH_DIGESTS.iter().copied().find(|c| c.eq_ignore_ascii_case(&n))
}

/// Cadrage de compression enregistré dans le profil (`comp-lzo`, `compress …`), `None` si vide.
pub fn compression(c: &OpenVpnConfig) -> Result<Compression, String> {
    let mut words = c.compression.split_whitespace();
    match words.next() {
        None => Ok(Compression::None),
        Some(name) => {
            let name = name.trim_start_matches("--").to_ascii_lowercase();
            if name != "comp-lzo" && name != "compress" {
                return Err(format!(
                    "Compression « {} » inconnue (comp-lzo, compress ou compress stub-v2 attendu)",
                    c.compression.trim()
                ));
            }
            Compression::from_directive(&name, words.next())
        }
    }
}

/// Texte canonique d'un cadrage (`compression` du profil).
fn compression_text(comp: Compression) -> &'static str {
    match comp {
        Compression::None => "",
        Compression::Lzo => "comp-lzo",
        Compression::Swap => "compress",
        Compression::V2 => "compress stub-v2",
    }
}

/// Réseau en notation CIDR (« 192.168.1.0/24 », « fd00::/64 », adresse seule = hôte), ramené à
/// son adresse de réseau.
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    match a.parse::<IpAddr>().ok()? {
        IpAddr::V4(v) => {
            let p: u8 = p.map_or(Some(32), |p| p.parse().ok())?;
            (p <= 32).then(|| {
                let m = u32::MAX.checked_shl(32 - p as u32).unwrap_or(0);
                (IpAddr::V4(Ipv4Addr::from(u32::from(v) & m)), p)
            })
        }
        IpAddr::V6(v) => {
            let p: u8 = p.map_or(Some(128), |p| p.parse().ok())?;
            (p <= 128).then(|| {
                let m = u128::MAX.checked_shl(128 - p as u32).unwrap_or(0);
                (IpAddr::V6(Ipv6Addr::from(u128::from(v) & m)), p)
            })
        }
    }
}

/// Routes du profil (`OpenVpnConfig::routes`).
pub fn profile_routes(c: &OpenVpnConfig) -> Result<Vec<(IpAddr, u8)>, String> {
    let mut out = Vec::new();
    for item in c.routes.split(|ch: char| ch.is_whitespace() || ch == ',' || ch == ';').filter(|s| !s.is_empty()) {
        let r = parse_cidr(item).ok_or_else(|| format!("Route du profil invalide : « {item} » (ex. 192.168.1.0/24)"))?;
        if !out.contains(&r) {
            out.push(r);
        }
    }
    Ok(out)
}

/// Masque IPv4 → préfixe (`None` si les bits ne sont pas contigus).
fn mask_prefix(m: Ipv4Addr) -> Option<u8> {
    let v = u32::from(m);
    let p = v.leading_ones();
    (v.checked_shl(p).unwrap_or(0) == 0).then_some(p as u8)
}

/// Ajoute une route au profil (texte CIDR), sans doublon.
fn add_route(c: &mut OpenVpnConfig, (net, p): (IpAddr, u8)) {
    let r = format!("{net}/{p}");
    if !c.routes.split_whitespace().any(|x| x == r) {
        if !c.routes.is_empty() {
            c.routes.push(' ');
        }
        c.routes.push_str(&r);
    }
}

fn parse_secs(a: &str, name: &str, n: usize) -> Result<u32, String> {
    a.parse::<u32>().map_err(|_| format!("Ligne {n} : durée « {a} » invalide pour « {name} »"))
}

/// Type de `verify-x509-name`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum X509NameType {
    /// Sujet complet (`C=FR, O=…, CN=…`), le type par défaut.
    Subject,
    /// CN exact.
    Name,
    /// CN commençant par le nom donné.
    NamePrefix,
}

/// Lit `OpenVpnConfig::verify_x509_name`, enregistré sous la forme `nom` (sujet complet),
/// `name:nom` ou `name-prefix:nom`. `None` = pas de vérification du nom.
pub fn x509_name(c: &OpenVpnConfig) -> Option<(X509NameType, String)> {
    let v = c.verify_x509_name.trim();
    if v.is_empty() {
        return None;
    }
    if let Some(n) = v.strip_prefix("name-prefix:") {
        Some((X509NameType::NamePrefix, n.to_string()))
    } else if let Some(n) = v.strip_prefix("name:") {
        Some((X509NameType::Name, n.to_string()))
    } else if let Some(n) = v.strip_prefix("subject:") {
        Some((X509NameType::Subject, n.to_string()))
    } else {
        Some((X509NameType::Subject, v.to_string()))
    }
}

/// Clé statique OpenVPN (« -----BEGIN OpenVPN Static key V1----- », 2048 bits en hexadécimal)
/// utilisée par `tls-auth` et `tls-crypt`.
pub fn parse_static_key(text: &str) -> Result<[u8; 256], String> {
    const BEGIN: &str = "-----BEGIN OpenVPN Static key V1-----";
    const END: &str = "-----END OpenVPN Static key V1-----";
    let start = text
        .find(BEGIN)
        .ok_or("Clé statique OpenVPN illisible (« BEGIN OpenVPN Static key V1 » absent)")?;
    let body = &text[start + BEGIN.len()..];
    let end = body
        .find(END)
        .ok_or("Clé statique OpenVPN tronquée (« END OpenVPN Static key V1 » absent)")?;
    let mut hex = Zeroizing::new(Vec::with_capacity(512));
    for line in body[..end].lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        for b in line.bytes().filter(|b| !b.is_ascii_whitespace()) {
            if !b.is_ascii_hexdigit() {
                return Err("Clé statique OpenVPN invalide (caractère non hexadécimal)".into());
            }
            hex.push(b);
        }
    }
    if hex.len() != 512 {
        return Err(format!(
            "Clé statique OpenVPN invalide : {} octets au lieu de 256",
            hex.len() / 2
        ));
    }
    let mut key = [0u8; 256];
    for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        key[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(key)
}

fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

/// Découpe une ligne d'options comme OpenVPN : espaces séparateurs, guillemets doubles (avec
/// `\\`, `\"`, `\ `), apostrophes littérales, commentaire `#` / `;` en début de mot.
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_tok = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            Some(_) => match c {
                '"' => quote = None,
                '\\' => match chars.next() {
                    Some(n) => cur.push(n),
                    None => return Err("Ligne terminée par « \\ » entre guillemets".into()),
                },
                _ => cur.push(c),
            },
            None => match c {
                c if c.is_whitespace() => {
                    if in_tok {
                        out.push(std::mem::take(&mut cur));
                        in_tok = false;
                    }
                }
                '#' | ';' if !in_tok => break,
                '"' | '\'' => {
                    quote = Some(c);
                    in_tok = true;
                }
                '\\' => {
                    in_tok = true;
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                }
                _ => {
                    in_tok = true;
                    cur.push(c);
                }
            },
        }
    }
    if quote.is_some() {
        return Err("Guillemets non refermés".into());
    }
    if in_tok {
        out.push(cur);
    }
    Ok(out)
}

/// Fichier référencé : `[inline]` (bloc `<x>`) ou chemin relatif au dossier du `.ovpn`.
#[derive(Default)]
enum Source {
    #[default]
    Absent,
    Inline,
    File(String),
}

/// `remote` / `port` / `proto` d'un niveau (fichier ou bloc `<connection>`).
#[derive(Default)]
struct Endpoint {
    remote: Option<(String, Option<u16>, Option<OpenVpnProto>)>,
    port: Option<u16>,
    proto: Option<OpenVpnProto>,
}

impl Endpoint {
    /// Traite `remote`, `port`, `rport`, `proto` ; `false` si l'option n'en est pas une.
    fn option(&mut self, name: &str, args: &[String], n: usize) -> Result<bool, String> {
        match name {
            "remote" => {
                let host = args
                    .first()
                    .ok_or_else(|| format!("Ligne {n} : « remote » sans adresse"))?;
                let port = args.get(1).map(|p| parse_port(p, n)).transpose()?;
                let proto = args.get(2).map(|p| parse_proto(p, n)).transpose()?;
                // le premier `remote` l'emporte, les suivants sont des secours
                if self.remote.is_none() {
                    self.remote = Some((host.clone(), port, proto));
                }
            }
            "port" | "rport" => self.port = Some(parse_port(arg(args, 0, name, n)?, n)?),
            "proto" => self.proto = Some(parse_proto(arg(args, 0, name, n)?, n)?),
            _ => return Ok(false),
        }
        Ok(true)
    }
}

fn arg<'a>(args: &'a [String], i: usize, name: &str, n: usize) -> Result<&'a str, String> {
    args.get(i)
        .map(String::as_str)
        .ok_or_else(|| format!("Ligne {n} : argument manquant pour « {name} »"))
}

fn parse_port(p: &str, n: usize) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(v) if v > 0 => Ok(v),
        _ => Err(format!("Ligne {n} : port invalide « {p} »")),
    }
}

fn parse_proto(p: &str, n: usize) -> Result<OpenVpnProto, String> {
    match p.to_ascii_lowercase().as_str() {
        "udp" | "udp4" | "udp6" => Ok(OpenVpnProto::Udp),
        "tcp" | "tcp4" | "tcp6" | "tcp-client" | "tcp4-client" | "tcp6-client" => {
            Ok(OpenVpnProto::Tcp)
        }
        "tcp-server" | "tcp4-server" | "tcp6-server" => Err(format!(
            "Ligne {n} : « proto {p} » est une configuration de serveur, pas de client"
        )),
        _ => Err(format!("Ligne {n} : transport « {p} » inconnu (udp ou tcp attendu)")),
    }
}

/// Liste `data-ciphers` normalisée ; les noms précédés de `?` (facultatifs) inconnus sont écartés.
fn parse_cipher_list(list: &str, n: usize) -> Result<String, String> {
    let mut out: Vec<&'static str> = Vec::new();
    for item in list.split(':').map(str::trim).filter(|s| !s.is_empty()) {
        let (optional, name) = match item.strip_prefix('?') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        match normalize_cipher(name) {
            Some(c) if !out.contains(&c) => out.push(c),
            Some(_) => {}
            None if optional => {}
            None => return Err(unsupported_cipher(name, Some(n))),
        }
    }
    if out.is_empty() {
        return Err(format!("Ligne {n} : aucun chiffrement pris en charge dans « {list} »"));
    }
    Ok(out.join(":"))
}

fn unsupported_cipher(name: &str, line: Option<usize>) -> String {
    let at = line.map(|n| format!("Ligne {n} : ")).unwrap_or_default();
    if name.eq_ignore_ascii_case("none") {
        format!("{at}« cipher none » (canal de données non chiffré) n'est pas pris en charge")
    } else {
        format!(
            "{at}chiffrement « {name} » non pris en charge (possibles : {})",
            DATA_CIPHERS.join(", ")
        )
    }
}

const PKCS12_HELP: &str = "les fichiers PKCS#12 (pkcs12 / .p12 / .pfx) ne sont pas pris en charge : \
convertissez-les en PEM puis intégrez-les au .ovpn (blocs <ca>, <cert>, <key>), par exemple \
« openssl pkcs12 -in client.p12 -cacerts -nokeys -out ca.crt », \
« openssl pkcs12 -in client.p12 -clcerts -nokeys -out client.crt » et \
« openssl pkcs12 -in client.p12 -nocerts -nodes -out client.key »";

/// Lit un fichier `.ovpn`. `base_dir` : dossier du fichier, pour les `ca`, `cert`… externes.
pub fn parse_ovpn(text: &str, base_dir: Option<&Path>) -> Result<OpenVpnConfig, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut c = OpenVpnConfig::default();
    let mut top = Endpoint::default();
    let mut conn: Option<Endpoint> = None;
    let (mut ca, mut cert, mut key, mut extra, mut tls_auth, mut tls_crypt) = Default::default();
    let mut inline: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut tls_auth_dir: Option<String> = None;
    let mut key_direction: Option<String> = None;
    let mut cipher = String::new();
    let mut fallback = String::new();

    let mut lines = text.lines().enumerate().map(|(i, l)| (i + 1, l.trim_end_matches('\r')));
    while let Some((n, raw)) = lines.next() {
        let line = raw.trim();
        // bloc intégré : <ca> … </ca>
        if line.starts_with('<') && line.ends_with('>') && !line.starts_with("</") {
            let tag = line[1..line.len() - 1].trim().to_ascii_lowercase();
            let close = format!("</{tag}>");
            let mut body = Zeroizing::new(String::new());
            let mut closed = false;
            for (_, l) in lines.by_ref() {
                if l.trim().eq_ignore_ascii_case(&close) {
                    closed = true;
                    break;
                }
                body.push_str(l.trim());
                body.push('\n');
            }
            if !closed {
                return Err(format!("Ligne {n} : bloc <{tag}> sans {close}"));
            }
            match tag.as_str() {
                "connection" => {
                    // seul le premier bloc <connection> est retenu (les suivants sont des secours)
                    if conn.is_none() {
                        let mut e = Endpoint::default();
                        for (k, l) in body.lines().enumerate() {
                            let t = tokenize(l).map_err(|e| format!("Ligne {} : {e}", n + 1 + k))?;
                            if let Some((name, args)) = t.split_first() {
                                let name = name.trim_start_matches("--").to_ascii_lowercase();
                                e.option(&name, args, n + 1 + k)?;
                            }
                        }
                        conn = Some(e);
                    }
                }
                "secret" => return Err(static_mode_error()),
                "tls-crypt-v2" => return Err(tls_crypt_v2_error()),
                "pkcs12" => return Err(format!("Ligne {n} : {PKCS12_HELP}")),
                _ => inline.push((tag, body)),
            }
            continue;
        }
        let tokens = tokenize(line).map_err(|e| format!("Ligne {n} : {e}"))?;
        let Some((name, args)) = tokens.split_first() else {
            continue;
        };
        let name = name.trim_start_matches("--").to_ascii_lowercase();
        if top.option(&name, args, n)? {
            continue;
        }
        let file_arg = |args: &[String]| -> Result<Source, String> {
            let a = arg(args, 0, &name, n)?;
            Ok(if a.eq_ignore_ascii_case("[inline]") {
                Source::Inline
            } else {
                Source::File(a.to_string())
            })
        };
        match name.as_str() {
            "ca" => ca = file_arg(args)?,
            "cert" => cert = file_arg(args)?,
            "key" => key = file_arg(args)?,
            "extra-certs" => extra = file_arg(args)?,
            "tls-auth" => {
                tls_auth = file_arg(args)?;
                tls_auth_dir = args.get(1).cloned();
            }
            "tls-crypt" => tls_crypt = file_arg(args)?,
            "key-direction" => key_direction = Some(arg(args, 0, &name, n)?.to_string()),
            // `cipher` n'est qu'un repli quand le serveur négocie (NCP, OpenVPN 2.4+) : un nom que
            // le client ne sait pas jouer (BF-CBC…) est écarté, la connexion n'échoue que si le
            // serveur ne pousse rien de mieux
            "cipher" => {
                let a = arg(args, 0, &name, n)?;
                if a.eq_ignore_ascii_case("none") {
                    return Err(unsupported_cipher(a, Some(n)));
                }
                cipher = normalize_cipher(a).unwrap_or_default().to_string();
            }
            "data-ciphers" | "ncp-ciphers" => {
                c.data_ciphers = parse_cipher_list(arg(args, 0, &name, n)?, n)?
            }
            "data-ciphers-fallback" => {
                let a = arg(args, 0, &name, n)?;
                if a.eq_ignore_ascii_case("none") {
                    return Err(unsupported_cipher(a, Some(n)));
                }
                fallback = normalize_cipher(a).unwrap_or_default().to_string();
            }
            "auth" => {
                let a = arg(args, 0, &name, n)?;
                c.auth = normalize_auth(a)
                    .ok_or_else(|| {
                        format!(
                            "Ligne {n} : condensé « auth {a} » non pris en charge (possibles : {})",
                            AUTH_DIGESTS.join(", ")
                        )
                    })?
                    .to_string();
            }
            // le fichier éventuel (identifiant / mot de passe) n'est pas lu : ils sont saisis dans le profil
            "auth-user-pass" => c.auth_user_pass = true,
            "verify-x509-name" => {
                let v = arg(args, 0, &name, n)?;
                c.verify_x509_name = match args.get(1).map(|t| t.to_ascii_lowercase()).as_deref() {
                    None | Some("subject") => v.to_string(),
                    Some("name") => format!("name:{v}"),
                    Some("name-prefix") => format!("name-prefix:{v}"),
                    Some(t) => {
                        return Err(format!("Ligne {n} : type « {t} » de verify-x509-name inconnu"));
                    }
                };
            }
            "remote-cert-tls" => match args.first().map(|a| a.to_ascii_lowercase()).as_deref() {
                Some("server") => c.remote_cert_tls = true,
                _ => return Err(format!("Ligne {n} : seul « remote-cert-tls server » est possible côté client")),
            },
            // ancêtre de remote-cert-tls (retiré d'OpenVPN 2.5) : même intention
            "ns-cert-type" => c.remote_cert_tls = true,
            "comp-lzo" | "compress" => {
                let comp = Compression::from_directive(&name, args.first().map(String::as_str))
                    .map_err(|e| format!("Ligne {n} : {e}"))?;
                c.compression = compression_text(comp).to_string();
            }
            "route" => {
                // « route réseau [masque] [passerelle] [métrique] » ; net_gateway = hors VPN. Un nom
                // d'hôte (résolu par OpenVPN au démarrage) ou un mot-clé n'est pas repris.
                let net = arg(args, 0, &name, n)?;
                if args.get(2).is_some_and(|g| g.eq_ignore_ascii_case("net_gateway")) {
                    continue;
                }
                let Ok(net) = net.parse::<Ipv4Addr>() else { continue };
                let p = match args.get(1).map(String::as_str) {
                    None | Some("default") => 32,
                    Some(m) => m
                        .parse::<Ipv4Addr>()
                        .ok()
                        .and_then(mask_prefix)
                        .ok_or_else(|| format!("Ligne {n} : masque « {m} » invalide pour « route »"))?,
                };
                if let Some(r) = parse_cidr(&format!("{net}/{p}")) {
                    add_route(&mut c, r);
                }
            }
            "route-ipv6" => {
                let net = arg(args, 0, &name, n)?;
                if args.get(1).is_some_and(|g| g.eq_ignore_ascii_case("net_gateway")) {
                    continue;
                }
                if let Some(r @ (IpAddr::V6(_), _)) = parse_cidr(net) {
                    add_route(&mut c, r);
                }
            }
            "redirect-gateway" => c.redirect_gateway = true,
            "route-nopull" => c.route_nopull = true,
            "reneg-sec" => c.reneg_sec = Some(parse_secs(arg(args, 0, &name, n)?, &name, n)?),
            "tun-mtu" => {
                let a = arg(args, 0, &name, n)?;
                c.tun_mtu = a
                    .parse()
                    .ok()
                    .filter(|m| *m >= 576)
                    .ok_or_else(|| format!("Ligne {n} : « tun-mtu {a} » invalide"))?;
            }
            "keepalive" => {
                c.ping = parse_secs(arg(args, 0, &name, n)?, &name, n)?;
                c.ping_restart = parse_secs(arg(args, 1, &name, n)?, &name, n)?;
            }
            "ping" => c.ping = parse_secs(arg(args, 0, &name, n)?, &name, n)?,
            "ping-restart" => c.ping_restart = parse_secs(arg(args, 0, &name, n)?, &name, n)?,
            "dev" => {
                let d = arg(args, 0, &name, n)?.to_ascii_lowercase();
                if d.starts_with("tap") {
                    return Err(format!("Ligne {n} : « dev tap » (pont Ethernet) n'est pas pris en charge, seul « dev tun » l'est"));
                }
            }
            "dev-type" => {
                if arg(args, 0, &name, n)?.eq_ignore_ascii_case("tap") {
                    return Err(format!("Ligne {n} : « dev-type tap » (pont Ethernet) n'est pas pris en charge, seul tun l'est"));
                }
            }
            "secret" => return Err(static_mode_error()),
            "tls-crypt-v2" => return Err(tls_crypt_v2_error()),
            "pkcs12" => return Err(format!("Ligne {n} : {PKCS12_HELP}")),
            "cryptoapicert" | "pkcs11-providers" | "pkcs11-id" | "management-external-key" => {
                return Err(format!(
                    "Ligne {n} : « {name} » (certificat dans le magasin Windows ou une carte) n'est pas pris en charge : \
                     exportez le certificat et la clé en PEM (<cert>, <key>)"
                ));
            }
            "http-proxy" | "socks-proxy" => {
                return Err(format!("Ligne {n} : « {name} » (passage par un proxy) n'est pas pris en charge"));
            }
            "fragment" => {
                return Err(format!("Ligne {n} : « fragment » n'est pas pris en charge"));
            }
            "server" | "mode" | "tls-server" | "server-bridge" => {
                return Err(format!("Ligne {n} : « {name} » : ce fichier configure un serveur OpenVPN, pas un client"));
            }
            _ => {}
        }
    }

    // destination : `remote` du fichier, sinon premier bloc <connection>
    let (host, port, proto) = match (top.remote.take(), conn) {
        (Some((h, p, pr)), _) => (h, p.or(top.port), pr.or(top.proto)),
        (None, Some(mut e)) => match e.remote.take() {
            Some((h, p, pr)) => (h, p.or(e.port).or(top.port), pr.or(e.proto).or(top.proto)),
            None => return Err(missing_remote()),
        },
        (None, None) => return Err(missing_remote()),
    };
    c.remote = host;
    c.port = port.unwrap_or(0);
    c.proto = proto.unwrap_or_default();

    let resolve = |src: Source, tag: &str| -> Result<String, String> {
        match src {
            Source::Absent => Ok(String::new()),
            Source::Inline => take_inline(&inline, tag)
                .ok_or_else(|| format!("« {tag} [inline] » sans bloc <{tag}>")),
            Source::File(f) => read_file(&f, base_dir, tag),
        }
    };
    let pick = |src: Source, tag: &str| -> Result<String, String> {
        match src {
            Source::Absent => Ok(take_inline(&inline, tag).unwrap_or_default()),
            s => resolve(s, tag),
        }
    };
    c.ca = pick(ca, "ca")?;
    c.cert = pick(cert, "cert")?;
    c.key = pick(key, "key")?;
    c.tls_auth = pick(tls_auth, "tls-auth")?;
    c.tls_crypt = pick(tls_crypt, "tls-crypt")?;
    let mut extra = Zeroizing::new(pick(extra, "extra-certs")?);
    // extra-certs : certificats intermédiaires envoyés avec le certificat client
    if !c.cert.is_empty() && !extra.trim().is_empty() {
        if !c.cert.ends_with('\n') {
            c.cert.push('\n');
        }
        c.cert.push_str(&extra);
    }
    extra.zeroize();

    if c.ca.trim().is_empty() {
        return Err("Autorité de certification absente : ajoutez un bloc <ca> ou une ligne « ca fichier.crt »".into());
    }
    c.key_direction = key_direction.or(tls_auth_dir).unwrap_or_default();
    c.cipher = if cipher.is_empty() { fallback } else { cipher };
    check_material(&c)?;
    Ok(c)
}

fn missing_remote() -> String {
    "Adresse du serveur OpenVPN absente (ligne « remote serveur port »)".into()
}

fn static_mode_error() -> String {
    "Le mode « clé statique » (secret) n'est pas pris en charge : il faut une configuration TLS (ca, cert / auth-user-pass)".into()
}

fn tls_crypt_v2_error() -> String {
    "« tls-crypt-v2 » n'est pas pris en charge (seuls tls-auth et tls-crypt le sont)".into()
}

fn take_inline(inline: &[(String, Zeroizing<String>)], tag: &str) -> Option<String> {
    inline.iter().rev().find(|(t, _)| t == tag).map(|(_, b)| b.to_string())
}

fn read_file(f: &str, base_dir: Option<&Path>, tag: &str) -> Result<String, String> {
    let p = PathBuf::from(f);
    let path = if p.is_absolute() {
        p
    } else {
        match base_dir {
            Some(d) => d.join(p),
            None => {
                return Err(format!(
                    "Fichier « {f} » ({tag}) introuvable : intégrez-le au .ovpn dans un bloc <{tag}>"
                ));
            }
        }
    };
    let meta = std::fs::metadata(&path)
        .map_err(|e| format!("Fichier « {} » ({tag}) illisible : {e}", path.display()))?;
    if meta.len() > MAX_FILE {
        return Err(format!("Fichier « {} » ({tag}) trop gros", path.display()));
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("Fichier « {} » ({tag}) illisible : {e}", path.display()))?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s.trim_start_matches('\u{feff}').replace("\r\n", "\n")),
        Err(e) => {
            let mut b = e.into_bytes();
            b.zeroize();
            if tag == "ca" || tag == "cert" || tag == "key" {
                Err(format!(
                    "Fichier « {} » ({tag}) n'est pas au format PEM (texte) : s'il s'agit d'un .p12/.pfx, {PKCS12_HELP}",
                    path.display()
                ))
            } else {
                Err(format!("Fichier « {} » ({tag}) n'est pas un fichier texte", path.display()))
            }
        }
    }
}

/// Vérifie les certificats, clés et noms de chiffrement (sans l'identifiant).
fn check_material(c: &OpenVpnConfig) -> Result<(), String> {
    let remote = c.remote.trim();
    if remote.is_empty() {
        return Err("Adresse du serveur OpenVPN (remote) manquante".into());
    }
    if remote.chars().any(char::is_whitespace) {
        return Err(format!("Adresse du serveur OpenVPN invalide : « {remote} »"));
    }
    if c.ca.trim().is_empty() {
        return Err("Autorité de certification (<ca>) manquante".into());
    }
    pem_certs(&c.ca, "de l'autorité de certification (<ca>)")?;
    if !c.cert.trim().is_empty() {
        pem_certs(&c.cert, "client (<cert>)")?;
        if c.key.trim().is_empty() {
            return Err("Clé privée client (<key>) manquante pour le certificat client".into());
        }
        pem_key(&c.key)?;
    } else if !c.key.trim().is_empty() {
        return Err("Clé privée (<key>) sans certificat client (<cert>)".into());
    } else if !c.auth_user_pass {
        return Err("Ni certificat client (<cert>) ni identifiant (auth-user-pass) : le serveur refusera la connexion".into());
    }
    if !c.tls_auth.trim().is_empty() && !c.tls_crypt.trim().is_empty() {
        return Err("tls-auth et tls-crypt ne peuvent pas être utilisés ensemble".into());
    }
    if !c.tls_auth.trim().is_empty() {
        parse_static_key(&c.tls_auth)
            .map(|mut k| k.zeroize())
            .map_err(|e| format!("tls-auth : {e}"))?;
    }
    if !c.tls_crypt.trim().is_empty() {
        parse_static_key(&c.tls_crypt)
            .map(|mut k| k.zeroize())
            .map_err(|e| format!("tls-crypt : {e}"))?;
    }
    if !matches!(c.key_direction.trim(), "" | "0" | "1") {
        return Err(format!(
            "key-direction « {} » invalide (0, 1 ou vide attendu)",
            c.key_direction
        ));
    }
    // `cipher` inconnu (BF-CBC…) : simple repli inutilisable, le serveur négocie ; « none » refusé
    let cipher = c.cipher.trim();
    if cipher.eq_ignore_ascii_case("none") {
        return Err(unsupported_cipher(cipher, None));
    }
    for item in c.data_ciphers.split(':').map(str::trim).filter(|s| !s.is_empty()) {
        let name = item.strip_prefix('?').unwrap_or(item);
        if normalize_cipher(name).is_none() && !item.starts_with('?') {
            return Err(unsupported_cipher(name, None));
        }
    }
    let auth = c.auth.trim();
    if !auth.is_empty() && normalize_auth(auth).is_none() {
        return Err(format!(
            "Condensé « auth {auth} » non pris en charge (possibles : {})",
            AUTH_DIGESTS.join(", ")
        ));
    }
    if let Some((_, name)) = x509_name(c)
        && name.trim().is_empty()
    {
        return Err("verify-x509-name sans nom".into());
    }
    compression(c)?;
    profile_routes(c)?;
    if c.tun_mtu != 0 && c.tun_mtu < 576 {
        return Err(format!("tun-mtu {} invalide (576 au moins)", c.tun_mtu));
    }
    Ok(())
}

fn pem_certs(pem: &str, what: &str) -> Result<usize, String> {
    let mut count = 0;
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        cert.map_err(|e| format!("Certificat {what} illisible : {e}"))?;
        count += 1;
    }
    if count == 0 {
        return Err(format!(
            "Certificat {what} illisible : aucun « -----BEGIN CERTIFICATE----- » trouvé"
        ));
    }
    Ok(count)
}

fn pem_key(pem: &str) -> Result<(), String> {
    if pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED") {
        return Err("Clé privée client protégée par une phrase de passe : non prise en charge, \
                    déchiffrez-la (« openssl pkey -in client.key -out client-clair.key ») puis réimportez"
            .into());
    }
    match PrivateKeyDer::from_pem_slice(pem.as_bytes()) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Clé privée client (<key>) illisible : {e}")),
    }
}

/// Vérifie une configuration avant de l'enregistrer.
pub fn check(c: &OpenVpnConfig, username: &str, _password: &str) -> Result<(), String> {
    check_material(c)?;
    if c.auth_user_pass && username.trim().is_empty() {
        return Err("Le serveur demande un identifiant (auth-user-pass) : renseignez-le dans le profil".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pki {
        ca: String,
        cert: String,
        key: String,
    }

    fn pki() -> Pki {
        let ca = rcgen::generate_simple_self_signed(vec!["vpn.example.test".into()]).unwrap();
        let cl = rcgen::generate_simple_self_signed(vec!["client".into()]).unwrap();
        Pki {
            ca: ca.cert.pem(),
            cert: cl.cert.pem(),
            key: cl.signing_key.serialize_pem(),
        }
    }

    fn static_key(seed: u8) -> String {
        let mut s = String::from(
            "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n",
        );
        for line in 0..16 {
            for i in 0..16u8 {
                s.push_str(&format!("{:02x}", seed.wrapping_add(line * 16 + i)));
            }
            s.push('\n');
        }
        s.push_str("-----END OpenVPN Static key V1-----\n");
        s
    }

    fn watchguard(p: &Pki) -> String {
        format!(
            "\u{feff}# WatchGuard Mobile VPN with SSL\r\n\
             client\r\ndev tun\r\nproto tcp\r\nremote 203.0.113.10 443\r\n\
             nobind\r\npersist-key\r\npersist-tun\r\nresolv-retry infinite\r\n\
             remote-cert-tls server\r\ncipher AES-256-CBC\r\nauth SHA256\r\n\
             auth-user-pass\r\nreneg-sec 3600\r\ncomp-lzo\r\nverb 3\r\n\
             keepalive 10 60\r\n\
             <ca>\r\n{}</ca>\r\n<cert>\r\n{}</cert>\r\n<key>\r\n{}</key>\r\n",
            p.ca.replace('\n', "\r\n"),
            p.cert.replace('\n', "\r\n"),
            p.key.replace('\n', "\r\n")
        )
    }

    fn pfsense(p: &Pki) -> String {
        format!(
            "dev tun\npersist-tun\npersist-key\n\
             data-ciphers AES-256-GCM:aes-128-gcm:CHACHA20-POLY1305:?BF-CBC\n\
             data-ciphers-fallback AES-256-CBC\nauth SHA256\ntls-client\nclient\n\
             resolv-retry infinite\nremote 198.51.100.1 1194 udp4\nnobind\n\
             verify-x509-name \"pfSense server\" name\nauth-user-pass\n\
             remote-cert-tls server\nexplicit-exit-notify\nsetenv opt block-outside-dns\n\
             <ca>\n{}</ca>\nkey-direction 1\n<tls-auth>\n{}</tls-auth>\n",
            p.ca,
            static_key(7)
        )
    }

    #[test]
    fn watchguard_profile() {
        let p = pki();
        let c = parse_ovpn(&watchguard(&p), None).unwrap();
        assert_eq!(c.remote, "203.0.113.10");
        assert_eq!(c.port, 443);
        assert_eq!(c.proto, OpenVpnProto::Tcp);
        assert_eq!(c.cipher, "AES-256-CBC");
        assert_eq!(c.auth, "SHA256");
        assert!(c.auth_user_pass && c.remote_cert_tls);
        assert_eq!(c.compression, "comp-lzo");
        assert_eq!((c.reneg_sec, c.ping, c.ping_restart), (Some(3600), 10, 60));
        assert!(c.ca.contains("BEGIN CERTIFICATE") && !c.ca.contains('\r'));
        assert!(c.key.contains("PRIVATE KEY"));
        assert!(c.tls_auth.is_empty() && c.tls_crypt.is_empty());
        assert!(check(&c, "", "").is_err());
        check(&c, "theo", "").unwrap();
    }

    #[test]
    fn pfsense_profile() {
        let p = pki();
        let c = parse_ovpn(&pfsense(&p), None).unwrap();
        assert_eq!(c.remote, "198.51.100.1");
        assert_eq!(c.port, 1194);
        assert_eq!(c.proto, OpenVpnProto::Udp);
        assert_eq!(c.data_ciphers, "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305");
        assert_eq!(c.cipher, "AES-256-CBC");
        assert_eq!(c.key_direction, "1");
        assert_eq!(x509_name(&c), Some((X509NameType::Name, "pfSense server".into())));
        assert!(c.compression.is_empty() && c.cert.is_empty());
        let k = parse_static_key(&c.tls_auth).unwrap();
        assert_eq!(k[0], 7);
        assert_eq!(k[255], 7u8.wrapping_add(255));
        check(&c, "u", "").unwrap();
    }

    #[test]
    fn external_files() {
        let p = pki();
        let dir = std::env::temp_dir().join(format!("escale-ovpn-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::write(dir.join("ca.crt"), p.ca.replace('\n', "\r\n")).unwrap();
        std::fs::write(dir.join("keys/client.crt"), &p.cert).unwrap();
        std::fs::write(dir.join("keys/client.key"), &p.key).unwrap();
        std::fs::write(dir.join("ta.key"), static_key(1)).unwrap();
        std::fs::write(dir.join("inter.crt"), &p.ca).unwrap();
        let text = "client\nremote vpn.example.test\nport 1195\nproto tcp-client\n\
                    ca ca.crt\ncert \"keys/client.crt\"\nkey 'keys/client.key'\n\
                    extra-certs inter.crt\ntls-auth ta.key 0\ncompress stub-v2\n";
        let c = parse_ovpn(text, Some(&dir)).unwrap();
        assert_eq!((c.port, c.proto), (1195, OpenVpnProto::Tcp));
        assert_eq!(c.key_direction, "0");
        assert_eq!(c.compression, "compress stub-v2");
        assert_eq!(compression(&c).unwrap(), Compression::V2);
        assert_eq!(pem_certs(&c.cert, "").unwrap(), 2);
        check(&c, "", "").unwrap();
        // sans dossier, un fichier relatif est introuvable
        assert!(parse_ovpn(text, None).unwrap_err().contains("ca.crt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_resolution() {
        let p = pki();
        let base = format!("auth-user-pass\n<ca>\n{}</ca>\n", p.ca);
        let c = parse_ovpn(&format!("remote a.test 1000 tcp\nremote b.test 2000 udp\nproto udp\nport 5\n{base}"), None).unwrap();
        assert_eq!((c.remote.as_str(), c.port, c.proto), ("a.test", 1000, OpenVpnProto::Tcp));
        let c = parse_ovpn(&format!("rport 4443\nproto tcp6\nremote h.test\n{base}"), None).unwrap();
        assert_eq!((c.port, c.proto), (4443, OpenVpnProto::Tcp));
        let c = parse_ovpn(&format!("remote h.test\n{base}"), None).unwrap();
        assert_eq!((c.port, c.proto), (0, OpenVpnProto::Udp));
        let c = parse_ovpn(
            &format!("proto tcp\n<connection>\nremote c1.test 443\n</connection>\n<connection>\nremote c2.test\n</connection>\n{base}"),
            None,
        )
        .unwrap();
        assert_eq!((c.remote.as_str(), c.port, c.proto), ("c1.test", 443, OpenVpnProto::Tcp));
        assert!(parse_ovpn(&base, None).unwrap_err().contains("remote"));
        assert!(parse_ovpn(&format!("remote h 99999\n{base}"), None).is_err());
        assert!(parse_ovpn(&format!("remote h 1 sctp\n{base}"), None).is_err());
    }

    #[test]
    fn rejections() {
        let p = pki();
        let base = format!("remote h.test\nauth-user-pass\n<ca>\n{}</ca>\n", p.ca);
        for (extra, needle) in [
            ("dev tap0\n", "tap"),
            ("dev-type tap\n", "tap"),
            ("secret static.key\n", "statique"),
            ("<secret>\nx\n</secret>\n", "statique"),
            ("tls-crypt-v2 c.key\n", "tls-crypt-v2"),
            ("<tls-crypt-v2>\nx\n</tls-crypt-v2>\n", "tls-crypt-v2"),
            ("pkcs12 client.p12\n", "openssl pkcs12"),
            ("cipher none\n", "none"),
            ("data-ciphers AES-256-GCM:BF-CBC\n", "BF-CBC"),
            ("auth MD5\n", "MD5"),
            ("remote-cert-tls client\n", "server"),
            ("http-proxy p 8080\n", "proxy"),
            ("verify-x509-name x weird\n", "weird"),
            ("<ca>\n", "</ca>"),
            ("remote \"unterminated\n", "Guillemets"),
        ] {
            let err = parse_ovpn(&format!("{base}{extra}"), None).unwrap_err();
            assert!(err.contains(needle), "{extra:?} -> {err}");
        }
        // ca absente
        let err = parse_ovpn("remote h\nauth-user-pass\n", None).unwrap_err();
        assert!(err.contains("certification"), "{err}");
        // ca illisible
        let err = parse_ovpn("remote h\nauth-user-pass\n<ca>\nnot a pem\n</ca>\n", None).unwrap_err();
        assert!(err.contains("certification"), "{err}");
        // ni cert ni auth-user-pass
        let err = parse_ovpn(&format!("remote h\n<ca>\n{}</ca>\n", p.ca), None).unwrap_err();
        assert!(err.contains("auth-user-pass"), "{err}");
        // cert sans clé
        let err = parse_ovpn(&format!("{base}<cert>\n{}</cert>\n", p.cert), None).unwrap_err();
        assert!(err.contains("<key>"), "{err}");
        // clé chiffrée
        let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let err = parse_ovpn(&format!("{base}<cert>\n{}</cert>\n<key>\n{enc}</key>\n", p.cert), None).unwrap_err();
        assert!(err.contains("phrase de passe"), "{err}");
        // tls-auth et tls-crypt ensemble
        let k = static_key(0);
        let err = parse_ovpn(&format!("{base}<tls-auth>\n{k}</tls-auth>\n<tls-crypt>\n{k}</tls-crypt>\n"), None).unwrap_err();
        assert!(err.contains("ensemble"), "{err}");
        // tls-auth [inline] sans bloc
        let err = parse_ovpn(&format!("{base}tls-auth [inline] 1\n"), None).unwrap_err();
        assert!(err.contains("<tls-auth>"), "{err}");
    }

    #[test]
    fn options_and_tokens() {
        let p = pki();
        let k = static_key(3);
        let text = format!(
            "  --remote \"vpn.example.test\" 443 tcp # secours\n\
             ; commentaire\n# autre\n\n\
             CIPHER aes-128-gcm\nauth sha-512\nncp-ciphers AES-256-GCM\n\
             comp-lzo no\nverify-x509-name 'C=FR, O=Escale, CN=vpn' subject\n\
             ns-cert-type server\nauth-user-pass creds.txt\n\
             tls-crypt [inline]\n<tls-crypt>\n{k}</tls-crypt>\n<ca>\n{}</ca>\n\
             <cert>\n{}</cert>\n<key>\n{}</key>\n",
            p.ca, p.cert, p.key
        );
        let c = parse_ovpn(&text, None).unwrap();
        assert_eq!(c.remote, "vpn.example.test");
        assert_eq!(c.cipher, "AES-128-GCM");
        assert_eq!(c.auth, "SHA512");
        assert_eq!(c.data_ciphers, "AES-256-GCM");
        assert!(c.remote_cert_tls && c.auth_user_pass);
        assert_eq!(compression(&c).unwrap(), Compression::Lzo);
        assert_eq!(x509_name(&c), Some((X509NameType::Subject, "C=FR, O=Escale, CN=vpn".into())));
        assert_eq!(parse_static_key(&c.tls_crypt).unwrap()[0], 3);
        // data-ciphers-fallback ne remplace pas un cipher explicite
        let c2 = parse_ovpn(&text.replace("CIPHER aes-128-gcm", "cipher AES-128-CBC\ndata-ciphers-fallback AES-256-CBC"), None).unwrap();
        assert_eq!(c2.cipher, "AES-128-CBC");

        assert_eq!(tokenize(r#"a "b c" 'd\e' f\ g "h\"i" #x"#).unwrap(), ["a", "b c", "d\\e", "f g", "h\"i"]);
        assert_eq!(tokenize("a#b ;c").unwrap(), ["a#b"]);
        assert!(tokenize("   # rien").unwrap().is_empty());
    }

    #[test]
    fn check_fields() {
        let p = pki();
        let mut c = OpenVpnConfig {
            remote: "h".into(),
            ca: p.ca.clone(),
            cert: p.cert.clone(),
            key: p.key.clone(),
            ..Default::default()
        };
        check(&c, "", "").unwrap();
        c.key_direction = "2".into();
        assert!(check(&c, "", "").is_err());
        c.key_direction = "".into();
        c.cipher = "aes-256-gcm".into();
        c.auth = "sha1".into();
        c.data_ciphers = "AES-128-GCM:?BF-CBC".into();
        check(&c, "", "").unwrap();
        c.data_ciphers = "AES-128-GCM:BF-CBC".into();
        assert!(check(&c, "", "").is_err());
        c.data_ciphers.clear();
        c.tls_auth = "-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----\n".into();
        assert!(check(&c, "", "").unwrap_err().contains("256"));
        c.tls_auth = static_key(9);
        check(&c, "", "").unwrap();
        c.key = "garbage".into();
        assert!(check(&c, "", "").is_err());
        c.key = p.key.clone();
        c.remote = "  ".into();
        assert!(check(&c, "", "").is_err());
    }

    #[test]
    fn routes_mtu_and_legacy_cipher() {
        let p = pki();
        let base = format!("remote h.test\nauth-user-pass\n<ca>\n{}</ca>\n", p.ca);
        let c = parse_ovpn(
            &format!(
                "{base}route 192.168.10.7 255.255.255.0\nroute 10.1.2.3\nroute 172.16.0.0 255.240.0.0 vpn_gateway 5\n\
                 route 8.8.8.8 255.255.255.255 net_gateway\nroute intranet.test 255.255.255.0\nroute-ipv6 fd00:1::/48\n\
                 route-ipv6 2001:db8::/32 net_gateway\nroute 192.168.10.0 255.255.255.0\nredirect-gateway def1\nroute-nopull\n\
                 tun-mtu 1400\nreneg-sec 0\nping 15\nping-restart 90\ncipher BF-CBC\ncompress lz4-v2\n"
            ),
            None,
        )
        .unwrap();
        assert_eq!(c.routes, "192.168.10.0/24 10.1.2.3/32 172.16.0.0/12 fd00:1::/48");
        assert_eq!(profile_routes(&c).unwrap().len(), 4);
        assert!(c.redirect_gateway && c.route_nopull);
        assert_eq!((c.tun_mtu, c.reneg_sec, c.ping, c.ping_restart), (1400, Some(0), 15, 90));
        // cipher ancien : écarté (repli absent), la négociation reste possible
        assert!(c.cipher.is_empty());
        assert_eq!(c.compression, "compress stub-v2");
        check(&c, "u", "").unwrap();
        // compress (stub / lz4) : octet 0xFB
        let c = parse_ovpn(&format!("{base}compress\n"), None).unwrap();
        assert_eq!(compression(&c).unwrap(), Compression::Swap);
        let c = parse_ovpn(&format!("{base}compress lzo\n"), None).unwrap();
        assert_eq!(c.compression, "comp-lzo");
        for (extra, needle) in [
            ("route 10.0.0.0 255.0.255.0\n", "masque"),
            ("tun-mtu 100\n", "tun-mtu"),
            ("keepalive 10\n", "keepalive"),
            ("compress zstd\n", "zstd"),
            ("data-ciphers-fallback none\n", "none"),
        ] {
            let err = parse_ovpn(&format!("{base}{extra}"), None).unwrap_err();
            assert!(err.contains(needle), "{extra:?} -> {err}");
        }
        let mut c = parse_ovpn(&base, None).unwrap();
        c.routes = "10.0.0.0/8, 192.168.1.1".into();
        assert_eq!(profile_routes(&c).unwrap().len(), 2);
        c.routes = "10.0.0.0/33".into();
        assert!(check(&c, "u", "").is_err());
        c.routes.clear();
        c.compression = "lz4".into();
        assert!(check(&c, "u", "").is_err());
    }

    #[test]
    fn old_profile_compression_flag() {
        let c: OpenVpnConfig = serde_json::from_str(r#"{"remote":"h","compression":true}"#).unwrap();
        assert_eq!(c.compression, "comp-lzo");
        let c: OpenVpnConfig = serde_json::from_str(r#"{"compression":false}"#).unwrap();
        assert!(c.compression.is_empty());
        let c: OpenVpnConfig = serde_json::from_str(r#"{"compression":"compress stub-v2"}"#).unwrap();
        assert_eq!(c.compression, "compress stub-v2");
    }

    #[test]
    fn static_key_parsing() {
        let k = parse_static_key(&static_key(0x10).to_uppercase().replace("BEGIN OPENVPN STATIC KEY V1", "BEGIN OpenVPN Static key V1").replace("END OPENVPN STATIC KEY V1", "END OpenVPN Static key V1")).unwrap();
        assert_eq!(k[1], 0x11);
        assert!(parse_static_key("nothing").is_err());
        assert!(parse_static_key("-----BEGIN OpenVPN Static key V1-----\nzz\n").is_err());
        let bad = static_key(0).replacen("00", "0g", 1);
        assert!(parse_static_key(&bad).unwrap_err().contains("hexadécimal"));
    }
}
