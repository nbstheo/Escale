//! Sessions RDP (IronRDP) : TLS seul ou NLA (CredSSP : NTLM, ou Kerberos si un KDC est indiqué),
//! pipeline graphique RDPGFX ou ancien mode bitmap, redimensionnement dynamique ou résolution fixe,
//! curseur distant, dossier partagé et reconnexion automatique. Toutes les options viennent de
//! l'hôte (`Host::rdp`). Le flux peut passer par les rebonds SSH de l'hôte.

use crate::desktop::{CursorImage, CursorShape, DesktopCmd, DesktopHandle, Frame, Input, MouseBtn, SharedFrame};
use crate::model::{Host, RdpCompression, RdpDisplay, RdpGraphics, RdpOptions, RdpSecurity};
use crate::rdpdr::{DRIVE_ID, DRIVE_NAME, DriveBackend};
use crate::ssh::{self, Event, Events};
use eframe::egui::Color32;
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::{ClientConnector, ConnectorResult, Credentials, DesktopSize, Sequence as _, ServerName};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason, fast_path};
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::sspi::network_client::NetworkProtocol;
use ironrdp_tokio::{FramedWrite, NetworkClient, split_tokio_framed};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub fn spawn(
    chain: Vec<Host>,
    size: (u16, u16),
    share: PathBuf,
    ctx: eframe::egui::Context,
) -> DesktopHandle {
    let (tx, cmd_rx) = mpsc::unbounded_channel();
    let (events, rx) = Events::new(ctx);
    let on_spawn_error = events.clone();
    let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
    let f = frame.clone();
    let drive = Arc::new(crate::rdpdr::DriveStatus::default());
    let d = drive.clone();
    // la pile CredSSP (sspi) produit des futures non `Send` : la session tourne sur son propre fil
    let spawned = std::thread::Builder::new().name("escale-rdp".into()).spawn(move || {
        let ev = events.clone();
        let res = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            // une panique interne ferme la session avec un message au lieu d'emporter Escale
            Ok(local) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| local.block_on(run(chain, size, share, d, cmd_rx, ev, f))))
                .unwrap_or_else(|_| Err("Erreur interne : la session a été interrompue (détails dans crash.log)".into())),
            Err(e) => Err(format!("Démarrage de la session impossible : {e}")),
        };
        events.send(Event::Closed(res.err()));
    });
    if let Err(e) = spawned {
        // sans fil, l'onglet resterait « en connexion » indéfiniment
        on_spawn_error.send(Event::Closed(Some(format!("Démarrage de la session impossible : {e}"))));
    }
    DesktopHandle { tx, rx, frame, drive: Some(drive) }
}

/// Client réseau de CredSSP : transmet les requêtes Kerberos au KDC de l'hôte (sans KDC, NTLM est
/// négocié et rien n'est envoyé). Le KDC est joint directement depuis cet ordinateur, pas à travers
/// les rebonds SSH, qui ne transportent que le flux RDP : il doit être accessible d'ici.
struct Kdc;

impl NetworkClient for Kdc {
    async fn send(&mut self, req: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        let what = req.url.to_string();
        match tokio::time::timeout(std::time::Duration::from_secs(15), kdc_send(req)).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(ironrdp_connector::custom_err!("KDC", std::io::Error::new(e.kind(), format!("{what} : {e}")))),
            Err(_) => Err(ironrdp_connector::custom_err!("KDC", std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{what} : délai dépassé")))),
        }
    }
}

/// Adresse du KDC saisie pour l'hôte -> URL comprise par sspi : `dc01.corp.local`, `dc01:88`,
/// `tcp://dc01:88`, `udp://dc01`, ou l'URL d'un proxy KDC (`https://passerelle/KdcProxy`).
fn kdc_url(kdc: &str) -> Option<String> {
    let kdc = kdc.trim();
    if kdc.is_empty() {
        return None;
    }
    let url = match kdc.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if !matches!(scheme.as_str(), "tcp" | "udp" | "http" | "https") || rest.is_empty() {
                return None;
            }
            format!("{scheme}://{rest}")
        }
        None => format!("tcp://{kdc}"),
    };
    ironrdp_connector::credssp::KerberosConfig::new(Some(url.clone()), String::new())
        .ok()
        .filter(|c| c.kdc_proxy_url.as_ref().is_some_and(|u| u.host_str().is_some()))
        .map(|_| url)
}

async fn kdc_send(req: &NetworkRequest) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let host = req.url.host_str().ok_or_else(|| Error::new(ErrorKind::InvalidInput, "adresse sans hôte"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match req.protocol {
        NetworkProtocol::Tcp => {
            // message déjà préfixé par sa longueur (4 octets, gros-boutiste), réponse de même
            let mut s = tokio::net::TcpStream::connect((host, req.url.port().unwrap_or(88))).await?;
            s.write_all(&req.data).await?;
            let mut len = [0u8; 4];
            s.read_exact(&mut len).await?;
            let n = u32::from_be_bytes(len) as usize;
            if n > 1 << 20 {
                return Err(Error::new(ErrorKind::InvalidData, "réponse trop longue"));
            }
            let mut out = vec![0; 4 + n];
            out[..4].copy_from_slice(&len);
            s.read_exact(&mut out[4..]).await?;
            Ok(out)
        }
        NetworkProtocol::Udp => {
            // datagramme sans longueur ; sspi attend la réponse préfixée comme en TCP
            let addr = tokio::net::lookup_host((host, req.url.port().unwrap_or(88)))
                .await?
                .next()
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "KDC introuvable"))?;
            let local: std::net::SocketAddr = if addr.is_ipv6() { ([0u16; 8], 0).into() } else { ([0u8; 4], 0).into() };
            let sock = tokio::net::UdpSocket::bind(local).await?;
            sock.connect(addr).await?;
            sock.send(&req.data).await?;
            let mut buf = vec![0; 65536];
            let n = sock.recv(&mut buf).await?;
            let mut out = (n as u32).to_be_bytes().to_vec();
            out.extend_from_slice(&buf[..n]);
            Ok(out)
        }
        NetworkProtocol::Http | NetworkProtocol::Https => {
            let https = req.protocol == NetworkProtocol::Https;
            let port = req.url.port().unwrap_or(if https { 443 } else { 80 });
            let mut path = req.url.path().to_string();
            if let Some(q) = req.url.query() {
                path = format!("{path}?{q}");
            }
            let head = format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/kerberos\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                req.url.host_str().unwrap_or(host),
                req.data.len()
            );
            let tcp = tokio::net::TcpStream::connect((host, port)).await?;
            // proxy KDC (MS-KKDCP) : les messages Kerberos sont protégés par eux-mêmes, comme en
            // TCP / UDP direct ; TLS n'apporte ici que la confidentialité (certificat non vérifié)
            let resp = if https {
                http_exchange(ironrdp_tls::upgrade(tcp, host).await?.0, head.as_bytes(), &req.data).await?
            } else {
                http_exchange(tcp, head.as_bytes(), &req.data).await?
            };
            http_body(&resp)
        }
    }
}

async fn http_exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S, head: &[u8], body: &[u8]) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(head).await?;
    s.write_all(body).await?;
    s.flush().await?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            // fin TLS sans close_notify : la réponse est déjà complète
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !out.is_empty() => break,
            Err(e) => return Err(e),
        }
        if out.len() > 1 << 20 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "réponse trop longue"));
        }
    }
    Ok(out)
}

/// Corps d'une réponse HTTP/1.1 (longueur fixe, découpage `chunked` ou jusqu'à la fermeture).
fn http_body(resp: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    let bad = |m: &str| Error::new(ErrorKind::InvalidData, format!("proxy KDC : {m}"));
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| bad("réponse incomplète"))?;
    let head = String::from_utf8_lossy(&resp[..end]).to_ascii_lowercase();
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(bad(status));
    }
    let header = |name: &str| lines.clone().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim() == name).map(|(_, v)| v.trim().to_string()));
    let body = &resp[end + 4..];
    if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        let (mut out, mut rest) = (Vec::new(), body);
        loop {
            let eol = rest.windows(2).position(|w| w == b"\r\n").ok_or_else(|| bad("bloc incomplet"))?;
            let size = String::from_utf8_lossy(&rest[..eol]);
            let size = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16).map_err(|_| bad("taille de bloc"))?;
            rest = &rest[eol + 2..];
            if size == 0 {
                return Ok(out);
            }
            out.extend_from_slice(rest.get(..size).ok_or_else(|| bad("bloc tronqué"))?);
            rest = rest.get(size + 2..).unwrap_or_default();
        }
    }
    match header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        Some(n) => Ok(body.get(..n).ok_or_else(|| bad("corps tronqué"))?.to_vec()),
        None => Ok(body.to_vec()),
    }
}

/// Empreinte SHA-256 de la clé publique du certificat, en hexadécimal groupé.
pub fn fingerprint(public_key: &[u8]) -> String {
    let d = Sha256::digest(public_key);
    let hex: Vec<String> = d.iter().map(|b| format!("{b:02X}")).collect();
    format!("SHA256:{}", hex.join(":"))
}

fn client_name() -> String {
    let n = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "ESCALE".into());
    n.chars().take(15).collect()
}

/// Disposition clavier locale (identifiant Windows), pour que le serveur traduise les touches comme ici.
fn keyboard_layout() -> u32 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetKeyboardLayout;
        (unsafe { GetKeyboardLayout(0) } as usize & 0xFFFF) as u32
    }
    #[cfg(not(windows))]
    0x409
}

/// Mise à l'échelle annoncée au serveur, en % (100 à 500) ; 0 = celle de cet écran.
fn scale_factor(o: &RdpOptions) -> u32 {
    let s = if o.scale == 0 { system_scale() } else { o.scale };
    s.clamp(100, 500)
}

fn system_scale() -> u32 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Graphics::Gdi::{GetDC, GetDeviceCaps, LOGPIXELSX, ReleaseDC};
        // Escale est déclaré sensible au DPI (winit) : valeur réelle de l'écran principal
        let dpi = unsafe {
            let dc = GetDC(std::ptr::null_mut());
            if dc.is_null() {
                return 100;
            }
            let dpi = GetDeviceCaps(dc, LOGPIXELSX as _);
            ReleaseDC(std::ptr::null_mut(), dc);
            dpi
        };
        if dpi > 0 { (dpi as u32 * 100 + 48) / 96 } else { 100 }
    }
    #[cfg(not(windows))]
    100
}

/// Taille de bureau demandée à la connexion : celle de la fenêtre, ou la résolution fixe de l'hôte
/// (largeur paire, 200 à 8192 pixels, comme l'exige le redimensionnement dynamique).
fn initial_size(o: &RdpOptions, window: (u16, u16)) -> (u16, u16) {
    if let Some(l) = multimon_layout(o) {
        return l.size();
    }
    let (w, h) = match o.display {
        RdpDisplay::Dynamic => return dynamic_size(window.0, window.1),
        RdpDisplay::FixedFit | RdpDisplay::FixedNative => (o.width as u32, o.height as u32),
    };
    let (w, h) = MonitorLayoutEntry::adjust_display_size(w, h);
    (w as u16, h as u16)
}

/// Écrans couverts par une session étendue à tous les écrans (option de l'hôte), sinon `None`.
fn multimon_layout(o: &RdpOptions) -> Option<crate::monitors::Layout> {
    if o.multimon { crate::monitors::layout(&o.screens) } else { None }
}

/// Le bureau distant suit la taille de la fenêtre (jamais pour une session sur tous les écrans,
/// dont la disposition est fixée à la connexion).
fn is_dynamic(o: &RdpOptions) -> bool {
    o.display == RdpDisplay::Dynamic && !o.multimon
}

/// Écrans annoncés au serveur (bloc GCC) : coordonnées du bureau virtuel de Windows décalées pour
/// que l'écran principal distant commence en (0, 0), bords inclusifs. Un seul écran : rien (la
/// taille du bureau suffit).
fn gcc_monitors(layout: Option<&crate::monitors::Layout>) -> Vec<ironrdp_pdu::gcc::Monitor> {
    use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
    match layout {
        Some(l) if l.screens.len() > 1 => l
            .screens
            .iter()
            .map(|s| Monitor {
                left: s.left - l.primary().left,
                top: s.top - l.primary().top,
                right: s.right - 1 - l.primary().left,
                bottom: s.bottom - 1 - l.primary().top,
                flags: if s.primary { MonitorFlags::PRIMARY } else { MonitorFlags::empty() },
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Taille de la fenêtre bornée à ce qu'accepte un serveur (fenêtre réduite : 0 × 0).
fn dynamic_size(w: u16, h: u16) -> (u16, u16) {
    (w.clamp(200, 8192), h.clamp(200, 8192))
}

/// Utilisateur et domaine envoyés au serveur. `CORP\alice` saisi dans le champ utilisateur est
/// découpé (son domaine l'emporte) ; un UPN (`alice@corp.local`) part tel quel, sans domaine :
/// sspi refuse le mélange des deux formes.
fn user_domain(host: &Host) -> (String, Option<String>) {
    let user = host.username.trim();
    if let Some((d, u)) = user.split_once('\\')
        && !d.is_empty()
        && !u.is_empty()
    {
        return (u.to_string(), Some(d.to_string()));
    }
    let domain = host.domain.trim();
    if user.contains('@') || domain.is_empty() {
        return (user.to_string(), None);
    }
    (user.to_string(), Some(domain.to_string()))
}

/// Nom du serveur pour TLS (SNI, aucun pour une IP) et CredSSP (SPN `TERMSRV/…`) : sans crochets
/// IPv6 ni port saisi dans l'adresse.
fn server_name(hostname: &str, port: u16) -> String {
    ssh::endpoint(hostname, port).0
}

fn compression_type(c: RdpCompression) -> Option<ironrdp_pdu::rdp::client_info::CompressionType> {
    use ironrdp_pdu::rdp::client_info::CompressionType as C;
    match c {
        RdpCompression::None => None,
        RdpCompression::K8 => Some(C::K8),
        RdpCompression::K64 => Some(C::K64),
        RdpCompression::Rdp6 => Some(C::Rdp6),
        RdpCompression::Rdp61 => Some(C::Rdp61),
    }
}

fn performance_flags(o: &RdpOptions) -> ironrdp_pdu::rdp::client_info::PerformanceFlags {
    use ironrdp_pdu::rdp::client_info::PerformanceFlags as P;
    let mut f = P::DISABLE_CURSOR_SHADOW;
    for (on, flag) in [
        (!o.wallpaper, P::DISABLE_WALLPAPER),
        (!o.full_window_drag, P::DISABLE_FULLWINDOWDRAG),
        (!o.menu_animations, P::DISABLE_MENUANIMATIONS),
        (!o.themes, P::DISABLE_THEMING),
        (o.font_smoothing, P::ENABLE_FONT_SMOOTHING),
        (o.desktop_composition, P::ENABLE_DESKTOP_COMPOSITION),
    ] {
        if on {
            f |= flag;
        }
    }
    f
}

fn connector_config(host: &Host, size: (u16, u16)) -> ironrdp_connector::Config {
    use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, client_codecs_capabilities};
    use ironrdp_pdu::rdp::client_info::TimezoneInfo;
    let o = &host.rdp;
    let gfx = o.graphics != RdpGraphics::Legacy;
    // le pipeline graphique exige une session 32 bits ; la profondeur choisie vaut pour l'ancien mode
    let color_depth = match o.color_depth {
        15 | 16 | 24 if !gfx => o.color_depth as u32,
        _ => 32,
    };
    let nla = o.security == RdpSecurity::Nla;
    let (username, domain) = user_domain(host);
    // tous les écrans : disposition relevée à chaque connexion (reconnexion comprise)
    let layout = multimon_layout(o);
    let size = layout.as_ref().map_or(size, |l| l.size());
    ironrdp_connector::Config {
        credentials: Credentials::UsernamePassword { username, password: host.password.clone() },
        domain,
        // NLA : TLS reste proposé pour les serveurs qui ne savent pas faire mieux (comme mstsc) ;
        // TLS seul : l'écran d'ouverture de session de Windows s'affiche
        enable_tls: true,
        enable_credssp: nla,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: if o.keyboard_layout == 0 { keyboard_layout() } else { o.keyboard_layout },
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width: size.0, height: size.1 },
        desktop_scale_factor: scale_factor(o),
        bitmap: Some(ironrdp_connector::BitmapConfig {
            color_depth,
            lossy_compression: true,
            // ancien mode : RemoteFX (surfaces), sinon Planar (32 bits) / RLE entrelacé (15 à 24 bits)
            // ou non compressé. NSCodec n'est pas annoncé : IronRDP ne sait pas le décoder.
            codecs: client_codecs_capabilities(&[]).unwrap_or_default(),
        }),
        // valeurs d'un mstsc récent (Windows 11)
        client_build: 22621,
        client_name: client_name(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".into(),
        platform: MajorPlatformType::WINDOWS,
        hardware_id: None,
        license_cache: None,
        enable_server_pointer: o.server_pointer,
        // sans mot de passe, l'écran d'ouverture de session de Windows s'affiche (TLS seul)
        autologon: !host.password.is_empty(),
        enable_audio_playback: host.rdp.audio == crate::model::RdpAudio::Local,
        remote_audio: host.rdp.audio == crate::model::RdpAudio::Remote,
        enable_audio_capture: host.rdp.microphone,
        enable_gfx: gfx,
        console_session: o.admin,
        monitors: gcc_monitors(layout.as_ref()),
        request_data: None,
        pointer_software_rendering: false,
        multitransport_flags: None,
        compression_type: compression_type(o.compression),
        performance_flags: performance_flags(o),
        timezone_info: TimezoneInfo::default(),
        alternate_shell: o.alternate_shell.trim().to_string(),
        work_dir: o.work_dir.trim().to_string(),
    }
}

/// Message lisible pour une erreur de connexion IronRDP.
fn describe(host: &Host, e: &ironrdp_connector::ConnectorError) -> String {
    use ironrdp_connector::ConnectorErrorKind as K;
    use ironrdp_connector::sspi::ErrorKind as S;
    match e.kind() {
        K::Credssp(s) => match s.error_type {
            S::LogonDenied | S::WrongCredentialHandle | S::InvalidToken | S::NoCredentials | S::MessageAltered => {
                format!("Authentification refusée pour {}", host.username)
            }
            _ => format!("Authentification NLA impossible : {}", s.description),
        },
        K::AccessDenied => "Accès refusé : l'utilisateur n'a pas le droit d'ouvrir une session Bureau à distance".into(),
        K::Negotiation(f) => format!("Négociation refusée par le serveur : {f}"),
        K::Reason(r) => format!("Connexion RDP refusée : {r}"),
        _ => {
            // cause la plus profonde, sans le contexte technique (fichier source…)
            let mut msg = e.kind().to_string();
            let mut src = std::error::Error::source(e.kind());
            while let Some(s) = src {
                msg = s.to_string();
                src = s.source();
            }
            format!("Connexion RDP : {msg}")
        }
    }
}

fn copy_region(image: &DecodedImage, frame: &SharedFrame, r: &InclusiveRectangle) {
    let Ok(mut f) = frame.lock() else { return };
    let (w, h) = (image.width() as usize, image.height() as usize);
    f.resize(w, h);
    let data = image.data();
    let stride = image.stride();
    let (x0, y0) = (r.left as usize, r.top as usize);
    let (x1, y1) = ((r.right as usize + 1).min(w), (r.bottom as usize + 1).min(h));
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    // ligne par ligne, sans indexation par pixel : la conversion RGBA -> Color32 se vectorise
    for y in y0..y1 {
        let src = &data[y * stride + x0 * 4..][..(x1 - x0) * 4];
        let dst = &mut f.pixels[y * w + x0..y * w + x1];
        for (d, s) in dst.iter_mut().zip(src.as_chunks::<4>().0) {
            *d = Color32::from_rgb(s[0], s[1], s[2]);
        }
    }
    f.mark(x0, y0, x1, y1);
}

/// Déplacements de souris consécutifs réduits au dernier : une file en retard (décodage d'une
/// grosse image) n'envoie pas au serveur une traîne de positions périmées. Les déplacements
/// séparés par un clic, une touche… sont gardés (le clic doit tomber au bon endroit).
fn coalesce_moves(input: &mut Vec<Input>) {
    let mut out: Vec<Input> = Vec::with_capacity(input.len());
    for i in input.drain(..) {
        if let (Input::Mouse { .. }, Some(Input::Mouse { .. })) = (&i, out.last()) {
            out.pop();
        }
        out.push(i);
    }
    *input = out;
}

/// Prochaine commande de l'interface : celle mise de côté d'abord, puis la file. Les lots d'entrées
/// déjà en attente sont réunis en un seul (déplacements de souris réduits au dernier).
async fn next_cmd(deferred: &mut Option<DesktopCmd>, rx: &mut mpsc::UnboundedReceiver<DesktopCmd>) -> Option<DesktopCmd> {
    let cmd = match deferred.take() {
        Some(c) => c,
        None => rx.recv().await?,
    };
    let DesktopCmd::Input(mut list) = cmd else { return Some(cmd) };
    while let Ok(more) = rx.try_recv() {
        match more {
            DesktopCmd::Input(l) => list.extend(l),
            other => {
                *deferred = Some(other);
                break;
            }
        }
    }
    coalesce_moves(&mut list);
    Some(DesktopCmd::Input(list))
}

fn whole(image: &DecodedImage) -> InclusiveRectangle {
    InclusiveRectangle { left: 0, top: 0, right: image.width().saturating_sub(1), bottom: image.height().saturating_sub(1) }
}

/// Entrées neutres -> événements RDP, dans l'ordre (l'état des touches est suivi par `db`).
fn to_fastpath(input: Vec<Input>, db: &mut Database) -> Vec<FastPathInputEvent> {
    let mut out = Vec::new();
    for i in input {
        let ops = match i {
            Input::Mouse { x, y } => vec![Operation::MouseMove(MousePosition { x, y })],
            Input::Button { button, down } => {
                let b = match button {
                    MouseBtn::Left => ironrdp_input::MouseButton::Left,
                    MouseBtn::Middle => ironrdp_input::MouseButton::Middle,
                    MouseBtn::Right => ironrdp_input::MouseButton::Right,
                    MouseBtn::X1 => ironrdp_input::MouseButton::X1,
                    MouseBtn::X2 => ironrdp_input::MouseButton::X2,
                };
                vec![if down { Operation::MouseButtonPressed(b) } else { Operation::MouseButtonReleased(b) }]
            }
            Input::Wheel { vertical, units } => vec![Operation::WheelRotations(WheelRotations { is_vertical: vertical, rotation_units: units })],
            // Pause : Ctrl préfixé E1 + Verr. Num, appui et relâchement d'un coup, rien au relâchement
            Input::Scancode { code: crate::desktop::PAUSE, down } => {
                if down {
                    use ironrdp_pdu::input::fast_path::KeyboardFlags as F;
                    out.extend([
                        FastPathInputEvent::KeyboardEvent(F::EXTENDED1, 0x1D),
                        FastPathInputEvent::KeyboardEvent(F::empty(), 0x45),
                        FastPathInputEvent::KeyboardEvent(F::EXTENDED1 | F::RELEASE, 0x1D),
                        FastPathInputEvent::KeyboardEvent(F::RELEASE, 0x45),
                    ]);
                }
                continue;
            }
            Input::Scancode { code, down } => {
                let s = Scancode::from_u16(code);
                // répétition automatique : nouvel appui sans relâchement, comme mstsc. IronRDP
                // intercalerait un relâchement : Win maintenue ouvrait le menu Démarrer distant,
                // Alt maintenue son menu, et les combinaisons en cours étaient rompues.
                if down && db.is_key_pressed(s) {
                    use ironrdp_pdu::input::fast_path::KeyboardFlags as F;
                    let (ext, c) = s.as_u8();
                    out.push(FastPathInputEvent::KeyboardEvent(if ext { F::EXTENDED } else { F::empty() }, c));
                    continue;
                }
                vec![if down { Operation::KeyPressed(s) } else { Operation::KeyReleased(s) }]
            }
            Input::Locks(l) => {
                out.push(ironrdp_input::synchronize_event(l.scroll, l.num, l.caps, false));
                continue;
            }
            Input::Text(t) => {
                // modificateurs relâchés d'abord : le texte ne doit pas devenir une suite de raccourcis
                let mut ops: Vec<Operation> = [0x1D, 0xE01D, 0x2A, 0x36, 0x38, 0xE038, 0xE05B, 0xE05C]
                    .into_iter()
                    .map(Scancode::from_u16)
                    .filter(|s| db.is_key_pressed(*s))
                    .map(Operation::KeyReleased)
                    .collect();
                for c in t.replace("\r\n", "\n").chars() {
                    if c == '\n' || c == '\r' {
                        // Entrée par sa touche : certaines applications ignorent l'Unicode 0x0D
                        ops.push(Operation::KeyPressed(Scancode::from_u16(0x1C)));
                        ops.push(Operation::KeyReleased(Scancode::from_u16(0x1C)));
                    } else {
                        ops.push(Operation::UnicodeKeyPressed(c));
                        ops.push(Operation::UnicodeKeyReleased(c));
                    }
                }
                ops
            }
            Input::Keysym { .. } => continue,
            Input::ReleaseAll => {
                out.extend(db.release_all());
                continue;
            }
        };
        out.extend(db.apply(ops));
    }
    out
}

/// État conservé d'une connexion à l'autre (reconnexion automatique).
struct Conn {
    /// Taille de bureau à demander (suit les redimensionnements en mode dynamique).
    size: (u16, u16),
    /// La session a atteint l'état connecté.
    connected: bool,
    /// La dernière erreur est une coupure réseau : une reconnexion peut réussir.
    lost: bool,
    /// Empreinte du certificat acceptée : pas de nouvelle question à la reconnexion.
    known_key: Option<String>,
}

impl Conn {
    fn new(size: (u16, u16)) -> Self {
        Self { size, connected: false, lost: false, known_key: None }
    }
}

/// Tentatives de reconnexion après une coupure, et délai avant chacune.
const RECONNECT_DELAYS: [u64; 5] = [1, 2, 4, 8, 15];

/// Délai de chaque étape réseau de la connexion (négociation, TLS) ; l'authentification, qui peut
/// interroger un KDC, a droit à plus. L'invite du certificat, elle, attend l'utilisateur.
const STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Attend la fermeture de l'onglet tant que la session n'est pas ouverte : les entrées sont
/// écartées, la dernière taille de fenêtre est retenue. Annulable sans perte.
async fn until_closed(cmd_rx: &mut mpsc::UnboundedReceiver<DesktopCmd>, resized: &mut Option<(u16, u16)>) {
    loop {
        match cmd_rx.recv().await {
            Some(DesktopCmd::Close) | None => return,
            Some(DesktopCmd::Resize(w, h)) => *resized = Some(dynamic_size(w, h)),
            Some(_) => {}
        }
    }
}

async fn run(
    mut chain: Vec<Host>,
    size: (u16, u16),
    share: PathBuf,
    drive: Arc<crate::rdpdr::DriveStatus>,
    mut cmd_rx: mpsc::UnboundedReceiver<DesktopCmd>,
    events: Events,
    frame: SharedFrame,
) -> Result<(), String> {
    let mut target = chain.last().ok_or("Aucun hôte")?.clone();
    let mut conn = Conn::new(initial_size(&target.rdp, size));
    let mut attempt = 0;
    let dynamic = is_dynamic(&target.rdp);
    loop {
        conn.connected = false;
        conn.lost = false;
        // les empreintes des rebonds acceptées restent dans `chain` : pas de nouvelle question à la
        // reconnexion ; la fermeture de l'onglet interrompt l'attente (rebond ou hôte injoignable)
        let mut resized = None;
        let opened = tokio::select! {
            r = ssh::open_stream_learning(&mut chain, &events) => r,
            () = until_closed(&mut cmd_rx, &mut resized) => return Ok(()),
        };
        if let Some(s) = resized.filter(|_| dynamic) {
            conn.size = s;
        }
        let res = match opened {
            Ok((stream, jumps)) => {
                let r = session(&target, stream, &mut conn, share.clone(), drive.clone(), &mut cmd_rx, &events, &frame).await;
                ssh::disconnect(&jumps).await;
                r
            }
            // hôte injoignable pendant une reconnexion : on réessaie, sauf clé ou identifiants refusés
            Err((e, definitive)) => {
                conn.lost = attempt > 0 && !definitive;
                Err(e)
            }
        };
        if let Some(k) = conn.known_key.take() {
            target.known_key = Some(k);
        }
        let Err(e) = res else { return Ok(()) };
        // seules les coupures réseau d'une session déjà ouverte sont rattrapées : une erreur
        // d'authentification, un certificat refusé ou une fermeture par le serveur sont définitifs
        if conn.connected {
            attempt = 0;
        }
        if !target.rdp.auto_reconnect || !conn.lost || (attempt == 0 && !conn.connected) || attempt >= RECONNECT_DELAYS.len() {
            return Err(e);
        }
        let delay = std::time::Duration::from_secs(RECONNECT_DELAYS[attempt]);
        attempt += 1;
        events.send(Event::Status(format!("Reconnexion… ({e}) — tentative {attempt}/{}", RECONNECT_DELAYS.len())));
        let until = tokio::time::Instant::now() + delay;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break,
                cmd = cmd_rx.recv() => match cmd {
                    Some(DesktopCmd::Close) | None => return Ok(()),
                    Some(DesktopCmd::Resize(w, h)) if dynamic => conn.size = dynamic_size(w, h),
                    // entrées perdues pendant la coupure
                    Some(_) => {}
                },
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn session(
    host: &Host,
    stream: Box<dyn ssh::Stream>,
    conn: &mut Conn,
    share: PathBuf,
    drive: Arc<crate::rdpdr::DriveStatus>,
    cmd_rx: &mut mpsc::UnboundedReceiver<DesktopCmd>,
    events: &Events,
    frame: &SharedFrame,
) -> Result<(), String> {
    let fail = |what: &str, e: &dyn std::fmt::Display| format!("{what} : {e}");
    let o = &host.rdp;
    if o.drive {
        let _ = std::fs::create_dir_all(&share);
    }

    // --- connexion : négociation, TLS, vérification du certificat, NLA
    let config = connector_config(host, conn.size);
    let scale = config.desktop_scale_factor;
    // Kerberos si un KDC est indiqué (NLA seulement), sinon NTLM
    let kerberos = match kdc_url(&o.kdc) {
        Some(url) => Some(ironrdp_connector::credssp::KerberosConfig::new(Some(url), client_name()).map_err(|e| describe(host, &e))?),
        None if o.kdc.trim().is_empty() => None,
        None => return Err(format!("Adresse du KDC invalide : {}", o.kdc.trim())),
    };
    // pipeline graphique moderne (H.264…) : utilisé si le serveur l'accepte, sinon ancien mode
    let gfx_state = Arc::new(crate::gfx::GfxState::default());
    let mut drdynvc = ironrdp_dvc::DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let codecs = match o.graphics {
        RdpGraphics::Auto => Some(crate::gfx::Codecs::Avc444),
        RdpGraphics::RemoteFx => Some(crate::gfx::Codecs::NoAvc),
        RdpGraphics::Legacy => None,
    };
    if let Some(codecs) = codecs {
        drdynvc = drdynvc.with_dynamic_channel(crate::gfx::channel(frame.clone(), events.clone(), gfx_state.clone(), codecs));
    }
    // micro (MS-RDPEAI) : paquets capturés transmis par la boucle de session
    let (mic_tx, mut mic_rx) = mpsc::channel(64);
    // écouteur : Windows ferme et rouvre AUDIO_INPUT à chaque application qui enregistre, un
    // processeur enregistré une fois serait détruit à la première fermeture
    if let Some(l) = crate::audin::listener(host, mic_tx) {
        drdynvc = drdynvc.with_listener(l);
    }
    let client = config.client_name.clone();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let mut connector = ClientConnector::new(config, addr).with_static_channel(drdynvc);
    // dossier partagé (MS-RDPEFS) : canal seulement si l'hôte le demande
    if o.drive {
        let rdpdr = ironrdp_rdpdr::Rdpdr::new(Box::new(DriveBackend::new(share, drive)), client)
            .with_drives(Some(vec![(DRIVE_ID, DRIVE_NAME.to_owned())]));
        connector.attach_static_channel(crate::rdpdr::SafeRdpdr(rdpdr));
    }
    // son (MS-RDPEA) : canal seulement s'il est joué ici
    if let Some(snd) = crate::rdpsnd::channel(host) {
        connector.attach_static_channel(snd);
    }
    // presse-papiers partagé (MS-RDPECLIP)
    let mut clip = None;
    if host.rdp.clipboard
        && let Some((svc, link)) = crate::rdpclip::open(host)
    {
        connector.attach_static_channel(svc);
        clip = Some(link);
    }

    // coupure réseau pendant la connexion : seule erreur qui autorise une nouvelle tentative
    let connect_err = |conn: &mut Conn, e: &ironrdp_connector::ConnectorError| {
        conn.lost = is_network(e);
        describe(host, e)
    };
    let timed_out = |conn: &mut Conn| {
        conn.lost = true;
        format!("Délai dépassé : {} ne répond pas", host.hostname)
    };
    let name = server_name(&host.hostname, host.port);
    // la fermeture de l'onglet interrompt la connexion (serveur muet, invite du certificat…) ; une
    // taille de fenêtre demandée entre-temps est appliquée dès l'ouverture du canal d'affichage
    let mut resized = None;
    let (result, framed) = {
        let connecting = async {
            let mut framed = ironrdp_tokio::TokioFramed::new(stream);
            let should_upgrade = match tokio::time::timeout(STEP_TIMEOUT, ironrdp_tokio::connect_begin(&mut framed, &mut connector)).await {
                Ok(Ok(u)) => u,
                Ok(Err(e)) => return Err(connect_err(conn, &e)),
                Err(_) => return Err(timed_out(conn)),
            };
            let (stream, leftover) = framed.into_inner();
            let (tls, cert) = match tokio::time::timeout(STEP_TIMEOUT, ironrdp_tls::upgrade(stream, &name)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    conn.lost = true;
                    return Err(fail("TLS", &e));
                }
                Err(_) => return Err(timed_out(conn)),
            };
            let public_key = ironrdp_tls::extract_tls_server_public_key(&cert)
                .ok_or("Clé publique du certificat illisible")?
                .to_owned();
            // le certificat est vérifié avant d'envoyer le moindre identifiant (TOFU, comme SSH)
            let fp = fingerprint(&public_key);
            let mut checked = host.clone();
            if conn.known_key.is_some() {
                checked.known_key = conn.known_key.clone();
            }
            if !events.verify(&checked, fp.clone()).await {
                return Err(format!("Certificat refusé pour {}", host.hostname));
            }
            conn.known_key = Some(fp);
            let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
            let mut framed = ironrdp_tokio::TokioFramed::new_with_leftover(tls, leftover);
            events.send(Event::Status(format!("Authentification sur {}…", host.address())));
            let mut kdc = Kdc;
            let finalize =
                ironrdp_tokio::connect_finalize(upgraded, connector, &mut framed, &mut kdc, ServerName::new(name.clone()), public_key, kerberos);
            match tokio::time::timeout(AUTH_TIMEOUT, finalize).await {
                Ok(Ok(r)) => Ok((r, framed)),
                Ok(Err(e)) => Err(connect_err(conn, &e)),
                Err(_) => Err(timed_out(conn)),
            }
        };
        tokio::select! {
            r = connecting => r?,
            () = until_closed(cmd_rx, &mut resized) => return Ok(()),
        }
    };
    conn.connected = true;
    events.send(Event::Connected);

    // --- session active
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let ds = result.desktop_size;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, ds.width, ds.height);
    if let Ok(mut f) = frame.lock() {
        f.resize(ds.width as usize, ds.height as usize);
    }
    let activation = result.activation_factory;
    let compression = result.compression_type;
    let mut stage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();
    let mut db = Database::new();
    // redimensionnement en attente (mode dynamique) : envoyé dès que le canal d'affichage est ouvert
    let mut pending = resized.filter(|_| is_dynamic(o));
    if let Some(s) = pending {
        conn.size = s;
        if MonitorLayoutEntry::adjust_display_size(s.0 as u32, s.1 as u32) == (ds.width as u32, ds.height as u32) {
            pending = None;
        }
    }

    // messages illisibles du serveur reçus d'affilée (cf. `tolerate`)
    let mut bad_pdus = 0u32;
    // fermeture demandée : le serveur peut couper la connexion sans message de fin
    let mut closing: Option<tokio::time::Instant> = None;
    // commande lue en avance par `next_cmd` (après un lot d'entrées) ; d'abord les verrous de cet
    // ordinateur (Verr. Num allumé par défaut) : sans cette synchronisation, le serveur garde les
    // siens et le pavé numérique envoie flèches, Origine, Fin… au lieu des chiffres
    let mut deferred: Option<DesktopCmd> = Some(DesktopCmd::Input(vec![Input::Locks(crate::desktop::current_locks())]));
    let reason = 'outer: loop {
        let mut outputs = tokio::select! {
            pdu = reader.read_pdu() => {
                let (action, payload) = match pdu {
                    Ok(p) => p,
                    Err(_) if closing.is_some() => break 'outer GracefulDisconnectReason::UserInitiated,
                    Err(e) => {
                        conn.lost = true;
                        return Err(fail("Connexion perdue", &e));
                    }
                };
                tolerate(stage.process(&mut image, action, &payload), &mut bad_pdus)?
            }
            _ = tokio::time::sleep_until(closing.unwrap_or_else(tokio::time::Instant::now)), if closing.is_some() => {
                break 'outer GracefulDisconnectReason::UserInitiated
            }
            // son capturé par le micro
            Some(pcm) = mic_rx.recv(), if closing.is_none() => crate::audin::send(&mut stage, pcm),
            // presse-papiers : copie locale annoncée, données demandées ou fournies
            ev = crate::rdpclip::recv(&mut clip), if closing.is_none() => soft("presse-papiers", crate::rdpclip::process(&mut stage, ev)),
            cmd = next_cmd(&mut deferred, cmd_rx), if closing.is_none() => match cmd {
                Some(DesktopCmd::Input(list)) => {
                    let fp = to_fastpath(list, &mut db);
                    soft("entrées", send_input(&mut stage, &mut image, &fp))
                }
                // résolution fixe : la fenêtre met l'image à l'échelle, le bureau distant ne change pas
                Some(DesktopCmd::Resize(..)) if !is_dynamic(o) => Vec::new(),
                Some(DesktopCmd::Resize(w, h)) => {
                    conn.size = dynamic_size(w, h);
                    pending = Some(conn.size);
                    Vec::new()
                }
                Some(DesktopCmd::Close) | None => {
                    closing = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(2));
                    // sans message de fin, le serveur verra simplement la connexion se fermer
                    soft("fermeture", stage.graceful_shutdown())
                }
            },
        };
        // canal d'affichage dynamique pas encore ouvert : la demande attend (sans lui, l'image est
        // simplement mise à l'échelle) ; elle part après les sorties déjà produites
        if let Some((w, h)) = pending
            && closing.is_none()
            && let Some(r) = resize_frame(&mut stage, w, h, scale)
        {
            pending = None;
            match r {
                Ok(f) => outputs.push(ActiveStageOutput::ResponseFrame(f)),
                Err(e) => log_error(&format!("redimensionnement ignoré : {e} — {e:?}")),
            }
        }

        // ancien mode : un seul rafraîchissement pour toutes les zones d'un message
        let mut drawn = false;
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(f) => {
                    if let Err(e) = writer.write_all(&f).await {
                        conn.lost = true;
                        return Err(fail("Connexion perdue", &e));
                    }
                }
                ActiveStageOutput::GraphicsUpdate(r) => {
                    // ancien mode seulement : en RDPGFX, l'image vient du compositeur
                    if !gfx_state.active() {
                        copy_region(&image, frame, &r);
                        drawn = true;
                    }
                }
                ActiveStageOutput::PointerDefault => set_cursor(frame, events, CursorShape::Default),
                ActiveStageOutput::PointerHidden => set_cursor(frame, events, CursorShape::Hidden),
                ActiveStageOutput::PointerPosition { .. } => {}
                ActiveStageOutput::PointerBitmap(p) => {
                    let pixels = p.bitmap_data.as_chunks::<4>().0.iter().map(|c| Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3])).collect();
                    let img = CursorImage { size: [p.width as usize, p.height as usize], hotspot: [p.hotspot_x, p.hotspot_y], pixels };
                    set_cursor(frame, events, CursorShape::Bitmap(Arc::new(img)));
                }
                ActiveStageOutput::DeactivateAll => {
                    // séquence de désactivation / réactivation (changement de résolution, etc.)
                    let mut seq = activation.create();
                    let io_channel = seq.io_channel_id();
                    let mut buf = WriteBuf::new();
                    loop {
                        buf.clear();
                        let step = if seq.next_pdu_hint().is_some() {
                            let (action, payload) = match reader.read_pdu().await {
                                Ok(p) => p,
                                Err(e) => {
                                    conn.lost = true;
                                    return Err(fail("Réactivation", &e));
                                }
                            };
                            match reactivation_pdu(io_channel, action, &payload) {
                                Reactivation::Sequence => seq.step(&payload, &mut buf),
                                // canal statique (son, presse-papiers, canaux dynamiques…) encore
                                // actif : traité comme en session, la réactivation continue
                                Reactivation::Channel => {
                                    for out in tolerate(stage.process(&mut image, action, &payload), &mut bad_pdus)? {
                                        match out {
                                            ActiveStageOutput::ResponseFrame(f) => {
                                                if let Err(e) = writer.write_all(&f).await {
                                                    conn.lost = true;
                                                    return Err(fail("Connexion perdue", &e));
                                                }
                                            }
                                            ActiveStageOutput::Terminate(reason) => break 'outer reason,
                                            _ => {}
                                        }
                                    }
                                    continue;
                                }
                                Reactivation::Ignore => continue,
                            }
                        } else {
                            seq.step_no_input(&mut buf)
                        };
                        let written = match step {
                            Ok(w) => w,
                            Err(e) => {
                                conn.lost = is_network(&e);
                                return Err(fail("Réactivation", &e));
                            }
                        };
                        if written.size().is_some()
                            && let Err(e) = writer.write_all(buf.filled()).await
                        {
                            conn.lost = true;
                            return Err(fail("Réactivation", &e));
                        }
                        if let ConnectionActivationState::Finalized { desktop_size, share_id, enable_server_pointer, pointer_software_rendering } =
                            seq.connection_activation_state()
                        {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            if !gfx_state.active() {
                                copy_region(&image, frame, &whole(&image));
                            }
                            stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: seq.io_channel_id(),
                                    user_channel_id: seq.user_channel_id(),
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    // même compression qu'à la connexion : sans décompresseur, la
                                    // première image compressée après un redimensionnement est illisible
                                    bulk_decompressor: compression.and_then(bulk_decompressor),
                                }
                                .build(),
                            );
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            events.repaint();
                            break;
                        }
                    }
                }
                ActiveStageOutput::Terminate(reason) => break 'outer reason,
                _ => {}
            }
        }
        if drawn {
            events.repaint();
        }
    };
    match reason {
        GracefulDisconnectReason::UserInitiated => Ok(()),
        GracefulDisconnectReason::ServerInitiated => Err("Session fermée par le serveur".into()),
        GracefulDisconnectReason::Other(r) => server_closed(&r),
    }
}

/// Fin de session annoncée par le serveur (Set Error Info, MS-RDPBCGR 2.2.5.1.1), en clair. Jamais
/// suivie d'une reconnexion : la session a été reprise, fermée ou refusée volontairement.
fn server_closed(description: &str) -> Result<(), String> {
    use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode as C};
    let known = [
        (C::RpcInitiatedDisconnect, "Session déconnectée par un administrateur du serveur"),
        (C::RpcInitiatedLogoff, "Session fermée par un administrateur du serveur"),
        (C::IdleTimeout, "Session déconnectée : délai d'inactivité du serveur dépassé"),
        (C::LogonTimeout, "Session déconnectée : durée maximale de session atteinte"),
        (C::DisconnectedByOtherconnection, "Session reprise par une autre connexion"),
        (C::OutOfMemory, "Le serveur manque de mémoire"),
        (C::ServerDeniedConnection, "Connexion refusée par le serveur"),
        (C::ServerInsufficientPrivileges, "Droits insuffisants pour ouvrir une session sur ce serveur"),
        (C::ServerFreshCredentialsRequired, "Le serveur exige la saisie des identifiants à chaque connexion"),
        // déconnexion ou fermeture de session demandée depuis la session elle-même : fin normale
        (C::RpcInitiatedDisconnectByuser, ""),
        (C::LogoffByUser, ""),
    ];
    match known.into_iter().find(|(c, _)| ErrorInfo::ProtocolIndependentCode(*c).description() == description) {
        Some((_, "")) => Ok(()),
        Some((_, msg)) => Err(msg.to_string()),
        None => Err(format!("Session fermée par le serveur : {description}")),
    }
}

/// Destination d'un PDU reçu pendant une réactivation.
#[derive(Debug, PartialEq)]
enum Reactivation {
    /// Séquence de réactivation (canal d'E/S), ou illisible : la séquence signale l'erreur.
    Sequence,
    /// Autre canal statique : traité par la session.
    Channel,
    /// Mise à jour graphique rapide de l'ancien bureau.
    Ignore,
}

fn reactivation_pdu(io_channel: u16, action: ironrdp_pdu::Action, payload: &[u8]) -> Reactivation {
    if action == ironrdp_pdu::Action::FastPath {
        return Reactivation::Ignore;
    }
    match ironrdp_pdu::mcs::decode_send_data_indication(payload) {
        Ok(ctx) if ctx.channel_id != io_channel => Reactivation::Channel,
        _ => Reactivation::Sequence,
    }
}

/// Erreur due au réseau (connexion coupée, refusée, délai dépassé…) plutôt qu'au protocole ou à
/// l'authentification.
fn is_network(e: &ironrdp_connector::ConnectorError) -> bool {
    use ironrdp_connector::ConnectorErrorKind as K;
    if matches!(e.kind(), K::Credssp(_) | K::AccessDenied | K::Negotiation(_) | K::Reason(_)) {
        return false;
    }
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e.kind());
    while let Some(s) = src {
        if s.downcast_ref::<std::io::Error>().is_some() {
            return true;
        }
        src = s.source();
    }
    false
}

/// Nouvelle disposition d'écran (MS-RDPEDISP) avec la mise à l'échelle de l'hôte ; `None` tant que
/// le canal d'affichage dynamique n'est pas ouvert.
/// Messages illisibles d'affilée au-delà desquels la session est quand même fermée.
const MAX_BAD_PDUS: u32 = 32;

/// Résultat du traitement d'un message du serveur. Un message illisible (type que IronRDP ne gère
/// pas, données compressées sur un chemin qui ne les décompresse pas, presse-papiers…) est ignoré
/// et consigné dans `rdp.log` au lieu de couper la session ; seule une suite ininterrompue d'erreurs
/// la ferme. Les vraies fins de session arrivent par `Terminate` ou une erreur de lecture.
fn tolerate(res: ironrdp_session::SessionResult<Vec<ActiveStageOutput>>, bad: &mut u32) -> Result<Vec<ActiveStageOutput>, String> {
    match res {
        Ok(out) => {
            *bad = 0;
            Ok(out)
        }
        Err(e) => {
            *bad += 1;
            log_error(&format!("message ignoré ({}/{MAX_BAD_PDUS}) : {e} — {e:?}", *bad));
            if *bad >= MAX_BAD_PDUS { Err(e.to_string()) } else { Ok(Vec::new()) }
        }
    }
}

/// Événements par message d'entrée rapide : IronRDP en refuse plus de 255 (`FastPathInput::new`,
/// signalé comme « decode error »), ce que dépasse un collage de plus de 127 caractères.
const MAX_INPUT_EVENTS: usize = 255;

/// Entrées clavier / souris découpées en messages acceptés par IronRDP.
fn send_input(stage: &mut ironrdp_session::ActiveStage, image: &mut DecodedImage, fp: &[FastPathInputEvent]) -> ironrdp_session::SessionResult<Vec<ActiveStageOutput>> {
    let mut out = Vec::new();
    for chunk in fp.chunks(MAX_INPUT_EVENTS) {
        out.extend(stage.process_fastpath_input(image, chunk)?);
    }
    Ok(out)
}

/// Erreur d'une action locale (entrées, presse-papiers, fermeture) : consignée dans `rdp.log`,
/// jamais fatale. Seuls la connexion et le serveur peuvent mettre fin à la session.
fn soft(what: &str, res: ironrdp_session::SessionResult<Vec<ActiveStageOutput>>) -> Vec<ActiveStageOutput> {
    res.unwrap_or_else(|e| {
        log_error(&format!("{what} : erreur ignorée : {e} — {e:?}"));
        Vec::new()
    })
}

/// Ajoute une ligne à `rdp.log` (dossier d'Escale), remis à zéro au-delà de 1 Mio.
fn log_error(msg: &str) {
    use std::io::Write;
    // les tests n'écrivent pas dans le dossier d'Escale de l'utilisateur
    if cfg!(test) {
        return;
    }
    let path = crate::vault::root().join("rdp.log");
    let big = std::fs::metadata(&path).is_ok_and(|m| m.len() > 1 << 20);
    let file = std::fs::OpenOptions::new().create(true).append(!big).write(true).truncate(big).open(&path);
    if let Ok(mut f) = file {
        let _ = writeln!(f, "[{}] {msg}", crate::vault::now());
    }
}

fn resize_frame(stage: &mut ironrdp_session::ActiveStage, w: u16, h: u16, scale: u32) -> Option<ironrdp_session::SessionResult<Vec<u8>>> {
    use ironrdp_displaycontrol::pdu::{DeviceScaleFactor, DisplayControlMonitorLayout, DisplayControlPdu};
    use ironrdp_session::SessionErrorExt as _;
    let (w, h) = MonitorLayoutEntry::adjust_display_size(w as u32, h as u32);
    let channel_id = stage.get_dvc::<DisplayControlClient>()?.channel_id()?;
    let device = match scale {
        ..=124 => DeviceScaleFactor::Scale100Percent,
        125..=174 => DeviceScaleFactor::Scale140Percent,
        _ => DeviceScaleFactor::Scale180Percent,
    };
    let msgs = MonitorLayoutEntry::new_primary(w, h)
        .and_then(|e| e.with_desktop_scale_factor(scale))
        .and_then(|e| DisplayControlMonitorLayout::new(&[e.with_device_scale_factor(device)]))
        .and_then(|l| ironrdp_dvc::encode_dvc_messages(channel_id, vec![Box::new(DisplayControlPdu::from(l))], ironrdp_svc::ChannelFlags::empty()));
    Some(match msgs {
        Ok(m) => stage.encode_dvc_messages(m),
        Err(e) => Err(ironrdp_session::SessionError::encode(e)),
    })
}

fn bulk_decompressor(ct: ironrdp_pdu::rdp::client_info::CompressionType) -> Option<ironrdp_bulk::BulkCompressor> {
    use ironrdp_pdu::rdp::client_info::CompressionType as C;
    let t = match ct {
        C::K8 => ironrdp_bulk::CompressionType::Rdp4,
        C::K64 => ironrdp_bulk::CompressionType::Rdp5,
        C::Rdp6 => ironrdp_bulk::CompressionType::Rdp6,
        C::Rdp61 => ironrdp_bulk::CompressionType::Rdp61,
    };
    ironrdp_bulk::BulkCompressor::new(t).ok()
}

fn set_cursor(frame: &SharedFrame, events: &Events, c: CursorShape) {
    if let Ok(mut f) = frame.lock() {
        f.set_cursor(c);
    }
    events.repaint();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_server::{
        BitmapUpdate, DesktopSize as SrvSize, DisplayUpdate, KeyboardEvent, MouseEvent, PixelFormat as SrvFormat, RdpServer,
        RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler,
    };
    use std::num::{NonZeroU16, NonZeroUsize};

    const W: u16 = 64;
    const H: u16 = 48;

    struct Display;
    struct Updates(bool);

    #[async_trait::async_trait]
    impl RdpServerDisplayUpdates for Updates {
        async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
            if self.0 {
                return std::future::pending().await;
            }
            self.0 = true;
            // carré rouge 16×16 en (8, 4), en BGRA
            let px: Vec<u8> = std::iter::repeat_n([0u8, 0, 255, 255], 16 * 16).flatten().collect();
            Ok(Some(DisplayUpdate::Bitmap(BitmapUpdate {
                x: 8,
                y: 4,
                width: NonZeroU16::new(16).unwrap(),
                height: NonZeroU16::new(16).unwrap(),
                format: SrvFormat::BgrA32,
                data: bytes::Bytes::from(px),
                stride: NonZeroUsize::new(16 * 4).unwrap(),
            })))
        }
    }

    #[async_trait::async_trait]
    impl RdpServerDisplay for Display {
        async fn size(&mut self) -> SrvSize {
            SrvSize { width: W, height: H }
        }
        async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
            Ok(Box::new(Updates(false)))
        }
    }

    struct Inputs(std::sync::mpsc::Sender<String>);

    impl RdpServerInputHandler for Inputs {
        fn keyboard(&mut self, e: KeyboardEvent) {
            match e {
                KeyboardEvent::Pressed { code, .. } => drop(self.0.send(format!("key:{code:#x}"))),
                KeyboardEvent::UnicodePressed(c) => drop(self.0.send(format!("unicode:{c:#x}"))),
                _ => {}
            }
        }
        fn mouse(&mut self, e: MouseEvent) {
            if let MouseEvent::Move { x, y } = e {
                let _ = self.0.send(format!("move:{x},{y}"));
            }
        }
    }

    /// Serveur IronRDP en mémoire avec NLA (CredSSP / NTLM) et certificat auto-signé.
    fn server(inputs: std::sync::mpsc::Sender<String>) -> RdpServer {
        use tokio_rustls::rustls;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pub_key = cert.signing_key.public_key_raw().to_vec();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], der).unwrap();
        let mut srv = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_hybrid(tokio_rustls::TlsAcceptor::from(Arc::new(config)), pub_key)
            .with_input_handler(Inputs(inputs))
            .with_display_handler(Display)
            .build();
        srv.set_credentials(Some(ironrdp_pdu::rdp::client_info::Credentials {
            username: "alice".into(),
            password: "s3cret".into(),
            domain: None,
        }));
        srv
    }

    fn rdp_host(password: &str) -> Host {
        let mut h = Host::default();
        h.protocol = crate::model::Protocol::Rdp;
        h.hostname = "localhost".into();
        h.port = 3389;
        h.username = "alice".into();
        h.password = password.into();
        h
    }

    /// Accepte toutes les empreintes et renvoie celles qui ont été présentées.
    fn accept_all(rx: std::sync::mpsc::Receiver<Event>) -> tokio::task::JoinHandle<Vec<String>> {
        tokio::spawn(async move {
            let mut seen = Vec::new();
            loop {
                match rx.try_recv() {
                    Ok(Event::VerifyHostKey { fingerprint, reply, .. }) => {
                        seen.push(fingerprint);
                        let _ = reply.send(true);
                    }
                    Ok(_) => {}
                    Err(std::sync::mpsc::TryRecvError::Empty) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => return seen,
                }
            }
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nla_session_draws_and_forwards_input() {
        // le serveur IronRDP n'est pas `Send` : il tourne sur ce fil
        tokio::task::LocalSet::new().run_until(nla_session_body()).await;
    }

    async fn nla_session_body() {
        let (in_tx, in_rx) = std::sync::mpsc::channel();
        let mut srv = server(in_tx);
        let (client, server_io) = tokio::io::duplex(1 << 20);
        tokio::task::spawn_local(async move {
            let _ = srv.run_connection(server_io).await;
        });

        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        let prompts = accept_all(ev_rx);
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (tx, mut cmd_rx) = mpsc::unbounded_channel();
        let share = std::env::temp_dir().join(format!("escale-rdp-{}", uuid::Uuid::new_v4()));
        let host = rdp_host("s3cret");

        let mut conn = Conn::new((W, H));
        let client_side = session(&host, Box::new(client), &mut conn, share.clone(), Default::default(), &mut cmd_rx, &events, &frame);
        let checks = async {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            // l'image du serveur arrive dans le tampon partagé
            loop {
                let red = frame.lock().ok().filter(|f| f.width == W as usize).map(|f| f.pixels[(10 * f.width) + 12]);
                // RemoteFX est un codec avec perte : rouge à une unité près
                if red.is_some_and(|c| c.r() > 240 && c.g() < 16 && c.b() < 16) {
                    break;
                }
                assert!(tokio::time::Instant::now() < deadline, "image non reçue : {red:?}");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert_eq!(frame.lock().unwrap().pixels[0], Color32::BLACK);
            // souris et clavier atteignent le serveur
            tx.send(DesktopCmd::Input(vec![Input::Mouse { x: 30, y: 20 }, Input::Scancode { code: 0x1E, down: true }, Input::Scancode { code: 0x1E, down: false }]))
                .unwrap();
            let mut got = Vec::new();
            while !(got.iter().any(|e: &String| e == "move:30,20") && got.iter().any(|e| e == "key:0x1e")) {
                got.extend(in_rx.try_iter());
                assert!(tokio::time::Instant::now() < deadline, "entrées non reçues : {got:?}");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            // long collage (plus de 255 événements) : découpé, la session continue
            let text: String = "abcdefghij".repeat(40) + "z";
            tx.send(DesktopCmd::Input(vec![Input::Text(text.clone())])).unwrap();
            tx.send(DesktopCmd::Input(vec![Input::Scancode { code: 0x30, down: true }, Input::Scancode { code: 0x30, down: false }])).unwrap();
            while !got.iter().any(|e| e == "key:0x30") {
                got.extend(in_rx.try_iter());
                assert!(tokio::time::Instant::now() < deadline, "collage : entrées non reçues");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert_eq!(got.iter().filter(|e| e.starts_with("unicode:")).count(), text.len(), "chaque caractère collé arrive");
            tx.send(DesktopCmd::Close).unwrap();
        };
        let (res, ()) = tokio::join!(client_side, checks);
        assert_eq!(res, Ok(()));
        assert!(share.is_dir(), "dossier partagé créé avant la connexion");
        let _ = std::fs::remove_dir_all(&share);
        drop(events);
        let seen = prompts.await.unwrap();
        assert_eq!(seen.len(), 1, "le certificat est présenté une fois");
        assert!(seen[0].starts_with("SHA256:"));
    }

    /// Écran qui change de résolution à la demande du client (canal d'affichage dynamique).
    struct ResizingDisplay {
        layout: tokio::sync::mpsc::UnboundedSender<()>,
        requests: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<()>>>,
        resized: Arc<std::sync::atomic::AtomicBool>,
    }
    struct ResizingUpdates {
        requests: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<()>>>,
        resized: Arc<std::sync::atomic::AtomicBool>,
        first_sent: bool,
    }

    fn solid(w: u16, h: u16, bgra: [u8; 4]) -> DisplayUpdate {
        let px: Vec<u8> = std::iter::repeat_n(bgra, w as usize * h as usize).flatten().collect();
        DisplayUpdate::Bitmap(BitmapUpdate {
            x: 0,
            y: 0,
            width: NonZeroU16::new(w).unwrap(),
            height: NonZeroU16::new(h).unwrap(),
            format: SrvFormat::BgrA32,
            data: bytes::Bytes::from(px),
            stride: NonZeroUsize::new(w as usize * 4).unwrap(),
        })
    }

    #[async_trait::async_trait]
    impl RdpServerDisplayUpdates for ResizingUpdates {
        async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
            let resized = self.resized.load(std::sync::atomic::Ordering::SeqCst);
            if !self.first_sent {
                // image complète de chaque flux : rouge avant, verte après le redimensionnement
                self.first_sent = true;
                return Ok(Some(if resized { solid(96, 64, [0, 255, 0, 255]) } else { solid(W, H, [0, 0, 255, 255]) }));
            }
            if resized {
                return std::future::pending().await;
            }
            self.requests.lock().await.recv().await;
            self.resized.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(DisplayUpdate::Resize(SrvSize { width: 96, height: 64 })))
        }
    }

    #[async_trait::async_trait]
    impl RdpServerDisplay for ResizingDisplay {
        async fn size(&mut self) -> SrvSize {
            if self.resized.load(std::sync::atomic::Ordering::SeqCst) { SrvSize { width: 96, height: 64 } } else { SrvSize { width: W, height: H } }
        }
        async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
            Ok(Box::new(ResizingUpdates { requests: self.requests.clone(), resized: self.resized.clone(), first_sent: false }))
        }
        fn request_layout(&mut self, _layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
            let _ = self.layout.send(());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resize_reactivates_and_keeps_drawing() {
        tokio::task::LocalSet::new().run_until(resize_body(false)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resize_requested_while_connecting_is_applied() {
        // une seule demande, envoyée avant l'ouverture du canal d'affichage : elle ne doit pas se perdre
        tokio::task::LocalSet::new().run_until(resize_body(true)).await;
    }

    async fn resize_body(once: bool) {
        use tokio_rustls::rustls;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pub_key = cert.signing_key.public_key_raw().to_vec();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], der).unwrap();
        let (layout_tx, layout_rx) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx, _in_rx) = std::sync::mpsc::channel();
        let mut srv = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_hybrid(tokio_rustls::TlsAcceptor::from(Arc::new(config)), pub_key)
            .with_input_handler(Inputs(in_tx))
            .with_display_handler(ResizingDisplay {
                layout: layout_tx,
                requests: Arc::new(tokio::sync::Mutex::new(layout_rx)),
                resized: Default::default(),
            })
            .build();
        srv.set_credentials(Some(ironrdp_pdu::rdp::client_info::Credentials { username: "alice".into(), password: "s3cret".into(), domain: None }));
        let (client, server_io) = tokio::io::duplex(1 << 20);
        tokio::task::spawn_local(async move {
            let _ = srv.run_connection(server_io).await;
        });

        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        let _prompts = accept_all(ev_rx);
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (tx, mut cmd_rx) = mpsc::unbounded_channel();
        let share = std::env::temp_dir().join(format!("escale-rdp-{}", uuid::Uuid::new_v4()));
        let host = rdp_host("s3cret");
        let mut conn = Conn::new((W, H));
        if once {
            tx.send(DesktopCmd::Resize(1024, 768)).unwrap();
        }
        let client_side = session(&host, Box::new(client), &mut conn, share.clone(), Default::default(), &mut cmd_rx, &events, &frame);
        let checks = async {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            let wait = |pred: &dyn Fn(&Frame) -> bool, what: &str| {
                let ok = frame.lock().map(|f| pred(&f)).unwrap_or(false);
                assert!(tokio::time::Instant::now() < deadline, "{what}");
                ok
            };
            if !once {
                while !wait(&|f| f.width == W as usize && f.pixels[W as usize * 10 + 10].r() > 240, "image initiale") {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
            // le canal d'affichage dynamique s'ouvre après la connexion : on réessaie jusqu'à la réactivation
            loop {
                if !once {
                    tx.send(DesktopCmd::Resize(1024, 768)).unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                if wait(&|f| f.width == 96 && f.height == 64, "pas de réactivation à la nouvelle taille") {
                    break;
                }
            }
            while !wait(&|f| f.width == 96 && f.pixels[96 * 32 + 48].g() > 240, "pas d'image après le redimensionnement") {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            tx.send(DesktopCmd::Close).unwrap();
        };
        let (res, ()) = tokio::join!(client_side, checks);
        assert_eq!(res, Ok(()));
        let _ = std::fs::remove_dir_all(&share);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_password_and_refused_certificate_fail_cleanly() {
        tokio::task::LocalSet::new().run_until(failures_body()).await;
    }

    async fn failures_body() {
        // mauvais mot de passe : l'authentification NLA échoue
        let (in_tx, _in_rx) = std::sync::mpsc::channel();
        let mut srv = server(in_tx);
        let (client, server_io) = tokio::io::duplex(1 << 20);
        tokio::task::spawn_local(async move {
            let _ = srv.run_connection(server_io).await;
        });
        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        let _prompts = accept_all(ev_rx);
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let share = std::env::temp_dir().join(format!("escale-rdp-{}", uuid::Uuid::new_v4()));
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            session(&rdp_host("faux"), Box::new(client), &mut Conn::new((W, H)), share.clone(), Default::default(), &mut cmd_rx, &events, &frame),
        )
        .await
        .expect("délai dépassé");
        let e = r.unwrap_err();
        assert!(e.contains("Authentification refusée"), "{e}");
        let _ = std::fs::remove_dir_all(&share);

        // certificat refusé : aucun identifiant n'est envoyé, erreur explicite
        let (in_tx, _in_rx) = std::sync::mpsc::channel();
        let mut srv = server(in_tx);
        let (client, server_io) = tokio::io::duplex(1 << 20);
        tokio::task::spawn_local(async move {
            let _ = srv.run_connection(server_io).await;
        });
        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        tokio::spawn(async move {
            loop {
                if let Ok(Event::VerifyHostKey { reply, .. }) = ev_rx.try_recv() {
                    let _ = reply.send(false);
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        let err = session(&rdp_host("s3cret"), Box::new(client), &mut Conn::new((W, H)), share.clone(), Default::default(), &mut cmd_rx, &events, &frame).await.unwrap_err();
        assert!(err.contains("Certificat refusé"), "{err}");
        let _ = std::fs::remove_dir_all(&share);
    }

    #[tokio::test]
    async fn late_mouse_moves_are_coalesced() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let m = |x| Input::Mouse { x, y: 0 };
        let click = Input::Button { button: MouseBtn::Left, down: true };
        // trois lots en attente (session occupée), puis une autre commande
        tx.send(DesktopCmd::Input(vec![m(1), m(2)])).unwrap();
        tx.send(DesktopCmd::Input(vec![m(3), click.clone(), m(4)])).unwrap();
        tx.send(DesktopCmd::Input(vec![m(5), m(6)])).unwrap();
        tx.send(DesktopCmd::Resize(800, 600)).unwrap();
        tx.send(DesktopCmd::Input(vec![m(7)])).unwrap();
        let mut deferred = None;
        let Some(DesktopCmd::Input(list)) = next_cmd(&mut deferred, &mut rx).await else { panic!() };
        // le clic garde sa position, seule la dernière position compte ensuite
        assert_eq!(list, vec![m(3), click, m(6)]);
        assert!(matches!(next_cmd(&mut deferred, &mut rx).await, Some(DesktopCmd::Resize(800, 600))), "rien de perdu ni de réordonné");
        assert!(matches!(next_cmd(&mut deferred, &mut rx).await, Some(DesktopCmd::Input(l)) if l == vec![m(7)]));
        drop(tx);
        assert!(next_cmd(&mut deferred, &mut rx).await.is_none());
    }

    #[test]
    fn region_copy_is_bounded() {
        let mut image = DecodedImage::new(PixelFormat::RgbA32, 8, 4);
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        // rectangle inversé puis débordant : ni panique ni écriture hors image (le contenu est vérifié de bout en bout)
        copy_region(&image, &frame, &InclusiveRectangle { left: 5, top: 1, right: 2, bottom: 3 });
        assert_eq!(frame.lock().unwrap().width, 8);
        copy_region(&image, &frame, &InclusiveRectangle { left: 6, top: 2, right: 50, bottom: 50 });
        let f = frame.lock().unwrap();
        assert!(f.pixels.iter().all(|p| *p == Color32::BLACK));
        drop(f);
        image = DecodedImage::new(PixelFormat::RgbA32, 2, 2);
        copy_region(&image, &frame, &whole(&image));
        assert_eq!(frame.lock().unwrap().pixels.len(), 4);
    }

    #[test]
    fn release_all_releases_only_pressed_keys() {
        let mut db = Database::new();
        let pressed = vec![
            Input::Scancode { code: 0x1E, down: true },
            Input::Scancode { code: 0xE048, down: true },
            Input::Button { button: MouseBtn::Left, down: true },
        ];
        assert_eq!(to_fastpath(pressed, &mut db).len(), 3);
        // deux touches + un bouton relâchés
        assert_eq!(to_fastpath(vec![Input::ReleaseAll], &mut db).len(), 3);
        assert!(to_fastpath(vec![Input::ReleaseAll], &mut db).is_empty());
    }

    #[test]
    fn auto_repeat_never_inserts_a_release() {
        use ironrdp_pdu::input::fast_path::KeyboardFlags as F;
        let mut db = Database::new();
        let down = |code| Input::Scancode { code, down: true };
        // Win maintenue : appuis répétés, aucun relâchement (sinon menu Démarrer distant)
        let ev = to_fastpath(vec![down(0xE05B), down(0xE05B), down(0xE05B)], &mut db);
        assert!(ev.iter().all(|e| matches!(e, FastPathInputEvent::KeyboardEvent(f, 0x5B) if *f == F::EXTENDED)), "{ev:?}");
        assert_eq!(ev.len(), 3);
        let ev = to_fastpath(vec![Input::Scancode { code: 0xE05B, down: false }], &mut db);
        assert!(matches!(ev[..], [FastPathInputEvent::KeyboardEvent(f, 0x5B)] if f == F::EXTENDED | F::RELEASE));
    }

    #[test]
    fn pasted_text_releases_modifiers_first() {
        let mut db = Database::new();
        to_fastpath(vec![Input::Scancode { code: 0x1D, down: true }, Input::Scancode { code: 0x2A, down: true }], &mut db);
        let ev = to_fastpath(vec![Input::Text("a".into())], &mut db);
        // Ctrl et Maj relâchés, puis « a » appuyé / relâché
        assert_eq!(ev.len(), 4);
        assert!(matches!(ev[0], FastPathInputEvent::KeyboardEvent(f, 0x1D) if f.contains(ironrdp_pdu::input::fast_path::KeyboardFlags::RELEASE)));
        assert!(matches!(ev[2], FastPathInputEvent::UnicodeKeyboardEvent(_, 0x61)));
    }

    #[test]
    fn lock_keys_become_a_synchronize_event() {
        use ironrdp_pdu::input::fast_path::SynchronizeFlags;
        let mut db = Database::new();
        let ev = to_fastpath(vec![Input::Locks(crate::desktop::LockKeys::default())], &mut db);
        assert!(matches!(ev[..], [FastPathInputEvent::SyncEvent(f)] if f == SynchronizeFlags::NUM_LOCK), "{ev:?}");
        let ev = to_fastpath(vec![Input::Locks(crate::desktop::LockKeys { num: false, caps: true, scroll: true })], &mut db);
        assert!(matches!(ev[..], [FastPathInputEvent::SyncEvent(f)] if f == SynchronizeFlags::CAPS_LOCK | SynchronizeFlags::SCROLL_LOCK));
    }

    #[test]
    fn numpad_keys_are_sent_as_is() {
        use ironrdp_pdu::input::fast_path::KeyboardFlags as F;
        let mut db = Database::new();
        // 1 du pavé (0x4F), Entrée du pavé (étendue), / du pavé (étendue), Verr. Num (non étendue)
        let ev = to_fastpath([0x4F, 0xE01C, 0xE035, 0x45].into_iter().map(|code| Input::Scancode { code, down: true }).collect(), &mut db);
        assert!(matches!(ev[0], FastPathInputEvent::KeyboardEvent(f, 0x4F) if f.is_empty()));
        assert!(matches!(ev[1], FastPathInputEvent::KeyboardEvent(f, 0x1C) if f == F::EXTENDED));
        assert!(matches!(ev[2], FastPathInputEvent::KeyboardEvent(f, 0x35) if f == F::EXTENDED));
        assert!(matches!(ev[3], FastPathInputEvent::KeyboardEvent(f, 0x45) if f.is_empty()));
    }

    #[test]
    fn pause_becomes_ctrl_e1_and_numlock() {
        use ironrdp_pdu::input::fast_path::KeyboardFlags as F;
        let mut db = Database::new();
        let ev = to_fastpath(vec![Input::Scancode { code: crate::desktop::PAUSE, down: true }], &mut db);
        assert_eq!(ev.len(), 4);
        assert!(matches!(ev[0], FastPathInputEvent::KeyboardEvent(f, 0x1D) if f == F::EXTENDED1));
        assert!(matches!(ev[1], FastPathInputEvent::KeyboardEvent(f, 0x45) if f.is_empty()));
        assert!(matches!(ev[3], FastPathInputEvent::KeyboardEvent(f, 0x45) if f == F::RELEASE));
        assert!(to_fastpath(vec![Input::Scancode { code: crate::desktop::PAUSE, down: false }], &mut db).is_empty(), "rien au relâchement");
        assert!(!db.is_key_pressed(Scancode::from_u16(0xE01D)), "Ctrl droit jamais vu enfoncé");
    }

    #[test]
    fn text_becomes_unicode_and_enter() {
        let mut db = Database::new();
        let ev = to_fastpath(vec![Input::Text("é\r\nx".into())], &mut db);
        assert_eq!(ev.len(), 6);
        assert!(matches!(ev[2], FastPathInputEvent::KeyboardEvent(_, 0x1C)));
        assert_eq!(fingerprint(b"abc").len(), "SHA256:".len() + 32 * 3 - 1);
    }

    /// Hôte de test sans ressources locales (son, presse-papiers) ; `f` règle les options.
    fn host_with(password: &str, f: impl FnOnce(&mut RdpOptions)) -> Host {
        let mut h = rdp_host(password);
        h.rdp.clipboard = false;
        h.rdp.audio = crate::model::RdpAudio::Off;
        f(&mut h.rdp);
        h
    }

    /// PDU émis par le client aux étapes que règlent les options : demande de connexion (sécurité),
    /// blocs GCC (affichage, graphisme, session console) et Client Info (compression, performances…).
    fn sent(host: &Host) -> (ironrdp_pdu::nego::ConnectionRequest, ironrdp_pdu::gcc::ClientGccBlocks, ironrdp_pdu::rdp::ClientInfoPdu) {
        use ironrdp_connector::{ClientConnectorState, Sequence as _};
        use ironrdp_pdu::{mcs, nego, x224::X224, x224::X224Data};
        let mut c = ClientConnector::new(connector_config(host, (1024, 768)), std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut buf = WriteBuf::new();
        c.step(&[], &mut buf).unwrap();
        let req = ironrdp_core::decode::<X224<nego::ConnectionRequest>>(buf.filled()).unwrap().0;
        c.state = ClientConnectorState::BasicSettingsExchangeSendInitial { selected_protocol: req.protocol };
        buf.clear();
        c.step(&[], &mut buf).unwrap();
        let data = ironrdp_core::decode::<X224<X224Data<'_>>>(buf.filled()).unwrap().0;
        let gcc = ironrdp_core::decode::<mcs::ConnectInitial>(&data.data).unwrap().conference_create_request.gcc_blocks().clone();
        c.state = ClientConnectorState::SecureSettingsExchange { io_channel_id: 1003, user_channel_id: 1007 };
        buf.clear();
        c.step(&[], &mut buf).unwrap();
        let info = match ironrdp_core::decode::<X224<mcs::McsMessage<'_>>>(buf.filled()).unwrap().0 {
            mcs::McsMessage::SendDataRequest(d) => ironrdp_core::decode::<ironrdp_pdu::rdp::ClientInfoPdu>(&d.user_data).unwrap(),
            other => panic!("{other:?}"),
        };
        (req, gcc, info)
    }

    #[test]
    fn host_options_reach_the_connection_pdus() {
        use ironrdp_pdu::gcc::{ClientEarlyCapabilityFlags as E, HighColorDepth, RedirectionFlags};
        use ironrdp_pdu::nego::SecurityProtocol as P;
        use ironrdp_pdu::rdp::client_info::{ClientInfoFlags as F, CompressionType, PerformanceFlags as Perf};

        // valeurs par défaut : NLA, RDPGFX, 32 bits, compression 64 Ko
        let (req, gcc, info) = sent(&host_with("s3cret", |o| o.scale = 125));
        assert!(req.protocol.contains(P::HYBRID | P::SSL));
        let early = gcc.core.optional_data.early_capability_flags.unwrap();
        assert!(early.contains(E::SUPPORT_DYN_VC_GFX_PROTOCOL | E::WANT_32_BPP_SESSION));
        assert!(gcc.cluster.is_none());
        assert_eq!(gcc.core.optional_data.desktop_scale_factor, Some(125));
        assert_eq!(gcc.core.optional_data.device_scale_factor, Some(140));
        assert_eq!((gcc.core.desktop_width, gcc.core.desktop_height), (1024, 768));
        assert_eq!(gcc.core.keyboard_layout, keyboard_layout());
        let ci = &info.client_info;
        assert!(ci.flags.contains(F::COMPRESSION | F::AUTOLOGON));
        assert_eq!(ci.compression_type, CompressionType::K64);
        let perf = ci.extra_info.optional_data.performance_flags().unwrap();
        assert!(perf.contains(Perf::ENABLE_FONT_SMOOTHING | Perf::ENABLE_DESKTOP_COMPOSITION | Perf::DISABLE_MENUANIMATIONS));
        assert!(!perf.intersects(Perf::DISABLE_WALLPAPER | Perf::DISABLE_THEMING | Perf::DISABLE_FULLWINDOWDRAG));

        // TLS seul, ancien mode 16 bits, sans compression, session console, programme de démarrage
        let (req, gcc, info) = sent(&host_with("", |o| {
            o.security = RdpSecurity::Tls;
            o.graphics = RdpGraphics::Legacy;
            o.color_depth = 16;
            o.compression = RdpCompression::None;
            o.admin = true;
            o.scale = 200;
            o.keyboard_layout = 0x40C;
            o.wallpaper = false;
            o.themes = false;
            o.font_smoothing = false;
            o.desktop_composition = false;
            o.full_window_drag = false;
            o.alternate_shell = "notepad.exe".into();
            o.work_dir = "C:\\Temp".into();
        }));
        assert_eq!(req.protocol, P::SSL, "TLS seul : pas de CredSSP");
        let early = gcc.core.optional_data.early_capability_flags.unwrap();
        assert!(!early.intersects(E::SUPPORT_DYN_VC_GFX_PROTOCOL | E::WANT_32_BPP_SESSION));
        assert_eq!(gcc.core.optional_data.high_color_depth, Some(HighColorDepth::Rgb565Bpp16));
        let cluster = gcc.cluster.expect("bloc Cluster de la session console");
        assert!(cluster.flags.contains(RedirectionFlags::REDIRECTED_SESSION_FIELD_VALID));
        assert_eq!(cluster.redirected_session_id, 0);
        assert_eq!(gcc.core.optional_data.device_scale_factor, Some(180));
        assert_eq!(gcc.core.keyboard_layout, 0x40C);
        let ci = &info.client_info;
        assert!(!ci.flags.intersects(F::COMPRESSION | F::AUTOLOGON), "ni compression ni ouverture automatique : {:?}", ci.flags);
        assert_eq!((ci.alternate_shell.as_str(), ci.work_dir.as_str()), ("notepad.exe", "C:\\Temp"));
        let perf = ci.extra_info.optional_data.performance_flags().unwrap();
        assert!(perf.contains(Perf::DISABLE_WALLPAPER | Perf::DISABLE_THEMING | Perf::DISABLE_FULLWINDOWDRAG));
        assert!(!perf.intersects(Perf::ENABLE_FONT_SMOOTHING | Perf::ENABLE_DESKTOP_COMPOSITION));

        // RDPGFX : session 32 bits quelle que soit la profondeur choisie pour l'ancien mode
        let (_, gcc, _) = sent(&host_with("x", |o| {
            o.graphics = RdpGraphics::RemoteFx;
            o.color_depth = 16;
        }));
        assert!(gcc.core.optional_data.early_capability_flags.unwrap().contains(E::SUPPORT_DYN_VC_GFX_PROTOCOL | E::WANT_32_BPP_SESSION));
    }

    #[test]
    fn fixed_resolution_is_bounded_and_scale_is_clamped() {
        let mut o = RdpOptions::default();
        assert_eq!(initial_size(&o, (1001, 700)), (1001, 700), "dynamique : taille de la fenêtre");
        o.display = RdpDisplay::FixedFit;
        (o.width, o.height) = (1281, 100);
        assert_eq!(initial_size(&o, (1001, 700)), (1280, 200), "largeur paire, 200 pixels au moins");
        o.display = RdpDisplay::FixedNative;
        (o.width, o.height) = (9000, 1080);
        assert_eq!(initial_size(&o, (1, 1)), (8192, 1080));
        o.scale = 50;
        assert_eq!(scale_factor(&o), 100);
        o.scale = 900;
        assert_eq!(scale_factor(&o), 500);
        o.scale = 0;
        assert!((100..=500).contains(&scale_factor(&o)), "échelle de cet écran");
    }

    #[test]
    fn kdc_addresses() {
        assert_eq!(kdc_url(""), None);
        assert_eq!(kdc_url("   "), None);
        assert_eq!(kdc_url("dc01.corp.local").as_deref(), Some("tcp://dc01.corp.local"));
        assert_eq!(kdc_url(" dc01:88 ").as_deref(), Some("tcp://dc01:88"));
        assert_eq!(kdc_url("TCP://dc01:88").as_deref(), Some("tcp://dc01:88"));
        assert_eq!(kdc_url("udp://10.0.0.1").as_deref(), Some("udp://10.0.0.1"));
        assert_eq!(kdc_url("[fd00::1]:88").as_deref(), Some("tcp://[fd00::1]:88"));
        assert_eq!(kdc_url("https://gw.corp.local/KdcProxy").as_deref(), Some("https://gw.corp.local/KdcProxy"));
        assert_eq!(kdc_url("ftp://dc01"), None);
        assert_eq!(kdc_url("tcp://"), None);
        assert_eq!(kdc_url("dc 01"), None);
        // l'URL retenue est celle que sspi utilisera
        let u = ironrdp_connector::credssp::KerberosConfig::new(kdc_url("dc01:88"), "PC".into()).unwrap().kdc_proxy_url.unwrap();
        assert_eq!((u.scheme(), u.host_str(), u.port()), ("tcp", Some("dc01"), Some(88)));
    }

    fn url(s: &str) -> ironrdp_connector::sspi::generator::NetworkRequest {
        let url = ironrdp_connector::credssp::KerberosConfig::new(Some(s.into()), String::new()).unwrap().kdc_proxy_url.unwrap();
        let protocol = match url.scheme() {
            "tcp" => NetworkProtocol::Tcp,
            "udp" => NetworkProtocol::Udp,
            "http" => NetworkProtocol::Http,
            _ => NetworkProtocol::Https,
        };
        NetworkRequest { protocol, url, data: Vec::new() }
    }

    #[tokio::test]
    async fn kdc_requests_over_tcp_udp_and_http() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // TCP : message et réponse préfixés par leur longueur (4 octets, gros-boutiste)
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut m = [0u8; 10];
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(&m, b"\0\0\0\x06AS-REQ");
            s.write_all(b"\0\0\0\x06AS-REP").await.unwrap();
        });
        let mut req = url(&format!("tcp://127.0.0.1:{port}"));
        req.data = b"\0\0\0\x06AS-REQ".to_vec();
        assert_eq!(Kdc.send(&req).await.unwrap(), b"\0\0\0\x06AS-REP");

        // UDP : datagramme brut, réponse rendue préfixée comme en TCP
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = u.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut m = [0u8; 64];
            let (n, peer) = u.recv_from(&mut m).await.unwrap();
            assert_eq!(&m[..n], b"TGS-REQ");
            u.send_to(b"TGS-REP", peer).await.unwrap();
        });
        let mut req = url(&format!("udp://127.0.0.1:{port}"));
        req.data = b"TGS-REQ".to_vec();
        assert_eq!(Kdc.send(&req).await.unwrap(), b"\0\0\0\x07TGS-REP");

        // proxy KDC en HTTP, réponse découpée (chunked)
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut b = [0u8; 1024];
            while !got.ends_with(b"\r\n\r\nPROXY") {
                let n = s.read(&mut b).await.unwrap();
                got.extend_from_slice(&b[..n]);
            }
            let head = String::from_utf8_lossy(&got).to_string();
            assert!(head.starts_with("POST /KdcProxy?t=1 HTTP/1.1\r\n"), "{head}");
            assert!(head.contains("Content-Length: 5\r\n"), "{head}");
            s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").await.unwrap();
        });
        let mut req = url(&format!("http://127.0.0.1:{port}/KdcProxy?t=1"));
        req.data = b"PROXY".to_vec();
        assert_eq!(Kdc.send(&req).await.unwrap(), b"abcde");

        // KDC injoignable : erreur explicite
        let req = url("tcp://127.0.0.1:1");
        assert!(Kdc.send(&req).await.is_err());
    }

    #[test]
    fn http_bodies() {
        assert_eq!(http_body(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef").unwrap(), b"abc");
        assert_eq!(http_body(b"HTTP/1.0 200 OK\r\n\r\nxyz").unwrap(), b"xyz");
        assert!(http_body(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").is_err());
        assert!(http_body(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc").is_err());
    }

    /// Serveur IronRDP en TLS seul (sans NLA ni identifiants exigés).
    fn tls_server(inputs: std::sync::mpsc::Sender<String>) -> RdpServer {
        use tokio_rustls::rustls;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], der).unwrap();
        RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_tls(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
            .with_input_handler(Inputs(inputs))
            .with_display_handler(Display)
            .build()
    }

    /// Attend le carré rouge du serveur de test dans l'image partagée.
    async fn wait_red(frame: &SharedFrame) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let red = frame.lock().ok().filter(|f| f.width == W as usize).map(|f| f.pixels[(10 * f.width) + 12]);
            if red.is_some_and(|c| c.r() > 240 && c.g() < 16 && c.b() < 16) {
                return;
            }
            assert!(tokio::time::Instant::now() < deadline, "image non reçue : {red:?}");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_only_legacy_session_without_compression() {
        tokio::task::LocalSet::new().run_until(tls_body()).await;
    }

    async fn tls_body() {
        let (in_tx, _in_rx) = std::sync::mpsc::channel();
        let mut srv = tls_server(in_tx);
        let (client, server_io) = tokio::io::duplex(1 << 20);
        tokio::task::spawn_local(async move {
            let _ = srv.run_connection(server_io).await;
        });
        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        let prompts = accept_all(ev_rx);
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (tx, mut cmd_rx) = mpsc::unbounded_channel();
        let share = std::env::temp_dir().join(format!("escale-rdp-{}", uuid::Uuid::new_v4()));
        // sans mot de passe : pas d'ouverture automatique, l'écran de connexion s'afficherait
        let host = host_with("", |o| {
            o.security = RdpSecurity::Tls;
            o.graphics = RdpGraphics::Legacy;
            o.compression = RdpCompression::None;
            o.drive = false;
        });
        let mut conn = Conn::new((W, H));
        let client_side = session(&host, Box::new(client), &mut conn, share.clone(), Default::default(), &mut cmd_rx, &events, &frame);
        let checks = async {
            wait_red(&frame).await;
            tx.send(DesktopCmd::Close).unwrap();
        };
        let (res, ()) = tokio::join!(client_side, checks);
        assert_eq!(res, Ok(()));
        assert!(conn.connected && !conn.lost);
        assert!(conn.known_key.as_deref().is_some_and(|k| k.starts_with("SHA256:")));
        assert!(!share.exists(), "sans lecteur partagé, aucun dossier créé");
        drop(events);
        assert_eq!(prompts.await.unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_resolution_ignores_resize() {
        tokio::task::LocalSet::new().run_until(fixed_body()).await;
    }

    async fn fixed_body() {
        use tokio_rustls::rustls;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pub_key = cert.signing_key.public_key_raw().to_vec();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], der).unwrap();
        let (layout_tx, layout_rx) = tokio::sync::mpsc::unbounded_channel();
        let requests = Arc::new(tokio::sync::Mutex::new(layout_rx));
        let resized: Arc<std::sync::atomic::AtomicBool> = Default::default();
        let (in_tx, _in_rx) = std::sync::mpsc::channel();
        let mut srv = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_hybrid(tokio_rustls::TlsAcceptor::from(Arc::new(config)), pub_key)
            .with_input_handler(Inputs(in_tx))
            .with_display_handler(ResizingDisplay { layout: layout_tx, requests, resized: resized.clone() })
            .build();
        srv.set_credentials(Some(ironrdp_pdu::rdp::client_info::Credentials { username: "alice".into(), password: "s3cret".into(), domain: None }));
        let (client, server_io) = tokio::io::duplex(1 << 20);
        tokio::task::spawn_local(async move {
            let _ = srv.run_connection(server_io).await;
        });

        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        let _prompts = accept_all(ev_rx);
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (tx, mut cmd_rx) = mpsc::unbounded_channel();
        let share = std::env::temp_dir().join(format!("escale-rdp-{}", uuid::Uuid::new_v4()));
        let host = host_with("s3cret", |o| o.display = RdpDisplay::FixedFit);
        let mut conn = Conn::new((W, H));
        let client_side = session(&host, Box::new(client), &mut conn, share.clone(), Default::default(), &mut cmd_rx, &events, &frame);
        let checks = async {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            while !frame.lock().map(|f| f.width == W as usize && f.pixels[W as usize * 10 + 10].r() > 240).unwrap_or(false) {
                assert!(tokio::time::Instant::now() < deadline, "image initiale");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            // en mode dynamique, ces demandes changent la résolution en moins d'une seconde
            for _ in 0..15 {
                tx.send(DesktopCmd::Resize(1024, 768)).unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let f = frame.lock().unwrap();
            assert_eq!((f.width, f.height), (W as usize, H as usize), "résolution fixe conservée");
            drop(f);
            tx.send(DesktopCmd::Close).unwrap();
        };
        let (res, ()) = tokio::join!(client_side, checks);
        assert_eq!(res, Ok(()));
        assert_eq!(conn.size, (W, H));
        assert!(!resized.load(std::sync::atomic::Ordering::SeqCst), "aucune disposition d'écran reçue par le serveur");
        let _ = std::fs::remove_dir_all(&share);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn network_loss_reconnects_without_new_prompt() {
        tokio::task::LocalSet::new().run_until(reconnect_body()).await;
    }

    async fn reconnect_body() {
        let (in_tx, _in_rx) = std::sync::mpsc::channel();
        let mut srv = server(in_tx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cut_tx, cut_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::task::spawn_local(async move {
            // première connexion coupée net (comme une panne réseau), puis une connexion normale
            let (s, _) = listener.accept().await.unwrap();
            tokio::select! {
                _ = srv.run_connection(s) => {}
                _ = cut_rx => {}
            }
            let (s, _) = listener.accept().await.unwrap();
            let _ = srv.run_connection(s).await;
        });

        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let l = log.clone();
        let collector = tokio::spawn(async move {
            loop {
                match ev_rx.try_recv() {
                    Ok(Event::VerifyHostKey { reply, .. }) => {
                        l.lock().unwrap().push("certificat".into());
                        let _ = reply.send(true);
                    }
                    Ok(Event::Connected) => l.lock().unwrap().push("connecté".into()),
                    Ok(Event::Status(s)) => l.lock().unwrap().push(s),
                    Ok(_) => {}
                    Err(std::sync::mpsc::TryRecvError::Empty) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                }
            }
        });
        let count = |what: &str| log.lock().unwrap().iter().filter(|e| e.starts_with(what)).count();
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (tx, cmd_rx) = mpsc::unbounded_channel();
        let share = std::env::temp_dir().join(format!("escale-rdp-{}", uuid::Uuid::new_v4()));
        let mut host = host_with("s3cret", |_| {});
        host.hostname = "127.0.0.1".into();
        host.port = port;
        let client_side = run(vec![host], (W, H), share.clone(), Default::default(), cmd_rx, events, frame.clone());
        let checks = async {
            wait_red(&frame).await;
            // le collecteur relève les événements toutes les 10 ms : l'image peut le devancer
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while count("connecté") == 0 {
                assert!(tokio::time::Instant::now() < deadline, "connexion non signalée");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert_eq!(count("connecté"), 1);
            frame.lock().unwrap().pixels.fill(Color32::BLACK);
            cut_tx.send(()).unwrap();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            while count("connecté") < 2 {
                assert!(tokio::time::Instant::now() < deadline, "pas de reconnexion : {:?}", log.lock().unwrap());
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            // la session reprend : nouvelle image
            wait_red(&frame).await;
            tx.send(DesktopCmd::Close).unwrap();
        };
        let (res, ()) = tokio::join!(client_side, checks);
        assert_eq!(res, Ok(()));
        collector.await.unwrap();
        let log = log.lock().unwrap();
        assert_eq!(log.iter().filter(|e| *e == "certificat").count(), 1, "certificat accepté une seule fois : {log:?}");
        assert!(log.iter().any(|e| e.starts_with("Reconnexion…")), "{log:?}");
        let _ = std::fs::remove_dir_all(&share);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refused_password_is_not_retried() {
        tokio::task::LocalSet::new().run_until(no_retry_body()).await;
    }

    async fn no_retry_body() {
        // erreur d'authentification à la connexion : échec immédiat, sans reconnexion
        let (in_tx, _in_rx) = std::sync::mpsc::channel();
        let mut srv = server(in_tx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::task::spawn_local(async move {
            while let Ok((s, _)) = listener.accept().await {
                let _ = srv.run_connection(s).await;
            }
        });
        let (events, ev_rx) = Events::new(eframe::egui::Context::default());
        let _prompts = accept_all(ev_rx);
        let (_tx, cmd_rx) = mpsc::unbounded_channel();
        let mut host = host_with("faux", |_| {});
        host.hostname = "127.0.0.1".into();
        host.port = port;
        let share = std::env::temp_dir().join(format!("escale-rdp-{}", uuid::Uuid::new_v4()));
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            run(vec![host], (W, H), share.clone(), Default::default(), cmd_rx, events, Arc::new(Mutex::new(Frame::new()))),
        )
        .await
        .expect("délai dépassé");
        assert!(r.unwrap_err().contains("Authentification refusée"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "pas de nouvelle tentative");
        let _ = std::fs::remove_dir_all(&share);
    }

    #[tokio::test]
    async fn close_while_connecting_returns_promptly() {
        // serveur muet (TCP ouvert, aucune réponse) : la fermeture de l'onglet doit arrêter la session
        let (client, _server_io) = tokio::io::duplex(1 << 16);
        let (events, _ev_rx) = Events::new(eframe::egui::Context::default());
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (tx, mut cmd_rx) = mpsc::unbounded_channel();
        tx.send(DesktopCmd::Close).unwrap();
        let host = host_with("s3cret", |o| o.drive = false);
        let mut conn = Conn::new((W, H));
        let share = std::env::temp_dir().join("escale-rdp-inutilise");
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            session(&host, Box::new(client), &mut conn, share, Default::default(), &mut cmd_rx, &events, &frame),
        )
        .await;
        assert_eq!(r.expect("fermeture ignorée pendant la connexion"), Ok(()));
        assert!(!conn.connected);
    }

    #[test]
    fn domain_typed_in_the_user_field() {
        use ironrdp_connector::sspi::Username;
        let creds = |user: &str, domain: &str| {
            let mut h = host_with("x", |_| {});
            (h.username, h.domain) = (user.into(), domain.into());
            let c = connector_config(&h, (1024, 768));
            let Credentials::UsernamePassword { username, .. } = c.credentials else { panic!() };
            // NLA : sspi doit accepter la combinaison
            assert!(Username::new(&username, c.domain.as_deref()).is_ok(), "{user} / {domain} -> {username} / {:?}", c.domain);
            (username, c.domain)
        };
        assert_eq!(creds("CORP\\alice", ""), ("alice".into(), Some("CORP".into())));
        assert_eq!(creds(" alice ", " CORP "), ("alice".into(), Some("CORP".into())));
        assert_eq!(creds("alice@corp.local", ""), ("alice@corp.local".into(), None));
        // UPN + domaine renseigné : sspi refuse le mélange, le UPN suffit
        assert_eq!(creds("alice@corp.local", "CORP"), ("alice@corp.local".into(), None));
        // domaine écrit des deux côtés : celui du champ utilisateur l'emporte
        assert_eq!(creds("CORP\\alice", "AUTRE"), ("alice".into(), Some("CORP".into())));
        assert_eq!(creds("alice", ""), ("alice".into(), None));

        // TLS seul : le serveur reçoit utilisateur et domaine séparés (Client Info)
        let mut h = host_with("x", |o| o.security = RdpSecurity::Tls);
        h.username = "CORP\\alice".into();
        let (_, _, info) = sent(&h);
        let c = &info.client_info.credentials;
        assert_eq!((c.username.as_str(), c.domain.as_deref()), ("alice", Some("CORP")));
    }

    #[test]
    fn tls_and_spn_names_without_brackets_or_port() {
        assert_eq!(server_name("[fd00::1]", 3389), "fd00::1");
        assert_eq!(server_name("fd00::1", 3389), "fd00::1");
        assert_eq!(server_name("srv.corp.local:3390", 3389), "srv.corp.local");
        assert_eq!(server_name("10.0.0.5", 3389), "10.0.0.5");
    }

    #[test]
    fn unreadable_server_messages_do_not_close_the_session() {
        use ironrdp_session::SessionErrorExt;
        let bad = || Err(ironrdp_session::SessionError::general("test"));
        let mut n = 0;
        for _ in 1..MAX_BAD_PDUS {
            assert!(tolerate(bad(), &mut n).is_ok_and(|o| o.is_empty()), "message ignoré, session gardée");
        }
        // un message lisible remet le compte à zéro
        assert!(tolerate(Ok(Vec::new()), &mut n).is_ok());
        assert_eq!(n, 0);
        for _ in 1..MAX_BAD_PDUS {
            let _ = tolerate(bad(), &mut n);
        }
        assert!(tolerate(bad(), &mut n).is_err(), "erreurs ininterrompues : session fermée");
    }

    #[test]
    fn all_screens_are_announced_with_inclusive_edges() {
        use crate::monitors::{Layout, Screen};
        use ironrdp_pdu::gcc::MonitorFlags;
        let screen = |left, top, right, bottom, primary| Screen { name: String::new(), left, top, right, bottom, primary };
        let l = Layout { screens: vec![screen(0, 0, 2560, 1440, true), screen(-1920, 200, 0, 1280, false)] };
        let m = gcc_monitors(Some(&l));
        assert_eq!((m[0].left, m[0].top, m[0].right, m[0].bottom, m[0].flags), (0, 0, 2559, 1439, MonitorFlags::PRIMARY));
        assert_eq!((m[1].left, m[1].top, m[1].right, m[1].bottom, m[1].flags), (-1920, 200, -1, 1279, MonitorFlags::empty()));
        assert_eq!(l.size(), (4480, 1440));
        // écran principal distant qui n'est pas celui de cet ordinateur : ramené en (0, 0)
        let l2 = Layout { screens: vec![screen(1920, 0, 3840, 1080, true), screen(3840, 0, 5760, 1080, false)] };
        let m = gcc_monitors(Some(&l2));
        assert_eq!((m[0].left, m[0].right, m[1].left, m[1].right), (0, 1919, 1920, 3839));
        // un seul écran : la taille du bureau suffit
        assert!(gcc_monitors(Some(&Layout { screens: vec![l.screens[0].clone()] })).is_empty());
        assert!(gcc_monitors(None).is_empty());
        let mut o = RdpOptions { multimon: true, ..Default::default() };
        assert!(!is_dynamic(&o), "tous les écrans : jamais redimensionné");
        o.multimon = false;
        assert!(is_dynamic(&o));
    }

    #[test]
    fn dynamic_size_stays_in_bounds() {
        let o = RdpOptions::default();
        assert_eq!(initial_size(&o, (0, 0)), (200, 200), "fenêtre réduite : taille minimale");
        assert_eq!(initial_size(&o, (9000, 700)), (8192, 700));
        assert_eq!(dynamic_size(1001, 0), (1001, 200));
    }

    #[test]
    fn server_disconnect_reasons() {
        use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode as C};
        let d = |c| ErrorInfo::ProtocolIndependentCode(c).description();
        // déconnecté par une autre connexion / un administrateur : message clair, pas de reconnexion
        assert_eq!(server_closed(&d(C::DisconnectedByOtherconnection)), Err("Session reprise par une autre connexion".to_string()));
        assert!(server_closed(&d(C::RpcInitiatedDisconnect)).unwrap_err().contains("administrateur"));
        assert!(server_closed(&d(C::IdleTimeout)).unwrap_err().contains("inactivité"));
        // l'utilisateur s'est déconnecté lui-même depuis la session : fin normale
        assert_eq!(server_closed(&d(C::LogoffByUser)), Ok(()));
        assert_eq!(server_closed(&d(C::RpcInitiatedDisconnectByuser)), Ok(()));
        assert_eq!(server_closed("autre chose"), Err("Session fermée par le serveur : autre chose".to_string()));
    }

    #[test]
    fn pdus_received_during_reactivation() {
        use ironrdp_pdu::mcs::SendDataIndication;
        let pdu = |channel_id| {
            let m = SendDataIndication { initiator_id: 1002, channel_id, user_data: std::borrow::Cow::Borrowed(&[1, 2, 3][..]) };
            ironrdp_core::encode_vec(&ironrdp_pdu::x224::X224(m)).unwrap()
        };
        let x = ironrdp_pdu::Action::X224;
        assert_eq!(reactivation_pdu(1003, x, &pdu(1003)), Reactivation::Sequence);
        // son, presse-papiers… : traités comme en session au lieu d'interrompre la réactivation
        assert_eq!(reactivation_pdu(1003, x, &pdu(1004)), Reactivation::Channel);
        // image de l'ancien bureau : ignorée
        assert_eq!(reactivation_pdu(1003, ironrdp_pdu::Action::FastPath, &[0, 3, 0]), Reactivation::Ignore);
        // illisible : laissé à la séquence, qui signale l'erreur
        assert_eq!(reactivation_pdu(1003, x, &[3, 0]), Reactivation::Sequence);
    }

}

