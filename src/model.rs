use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// Protocole de connexion d'un hôte.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug, Hash)]
pub enum Protocol {
    #[default]
    Ssh,
    Rdp,
    Vnc,
}

impl Protocol {
    pub const ALL: [Protocol; 3] = [Protocol::Ssh, Protocol::Rdp, Protocol::Vnc];

    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh => 22,
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Protocol::Ssh => "SSH",
            Protocol::Rdp => "RDP",
            Protocol::Vnc => "VNC",
        }
    }

    /// Bureau graphique (RDP, VNC) plutôt que terminal.
    pub fn is_graphical(self) -> bool {
        self != Protocol::Ssh
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum Auth {
    #[default]
    Password,
    Key,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Host {
    pub id: Uuid,
    pub label: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub protocol: Protocol,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    /// Domaine Windows (RDP uniquement, optionnel).
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub auth: Auth,
    #[serde(default)]
    pub password: String,
    /// Contenu PEM/OpenSSH de la clé privée (stocké dans le coffre chiffré).
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub passphrase: String,
    /// Hôte de rebond (ProxyJump). Peut lui-même avoir un rebond : chaîne résolue récursivement.
    #[serde(default)]
    pub jump: Option<Uuid>,
    /// Profil VPN par lequel passe la connexion (tunnel propre à Escale, le reste du PC n'est pas concerné).
    #[serde(default)]
    pub vpn: Option<Uuid>,
    /// Profil VPN résolu par `VaultData::chain` sur le premier hôte de la chaîne : c'est lui qui
    /// ouvre la première connexion TCP, à travers ce tunnel. Jamais enregistré.
    #[serde(skip)]
    pub route_vpn: Option<std::sync::Arc<VpnProfile>>,
    /// Empreinte SHA256 de la clé serveur (SSH) ou de la clé publique du certificat (RDP), mémorisée (TOFU).
    #[serde(default)]
    pub known_key: Option<String>,
    /// Options du bureau à distance (RDP uniquement), propres à chaque hôte.
    #[serde(default)]
    pub rdp: RdpOptions,
}

/// Pipeline graphique demandé au serveur RDP.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum RdpGraphics {
    /// RDPGFX avec H.264 (AVC444 puis AVC420), repli automatique sur l'ancien mode.
    #[default]
    Auto,
    /// RDPGFX sans H.264 : RemoteFX Progressive, ClearCodec, Planar (sans perte possible).
    RemoteFx,
    /// Ancien mode bitmap (RemoteFX / NSCodec / Planar / RLE), compatible avec tous les serveurs.
    Legacy,
}

/// Sécurité de la connexion RDP.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum RdpSecurity {
    /// NLA (CredSSP) : identifiants vérifiés avant l'ouverture de la session. NTLM, ou Kerberos si un KDC est indiqué.
    #[default]
    Nla,
    /// TLS seul : l'écran d'ouverture de session Windows s'affiche (serveurs sans NLA).
    Tls,
}

/// Affichage du bureau distant.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum RdpDisplay {
    /// Résolution suivant la taille de la fenêtre (redimensionnement dynamique).
    #[default]
    Dynamic,
    /// Résolution fixe, image mise à l'échelle dans la fenêtre.
    FixedFit,
    /// Résolution fixe, pixels 1:1 (défilement si la fenêtre est plus petite).
    FixedNative,
}

/// Son du bureau distant.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum RdpAudio {
    /// Joué sur cet ordinateur.
    #[default]
    Local,
    /// Laissé sur l'ordinateur distant.
    Remote,
    /// Aucun son.
    Off,
}

/// Compression des données RDP (MPPC / XCRUSH).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum RdpCompression {
    None,
    K8,
    #[default]
    K64,
    Rdp6,
    Rdp61,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct RdpOptions {
    // --- affichage
    pub graphics: RdpGraphics,
    pub display: RdpDisplay,
    /// Bureau distant étendu à tous les écrans de cet ordinateur (`mstsc /multimon`) : ouvert dans
    /// une fenêtre qui les couvre tous ; la résolution suit leur disposition.
    pub multimon: bool,
    /// Écrans choisis pour `multimon` (noms Windows, `\\.\DISPLAY2`) ; vide = tous.
    pub screens: Vec<String>,
    /// Résolution fixe (modes `FixedFit` / `FixedNative`).
    pub width: u16,
    pub height: u16,
    /// Mise à l'échelle annoncée au serveur, en % (100, 125, 150, 175, 200…). 0 = celle de cet écran.
    pub scale: u32,
    /// Profondeur de couleur (ancien mode) : 32, 24, 16 ou 15.
    pub color_depth: u8,
    /// Curseur dessiné par le serveur (formes Windows) plutôt que la flèche locale.
    pub server_pointer: bool,
    // --- sécurité
    pub security: RdpSecurity,
    /// Centre de distribution Kerberos (ex. `dc01.corp.local` ou `tcp://dc01:88`). Vide = NTLM.
    pub kdc: String,
    // --- ressources locales
    pub audio: RdpAudio,
    /// Micro de cet ordinateur transmis au bureau distant.
    pub microphone: bool,
    /// Presse-papiers partagé (texte, images, fichiers).
    pub clipboard: bool,
    /// Dossier local partagé (`\\tsclient\Escale`).
    pub drive: bool,
    /// Dossier partagé personnalisé ; vide = dossier propre à l'hôte dans le profil d'Escale.
    pub drive_path: String,
    /// Disposition clavier (identifiant Windows, ex. 0x040C) ; 0 = celle de cet ordinateur.
    pub keyboard_layout: u32,
    /// Raccourcis Windows (Alt+Tab, Win…) envoyés au bureau distant quand il a le focus.
    pub windows_keys: bool,
    // --- performances (expérience)
    pub compression: RdpCompression,
    pub wallpaper: bool,
    pub full_window_drag: bool,
    pub menu_animations: bool,
    pub themes: bool,
    pub font_smoothing: bool,
    pub desktop_composition: bool,
    // --- programme et session
    /// Programme lancé à l'ouverture de session à la place du bureau (vide = bureau).
    pub alternate_shell: String,
    pub work_dir: String,
    /// Session console / administrateur (`mstsc /admin`).
    pub admin: bool,
    /// Reconnexion automatique après une coupure réseau.
    pub auto_reconnect: bool,
}

impl Default for RdpOptions {
    fn default() -> Self {
        Self {
            graphics: RdpGraphics::Auto,
            display: RdpDisplay::Dynamic,
            multimon: false,
            screens: Vec::new(),
            width: 1920,
            height: 1080,
            scale: 0,
            color_depth: 32,
            server_pointer: true,
            security: RdpSecurity::Nla,
            kdc: String::new(),
            audio: RdpAudio::Local,
            microphone: false,
            clipboard: true,
            drive: true,
            drive_path: String::new(),
            keyboard_layout: 0,
            windows_keys: true,
            compression: RdpCompression::K64,
            wallpaper: true,
            full_window_drag: true,
            menu_animations: false,
            themes: true,
            font_smoothing: true,
            desktop_composition: true,
            alternate_shell: String::new(),
            work_dir: String::new(),
            admin: false,
            auto_reconnect: true,
        }
    }
}

impl Default for Host {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            label: String::new(),
            group: String::new(),
            protocol: Protocol::Ssh,
            hostname: String::new(),
            port: 22,
            username: "root".into(),
            domain: String::new(),
            auth: Auth::Password,
            password: String::new(),
            private_key: String::new(),
            passphrase: String::new(),
            jump: None,
            vpn: None,
            route_vpn: None,
            known_key: None,
            rdp: RdpOptions::default(),
        }
    }
}

impl Host {
    pub fn display_name(&self) -> &str {
        if self.label.is_empty() { &self.hostname } else { &self.label }
    }

    pub fn address(&self) -> String {
        let host = if self.port == self.protocol.default_port() {
            self.hostname.clone()
        } else {
            format!("{}:{}", self.hostname, self.port)
        };
        match self.protocol {
            Protocol::Vnc => host,
            Protocol::Rdp if self.username.is_empty() => host,
            Protocol::Rdp if !self.domain.is_empty() => format!("{}\\{}@{host}", self.domain, self.username),
            _ => format!("{}@{host}", self.username),
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.password.zeroize();
        self.private_key.zeroize();
        self.passphrase.zeroize();
    }
}

/// Type de VPN d'un profil.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum VpnKind {
    #[default]
    WireGuard,
    OpenVpn,
}

impl VpnKind {
    pub fn label(self) -> &'static str {
        match self {
            VpnKind::WireGuard => "WireGuard",
            VpnKind::OpenVpn => "OpenVPN",
        }
    }
}

/// Réglages WireGuard, tels qu'écrits dans un fichier `.conf` ([Interface] / [Peer]).
/// Les listes restent du texte saisi (« 10.0.0.2/32, fd00::2/128 ») et sont vérifiées à la connexion.
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
#[serde(default)]
pub struct WireGuardConfig {
    /// Clé privée de ce poste (base64).
    pub private_key: String,
    /// Adresses de ce poste dans le VPN (`Address`).
    pub address: String,
    /// Serveurs DNS du VPN, éventuellement suivis de domaines de recherche (`DNS`).
    pub dns: String,
    /// 0 = automatique (1420).
    pub mtu: u16,
    /// Clé publique du serveur (base64).
    pub peer_public_key: String,
    /// Clé partagée optionnelle (base64).
    pub preshared_key: String,
    /// Serveur VPN : `vpn.exemple.fr:51820`.
    pub endpoint: String,
    /// Réseaux joignables par le tunnel (`AllowedIPs`). Vide = tout.
    pub allowed_ips: String,
    /// Keepalive persistant en secondes (0 = aucun).
    pub keepalive: u16,
}

impl Drop for VpnProfile {
    fn drop(&mut self) {
        self.wireguard.private_key.zeroize();
        self.wireguard.preshared_key.zeroize();
        self.openvpn.key.zeroize();
        self.openvpn.tls_auth.zeroize();
        self.openvpn.tls_crypt.zeroize();
        self.password.zeroize();
    }
}

/// Transport d'un VPN OpenVPN.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum OpenVpnProto {
    #[default]
    Udp,
    Tcp,
}

/// Réglages OpenVPN, tels qu'écrits dans un fichier `.ovpn` (fichiers `<ca>`, `<cert>`… intégrés).
/// Les options poussées par le serveur (adresse, routes, DNS, chiffrement négocié) ne sont pas
/// enregistrées : elles arrivent à chaque connexion.
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
#[serde(default)]
pub struct OpenVpnConfig {
    /// Serveur (`remote`) : nom ou adresse IP, sans port.
    pub remote: String,
    /// 0 = 1194.
    pub port: u16,
    pub proto: OpenVpnProto,
    /// Autorité de certification du serveur (PEM, `<ca>`).
    pub ca: String,
    /// Certificat client (PEM, `<cert>`), vide si le serveur ne l'exige pas.
    pub cert: String,
    /// Clé privée client (PEM, `<key>`).
    pub key: String,
    /// Clé statique `tls-auth` (« -----BEGIN OpenVPN Static key V1----- »), vide = aucune.
    pub tls_auth: String,
    /// `key-direction` / 2e argument de `tls-auth` : "" (bidirectionnel), "0" ou "1".
    pub key_direction: String,
    /// Clé statique `tls-crypt`, vide = aucune.
    pub tls_crypt: String,
    /// `cipher` historique (ex. AES-256-CBC), utilisé si le serveur ne négocie pas.
    pub cipher: String,
    /// `data-ciphers` (ex. AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305), vide = valeurs par défaut.
    pub data_ciphers: String,
    /// `auth` : condensé HMAC (SHA1 par défaut, SHA256, SHA512).
    pub auth: String,
    /// `auth-user-pass` : identifiant et mot de passe du profil envoyés au serveur.
    pub auth_user_pass: bool,
    /// `verify-x509-name` (nom attendu dans le certificat du serveur), vide = non vérifié.
    pub verify_x509_name: String,
    /// `remote-cert-tls server`.
    pub remote_cert_tls: bool,
    /// Cadrage de compression du profil (jamais compressé, seul l'octet d'en-tête est géré) :
    /// "" (aucun), "comp-lzo", "compress" (stub / lz4) ou "compress stub-v2" (lz4-v2).
    /// Un ancien profil enregistré avec un booléen est relu (vrai = "comp-lzo").
    #[serde(deserialize_with = "compression_compat")]
    pub compression: String,
    /// `route` / `route-ipv6` du profil : réseaux joignables en plus de ceux poussés par le
    /// serveur, en notation CIDR séparés par des espaces (« 192.168.1.0/24 fd00::/64 »).
    pub routes: String,
    /// `redirect-gateway` dans le profil : tout passe par le VPN.
    pub redirect_gateway: bool,
    /// `route-nopull` : routes poussées par le serveur ignorées (seules celles du profil comptent).
    pub route_nopull: bool,
    /// `reneg-sec` : durée de vie d'une clé en secondes ; `None` = 3600, `Some(0)` = jamais.
    pub reneg_sec: Option<u32>,
    /// `tun-mtu` du profil, 0 = 1500 (un `tun-mtu` poussé l'emporte).
    pub tun_mtu: u16,
    /// `ping` / `keepalive` du profil en secondes, 0 = non indiqué (une option poussée l'emporte).
    pub ping: u32,
    /// `ping-restart` / `keepalive` du profil en secondes, 0 = non indiqué.
    pub ping_restart: u32,
}

/// `compression` : texte de la directive, ou booléen des profils d'avant (vrai = comp-lzo).
fn compression_compat<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Compat {
        Flag(bool),
        Text(String),
    }
    Ok(match Compat::deserialize(d)? {
        Compat::Flag(true) => "comp-lzo".into(),
        Compat::Flag(false) => String::new(),
        Compat::Text(t) => t,
    })
}

/// Profil VPN réutilisable : plusieurs hôtes peuvent passer par le même tunnel.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct VpnProfile {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub kind: VpnKind,
    #[serde(default)]
    pub wireguard: WireGuardConfig,
    #[serde(default)]
    pub openvpn: OpenVpnConfig,
    /// Identifiant envoyé au serveur VPN (OpenVPN `auth-user-pass`).
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

impl Default for VpnProfile {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            kind: VpnKind::WireGuard,
            wireguard: WireGuardConfig::default(),
            openvpn: OpenVpnConfig::default(),
            username: String::new(),
            password: String::new(),
        }
    }
}

impl VpnProfile {
    /// Serveur VPN, pour l'affichage.
    pub fn server(&self) -> &str {
        match self.kind {
            VpnKind::WireGuard => self.wireguard.endpoint.trim(),
            VpnKind::OpenVpn => self.openvpn.remote.trim(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    pub font_size: f32,
    pub scrollback: usize,
    /// La sélection est copiée automatiquement dans le presse-papiers.
    pub copy_on_select: bool,
    /// Clic droit = coller (style PuTTY) au lieu du menu contextuel.
    pub right_click_paste: bool,
    /// Demander confirmation avant de coller plusieurs lignes.
    pub confirm_multiline_paste: bool,
    /// Autoriser les applications distantes à écrire dans le presse-papiers (OSC 52).
    pub allow_osc52: bool,
    pub cursor_blink: bool,
    /// Clignotement visuel sur la cloche (BEL).
    pub visual_bell: bool,
    /// Terminal actif : Ctrl+Tab, Alt+1…9, Ctrl+−/=/0, Ctrl+, et F11 vont au serveur au lieu d'Escale.
    pub keys_to_server: bool,
    /// Invite `[sudo]` : le mot de passe enregistré de l'hôte est envoyé automatiquement.
    pub sudo_autosend: bool,
    /// Barre latérale gauche repliée (seules les icônes restent visibles).
    pub sidebar_collapsed: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            font_size: 14.0,
            scrollback: 5000,
            copy_on_select: true,
            right_click_paste: false,
            confirm_multiline_paste: true,
            allow_osc52: true,
            cursor_blink: true,
            visual_bell: true,
            keys_to_server: false,
            sudo_autosend: false,
            sidebar_collapsed: false,
        }
    }
}

/// Taille de l'historique des connexions.
pub const RECENT_MAX: usize = 8;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct VaultData {
    pub hosts: Vec<Host>,
    /// Profils VPN, choisis dans l'éditeur d'hôte.
    #[serde(default)]
    pub vpns: Vec<VpnProfile>,
    /// Propriétaire du coffre (fait foi : `profil.json` n'en est qu'une copie en clair).
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub settings: Settings,
    /// Code PIN choisi (conservé chiffré ici pour réactiver le déverrouillage rapide
    /// après une saisie de mot de passe maître).
    #[serde(default)]
    pub pin: Option<String>,
    /// Derniers hôtes connectés, du plus récent au plus ancien.
    #[serde(default)]
    pub recent: Vec<Uuid>,
}

impl VaultData {
    pub fn host(&self, id: Uuid) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == id)
    }

    /// Place l'hôte en tête de l'historique des connexions.
    pub fn touch_recent(&mut self, id: Uuid) {
        let hosts = &self.hosts;
        self.recent.retain(|r| *r != id && hosts.iter().any(|h| h.id == *r));
        self.recent.insert(0, id);
        self.recent.truncate(RECENT_MAX);
    }

    pub fn vpn(&self, id: Uuid) -> Option<&VpnProfile> {
        self.vpns.iter().find(|v| v.id == id)
    }

    /// Chaîne de connexion : [premier rebond, ..., cible]. Erreur si cycle ou hôte manquant.
    /// Le VPN choisi sur l'un des hôtes de la chaîne est rattaché au premier (`route_vpn`) :
    /// VPN → rebonds SSH → cible.
    pub fn chain(&self, target: Uuid) -> Result<Vec<Host>, String> {
        let mut chain = Vec::new();
        let mut cur = Some(target);
        while let Some(id) = cur {
            if chain.iter().any(|h: &Host| h.id == id) {
                return Err("Boucle détectée dans la chaîne de rebonds".into());
            }
            let h = self.host(id).ok_or("Hôte de rebond introuvable")?;
            // seul SSH sait ouvrir un tunnel vers l'hôte suivant
            if !chain.is_empty() && h.protocol != Protocol::Ssh {
                return Err(format!("Le rebond « {} » n'est pas un hôte SSH", h.display_name()));
            }
            chain.push(h.clone());
            cur = h.jump;
        }
        chain.reverse();
        let mut vpn: Option<Uuid> = None;
        for h in &chain {
            match (vpn, h.vpn) {
                (Some(a), Some(b)) if a != b => {
                    return Err(format!("« {} » passe par un autre VPN que le reste de la chaîne : un seul VPN par connexion", h.display_name()));
                }
                (None, Some(b)) => vpn = Some(b),
                _ => {}
            }
        }
        if let Some(id) = vpn {
            let p = self.vpn(id).ok_or("Profil VPN introuvable")?;
            chain[0].route_vpn = Some(std::sync::Arc::new(p.clone()));
        }
        Ok(chain)
    }
}
