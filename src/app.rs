use crate::desktop::{self, DesktopCmd, DesktopHandle, DesktopView};
use crate::files::FileManager;
use crate::lock::LockScreen;
use crate::model::{Auth, Host, Protocol, RdpAudio, RdpCompression, RdpDisplay, RdpGraphics, RdpOptions, RdpSecurity, VaultData, VpnKind, VpnProfile, OpenVpnProto};
use crate::pin;
use crate::ssh::{self, Cmd, Event, SessionHandle};
use crate::terminal::{self, Terminal};
use crate::theme::*;
use crate::vault::{self, Vault};
use crate::widgets::{self as w, Icon, Kind};
use crate::{rdp, rfb};
use eframe::egui::{self, Align2, Color32, FontId, Margin, Rect, RichText, Sense, Stroke, Vec2, pos2, vec2};
use std::path::{Path, PathBuf};
use tokio::sync::oneshot;
use uuid::Uuid;
use zeroize::Zeroize;

enum TabState {
    Connecting,
    Connected,
    Closed(Option<String>),
}

// quelques onglets au plus : la différence de taille entre les variantes ne coûte rien
#[allow(clippy::large_enum_variant)]
enum Session {
    Term { term: Terminal, handle: SessionHandle },
    Desktop { view: DesktopView, handle: DesktopHandle },
}

impl Session {
    fn rx(&self) -> &std::sync::mpsc::Receiver<Event> {
        match self {
            Session::Term { handle, .. } => &handle.rx,
            Session::Desktop { handle, .. } => &handle.rx,
        }
    }

    fn close(&self) {
        match self {
            Session::Term { handle, .. } => {
                let _ = handle.tx.send(Cmd::Close);
            }
            Session::Desktop { handle, .. } => {
                let _ = handle.tx.send(DesktopCmd::Close);
            }
        }
    }

    /// Message affiché dans le terminal, ou rien pour un bureau graphique.
    fn note(&mut self, text: &str) {
        if let Session::Term { term, .. } = self {
            let _ = term.feed(text.as_bytes());
        }
    }
}

struct Tab {
    host_id: Uuid,
    title: String,
    protocol: Protocol,
    session: Session,
    state: TabState,
    /// Dernière étape de connexion (bureaux graphiques, qui n'ont pas de terminal pour l'afficher).
    status: String,
    /// Nouvelle sortie ou cloche dans un onglet en arrière-plan.
    activity: bool,
    /// Gestionnaire de fichiers (SFTP / dossier partagé), créé à la première ouverture.
    files: Option<FileManager>,
    show_files: bool,
    /// Identifiant stable (fenêtre séparée).
    uid: Uuid,
    /// Session affichée dans sa propre fenêtre.
    popped: bool,
    popup_fullscreen: bool,
    /// Bureau RDP sur plusieurs écrans (option de l'hôte) : sa fenêtre séparée les couvre.
    multimon: bool,
    /// Écrans choisis dans l'hôte à l'ouverture de la session (vide = tous).
    screens: Vec<String>,
    /// Barre flottante visible jusqu'à cet instant (plein écran, fenêtre séparée).
    toolbar_until: f64,
    /// La session actuelle a déjà été ouverte (un nouvel `Connected` = reconnexion automatique).
    was_connected: bool,
    /// Dossier partagé par la session RDP en cours (option de l'hôte à son ouverture), sinon `None`.
    share: Option<PathBuf>,
    /// Ce que montre le panneau Fichiers d'un bureau RDP (cf. `rdp_files`), pour le refaire si cela change.
    files_for: Option<Result<PathBuf, &'static str>>,
    /// L'hôte a un mot de passe enregistré (bouton « Saisir le mot de passe » sur une invite sudo).
    has_password: bool,
    /// Bouton cliqué : le mot de passe part à l'image suivante (le coffre n'est pas accessible au rendu).
    pw_request: bool,
    /// Mot de passe déjà envoyé à l'invite affichée (masque le bouton jusqu'à la prochaine sortie).
    pw_sent: bool,
    /// Mot de passe déjà envoyé automatiquement (réglage `sudo_autosend`) depuis la dernière commande
    /// validée : une invite qui réapparaît (mot de passe refusé) n'est pas resservie.
    pw_auto: bool,
}

impl Tab {
    fn title(&self) -> &str {
        match &self.session {
            Session::Term { term, .. } => term.title().unwrap_or(&self.title),
            Session::Desktop { .. } => &self.title,
        }
    }
}

/// Filtre de la page des hôtes.
#[derive(Default, Clone, PartialEq)]
struct HostFilter {
    protocol: Option<Protocol>,
    /// `Some("")` = sans groupe.
    group: Option<String>,
}

impl HostFilter {
    fn matches(&self, h: &Host) -> bool {
        self.protocol.is_none_or(|p| p == h.protocol) && self.group.as_ref().is_none_or(|g| *g == h.group)
    }
}

struct HostKeyPrompt {
    host_id: Uuid,
    host_name: String,
    fingerprint: String,
    previous: Option<String>,
    reply: Option<oneshot::Sender<bool>>,
}

/// Clé SSH en cours d'installation sur un hôte (bouton « Clé » de la barre de session).
struct KeySetup {
    host_id: Uuid,
    host_name: String,
    /// Clé privée générée, enregistrée dans l'hôte une fois la clé publique ajoutée au serveur.
    private_key: zeroize::Zeroizing<String>,
    reply: oneshot::Receiver<Result<(), String>>,
    /// Résultat, une fois l'installation terminée.
    done: Option<Result<(), String>>,
}

struct Editor {
    host: Host,
    is_new: bool,
    show_password: bool,
    show_passphrase: bool,
    show_key: bool,
    /// Onglet affiché dans les options du bureau à distance.
    rdp_tab: RdpTab,
    error: Option<String>,
}

/// Éditeur d'un profil VPN (ouvert depuis l'éditeur d'hôte ou les paramètres).
struct VpnEditor {
    profile: VpnProfile,
    is_new: bool,
    show_key: bool,
    show_psk: bool,
    /// Mot de passe OpenVPN affiché.
    show_password: bool,
    /// Fichier OpenVPN intégré ouvert en édition (un seul à la fois).
    open_part: Option<OvpnPart>,
    /// Ouvert depuis l'éditeur d'hôte : un nouveau profil y est choisi à l'enregistrement.
    from_host: bool,
    /// Second clic sur « Supprimer » attendu.
    confirm_delete: bool,
    error: Option<String>,
    notice: Option<String>,
}

impl VpnEditor {
    fn new(profile: VpnProfile, is_new: bool, from_host: bool) -> Self {
        Self {
            profile,
            is_new,
            show_key: false,
            show_psk: false,
            show_password: false,
            open_part: None,
            from_host,
            confirm_delete: false,
            error: None,
            notice: None,
        }
    }
}

struct PinFlow {
    first: String,
    second: String,
    confirm: bool,
    shake_at: Option<f64>,
}

#[derive(Default)]
struct SettingsDialog {
    open: bool,
    old_pw: String,
    new_pw: String,
    new_pw2: String,
    show_pw: bool,
    message: Option<(bool, String)>,
    pin_flow: Option<PinFlow>,
    pin_message: Option<(bool, String)>,
    export_pw: String,
    show_export_pw: bool,
    export_message: Option<(bool, String)>,
    import_pw: String,
    show_import_pw: bool,
    import_message: Option<(bool, String)>,
    /// Coffres de l'appareil (relus à l'ouverture des paramètres).
    vaults: Option<Vec<vault::VaultInfo>>,
    owner_message: Option<(bool, String)>,
}

#[derive(Default)]
struct Palette {
    query: String,
    selected: usize,
    /// Amener la ligne sélectionnée à l'écran (après une navigation clavier uniquement).
    scroll: bool,
}

enum Action {
    Connect(Uuid),
    Edit(Uuid),
    New,
    Delete(Uuid),
    Lock,
    Settings,
    Shortcuts,
    Palette,
    Home,
    Select(usize),
    CloseTab(usize),
    Reconnect(usize),
    Zoom(i8),
    /// Affiche la session seule (terminal ou bureau).
    Console(usize),
    /// Ouvre / ferme le panneau de fichiers.
    Files(usize),
    /// Fichiers déposés sur la fenêtre, à envoyer vers l'hôte de l'onglet.
    Upload(usize, Vec<PathBuf>),
    ToggleSidebar,
    /// Session dans sa propre fenêtre / retour dans Escale.
    PopOut(usize),
    PopIn(usize),
    /// Fenêtre séparée en plein écran ou non.
    PopupFullscreen(usize, bool),
    /// Plein écran de la session dans la fenêtre principale (barres masquées).
    Immersive(bool),
    CtrlAltDel(usize),
    /// Ctrl+Maj+Échap (gestionnaire des tâches) envoyé au bureau distant.
    TaskManager(usize),
    FocusPopup(usize),
    /// Réduit la fenêtre séparée d'une session.
    Minimize(usize),
    /// Génère une clé, l'ajoute au serveur par la session ouverte et passe l'hôte en connexion par clé.
    SetupKey(usize),
}

struct Unlocked {
    vault: Vault,
    data: VaultData,
    tabs: Vec<Tab>,
    active: Option<usize>,
    search: String,
    editor: Option<Editor>,
    vpn_editor: Option<VpnEditor>,
    confirm_delete: Option<Uuid>,
    prompts: Vec<HostKeyPrompt>,
    settings: SettingsDialog,
    palette: Option<Palette>,
    show_shortcuts: bool,
    error: Option<String>,
    primary: String,
    /// Collage multiligne en attente de confirmation : (onglet, texte).
    paste_confirm: Option<(usize, String)>,
    /// Case « Ne plus demander » de la confirmation de collage.
    paste_dont_ask: bool,
    key_setup: Option<KeySetup>,
    filter: HostFilter,
    /// Session active en plein écran dans la fenêtre principale.
    immersive: bool,
    /// Taille de la zone de session en pixels, pour la résolution initiale des bureaux RDP.
    view_px: Vec2,
}

pub struct EscaleApp {
    rt: tokio::runtime::Runtime,
    logo: egui::TextureHandle,
    state: Option<Unlocked>,
    lock: LockScreen,
    fullscreen: bool,
    /// Icône des fenêtres séparées.
    icon: std::sync::Arc<egui::IconData>,
    /// Titre appliqué à la fenêtre principale.
    window_title: String,
}

const SHORTCUTS: &[(&str, &[(&str, &str)])] = &[
    (
        "Onglets",
        &[
            ("Nouvel onglet (connexion rapide)", "Ctrl+Maj+T"),
            ("Fermer l'onglet", "Ctrl+Maj+W"),
            ("Onglet suivant", "Ctrl+PgSuiv"),
            ("Onglet précédent", "Ctrl+PgPréc"),
            ("Aller à l'onglet 1…9", "Alt+1…9"),
            ("Reconnecter", "Ctrl+Maj+R"),
            ("Liste des hôtes", "Ctrl+Maj+H"),
            ("Fichiers (SFTP / partage)", "Ctrl+Maj+E"),
            ("Session en plein écran", "Ctrl+Maj+Entrée"),
        ],
    ),
    (
        "Terminal",
        &[
            ("Copier", "Ctrl+Maj+C"),
            ("Coller", "Ctrl+Maj+V"),
            ("Coller", "Maj+Inser"),
            ("Coller la sélection", "Clic molette"),
            ("Sélectionner un mot / une ligne", "Double/Triple-clic"),
            ("Étendre la sélection", "Maj+clic"),
            ("Tout sélectionner", "Ctrl+Maj+A"),
            ("Rechercher", "Ctrl+Maj+F"),
            ("Saisir le mot de passe (sudo)", "Ctrl+Maj+M"),
            ("Effacer l'historique", "Ctrl+Maj+K"),
            ("Ouvrir un lien", "Ctrl+clic"),
            ("Défiler l'historique", "Maj+PgPréc/PgSuiv"),
            ("Haut / bas de l'historique", "Maj+Début/Fin"),
            ("Sélection dans vim/htop", "Maj+glisser"),
            ("Interrompre (SIGINT)", "Ctrl+C"),
        ],
    ),
    (
        "Application",
        &[
            ("Palette de connexion", "Ctrl+Maj+P"),
            ("Nouvel hôte", "Ctrl+Maj+N"),
            ("Paramètres", "Ctrl+,"),
            ("Replier la barre latérale", "Ctrl+Maj+B"),
            ("Verrouiller", "Ctrl+Maj+L"),
            ("Agrandir / réduire le texte", "Ctrl+Plus/Moins"),
            ("Taille normale", "Ctrl+0"),
            ("Plein écran", "F11"),
            ("Afficher les raccourcis", "Ctrl+Maj+?"),
        ],
    ),
];

impl EscaleApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply(&cc.egui_ctx);
        let img = egui::ColorImage::from_rgba_unmultiplied([128, 128], &crate::logo::render(128));
        let logo = cc.egui_ctx.load_texture("logo", img, egui::TextureOptions::LINEAR);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime tokio");
        let icon = std::sync::Arc::new(egui::IconData { rgba: crate::logo::render(64), width: 64, height: 64 });
        Self { rt, logo, state: None, lock: LockScreen::new(), fullscreen: false, icon, window_title: "Escale".into() }
    }
}

/// Retire un raccourci clavier de la file d'événements s'il a été pressé (modificateurs exacts).
fn take(ctx: &egui::Context, ctrl: bool, shift: bool, alt: bool, key: egui::Key) -> bool {
    ctx.input_mut(|i| {
        let mut hit = false;
        let mut n = 0;
        while n < i.events.len() {
            match &i.events[n] {
                egui::Event::Key { key: k, pressed: true, modifiers: m, .. }
                    if *k == key && m.ctrl == ctrl && m.shift == shift && m.alt == alt =>
                {
                    hit = true;
                    i.events.remove(n);
                    // Alt+touche produit aussi son caractère : il ne doit pas atteindre le terminal
                    if alt && matches!(i.events.get(n), Some(egui::Event::Text(_))) {
                        i.events.remove(n);
                    }
                }
                _ => n += 1,
            }
        }
        hit
    })
}

impl Unlocked {
    fn new(vault: Vault, mut data: VaultData) -> Self {
        // ancien préréglage « Réseau local » (RemoteFX sans H.264) : passé en H.264, plus fluide
        for h in &mut data.hosts {
            let o = &mut h.rdp;
            if o.graphics == RdpGraphics::RemoteFx
                && o.compression == RdpCompression::None
                && [o.wallpaper, o.full_window_drag, o.menu_animations, o.themes, o.font_smoothing, o.desktop_composition] == [true; 6]
            {
                o.graphics = RdpGraphics::Auto;
            }
        }
        // Le propriétaire chiffré fait foi : le profil en clair (simple étiquette) est réaligné.
        let mut profile = vault::read_profile(vault.path());
        if data.owner.trim().is_empty() && !profile.owner.trim().is_empty() {
            data.owner = profile.owner.clone();
            let _ = vault.save(&data);
        }
        if profile.owner != data.owner || profile.windows_user.is_empty() {
            profile.owner = data.owner.clone();
            if profile.windows_user.is_empty() {
                profile.windows_user = vault::windows_user();
            }
            let _ = vault::write_profile(vault.path(), &profile);
        }
        vault::set_last_used(vault.path());
        // PIN connu mais fichier absent (erreur précédente, changement de mot de passe) : on le réactive.
        let mut error = None;
        if let Some(p) = &data.pin
            && !pin::is_enabled(vault.path())
            && let Err(e) = pin::enable(&vault, p)
        {
            error = Some(format!("Réactivation du PIN impossible : {e}"));
        }
        Self {
            vault,
            data,
            tabs: Vec::new(),
            active: None,
            search: String::new(),
            editor: None,
            vpn_editor: None,
            confirm_delete: None,
            prompts: Vec::new(),
            settings: SettingsDialog::default(),
            palette: None,
            show_shortcuts: false,
            error,
            primary: String::new(),
            paste_confirm: None,
            paste_dont_ask: false,
            key_setup: None,
            filter: HostFilter::default(),
            immersive: false,
            view_px: vec2(1280.0, 800.0),
        }
    }

    fn modal_open(&self) -> bool {
        self.editor.is_some()
            || self.vpn_editor.is_some()
            || !self.prompts.is_empty()
            || self.confirm_delete.is_some()
            || self.settings.open
            || self.palette.is_some()
            || self.show_shortcuts
            || self.error.is_some()
            || self.paste_confirm.is_some()
            || self.key_setup.is_some()
    }

    /// Envoie le mot de passe enregistré aux invites sudo demandées (bouton ou Ctrl+Maj+M) et
    /// tient à jour la présence d'un mot de passe pour chaque onglet.
    fn send_passwords(&mut self) {
        for t in &mut self.tabs {
            let host = self.data.host(t.host_id);
            t.has_password = host.is_some_and(|h| !h.password.is_empty());
            if !std::mem::take(&mut t.pw_request) {
                continue;
            }
            if let (Some(h), Session::Term { handle, .. }) = (host, &t.session)
                && !h.password.is_empty()
            {
                let mut line = zeroize::Zeroizing::new(Vec::with_capacity(h.password.len() + 1));
                line.extend_from_slice(h.password.as_bytes());
                line.push(b'\r');
                let _ = handle.tx.send(Cmd::Data(line.to_vec()));
                t.pw_sent = true;
            }
        }
    }

    fn save(&mut self) {
        if let Err(e) = self.vault.save(&self.data) {
            self.error = Some(e);
        }
    }

    // ------------------------------------------------------------ raccourcis

    /// `term_focus` : un terminal a le focus ; avec le réglage `keys_to_server`, seuls les raccourcis
    /// Ctrl+Maj+… restent à Escale, tout le reste part vers l'application distante.
    fn shortcuts(&mut self, ctx: &egui::Context, term_focus: bool, actions: &mut Vec<Action>) {
        use egui::Key as K;
        let to_server = term_focus && self.data.settings.keys_to_server;
        if (!to_server && (take(ctx, true, true, false, K::Slash) || take(ctx, true, true, false, K::Questionmark)))
            || take(ctx, true, true, false, K::Comma)
        {
            self.show_shortcuts = !self.show_shortcuts;
        }
        if self.modal_open() {
            return;
        }
        if take(ctx, true, true, false, K::T) || take(ctx, true, true, false, K::P) {
            actions.push(Action::Palette);
        }
        // mot de passe enregistré sur une invite sudo / su de l'onglet actif
        if take(ctx, true, true, false, K::M)
            && let Some(tab) = self.active.and_then(|i| self.tabs.get_mut(i))
            && let Session::Term { term, .. } = &tab.session
            && matches!(tab.state, TabState::Connected)
            && !tab.pw_sent
            && term.password_prompt()
        {
            tab.pw_request = true;
            ctx.request_repaint();
        }
        if take(ctx, true, true, false, K::N) {
            actions.push(Action::New);
        }
        if take(ctx, true, true, false, K::L) {
            actions.push(Action::Lock);
        }
        if !to_server && take(ctx, true, false, false, K::Comma) {
            actions.push(Action::Settings);
        }
        if take(ctx, true, true, false, K::H) {
            actions.push(Action::Home);
        }
        if take(ctx, true, true, false, K::B) {
            actions.push(Action::ToggleSidebar);
        }
        if let Some(i) = self.active {
            if take(ctx, true, true, false, K::W) {
                actions.push(Action::CloseTab(i));
            }
            if take(ctx, true, true, false, K::R) {
                actions.push(Action::Reconnect(i));
            }
            if take(ctx, true, true, false, K::Enter) {
                actions.push(Action::Immersive(!self.immersive));
            }
            if take(ctx, true, true, false, K::E) {
                actions.push(if self.tabs.get(i).is_some_and(|t| t.show_files) { Action::Console(i) } else { Action::Files(i) });
            }
        }
        if to_server {
            return;
        }
        let n = self.tabs.len();
        if n > 0 {
            let cur = self.active.map(|a| a as i64).unwrap_or(-1);
            if take(ctx, true, false, false, K::PageDown) || take(ctx, true, false, false, K::Tab) {
                actions.push(Action::Select(((cur + 1).rem_euclid(n as i64)) as usize));
            }
            if take(ctx, true, false, false, K::PageUp) || take(ctx, true, true, false, K::Tab) {
                actions.push(Action::Select(((cur - 1).rem_euclid(n as i64)) as usize));
            }
            let digits = [K::Num1, K::Num2, K::Num3, K::Num4, K::Num5, K::Num6, K::Num7, K::Num8, K::Num9];
            for (i, k) in digits.into_iter().enumerate() {
                if take(ctx, false, false, true, k) && i < n {
                    actions.push(Action::Select(i));
                }
            }
        }
        for (shift, key) in [(false, K::Plus), (true, K::Plus), (false, K::Equals), (true, K::Equals)] {
            if take(ctx, true, shift, false, key) {
                actions.push(Action::Zoom(1));
            }
        }
        if take(ctx, true, false, false, K::Minus) {
            actions.push(Action::Zoom(-1));
        }
        if take(ctx, true, false, false, K::Num0) || take(ctx, true, true, false, K::Num0) {
            actions.push(Action::Zoom(0));
        }
    }

    // ------------------------------------------------------------ sessions

    /// Dossier local partagé avec un hôte RDP : celui choisi dans ses options, sinon un dossier propre
    /// à l'hôte dans le profil d'Escale (rien ne fuit d'un serveur à l'autre).
    fn share_dir(&self, h: &Host) -> PathBuf {
        share_dir_in(self.vault.path().parent().unwrap_or(Path::new(".")), h)
    }

    /// Dossier partagé par une nouvelle session de cet hôte (`None` : partage désactivé).
    fn session_share(&self, chain: &[Host]) -> Option<PathBuf> {
        chain.last().filter(|h| h.protocol == Protocol::Rdp && h.rdp.drive).map(|h| self.share_dir(h))
    }

    fn spawn_session(&self, rt: &tokio::runtime::Runtime, ctx: &egui::Context, chain: Vec<Host>, term: Option<Terminal>) -> Session {
        let target = chain.last().cloned().unwrap_or_default();
        match target.protocol {
            Protocol::Ssh => {
                let term = term.unwrap_or_else(|| Terminal::new(self.data.settings.scrollback));
                let (cols, rows) = term.size();
                let handle = ssh::spawn(rt, chain, cols as u32, rows as u32, ctx.clone());
                Session::Term { term, handle }
            }
            Protocol::Rdp => {
                let o = &target.rdp;
                // taille de la zone de session ; en résolution fixe, la session prend celle de l'hôte
                // (mêmes bornes que la validation : 200 à 8192 pixels, largeur paire)
                let size = desktop::clamp_size(self.view_px.x, self.view_px.y);
                let view = DesktopView::new(Protocol::Rdp).with_options(desktop::ViewOptions::from_rdp(o));
                let handle = rdp::spawn(chain, size, self.share_dir(&target), ctx.clone());
                Session::Desktop { view, handle }
            }
            Protocol::Vnc => Session::Desktop { view: DesktopView::new(Protocol::Vnc), handle: rfb::spawn(rt, chain, ctx.clone()) },
        }
    }

    fn connect(&mut self, rt: &tokio::runtime::Runtime, ctx: &egui::Context, host_id: Uuid) {
        let chain = match self.data.chain(host_id) {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let Some(target) = chain.last() else { return };
        let (title, protocol) = (target.display_name().to_string(), target.protocol);
        let multimon = uses_all_screens(target);
        let screens = target.rdp.screens.clone();
        let share = self.session_share(&chain);
        let session = self.spawn_session(rt, ctx, chain, None);
        self.tabs.push(Tab {
            host_id,
            title,
            protocol,
            session,
            state: TabState::Connecting,
            status: "Connexion…".into(),
            activity: false,
            files: None,
            show_files: false,
            uid: Uuid::new_v4(),
            // plusieurs écrans : la fenêtre qui les couvre s'ouvre une fois connecté (l'invite du
            // certificat, dans la fenêtre Escale, reste visible)
            popped: false,
            popup_fullscreen: false,
            multimon,
            screens,
            toolbar_until: 0.0,
            was_connected: false,
            share,
            files_for: None,
            has_password: false,
            pw_request: false,
            pw_sent: false,
            pw_auto: false,
        });
        self.active = Some(self.tabs.len() - 1);
        self.data.touch_recent(host_id);
        self.save();
    }

    fn reconnect(&mut self, rt: &tokio::runtime::Runtime, ctx: &egui::Context, idx: usize) {
        let Some(tab) = self.tabs.get(idx) else { return };
        let chain = match self.data.chain(tab.host_id) {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let tab = &mut self.tabs[idx];
        tab.session.close();
        // le terminal garde son historique ; le bureau repart d'une image neuve
        let term = match &mut tab.session {
            Session::Term { term, .. } => {
                let _ = term.feed(b"\r\n\x1b[90m\xe2\x80\xba Reconnexion\xe2\x80\xa6\x1b[0m\r\n");
                Some(std::mem::replace(term, Terminal::new(1)))
            }
            Session::Desktop { .. } => None,
        };
        let share = self.session_share(&chain);
        let multimon = chain.last().is_some_and(uses_all_screens);
        let screens = chain.last().map(|h| h.rdp.screens.clone()).unwrap_or_default();
        let session = self.spawn_session(rt, ctx, chain, term);
        let tab = &mut self.tabs[idx];
        // option « plusieurs écrans » changée dans l'hôte : la fenêtre suit (rouverte une fois connecté)
        if multimon != tab.multimon {
            tab.multimon = multimon;
            tab.popped = false;
            tab.popup_fullscreen = false;
        }
        tab.screens = screens;
        tab.session = session;
        tab.share = share;
        tab.was_connected = false;
        tab.pw_auto = false;
        tab.state = TabState::Connecting;
        tab.status = "Reconnexion…".into();
        // le panneau SFTP dépend de la connexion SSH : il sera rouvert sur la nouvelle
        if tab.files.as_ref().is_some_and(|f| f.is_sftp()) {
            tab.files = None;
            tab.show_files = false;
        }
        // bureau RDP : le dossier partagé (et l'état du lecteur côté serveur) est celui de la nouvelle
        // session, qui suit les options actuelles de l'hôte ; un transfert en cours n'est pas coupé
        if tab.protocol == Protocol::Rdp {
            if !tab.files.as_ref().is_some_and(|f| f.busy()) {
                tab.files = None;
                tab.files_for = None;
            }
            if tab.show_files {
                self.open_files(rt, ctx, idx);
            }
        }
    }

    fn open_files(&mut self, rt: &tokio::runtime::Runtime, ctx: &egui::Context, idx: usize) {
        let Some(tab) = self.tabs.get(idx) else { return };
        let title = tab.title.clone();
        // bureau RDP : panneau refait si ce qu'il doit montrer a changé (partage activé dans l'hôte
        // pendant la session, reconnexion), sauf pendant un transfert
        let rdp_plan = (tab.protocol == Protocol::Rdp)
            .then(|| rdp_files(tab.share.as_deref(), self.data.host(tab.host_id).is_some_and(|h| h.rdp.drive)));
        if rdp_plan.is_some() && tab.files_for != rdp_plan && !tab.files.as_ref().is_some_and(|f| f.busy()) {
            self.tabs[idx].files = None;
        }
        let tab = &self.tabs[idx];
        if tab.files.is_none() {
            let manager = match (&tab.session, &rdp_plan) {
                (Session::Term { handle, .. }, _) => {
                    let (reply, opening) = oneshot::channel();
                    let _ = handle.tx.send(Cmd::OpenSftp(reply));
                    FileManager::sftp(opening, &title, rt.handle().clone(), ctx.clone())
                }
                (Session::Desktop { handle, .. }, Some(Ok(dir))) => FileManager::shared(dir.clone(), handle.drive.clone(), &title, rt.handle().clone(), ctx.clone()),
                (Session::Desktop { .. }, Some(Err(why))) => FileManager::unavailable(why, &title, rt.handle().clone(), ctx.clone()),
                _ => FileManager::unavailable(
                    "Le protocole VNC ne transporte pas de fichiers. Pour échanger des fichiers avec cette machine, ajoutez-la aussi en SSH (SFTP).",
                    &title,
                    rt.handle().clone(),
                    ctx.clone(),
                ),
            };
            self.tabs[idx].files = Some(manager);
            self.tabs[idx].files_for = rdp_plan;
        }
        let tab = &mut self.tabs[idx];
        // le bureau distant n'est plus affiché : rien ne doit rester enfoncé côté serveur
        if let Session::Desktop { handle, .. } = &tab.session {
            let _ = handle.tx.send(DesktopCmd::Input(vec![desktop::Input::ReleaseAll]));
        }
        tab.show_files = true;
    }

    /// Bouton « Clé » : clé ed25519 générée ici, clé publique ajoutée au serveur par la session SSH
    /// ouverte ; l'hôte ne passe en connexion par clé (mot de passe en secours) qu'après confirmation.
    fn setup_key(&mut self, idx: usize) {
        let Some(tab) = self.tabs.get(idx) else { return };
        let (Session::Term { handle, .. }, TabState::Connected) = (&tab.session, &tab.state) else { return };
        let Some(host) = self.data.host(tab.host_id) else { return };
        let (private_key, public) = match ssh::generate_key() {
            Ok(k) => k,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let (reply, rx) = oneshot::channel();
        let _ = handle.tx.send(Cmd::InstallKey(public, reply));
        self.key_setup = Some(KeySetup {
            host_id: host.id,
            host_name: host.display_name().to_string(),
            private_key,
            reply: rx,
            done: None,
        });
    }

    fn close_tab(&mut self, idx: usize) {
        if idx >= self.tabs.len() {
            return;
        }
        let tab = self.tabs.remove(idx);
        tab.session.close();
        self.active = match self.active {
            _ if self.tabs.is_empty() => None,
            Some(a) if a > idx => Some(a - 1),
            Some(a) if a == idx => Some(idx.min(self.tabs.len() - 1)),
            a => a,
        };
    }

    fn pump_events(&mut self, ctx: &egui::Context) {
        let now = ctx.input(|i| i.time);
        let allow_osc52 = self.data.settings.allow_osc52;
        let sudo_autosend = self.data.settings.sudo_autosend;
        for (i, tab) in self.tabs.iter_mut().enumerate() {
            let background = self.active != Some(i);
            let events: Vec<Event> = tab.session.rx().try_iter().collect();
            let had_output = events.iter().any(|e| matches!(e, Event::Output(_)));
            for ev in events {
                match ev {
                    Event::Output(d) => {
                        tab.pw_sent = false;
                        let Session::Term { term, handle } = &mut tab.session else { continue };
                        let f = term.feed(&d);
                        // réponses du terminal (position du curseur, identification…)
                        if !f.reply.is_empty() {
                            let _ = handle.tx.send(Cmd::Data(f.reply));
                        }
                        if let Some(text) = f.clipboard.filter(|_| allow_osc52) {
                            ctx.copy_text(text);
                        }
                        if f.bell {
                            term.ring(now);
                        }
                        if background {
                            tab.activity = true;
                        }
                    }
                    Event::VerifyHostKey { host_id, host_name, fingerprint, previous, reply } => {
                        self.prompts.push(HostKeyPrompt { host_id, host_name, fingerprint, previous, reply: Some(reply) });
                    }
                    ev @ (Event::Status(_) | Event::Connected | Event::Closed(_)) => session_state(tab, ev),
                }
            }
            // envoi automatique sur une invite sudo : une seule fois par commande ; sans mot de passe
            // enregistré, rien ne part et le bouton « Aucun mot de passe enregistré » reste affiché
            if sudo_autosend
                && had_output
                && !tab.pw_auto
                && !tab.pw_sent
                && matches!(tab.state, TabState::Connected)
                && let Session::Term { term, .. } = &tab.session
                && term.sudo_prompt()
                && self.data.host(tab.host_id).is_some_and(|h| !h.password.is_empty())
            {
                tab.pw_request = true;
                tab.pw_auto = true;
            }
        }
    }

    /// Chemin affiché sous le nom de l'hôte : VPN et / ou rebond.
    fn jump_name(&self, h: &Host) -> Option<String> {
        let vpn = h.vpn.and_then(|v| self.data.vpn(v)).map(|v| format!("VPN {}", v.name));
        let jump = h.jump.and_then(|j| self.data.host(j)).map(|j| j.display_name().to_string());
        match (vpn, jump) {
            (Some(v), Some(j)) => Some(format!("{v} › {j}")),
            (v, j) => v.or(j),
        }
    }

    fn is_connected(&self, id: Uuid) -> bool {
        self.tabs.iter().any(|t| t.host_id == id && matches!(t.state, TabState::Connected))
    }

    // ------------------------------------------------------------ barre latérale

    /// Barre latérale repliée : logo, hôtes en pastilles, actions en icônes.
    fn sidebar_rail(&mut self, ui: &mut egui::Ui, logo: &egui::TextureHandle, actions: &mut Vec<Action>) {
        let max = ui.max_rect();
        w::drag_area(ui, Rect::from_min_size(pos2(max.left() - 10.0, max.top()), vec2(max.width() + 20.0, 64.0)), "sidebar");
        ui.vertical_centered(|ui| {
            ui.add_space(18.0);
            ui.add(egui::Image::from_texture(logo).fit_to_exact_size(Vec2::splat(30.0)));
            ui.add_space(14.0);
            if w::icon_button(ui, Icon::Forward, "Déplier la barre latérale  (Ctrl+Maj+B)").clicked() {
                actions.push(Action::ToggleSidebar);
            }
            ui.add_space(4.0);
            if w::icon_button(ui, Icon::Plus, "Nouvel hôte  (Ctrl+Maj+N)").clicked() {
                actions.push(Action::New);
            }
            if w::icon_button(ui, Icon::Search, "Connexion rapide  (Ctrl+Maj+P)").clicked() {
                actions.push(Action::Palette);
            }
            ui.add_space(8.0);
            ui.painter().hline(ui.max_rect().x_range().shrink(8.0), ui.cursor().top(), Stroke::new(1.0, BORDER));
            ui.add_space(8.0);
        });

        let mut hosts: Vec<&Host> = self.data.hosts.iter().collect();
        hosts.sort_by_key(|h| (h.group.to_lowercase(), h.display_name().to_lowercase()));
        let footer_h = 118.0;
        let list_h = (ui.available_height() - footer_h).max(40.0);
        let active_host = self.active.and_then(|i| self.tabs.get(i)).map(|t| t.host_id);
        egui::ScrollArea::vertical().max_height(list_h).auto_shrink([false, false]).show(ui, |ui| {
            ui.vertical_centered(|ui| {
                for h in hosts {
                    let (r, resp) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::click());
                    let hover = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.1);
                    if active_host == Some(h.id) {
                        ui.painter().rect_filled(r, 10.0, ELEVATED);
                    } else if hover > 0.0 {
                        ui.painter().rect_filled(r, 10.0, HOVER.gamma_multiply(0.55 * hover));
                    }
                    let av = r.shrink(5.0);
                    w::paint_avatar(ui.painter(), av, h.display_name());
                    if self.is_connected(h.id) {
                        let c = av.right_bottom() - vec2(2.0, 2.0);
                        ui.painter().circle_filled(c, 5.5, PANEL);
                        ui.painter().circle_filled(c, 3.8, ACCENT);
                    }
                    let resp = resp.on_hover_text(format!("{}  ·  {}  {}", h.display_name(), h.protocol.label(), h.address()));
                    if resp.clicked() {
                        actions.push(Action::Connect(h.id));
                    }
                    host_context_menu(&resp, h.id, actions);
                }
            });
        });

        let max = ui.max_rect();
        let rect = Rect::from_min_size(pos2(max.left(), max.bottom() - footer_h), vec2(max.width(), footer_h));
        ui.painter().hline(rect.x_range(), rect.top(), Stroke::new(1.0, BORDER));
        ui.scope_builder(egui::UiBuilder::new().max_rect(rect.shrink2(vec2(0.0, 8.0))), |ui| {
            ui.vertical_centered(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if w::icon_button(ui, Icon::Gear, "Paramètres  (Ctrl+,)").clicked() {
                    actions.push(Action::Settings);
                }
                if w::icon_button(ui, Icon::Keyboard, "Raccourcis  (Ctrl+Maj+?)").clicked() {
                    actions.push(Action::Shortcuts);
                }
                if w::icon_button(ui, Icon::Lock, "Verrouiller  (Ctrl+Maj+L)").clicked() {
                    actions.push(Action::Lock);
                }
            });
        });
    }

    fn sidebar(&mut self, ui: &mut egui::Ui, logo: &egui::TextureHandle, actions: &mut Vec<Action>) {
        // l'en-tête de la barre latérale sert aussi à déplacer la fenêtre
        let max = ui.max_rect();
        w::drag_area(ui, Rect::from_min_size(pos2(max.left() - 14.0, max.top()), vec2(max.width() + 28.0, 64.0)), "sidebar");
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.add(egui::Image::from_texture(logo).fit_to_exact_size(Vec2::splat(30.0)));
            ui.add_space(2.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(RichText::new("Escale").font(bold(17.0)));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if w::icon_button(ui, Icon::Back, "Replier la barre latérale  (Ctrl+Maj+B)").clicked() {
                    actions.push(Action::ToggleSidebar);
                }
            });
        });
        ui.add_space(18.0);
        w::search_input(ui, &mut self.search, "Rechercher un hôte…");
        ui.add_space(8.0);
        if w::button(ui, Kind::Primary, Some(Icon::Plus), "Nouvel hôte", ui.available_width()).clicked() {
            actions.push(Action::New);
        }
        ui.add_space(14.0);

        let q = self.search.to_lowercase();
        let mut hosts: Vec<&Host> = self
            .data
            .hosts
            .iter()
            .filter(|h| {
                q.is_empty()
                    || host_matches(h, &q)
            })
            .collect();
        hosts.sort_by_key(|h| (h.group.to_lowercase(), h.display_name().to_lowercase()));

        let footer_h = 58.0;
        let list_h = (ui.available_height() - footer_h).max(80.0);
        egui::ScrollArea::vertical().max_height(list_h).auto_shrink([false, false]).show(ui, |ui| {
            let mut last_group: Option<&str> = None;
            for h in &hosts {
                if last_group != Some(h.group.as_str()) {
                    last_group = Some(h.group.as_str());
                    let g = if h.group.is_empty() { "Hôtes" } else { h.group.as_str() };
                    let count = hosts.iter().filter(|x| x.group == h.group).count();
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(g.to_uppercase()).font(bold(11.0)).color(MUTED));
                        ui.label(RichText::new(count.to_string()).size(11.0).color(MUTED.gamma_multiply(0.7)));
                    });
                    ui.add_space(2.0);
                }
                let active_host = self.active.and_then(|i| self.tabs.get(i)).map(|t| t.host_id) == Some(h.id);
                host_row(ui, h, self.is_connected(h.id), active_host, self.jump_name(h), actions);
            }
            if self.data.hosts.is_empty() {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| {
                    w::icon_size(ui, Icon::Server, 26.0, MUTED);
                    ui.label(RichText::new("Aucun hôte").color(TEXT_DIM));
                    ui.label(RichText::new("Ajoutez votre premier serveur").size(12.0).color(MUTED));
                });
            } else if hosts.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| ui.label(RichText::new("Aucun résultat").color(MUTED)));
            }
        });

        // pied de barre latérale
        let max = ui.max_rect();
        let rect = Rect::from_min_size(pos2(max.left(), max.bottom() - footer_h), vec2(max.width(), footer_h));
        ui.painter().hline(rect.x_range(), rect.top(), Stroke::new(1.0, BORDER));
        ui.scope_builder(egui::UiBuilder::new().max_rect(rect.shrink2(vec2(0.0, 12.0))), |ui| {
            ui.horizontal_centered(|ui| {
                w::icon_size(ui, Icon::Shield, 15.0, ACCENT);
                ui.label(RichText::new("Coffre chiffré").size(12.0).color(TEXT_DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    if w::icon_button(ui, Icon::Lock, "Verrouiller  (Ctrl+Maj+L)").clicked() {
                        actions.push(Action::Lock);
                    }
                    if w::icon_button(ui, Icon::Keyboard, "Raccourcis  (Ctrl+Maj+?)").clicked() {
                        actions.push(Action::Shortcuts);
                    }
                    if w::icon_button(ui, Icon::Gear, "Paramètres  (Ctrl+,)").clicked() {
                        actions.push(Action::Settings);
                    }
                });
            });
        });
    }

    // ------------------------------------------------------------ onglets

    fn tab_bar(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        // l'espace libre de la barre d'onglets déplace la fenêtre (comme une barre de titre)
        let max = ui.max_rect();
        w::drag_area(ui, max.expand2(vec2(6.0, 0.0)), "tabbar");
        // onglet actif / nombre d'onglets : on ne fait défiler vers l'onglet actif qu'au changement
        let key = (self.active, self.tabs.len());
        let mem = egui::Id::new("tabbar-active");
        let changed = ui.data_mut(|d| d.get_temp::<(Option<usize>, usize)>(mem) != Some(key));
        ui.data_mut(|d| d.insert_temp(mem, key));
        ui.horizontal_centered(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if tab_pill(ui, Some(Icon::Home), "Hôtes", self.active.is_none(), None, false).0.clicked() {
                actions.push(Action::Home);
            }
            // place réservée à droite : « + », un peu de vide pour déplacer la fenêtre, puis − □ ×
            let reserve = 30.0 + 6.0 + 48.0 + w::WINDOW_CONTROLS_W;
            let tabs_w = (ui.available_width() - reserve).max(0.0);
            let h = ui.available_height();
            let out = ui
                .allocate_ui_with_layout(vec2(tabs_w, h), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    // molette verticale → défilement horizontal
                    ui.style_mut().always_scroll_the_only_direction = true;
                    egui::ScrollArea::horizontal()
                        .id_salt("tabbar-scroll")
                        .max_width(tabs_w)
                        .auto_shrink([true, false])
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                        .scroll_source(egui::scroll_area::ScrollSource::ALL)
                        .show(ui, |ui| {
                            ui.horizontal_centered(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                self.tab_pills(ui, changed, actions);
                            });
                        })
                })
                .inner;
            // fondus sur les bords quand des onglets sont masqués
            let r = out.inner_rect;
            let off = out.state.offset.x;
            let hidden_right = out.content_size.x - r.width() - off;
            if off > 1.0 {
                fade_edge(ui.painter(), r, true);
            }
            if hidden_right > 1.0 {
                fade_edge(ui.painter(), r, false);
            }
            if w::icon_button_sized(ui, Icon::Plus, 30.0, "Nouvel onglet  (Ctrl+Maj+T)").clicked() {
                actions.push(Action::Palette);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                w::window_controls(ui);
            });
        });
    }

    /// Pastilles des sessions ouvertes (dans la zone défilante de la barre d'onglets).
    fn tab_pills(&self, ui: &mut egui::Ui, scroll_to_active: bool, actions: &mut Vec<Action>) {
        for (i, tab) in self.tabs.iter().enumerate() {
            let dot = match tab.state {
                TabState::Connecting => WARN,
                TabState::Connected if tab.activity => TEXT,
                TabState::Connected => ACCENT,
                TabState::Closed(Some(_)) => DANGER,
                TabState::Closed(None) => MUTED,
            };
            // titre défini par le serveur (OSC 0/2), sinon nom de l'hôte
            let label = tab.title();
            let (resp, closed) = tab_pill(ui, None, label, self.active == Some(i), Some(dot), true);
            let resp = resp.on_hover_text(&tab.title);
            if scroll_to_active && self.active == Some(i) {
                resp.scroll_to_me(None);
            }
            if resp.clicked() {
                actions.push(Action::Select(i));
            }
            if resp.middle_clicked() || closed {
                actions.push(Action::CloseTab(i));
            }
            resp.context_menu(|ui| {
                if ui.button("Reconnecter").clicked() {
                    actions.push(Action::Reconnect(i));
                    ui.close();
                }
                if ui.button("Fermer").clicked() {
                    actions.push(Action::CloseTab(i));
                    ui.close();
                }
            });
        }
    }

    // ------------------------------------------------------------ accueil

    fn home(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(RichText::new("Hôtes").font(bold(28.0)));
                    let n = self.data.hosts.len();
                    let txt = match n {
                        0 => "Aucun serveur enregistré".to_string(),
                        1 => "1 serveur · double-clic pour se connecter".to_string(),
                        n => format!("{n} serveurs · double-clic pour se connecter"),
                    };
                    ui.label(RichText::new(txt).color(MUTED));
                });
                if !self.data.hosts.is_empty() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if w::button(ui, Kind::Primary, Some(Icon::Plus), "Nouvel hôte", 0.0).clicked() {
                            actions.push(Action::New);
                        }
                        if w::button(ui, Kind::Secondary, Some(Icon::Search), "Connexion rapide", 0.0)
                            .on_hover_text("Ctrl+Maj+T")
                            .clicked()
                        {
                            actions.push(Action::Palette);
                        }
                    });
                }
            });
            ui.add_space(22.0);

            if self.data.hosts.is_empty() {
                empty_state(ui, actions);
                return;
            }

            // --- filtres : protocole, puis groupe
            let all = &self.data.hosts;
            let mut groups: Vec<String> = all.iter().map(|h| h.group.clone()).collect();
            groups.sort_by_key(|g| (g.is_empty(), g.to_lowercase()));
            groups.dedup();
            if self.filter.group.as_ref().is_some_and(|g| !groups.contains(g)) {
                self.filter.group = None;
            }
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
                let in_group = |h: &&Host| self.filter.group.as_ref().is_none_or(|g| *g == h.group);
                let n = all.iter().filter(in_group).count();
                if filter_chip(ui, None, "Tous", n, self.filter.protocol.is_none(), TEXT_DIM).clicked() {
                    self.filter.protocol = None;
                }
                for p in Protocol::ALL {
                    let n = all.iter().filter(in_group).filter(|h| h.protocol == p).count();
                    if n == 0 && self.filter.protocol != Some(p) {
                        continue;
                    }
                    let sel = self.filter.protocol == Some(p);
                    if filter_chip(ui, Some(protocol_icon(p)), p.label(), n, sel, protocol_color(p)).clicked() {
                        self.filter.protocol = if sel { None } else { Some(p) };
                    }
                }
                if groups.len() > 1 || groups.first().is_some_and(|g| !g.is_empty()) {
                    ui.add_space(8.0);
                    let (r, _) = ui.allocate_exact_size(vec2(1.0, 22.0), Sense::hover());
                    ui.painter().vline(r.center().x, r.y_range(), Stroke::new(1.0, BORDER_STRONG));
                    ui.add_space(8.0);
                    let in_proto = |h: &&Host| self.filter.protocol.is_none_or(|p| p == h.protocol);
                    let n = all.iter().filter(in_proto).count();
                    if filter_chip(ui, None, "Tous les groupes", n, self.filter.group.is_none(), TEXT_DIM).clicked() {
                        self.filter.group = None;
                    }
                    for g in &groups {
                        let n = all.iter().filter(in_proto).filter(|h| h.group == *g).count();
                        let sel = self.filter.group.as_ref() == Some(g);
                        if n == 0 && !sel {
                            continue;
                        }
                        let label = if g.is_empty() { "Sans groupe" } else { g.as_str() };
                        if filter_chip(ui, Some(Icon::Folder), label, n, sel, ACCENT).clicked() {
                            self.filter.group = if sel { None } else { Some(g.clone()) };
                        }
                    }
                }
            });
            ui.add_space(18.0);

            let mut hosts: Vec<&Host> = self.data.hosts.iter().filter(|h| self.filter.matches(h)).collect();
            hosts.sort_by_key(|h| (h.group.to_lowercase(), h.display_name().to_lowercase()));
            if hosts.is_empty() {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| {
                    w::icon_size(ui, Icon::Search, 24.0, MUTED);
                    ui.label(RichText::new("Aucun hôte ne correspond à ce filtre").color(TEXT_DIM));
                    if w::link(ui, "Réinitialiser les filtres").clicked() {
                        self.filter = HostFilter::default();
                    }
                });
                return;
            }
            let gap = 14.0;
            let min_w = 270.0;
            let avail = ui.available_width();
            let cols = ((avail + gap) / (min_w + gap)).floor().max(1.0) as usize;
            let cw = (avail - gap * (cols - 1) as f32) / cols as f32;

            let mut groups: Vec<(&str, Vec<&Host>)> = Vec::new();
            for h in hosts {
                match groups.last_mut() {
                    Some((g, v)) if *g == h.group.as_str() => v.push(h),
                    _ => groups.push((h.group.as_str(), vec![h])),
                }
            }
            for (g, hs) in groups {
                w::section_title(ui, if g.is_empty() { "Sans groupe" } else { g });
                ui.add_space(4.0);
                // grille placée explicitement : une ligne de `cols` cartes à la fois
                let card_h = 78.0;
                for chunk in hs.chunks(cols) {
                    let (row, _) = ui.allocate_exact_size(vec2(avail, card_h), Sense::hover());
                    for (k, h) in chunk.iter().enumerate() {
                        let r = Rect::from_min_size(pos2(row.left() + k as f32 * (cw + gap), row.top()), vec2(cw, card_h));
                        host_card(ui, r, h, self.is_connected(h.id), actions);
                    }
                    ui.add_space(gap);
                }
                ui.add_space(12.0);
            }
        });
    }

    // ------------------------------------------------------------ éditeur d'hôte

    fn editor_modal(&mut self, ctx: &egui::Context) {
        let Some(ed) = &mut self.editor else { return };
        let mut close = false;
        let mut save = false;
        let mut delete = false;
        // seuls les hôtes SSH peuvent servir de rebond
        let others: Vec<(Uuid, String, String)> = self
            .data
            .hosts
            .iter()
            .filter(|h| h.id != ed.host.id && h.protocol == Protocol::Ssh)
            .map(|h| (h.id, h.display_name().to_string(), h.address()))
            .collect();
        // aperçu de la chaîne de rebonds
        let mut chain: Vec<String> = Vec::new();
        // VPN choisi sur l'un des rebonds (le plus proche de ce poste l'emporte, comme à la connexion)
        let mut jump_vpn: Option<Uuid> = None;
        let mut cur = ed.host.jump;
        while let Some(id) = cur {
            if chain.len() > 8 || id == ed.host.id {
                break;
            }
            match self.data.host(id) {
                Some(h) => {
                    chain.insert(0, h.display_name().to_string());
                    jump_vpn = h.vpn.or(jump_vpn);
                    cur = h.jump;
                }
                None => break,
            }
        }
        let vpns: Vec<(Uuid, String, String)> =
            self.data.vpns.iter().map(|v| (v.id, v.name.clone(), v.server().to_string())).collect();
        let vpn_name = |id: Uuid| vpns.iter().find(|(v, ..)| *v == id).map(|(_, n, _)| n.clone());
        let route_vpn = jump_vpn.or(ed.host.vpn).and_then(vpn_name);
        let jump_vpn_name = jump_vpn.filter(|j| Some(*j) != ed.host.vpn).and_then(vpn_name);
        // profil VPN à ouvrir : Some(None) = nouveau
        let mut open_vpn: Option<Option<Uuid>> = None;

        let width: f32 = 560.0;
        w::modal("host-editor").show(ctx, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                w::modal_header(
                    ui,
                    Icon::Server,
                    ACCENT,
                    if ed.is_new { "Nouvel hôte" } else { "Modifier l'hôte" },
                    "Les informations sont chiffrées dans votre coffre.",
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    if w::icon_button(ui, Icon::Close, "Fermer  (Échap)").clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(14.0);
            w::divider(ui);
            ui.add_space(8.0);

            egui::ScrollArea::vertical().max_height(ctx.content_rect().height() * 0.62).show(ui, |ui| {
                ui.set_width(width);
                let h = &mut ed.host;
                let half = (width - 12.0) / 2.0;

                w::section_title(ui, "Général");
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(half);
                        w::label(ui, "Nom");
                        w::input(ui, &mut h.label, "ex. Serveur web prod", false, half);
                    });
                    ui.vertical(|ui| {
                        ui.set_width(half);
                        w::label(ui, "Groupe");
                        w::input(ui, &mut h.group, "ex. Production", false, half);
                    });
                });
                ui.add_space(10.0);

                w::section_title(ui, "Connexion");
                let before = h.protocol;
                w::segmented(
                    ui,
                    &mut h.protocol,
                    &[(Protocol::Ssh, Icon::Terminal, "SSH"), (Protocol::Rdp, Icon::Monitor, "RDP"), (Protocol::Vnc, Icon::Monitor, "VNC")],
                    width,
                );
                if h.protocol != before {
                    // port par défaut du nouveau protocole, sauf port personnalisé
                    if h.port == before.default_port() || h.port == 0 {
                        h.port = h.protocol.default_port();
                    }
                    match (before, h.protocol) {
                        (Protocol::Ssh, Protocol::Rdp) if h.username == "root" => h.username = "Administrateur".into(),
                        (Protocol::Rdp, Protocol::Ssh) if h.username == "Administrateur" => h.username = "root".into(),
                        _ => {}
                    }
                    if h.protocol.is_graphical() {
                        h.auth = Auth::Password;
                    }
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let host_w = width - 120.0 - 12.0;
                    ui.vertical(|ui| {
                        ui.set_width(host_w);
                        w::label(ui, "Adresse");
                        w::input(ui, &mut h.hostname, "nom d'hôte ou adresse IP", false, host_w);
                    });
                    ui.vertical(|ui| {
                        ui.set_width(120.0);
                        w::label(ui, "Port");
                        let mut port = if h.port == 0 { String::new() } else { h.port.to_string() };
                        if w::input(ui, &mut port, &h.protocol.default_port().to_string(), false, 120.0).changed() {
                            port.retain(|c| c.is_ascii_digit());
                            h.port = port.parse().unwrap_or(0);
                        }
                    });
                });
                ui.add_space(4.0);
                match h.protocol {
                    Protocol::Ssh => {
                        w::label(ui, "Utilisateur");
                        w::input(ui, &mut h.username, "root", false, width);
                    }
                    Protocol::Rdp => {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.set_width(half);
                                w::label(ui, "Utilisateur");
                                w::input(ui, &mut h.username, "Administrateur", false, half);
                            });
                            ui.vertical(|ui| {
                                ui.set_width(half);
                                w::label(ui, "Domaine");
                                w::input(ui, &mut h.domain, "optionnel (ex. CORP)", false, half);
                            });
                        });
                    }
                    Protocol::Vnc => {}
                }
                ui.add_space(10.0);

                w::section_title(ui, "Authentification");
                if h.protocol == Protocol::Ssh {
                    w::segmented(ui, &mut h.auth, &[(Auth::Password, Icon::Lock, "Mot de passe"), (Auth::Key, Icon::Key, "Clé SSH")], width);
                    ui.add_space(8.0);
                }
                if h.protocol == Protocol::Rdp {
                    w::label(ui, "Mot de passe");
                    w::password_input(ui, &mut h.password, "Mot de passe Windows (NLA)", &mut ed.show_password, width);
                } else if h.protocol == Protocol::Vnc {
                    w::label(ui, "Mot de passe VNC");
                    w::password_input(ui, &mut h.password, "Vide si le serveur n'en demande pas", &mut ed.show_password, width);
                } else if h.auth == Auth::Key {
                    key_box(ui, h, &mut ed.show_key, &mut ed.error, width);
                    ui.add_space(6.0);
                    w::label(ui, "Phrase secrète");
                    w::password_input(ui, &mut h.passphrase, "Uniquement si la clé est protégée", &mut ed.show_passphrase, width);
                    ui.add_space(4.0);
                    w::label(ui, "Mot de passe de secours");
                    w::password_input(ui, &mut h.password, "Utilisé si la clé est refusée (optionnel)", &mut ed.show_password, width);
                } else {
                    w::label(ui, "Mot de passe");
                    w::password_input(ui, &mut h.password, "Mot de passe SSH", &mut ed.show_password, width);
                }
                ui.add_space(10.0);

                w::section_title(ui, "Rebond (jump host)");
                let current = h
                    .jump
                    .and_then(|j| others.iter().find(|(id, ..)| *id == j))
                    .map(|(_, n, a)| format!("{n}  ·  {a}"))
                    .unwrap_or_else(|| "Connexion directe".into());
                egui::ComboBox::from_id_salt("jump").selected_text(current).width(width).height(260.0).show_ui(ui, |ui| {
                    ui.selectable_value(&mut h.jump, None, "Connexion directe");
                    for (id, name, addr) in &others {
                        ui.selectable_value(&mut h.jump, Some(*id), format!("{name}  ·  {addr}"));
                    }
                });
                ui.add_space(10.0);

                w::section_title(ui, "VPN");
                ui.horizontal(|ui| {
                    let buttons = if h.vpn.is_some() { 2.0 } else { 1.0 } * 36.0;
                    let combo_w = width - buttons - 8.0;
                    let current = h
                        .vpn
                        .and_then(|v| vpns.iter().find(|(id, ..)| *id == v))
                        .map(|(_, n, s)| if s.is_empty() { n.clone() } else { format!("{n}  ·  {s}") })
                        .unwrap_or_else(|| "Aucun VPN".into());
                    egui::ComboBox::from_id_salt("vpn").selected_text(current).width(combo_w).height(260.0).show_ui(ui, |ui| {
                        ui.selectable_value(&mut h.vpn, None, "Aucun VPN");
                        for (id, name, server) in &vpns {
                            let label = if server.is_empty() { name.clone() } else { format!("{name}  ·  {server}") };
                            ui.selectable_value(&mut h.vpn, Some(*id), label);
                        }
                    });
                    if let Some(id) = h.vpn
                        && w::icon_button(ui, Icon::Edit, "Modifier ce profil VPN").clicked()
                    {
                        open_vpn = Some(Some(id));
                    }
                    if w::icon_button(ui, Icon::Plus, "Nouveau profil VPN").clicked() {
                        open_vpn = Some(None);
                    }
                });
                ui.add_space(4.0);
                let hint = match (&jump_vpn_name, h.vpn.is_some(), h.jump.is_some()) {
                    (Some(j), ..) => format!("Le rebond passe déjà par le VPN « {j} » : cette connexion l'emprunte aussi."),
                    (None, true, true) => "Le VPN est ouvert en premier, puis le rebond est joint à travers lui.".into(),
                    (None, true, false) => "Le tunnel ne sert qu'à Escale : le reste de cet ordinateur n'est pas concerné.".into(),
                    (None, false, _) => "Connexion depuis le réseau de cet ordinateur.".into(),
                };
                ui.label(RichText::new(hint).size(12.0).color(MUTED));
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    w::chip(ui, Some(Icon::Terminal), "Vous", TEXT_DIM);
                    if let Some(v) = &route_vpn {
                        w::icon_size(ui, Icon::Hop, 12.0, MUTED);
                        w::chip(ui, Some(Icon::Shield), &format!("VPN {v}"), WARN);
                    }
                    for c in &chain {
                        w::icon_size(ui, Icon::Hop, 12.0, MUTED);
                        w::chip(ui, Some(Icon::Server), c, ACCENT_2);
                    }
                    w::icon_size(ui, Icon::Hop, 12.0, MUTED);
                    let me = if h.label.is_empty() { "Ce serveur" } else { h.label.as_str() };
                    w::chip(ui, Some(Icon::Server), me, ACCENT);
                });

                if let Some(fp) = h.known_key.clone() {
                    ui.add_space(12.0);
                    w::section_title(ui, if h.protocol == Protocol::Rdp { "Empreinte du certificat" } else { "Empreinte du serveur" });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(fp).monospace().size(11.5).color(TEXT_DIM));
                        if w::link(ui, "Oublier").clicked() {
                            h.known_key = None;
                        }
                    });
                }

                if h.protocol == Protocol::Rdp {
                    ui.add_space(12.0);
                    rdp_options_ui(ui, &mut h.rdp, &mut ed.rdp_tab, width);
                }
            });

            if let Some(e) = &ed.error {
                ui.add_space(8.0);
                w::callout(ui, Icon::Warning, DANGER, e);
            }
            ui.add_space(12.0);
            w::divider(ui);
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if !ed.is_new && w::button(ui, Kind::Danger, Some(Icon::Trash), "Supprimer", 0.0).clicked() {
                    delete = true;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if w::button(ui, Kind::Primary, Some(Icon::Check), "Enregistrer", 0.0).clicked() {
                        save = true;
                    }
                    if w::button(ui, Kind::Ghost, None, "Annuler", 0.0).clicked() {
                        close = true;
                    }
                });
            });
        });
        // Échap ferme d'abord l'éditeur de profil VPN ouvert par-dessus
        if self.vpn_editor.is_none() && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            close = true;
        }
        if let Some(id) = open_vpn {
            let (profile, is_new) = match id.and_then(|id| self.data.vpn(id)) {
                Some(p) => (p.clone(), false),
                None => (VpnProfile::default(), true),
            };
            self.vpn_editor = Some(VpnEditor::new(profile, is_new, true));
        }

        if delete {
            self.confirm_delete = Some(ed.host.id);
            self.editor = None;
            return;
        }
        if save {
            let h = &ed.host;
            let pass = (!h.passphrase.is_empty()).then_some(h.passphrase.as_str());
            let err = if h.hostname.trim().is_empty() {
                Some("L'adresse est obligatoire.".to_string())
            } else if h.port == 0 {
                Some("Port invalide.".to_string())
            } else if h.protocol != Protocol::Vnc && h.username.trim().is_empty() {
                Some("L'utilisateur est obligatoire.".to_string())
            } else if h.protocol == Protocol::Ssh && h.auth == Auth::Key && h.private_key.trim().is_empty() {
                Some("Aucune clé privée renseignée.".to_string())
            } else if h.protocol == Protocol::Ssh
                && h.auth == Auth::Key
                && let Err(e) = russh::keys::decode_secret_key(&h.private_key, pass)
            {
                Some(format!("Clé invalide : {e}"))
            } else if h.protocol == Protocol::Rdp {
                validate_rdp(&h.rdp).err()
            } else {
                None
            };
            if let Some(e) = err {
                ed.error = Some(e);
                return;
            }
            if h.protocol != Protocol::Ssh
                && let Some(user) = self.data.hosts.iter().find(|x| x.jump == Some(h.id))
            {
                ed.error = Some(format!("Cet hôte sert de rebond à « {} » : il doit rester en SSH.", user.display_name()));
                return;
            }
            let mut host = ed.host.clone();
            host.hostname = host.hostname.trim().to_string();
            host.username = host.username.trim().to_string();
            for s in [&mut host.rdp.drive_path, &mut host.rdp.kdc, &mut host.rdp.alternate_shell, &mut host.rdp.work_dir] {
                *s = s.trim().to_string();
            }
            // empreinte d'un autre protocole (clé SSH ≠ certificat RDP) : à revalider
            if self.data.host(host.id).is_some_and(|old| old.protocol != host.protocol) {
                host.known_key = None;
            }
            let mut data = self.data.clone();
            match data.hosts.iter_mut().find(|x| x.id == host.id) {
                Some(slot) => *slot = host.clone(),
                None => data.hosts.push(host.clone()),
            }
            if let Err(e) = data.chain(host.id) {
                ed.error = Some(e);
                return;
            }
            self.data = data;
            self.editor = None;
            self.save();
        } else if close {
            self.editor = None;
        }
    }

    // ------------------------------------------------------------ éditeur de profil VPN

    fn vpn_modal(&mut self, ctx: &egui::Context) {
        let Some(ve) = &mut self.vpn_editor else { return };
        let mut close = false;
        let mut save = false;
        let mut delete = false;
        let id = ve.profile.id;
        let users: Vec<String> = self.data.hosts.iter().filter(|h| h.vpn == Some(id)).map(|h| h.display_name().to_string()).collect();
        let width: f32 = 560.0;
        let m = w::modal("vpn-editor").show(ctx, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                w::modal_header(
                    ui,
                    Icon::Shield,
                    WARN,
                    if ve.is_new { "Nouveau profil VPN" } else { "Modifier le profil VPN" },
                    "Le tunnel ne sert qu'à Escale : le reste de cet ordinateur n'est pas concerné.",
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    if w::icon_button(ui, Icon::Close, "Fermer  (Échap)").clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(14.0);
            w::divider(ui);
            ui.add_space(8.0);

            egui::ScrollArea::vertical().max_height(ctx.content_rect().height() * 0.62).show(ui, |ui| {
                vpn_form(ui, ve, &users, width);
            });

            if let Some(e) = &ve.error {
                ui.add_space(8.0);
                w::callout(ui, Icon::Warning, DANGER, e);
            }
            ui.add_space(12.0);
            w::divider(ui);
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if !ve.is_new {
                    let label = if ve.confirm_delete { "Confirmer la suppression" } else { "Supprimer" };
                    let resp = w::button(ui, Kind::Danger, Some(Icon::Trash), label, 0.0);
                    let resp = if ve.confirm_delete && !users.is_empty() {
                        resp.on_hover_text("Les hôtes qui l'utilisent passeront en connexion directe")
                    } else {
                        resp
                    };
                    if resp.clicked() {
                        if ve.confirm_delete {
                            delete = true;
                        } else {
                            ve.confirm_delete = true;
                        }
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if w::button(ui, Kind::Primary, Some(Icon::Check), "Enregistrer", 0.0).clicked() {
                        save = true;
                    }
                    if w::button(ui, Kind::Ghost, None, "Annuler", 0.0).clicked() {
                        close = true;
                    }
                });
            });
            if ve.confirm_delete && !users.is_empty() {
                ui.add_space(6.0);
                let n = users.len();
                let txt = if n > 1 { format!("{n} hôtes passeront en connexion directe.") } else { "1 hôte passera en connexion directe.".into() };
                ui.label(RichText::new(txt).size(12.0).color(DANGER));
            }
        });
        if m.should_close() {
            close = true;
        }

        if delete {
            self.data.vpns.retain(|v| v.id != id);
            for h in &mut self.data.hosts {
                if h.vpn == Some(id) {
                    h.vpn = None;
                }
            }
            if let Some(ed) = &mut self.editor
                && ed.host.vpn == Some(id)
            {
                ed.host.vpn = None;
            }
            self.vpn_editor = None;
            self.save();
            return;
        }
        if save {
            let mut p = ve.profile.clone();
            p.name = p.name.trim().to_string();
            let wg = &mut p.wireguard;
            for s in [&mut wg.private_key, &mut wg.address, &mut wg.dns, &mut wg.peer_public_key, &mut wg.preshared_key, &mut wg.endpoint, &mut wg.allowed_ips] {
                trim_in_place(s);
            }
            let o = &mut p.openvpn;
            for s in [
                &mut o.remote,
                &mut o.ca,
                &mut o.cert,
                &mut o.key,
                &mut o.tls_auth,
                &mut o.key_direction,
                &mut o.tls_crypt,
                &mut o.cipher,
                &mut o.data_ciphers,
                &mut o.auth,
                &mut o.verify_x509_name,
                &mut p.username,
            ] {
                trim_in_place(s);
            }
            if let Err(e) = crate::vpn::check(&p) {
                ve.error = Some(e);
                return;
            }
            let (is_new, from_host) = (ve.is_new, ve.from_host);
            match self.data.vpns.iter_mut().find(|v| v.id == p.id) {
                Some(slot) => *slot = p,
                None => self.data.vpns.push(p),
            }
            if is_new
                && from_host
                && let Some(ed) = &mut self.editor
            {
                ed.host.vpn = Some(id);
            }
            self.vpn_editor = None;
            self.save();
        } else if close {
            self.vpn_editor = None;
        }
    }

    // ------------------------------------------------------------ palette de connexion rapide

    fn palette_modal(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        let Some(pal) = &mut self.palette else { return };
        let q = pal.query.to_lowercase();
        let recent = &self.data.recent;
        let rank = |h: &Host| recent.iter().position(|r| *r == h.id).unwrap_or(usize::MAX);
        let mut hosts: Vec<&Host> = self
            .data
            .hosts
            .iter()
            .filter(|h| q.is_empty() || host_matches(h, &q))
            .collect();
        // sans recherche : les derniers hôtes connectés d'abord, puis les autres par nom
        let n_recent = if q.is_empty() { hosts.iter().filter(|h| rank(h) != usize::MAX).count() } else { 0 };
        if q.is_empty() {
            hosts.sort_by_cached_key(|h| (rank(h), h.display_name().to_lowercase()));
        } else {
            hosts.sort_by_cached_key(|h| (h.display_name().to_lowercase(), rank(h)));
        }
        let n = hosts.len();
        if n > 0 {
            if take(ctx, false, false, false, egui::Key::ArrowDown) {
                pal.selected = (pal.selected + 1) % n;
                pal.scroll = true;
            }
            if take(ctx, false, false, false, egui::Key::ArrowUp) {
                pal.selected = (pal.selected + n - 1) % n;
                pal.scroll = true;
            }
            pal.selected = pal.selected.min(n - 1);
        }
        let enter = take(ctx, false, false, false, egui::Key::Enter);
        let mut chosen = None;
        let modal = egui::Modal::new(egui::Id::new("palette"))
            .frame(w::modal_frame().inner_margin(Margin::same(10)))
            .backdrop_color(Color32::from_black_alpha(150))
            .show(ctx, |ui| {
                ui.set_width(540.0);
                let r = w::search_input(ui, &mut pal.query, "Se connecter à…  (nom, adresse, groupe)");
                r.request_focus();
                if r.changed() {
                    pal.selected = 0;
                    pal.scroll = true;
                }
                ui.add_space(6.0);
                if hosts.is_empty() {
                    ui.add_space(18.0);
                    ui.vertical_centered(|ui| ui.label(RichText::new("Aucun hôte trouvé").color(MUTED)));
                    ui.add_space(18.0);
                }
                egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                    for (i, h) in hosts.iter().enumerate() {
                        if n_recent > 0 && (i == 0 || i == n_recent) {
                            ui.add_space(if i == 0 { 2.0 } else { 8.0 });
                            ui.horizontal(|ui| {
                                ui.add_space(10.0);
                                ui.label(RichText::new(if i == 0 { "RÉCENTS" } else { "TOUS LES HÔTES" }).font(bold(11.0)).color(MUTED));
                            });
                            ui.add_space(2.0);
                        }
                        let sel = i == pal.selected;
                        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 50.0), Sense::click());
                        if sel || resp.hovered() {
                            ui.painter().rect_filled(rect, 10.0, if sel { ELEVATED } else { HOVER.gamma_multiply(0.5) });
                        }
                        // une seule fois par navigation : sinon la molette est ramenée sur la sélection à chaque image
                        if sel && pal.scroll {
                            ui.scroll_to_rect(rect, None);
                            pal.scroll = false;
                        }
                        let av = Rect::from_min_size(rect.min + vec2(10.0, 9.0), Vec2::splat(32.0));
                        w::paint_avatar(ui.painter(), av, h.display_name());
                        ui.painter().text(rect.min + vec2(54.0, 9.0), Align2::LEFT_TOP, h.display_name(), bold(14.0), TEXT);
                        let sub = match h.jump.and_then(|j| self.data.host(j)) {
                            Some(j) => format!("{}  ·  {}  ·  via {}", h.protocol.label(), h.address(), j.display_name()),
                            None => format!("{}  ·  {}", h.protocol.label(), h.address()),
                        };
                        ui.painter().text(rect.min + vec2(54.0, 28.0), Align2::LEFT_TOP, sub, FontId::proportional(12.0), MUTED);
                        if sel {
                            ui.painter().text(rect.right_center() - vec2(14.0, 0.0), Align2::RIGHT_CENTER, "Entrée", FontId::proportional(12.0), TEXT_DIM);
                        }
                        if resp.clicked() {
                            chosen = Some(h.id);
                        }
                    }
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.label(RichText::new("↑↓ naviguer   ·   Entrée se connecter   ·   Échap fermer").size(11.5).color(MUTED));
                });
            });
        if enter && n > 0 {
            chosen = Some(hosts[pal.selected].id);
        }
        if let Some(id) = chosen {
            actions.push(Action::Connect(id));
            self.palette = None;
        } else if modal.should_close() {
            self.palette = None;
        }
    }

    // ------------------------------------------------------------ autres modales

    fn host_key_modal(&mut self, ctx: &egui::Context) {
        let Some(p) = self.prompts.first_mut() else { return };
        let mut decision = None;
        w::modal("hostkey").show(ctx, |ui| {
            ui.set_width(500.0);
            if p.previous.is_some() {
                w::modal_header(ui, Icon::Warning, DANGER, "La clé du serveur a changé", &p.host_name);
                ui.add_space(12.0);
                w::callout(
                    ui,
                    Icon::Warning,
                    DANGER,
                    "Cela peut indiquer une attaque de type « homme du milieu », ou simplement une réinstallation du serveur. Vérifiez avant de continuer.",
                );
            } else {
                w::modal_header(ui, Icon::Shield, ACCENT, "Nouveau serveur", &p.host_name);
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Première connexion : comparez l'empreinte avec celle du serveur avant de lui faire confiance.")
                        .color(TEXT_DIM),
                );
            }
            ui.add_space(12.0);
            egui::Frame::new()
                .fill(INPUT)
                .stroke(Stroke::new(1.0, BORDER))
                .corner_radius(RADIUS)
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if let Some(prev) = &p.previous {
                        ui.label(RichText::new("ANCIENNE").font(bold(10.5)).color(MUTED));
                        ui.label(RichText::new(prev).monospace().size(12.0).color(TEXT_DIM).strikethrough());
                        ui.add_space(6.0);
                        ui.label(RichText::new("NOUVELLE").font(bold(10.5)).color(MUTED));
                    }
                    ui.label(RichText::new(&p.fingerprint).monospace().size(12.5).color(ACCENT));
                });
            ui.add_space(18.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if p.previous.is_some() { "Remplacer et continuer" } else { "Faire confiance" };
                let kind = if p.previous.is_some() { Kind::Danger } else { Kind::Primary };
                if w::button(ui, kind, Some(Icon::Check), label, 0.0).clicked() {
                    decision = Some(true);
                }
                if w::button(ui, Kind::Ghost, None, "Refuser", 0.0).clicked() {
                    decision = Some(false);
                }
            });
        });
        if let Some(ok) = decision {
            let mut p = self.prompts.remove(0);
            if let Some(r) = p.reply.take() {
                let _ = r.send(ok);
            }
            if ok {
                if let Some(h) = self.data.hosts.iter_mut().find(|h| h.id == p.host_id) {
                    h.known_key = Some(p.fingerprint.clone());
                }
                self.save();
            }
        }
    }

    fn delete_modal(&mut self, ctx: &egui::Context) {
        let Some(id) = self.confirm_delete else { return };
        let name = self.data.host(id).map(|h| h.display_name().to_string()).unwrap_or_default();
        let mut decision = None;
        let m = w::modal("delete").show(ctx, |ui| {
            ui.set_width(420.0);
            w::modal_header(ui, Icon::Trash, DANGER, &format!("Supprimer « {name} » ?"), "Cette action est définitive.");
            ui.add_space(12.0);
            ui.label(RichText::new("Les hôtes qui l'utilisent comme rebond passeront en connexion directe.").color(TEXT_DIM));
            ui.add_space(18.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if w::button(ui, Kind::Danger, Some(Icon::Trash), "Supprimer", 0.0).clicked() {
                    decision = Some(true);
                }
                if w::button(ui, Kind::Ghost, None, "Annuler", 0.0).clicked() {
                    decision = Some(false);
                }
            });
        });
        if m.should_close() {
            decision = decision.or(Some(false));
        }
        if let Some(yes) = decision {
            self.confirm_delete = None;
            if yes {
                self.data.hosts.retain(|h| h.id != id);
                for h in &mut self.data.hosts {
                    if h.jump == Some(id) {
                        h.jump = None;
                    }
                }
                self.save();
            }
        }
    }

    fn key_setup_modal(&mut self, ctx: &egui::Context) {
        let Some(k) = &mut self.key_setup else { return };
        if k.done.is_none() {
            k.done = match k.reply.try_recv() {
                Ok(r) => Some(r),
                Err(oneshot::error::TryRecvError::Empty) => None,
                Err(oneshot::error::TryRecvError::Closed) => Some(Err("La session s'est fermée pendant la configuration".into())),
            };
            // clé publique en place sur le serveur : l'hôte passe en connexion par clé, mot de passe en secours
            if let Some(Ok(())) = k.done {
                let (id, key) = (k.host_id, k.private_key.to_string());
                if let Some(h) = self.data.hosts.iter_mut().find(|h| h.id == id) {
                    h.auth = Auth::Key;
                    h.private_key = key;
                    h.passphrase.zeroize();
                }
                self.save();
            }
        }
        let Some(k) = &self.key_setup else { return };
        let mut close = false;
        w::modal("key-setup").show(ctx, |ui| {
            ui.set_width(440.0);
            match &k.done {
                None => {
                    w::modal_header(ui, Icon::Key, ACCENT, "Configuration de la clé en cours…", &k.host_name);
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(18.0).color(ACCENT));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Ajout d'une clé ed25519 dans ~/.ssh/authorized_keys du serveur").color(TEXT_DIM));
                    });
                    ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
                }
                Some(Ok(())) => {
                    w::modal_header(ui, Icon::Check, ACCENT, "Clé configurée", &k.host_name);
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(
                            "La clé privée est enregistrée dans le coffre et la clé publique sur le serveur. Les prochaines connexions se feront par clé, avec le mot de passe en secours.",
                        )
                        .color(TEXT_DIM),
                    );
                    ui.add_space(16.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        close = w::button(ui, Kind::Primary, None, "OK", 90.0).clicked();
                    });
                }
                Some(Err(e)) => {
                    w::modal_header(ui, Icon::Warning, DANGER, "Échec de la configuration de la clé", &k.host_name);
                    ui.add_space(10.0);
                    ui.label(RichText::new(e).color(TEXT_DIM));
                    ui.add_space(6.0);
                    ui.label(RichText::new("Le mode de connexion de l'hôte n'a pas été modifié.").size(12.5).color(MUTED));
                    ui.add_space(16.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        close = w::button(ui, Kind::Primary, None, "Fermer", 90.0).clicked();
                    });
                }
            }
        });
        if close {
            self.key_setup = None;
        }
    }

    fn error_modal(&mut self, ctx: &egui::Context) {
        let Some(e) = self.error.clone() else { return };
        let m = w::modal("error").show(ctx, |ui| {
            ui.set_width(420.0);
            w::modal_header(ui, Icon::Warning, DANGER, "Une erreur est survenue", "");
            ui.add_space(10.0);
            ui.label(RichText::new(e).color(TEXT_DIM));
            ui.add_space(16.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if w::button(ui, Kind::Primary, None, "OK", 90.0).clicked() {
                    self.error = None;
                }
            });
        });
        if m.should_close() {
            self.error = None;
        }
    }

    fn paste_modal(&mut self, ctx: &egui::Context) {
        let Some((idx, text)) = self.paste_confirm.clone() else { return };
        let lines = text.trim_end_matches(['\r', '\n']).lines().count();
        let mut decision = None;
        let m = w::modal("paste").show(ctx, |ui| {
            ui.set_width(540.0);
            w::modal_header(
                ui,
                Icon::Warning,
                WARN,
                &format!("Coller {lines} lignes ?"),
                "Chaque ligne peut être exécutée immédiatement par le shell distant.",
            );
            ui.add_space(12.0);
            egui::Frame::new()
                .fill(terminal::BG)
                .stroke(Stroke::new(1.0, BORDER))
                .corner_radius(RADIUS)
                .inner_margin(Margin::same(12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                        let preview: String = text.lines().take(40).collect::<Vec<_>>().join("\n");
                        ui.label(RichText::new(preview).monospace().size(12.0).color(TEXT_DIM));
                    });
                });
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                w::toggle(ui, &mut self.paste_dont_ask);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(RichText::new("Ne plus demander").color(TEXT));
                    ui.label(RichText::new("Réactivable dans Paramètres › Copier / coller").size(11.5).color(MUTED));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if w::button(ui, Kind::Primary, Some(Icon::Check), "Coller", 0.0).clicked() {
                        decision = Some(true);
                    }
                    if w::button(ui, Kind::Ghost, None, "Annuler", 0.0).clicked() {
                        decision = Some(false);
                    }
                });
            });
        });
        if ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
            decision = decision.or(Some(true));
        }
        if m.should_close() {
            decision = decision.or(Some(false));
        }
        if let Some(ok) = decision {
            self.paste_confirm = None;
            if std::mem::take(&mut self.paste_dont_ask) {
                self.data.settings.confirm_multiline_paste = false;
                self.save();
            }
            if ok
                && let Some(tab) = self.tabs.get(idx)
                && let (TabState::Connected, Session::Term { term, handle }) = (&tab.state, &tab.session)
            {
                let _ = handle.tx.send(Cmd::Data(term.paste_payload(&text)));
            }
        }
    }

    fn shortcuts_modal(&mut self, ctx: &egui::Context) {
        if !self.show_shortcuts {
            return;
        }
        let m = w::modal("shortcuts").show(ctx, |ui| {
            ui.set_width(780.0);
            ui.horizontal(|ui| {
                w::modal_header(ui, Icon::Keyboard, ACCENT_2, "Raccourcis clavier", "Inspirés de GNOME Terminal et des terminaux Linux.");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    if w::icon_button(ui, Icon::Close, "Fermer").clicked() {
                        self.show_shortcuts = false;
                    }
                });
            });
            ui.add_space(16.0);
            ui.columns(3, |cols| {
                for (col, (title, items)) in cols.iter_mut().zip(SHORTCUTS) {
                    w::section_title(col, title);
                    col.add_space(4.0);
                    for (label, keys) in *items {
                        col.label(RichText::new(*label).size(12.5).color(TEXT_DIM));
                        w::shortcut(col, keys);
                        col.add_space(6.0);
                    }
                }
            });
        });
        if m.should_close() {
            self.show_shortcuts = false;
        }
    }

    /// Liste des coffres de l'appareil et de leurs propriétaires ; le nom du coffre ouvert est
    /// modifiable. Renvoie `true` si ce nom doit être enregistré.
    fn vaults_card(&mut self, ui: &mut egui::Ui) -> bool {
        let vaults = self.settings.vaults.get_or_insert_with(vault::list).clone();
        let mut commit = false;
        w::card().inner_margin(Margin::same(16)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new("Chaque coffre est chiffré avec son propre mot de passe maître. Son PIN est lié à ce coffre précis et à la session Windows qui l'a activé : il ne peut pas en ouvrir un autre.")
                    .size(12.0)
                    .color(MUTED),
            );
            ui.add_space(10.0);
            for (i, v) in vaults.iter().enumerate() {
                if i > 0 {
                    ui.add_space(6.0);
                    w::divider(ui);
                    ui.add_space(6.0);
                }
                let mine = v.path == *self.vault.path();
                let owner = if mine && !self.data.owner.trim().is_empty() { self.data.owner.clone() } else { v.owner().to_string() };
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
                    w::paint_avatar(ui.painter(), r, &owner);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&owner).font(bold(14.0)));
                            if mine {
                                w::chip(ui, Some(Icon::Check), "Ouvert", ACCENT);
                            }
                            if pin::is_enabled(&v.path) {
                                w::chip(ui, Some(Icon::Lock), "PIN", ACCENT_2);
                            }
                        });
                        let mut sub = v.folder.clone();
                        if !v.profile.windows_user.is_empty() {
                            sub.push_str(&format!(" · session Windows « {} »", v.profile.windows_user));
                        }
                        if let Some(d) = date_fr(v.profile.created) {
                            sub.push_str(&format!(" · créé le {d}"));
                        }
                        ui.label(RichText::new(sub).size(12.0).color(MUTED));
                    });
                });
                if mine {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Propriétaire").size(12.5).color(TEXT_DIM));
                        let r = w::input(ui, &mut self.data.owner, "Nom du propriétaire", false, 240.0);
                        commit |= r.lost_focus();
                    });
                    if let Some((ok, m)) = self.settings.owner_message.as_ref().filter(|(_, m)| !m.is_empty()) {
                        ui.label(RichText::new(m).size(12.5).color(if *ok { ACCENT } else { DANGER }));
                    }
                }
            }
            if vault::can_add() {
                ui.add_space(10.0);
                ui.label(RichText::new("Pour ouvrir ou créer un autre coffre : verrouillez Escale (Ctrl+Maj+L), puis « Changer de coffre ».").size(12.0).color(MUTED));
            }
        });
        commit
    }

    /// Enregistre le nom du propriétaire dans le coffre chiffré et dans son profil en clair.
    fn rename_owner(&mut self) -> (bool, String) {
        let owner = self.data.owner.trim().to_string();
        let mut profile = vault::read_profile(self.vault.path());
        if owner == profile.owner {
            self.data.owner = owner;
            return (true, String::new());
        }
        if owner.is_empty() {
            self.data.owner = profile.owner;
            return (false, "Le nom du propriétaire ne peut pas être vide.".into());
        }
        self.data.owner = owner.clone();
        if let Err(e) = self.vault.save(&self.data) {
            return (false, e);
        }
        profile.owner = owner;
        self.settings.vaults = None;
        match vault::write_profile(self.vault.path(), &profile) {
            Ok(()) => (true, "Propriétaire enregistré.".into()),
            Err(e) => (false, e),
        }
    }

    /// Ajoute au coffre les hôtes d'une sauvegarde (ouverte avec son propre mot de passe maître).
    fn import_vault(&mut self) -> (bool, String) {
        if self.settings.import_pw.is_empty() {
            return (false, "Saisissez le mot de passe maître de la sauvegarde.".into());
        }
        let Some(src) = rfd::FileDialog::new().set_title("Importer un coffre").add_filter("Coffre Escale", &["escale"]).pick_file() else {
            return (false, "Import annulé.".into());
        };
        let imported = match Vault::open_at(src, &self.settings.import_pw) {
            Ok((_, data)) => data,
            Err(e) => return (false, if e.contains("incorrect") { "Mot de passe incorrect pour cette sauvegarde.".into() } else { e }),
        };
        let (added, skipped) = merge_hosts(&mut self.data, imported);
        if added > 0
            && let Err(e) = self.vault.save(&self.data)
        {
            return (false, e);
        }
        let plural = |n: usize, w: &str| if n > 1 { format!("{n} {w}s") } else { format!("{n} {w}") };
        let mut msg = match added {
            0 => "Aucun nouvel hôte".to_string(),
            n => format!("{} importé{}", plural(n, "hôte"), if n > 1 { "s" } else { "" }),
        };
        if skipped > 0 {
            msg.push_str(&format!(" · {} déjà présent{}", plural(skipped, "hôte"), if skipped > 1 { "s" } else { "" }));
        }
        (true, msg + ".")
    }

    /// Copie chiffrée du coffre, après vérification du mot de passe maître.
    fn export_vault(&mut self) -> (bool, String) {
        if self.settings.export_pw.is_empty() {
            return (false, "Saisissez le mot de passe maître.".into());
        }
        if Vault::open_at(self.vault.path().clone(), &self.settings.export_pw).is_err() {
            return (false, "Mot de passe maître incorrect.".into());
        }
        // contenu à jour sur disque avant la copie
        if let Err(e) = self.vault.save(&self.data) {
            return (false, e);
        }
        let Some(dest) = rfd::FileDialog::new()
            .set_title("Exporter le coffre")
            .set_file_name("escale-sauvegarde.escale")
            .add_filter("Coffre Escale", &["escale"])
            .save_file()
        else {
            return (false, "Export annulé.".into());
        };
        if dest == *self.vault.path() {
            return (false, "Choisissez un autre emplacement que le coffre lui-même.".into());
        }
        match std::fs::copy(self.vault.path(), &dest) {
            Ok(_) => (true, format!("Coffre exporté : {}", dest.display())),
            Err(e) => (false, format!("Export impossible : {e}")),
        }
    }

    fn settings_modal(&mut self, ctx: &egui::Context) {
        if !self.settings.open {
            return;
        }
        let mut close = false;
        let mut change_pw = false;
        let mut dirty = false;
        let mut start_pin = false;
        let mut remove_pin = false;
        let mut export = false;
        let mut import = false;
        let mut pin_done: Option<Option<String>> = None;
        let mut owner_changed = false;
        let mut open_vpn: Option<Option<Uuid>> = None;
        let pin_on = self.data.pin.is_some();
        let width = 560.0;
        let m = w::modal("settings").show(ctx, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                w::modal_header(ui, Icon::Gear, ACCENT, "Paramètres", "Apparence, terminal et sécurité.");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    if w::icon_button(ui, Icon::Close, "Fermer").clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(14.0);
            w::divider(ui);
            egui::ScrollArea::vertical().max_height(ctx.content_rect().height() * 0.66).show(ui, |ui| {
                ui.set_width(width);
                ui.add_space(10.0);
                w::section_title(ui, "Terminal");
                setting_row(ui, "Taille du texte", "Ctrl+Plus / Ctrl+Moins à tout moment", |ui| {
                    dirty |= ui.add(egui::Slider::new(&mut self.data.settings.font_size, 10.0..=24.0).step_by(0.5).suffix(" px")).changed();
                });
                setting_row(ui, "Historique", "Lignes conservées par onglet", |ui| {
                    dirty |= ui
                        .add(egui::DragValue::new(&mut self.data.settings.scrollback).range(500..=100_000).speed(100).suffix(" lignes"))
                        .changed();
                });
                egui::Frame::new()
                    .fill(terminal::BG)
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(RADIUS)
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let f = FontId::monospace(self.data.settings.font_size);
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.label(RichText::new("user").font(f.clone()).color(ACCENT));
                            ui.label(RichText::new("@escale").font(f.clone()).color(ACCENT_2));
                            ui.label(RichText::new(":~$ ").font(f.clone()).color(TEXT));
                            ui.label(RichText::new("ls -la /etc").font(f.clone()).color(TEXT));
                        });
                    });

                ui.add_space(8.0);
                {
                    let s = &mut self.data.settings;
                    setting_row(ui, "Curseur clignotant", "Les applications peuvent aussi le figer", |ui| {
                        dirty |= w::toggle(ui, &mut s.cursor_blink).changed();
                    });
                    setting_row(ui, "Cloche visuelle", "Flash discret à la réception d'un BEL", |ui| {
                        dirty |= w::toggle(ui, &mut s.visual_bell).changed();
                    });
                    setting_row(ui, "Tous les raccourcis au serveur", "Ctrl+Tab, Alt+1…9, zoom, F11 et Ctrl+Maj+Échap vont à l'appli distante", |ui| {
                        dirty |= w::toggle(ui, &mut s.keys_to_server).changed();
                    });
                    setting_row(ui, "Envoi automatique du mot de passe sudo", "À l'invite [sudo], saisit le mot de passe enregistré de l'hôte", |ui| {
                        dirty |= w::toggle(ui, &mut s.sudo_autosend).changed();
                    });
                }


                ui.add_space(16.0);
                w::section_title(ui, "Copier / coller");
                {
                    let s = &mut self.data.settings;
                    setting_row(ui, "Copier la sélection automatiquement", "Sélectionner suffit pour copier (sinon Ctrl+Maj+C)", |ui| {
                        dirty |= w::toggle(ui, &mut s.copy_on_select).changed();
                    });
                    setting_row(ui, "Clic droit colle", "Style PuTTY ; sinon le clic droit ouvre un menu", |ui| {
                        dirty |= w::toggle(ui, &mut s.right_click_paste).changed();
                    });
                    setting_row(ui, "Confirmer le collage multiligne", "Évite d'exécuter des commandes par erreur", |ui| {
                        dirty |= w::toggle(ui, &mut s.confirm_multiline_paste).changed();
                    });
                    setting_row(ui, "Presse-papiers distant (OSC 52)", "Autoriser vim, tmux… à copier vers votre presse-papiers", |ui| {
                        dirty |= w::toggle(ui, &mut s.allow_osc52).changed();
                    });
                }

                ui.add_space(16.0);
                w::section_title(ui, "Profils VPN");
                w::card().inner_margin(Margin::same(16)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if self.data.vpns.is_empty() {
                        ui.label(RichText::new("Aucun profil").font(bold(13.5)));
                        ui.label(
                            RichText::new("Un profil VPN se choisit ensuite dans chaque hôte ; le tunnel ne sert qu'à Escale.")
                                .size(12.0)
                                .color(MUTED),
                        );
                        ui.add_space(8.0);
                    }
                    let mut vpns: Vec<&VpnProfile> = self.data.vpns.iter().collect();
                    vpns.sort_by_key(|v| v.name.to_lowercase());
                    for v in vpns {
                        let n = self.data.hosts.iter().filter(|h| h.vpn == Some(v.id)).count();
                        ui.horizontal(|ui| {
                            w::icon_size(ui, Icon::Shield, 16.0, WARN);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 1.0;
                                ui.label(RichText::new(&v.name).font(bold(13.5)));
                                let hosts = match n {
                                    0 => "aucun hôte".to_string(),
                                    1 => "1 hôte".to_string(),
                                    n => format!("{n} hôtes"),
                                };
                                let server = match (v.kind, v.server()) {
                                    (_, "") => "serveur non renseigné".to_string(),
                                    (VpnKind::OpenVpn, s) => {
                                        let o = &v.openvpn;
                                        let proto = if o.proto == OpenVpnProto::Tcp { "TCP" } else { "UDP" };
                                        format!("{s}:{} {proto}", if o.port == 0 { 1194 } else { o.port })
                                    }
                                    (VpnKind::WireGuard, s) => s.to_string(),
                                };
                                ui.label(RichText::new(format!("{}  ·  {server}  ·  {hosts}", v.kind.label())).size(12.0).color(MUTED));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if w::icon_button(ui, Icon::Edit, "Modifier").clicked() {
                                    open_vpn = Some(Some(v.id));
                                }
                            });
                        });
                        ui.add_space(6.0);
                    }
                    if w::button(ui, Kind::Secondary, Some(Icon::Plus), "Nouveau profil VPN", 0.0).clicked() {
                        open_vpn = Some(None);
                    }
                });
                ui.add_space(16.0);
                w::section_title(ui, "Coffres de cet appareil");
                owner_changed |= self.vaults_card(ui);
                ui.add_space(16.0);
                w::section_title(ui, "Sécurité");
                // --- code PIN
                w::card().inner_margin(Margin::same(16)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if let Some(flow) = &mut self.settings.pin_flow {
                        {
                            let target = if flow.confirm { &mut flow.second } else { &mut flow.first };
                            w::read_digits(ui.ctx(), target, 6);
                        }
                        let mut cancel = false;
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new(if flow.confirm { "Confirmez le nouveau code PIN" } else { "Nouveau code PIN" })
                                    .font(bold(15.0)),
                            );
                            ui.add_space(10.0);
                            let shown = if flow.confirm { &flow.second } else { &flow.first };
                            w::pin_boxes(ui, shown, flow.shake_at, true);
                            ui.add_space(10.0);
                            cancel = w::link(ui, "Annuler").clicked();
                        });
                        if !flow.confirm && flow.first.len() == 6 {
                            flow.confirm = true;
                        } else if flow.confirm && flow.second.len() == 6 {
                            if flow.first == flow.second {
                                pin_done = Some(Some(std::mem::take(&mut flow.first)));
                                flow.second.zeroize();
                            } else {
                                flow.first.zeroize();
                                flow.second.zeroize();
                                flow.confirm = false;
                                flow.shake_at = Some(ui.input(|i| i.time));
                                self.settings.pin_message = Some((false, "Les codes ne correspondent pas. Recommencez.".into()));
                            }
                        }
                        if cancel {
                            pin_done = Some(None);
                        }
                    } else {
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                            ui.painter().rect_filled(r, 10.0, ACCENT.gamma_multiply(0.12));
                            w::paint_icon(ui.painter(), r.shrink(9.0), Icon::Lock, ACCENT);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("Code PIN").font(bold(14.0)));
                                    if pin_on {
                                        w::chip(ui, Some(Icon::Check), "Activé", ACCENT);
                                    } else {
                                        w::chip(ui, None, "Désactivé", MUTED);
                                    }
                                });
                                ui.label(RichText::new("6 chiffres · une erreur exige le mot de passe maître").size(12.0).color(MUTED));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if pin_on && w::button(ui, Kind::Danger, None, "Désactiver", 0.0).clicked() {
                                    remove_pin = true;
                                }
                                if w::button(ui, Kind::Secondary, None, if pin_on { "Modifier" } else { "Activer" }, 0.0).clicked() {
                                    start_pin = true;
                                }
                            });
                        });
                    }
                    if let Some((ok, msg)) = &self.settings.pin_message {
                        ui.add_space(6.0);
                        ui.label(RichText::new(msg).size(12.5).color(if *ok { ACCENT } else { DANGER }));
                    }
                });

                // --- mot de passe maître (masqué pendant la saisie du PIN : les chiffres y sont capturés)
                if self.settings.pin_flow.is_none() {
                    ui.add_space(10.0);
                    w::card().inner_margin(Margin::same(16)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let fw = ui.available_width();
                        let s = &mut self.settings;
                        ui.label(RichText::new("Mot de passe maître").font(bold(14.0)));
                        ui.label(RichText::new("Ré-chiffre tout le coffre avec une nouvelle clé.").size(12.0).color(MUTED));
                        ui.add_space(8.0);
                        w::password_input(ui, &mut s.old_pw, "Mot de passe actuel", &mut s.show_pw, fw);
                        w::password_input(ui, &mut s.new_pw, "Nouveau mot de passe", &mut s.show_pw, fw);
                        w::strength_meter(ui, &s.new_pw, fw);
                        w::password_input(ui, &mut s.new_pw2, "Confirmer le nouveau mot de passe", &mut s.show_pw, fw);
                        if let Some((ok, m)) = &s.message {
                            ui.label(RichText::new(m).size(12.5).color(if *ok { ACCENT } else { DANGER }));
                        }
                        ui.add_space(4.0);
                        if w::button(ui, Kind::Secondary, None, "Mettre à jour", 0.0).clicked() {
                            change_pw = true;
                        }
                    });
                }

                // --- export (masqué pendant la saisie du PIN : les chiffres y sont capturés)
                if self.settings.pin_flow.is_none() {
                    ui.add_space(10.0);
                    w::card().inner_margin(Margin::same(16)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let fw = ui.available_width();
                        let s = &mut self.settings;
                        ui.horizontal(|ui| {
                            w::icon_size(ui, Icon::Download, 16.0, ACCENT);
                            ui.label(RichText::new("Exporter le coffre").font(bold(14.0)));
                        });
                        ui.label(
                            RichText::new("Copie chiffrée de tous vos hôtes, mots de passe et clés. Elle s'ouvre avec le même mot de passe maître.")
                                .size(12.0)
                                .color(MUTED),
                        );
                        ui.add_space(8.0);
                        let r = w::password_input(ui, &mut s.export_pw, "Mot de passe maître", &mut s.show_export_pw, fw);
                        if let Some((ok, m)) = &s.export_message {
                            ui.label(RichText::new(m).size(12.5).color(if *ok { ACCENT } else { DANGER }));
                        }
                        ui.add_space(4.0);
                        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if w::button(ui, Kind::Secondary, Some(Icon::Download), "Exporter…", 0.0).clicked() || enter {
                            export = true;
                        }
                    });
                }

                // --- import
                if self.settings.pin_flow.is_none() {
                    ui.add_space(10.0);
                    w::card().inner_margin(Margin::same(16)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let fw = ui.available_width();
                        let s = &mut self.settings;
                        ui.horizontal(|ui| {
                            w::icon_size(ui, Icon::Upload, 16.0, ACCENT);
                            ui.label(RichText::new("Importer un coffre").font(bold(14.0)));
                        });
                        ui.label(
                            RichText::new("Ajoute les hôtes d'une sauvegarde à ce coffre. Les hôtes déjà présents ne sont pas modifiés.")
                                .size(12.0)
                                .color(MUTED),
                        );
                        ui.add_space(8.0);
                        let r = w::password_input(ui, &mut s.import_pw, "Mot de passe maître de la sauvegarde", &mut s.show_import_pw, fw);
                        if let Some((ok, m)) = &s.import_message {
                            ui.label(RichText::new(m).size(12.5).color(if *ok { ACCENT } else { DANGER }));
                        }
                        ui.add_space(4.0);
                        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if w::button(ui, Kind::Secondary, Some(Icon::Upload), "Importer…", 0.0).clicked() || enter {
                            import = true;
                        }
                    });
                }

                ui.add_space(16.0);
                w::section_title(ui, "À propos");
                ui.label(RichText::new(format!("Escale {}", env!("CARGO_PKG_VERSION"))).color(TEXT_DIM));
                ui.label(RichText::new(self.vault.path().display().to_string()).monospace().size(11.5).color(MUTED));
                ui.add_space(6.0);
            });
            ui.add_space(10.0);
            w::divider(ui);
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if w::button(ui, Kind::Primary, None, "Terminé", 110.0).clicked() {
                    close = true;
                }
            });
        });
        if dirty {
            self.save();
        }
        if owner_changed {
            self.settings.owner_message = Some(self.rename_owner());
        }
        if let Some(done) = pin_done {
            self.settings.pin_flow = None;
            if let Some(p) = done {
                self.data.pin = Some(p.clone());
                let r = self.vault.save(&self.data).and_then(|_| pin::enable(&self.vault, &p));
                self.settings.pin_message = Some(match r {
                    Ok(()) => (true, "Code PIN enregistré.".into()),
                    Err(e) => (false, e),
                });
            }
        }
        if start_pin {
            self.settings.pin_message = None;
            self.settings.pin_flow = Some(PinFlow { first: String::new(), second: String::new(), confirm: false, shake_at: None });
        }
        if remove_pin {
            self.data.pin = None;
            pin::disable(self.vault.path());
            self.save();
            self.settings.pin_message = Some((true, "Code PIN désactivé.".into()));
        }
        if change_pw {
            let s = &mut self.settings;
            s.message = Some(if s.new_pw.chars().count() < 8 {
                (false, "8 caractères minimum.".into())
            } else if s.new_pw != s.new_pw2 {
                (false, "Les mots de passe ne correspondent pas.".into())
            } else if Vault::open_at(self.vault.path().clone(), &s.old_pw).is_err() {
                (false, "Mot de passe actuel incorrect.".into())
            } else {
                match self.vault.change_password(&s.new_pw, &self.data) {
                    // la clé du coffre a changé : le PIN doit l'envelopper à nouveau
                    Ok(()) => match &self.data.pin {
                        Some(p) => match pin::enable(&self.vault, p) {
                            Ok(()) => (true, "Mot de passe maître modifié.".into()),
                            Err(e) => (false, format!("Mot de passe modifié, mais PIN non réactivé : {e}")),
                        },
                        None => (true, "Mot de passe maître modifié.".into()),
                    },
                    Err(e) => (false, e),
                }
            });
            s.old_pw.zeroize();
            s.new_pw.zeroize();
            s.new_pw2.zeroize();
        }
        if export {
            self.settings.export_message = Some(self.export_vault());
            self.settings.export_pw.zeroize();
        }
        if import {
            self.settings.import_message = Some(self.import_vault());
            self.settings.import_pw.zeroize();
        }
        if let Some(id) = open_vpn {
            let (profile, is_new) = match id.and_then(|id| self.data.vpn(id)) {
                Some(p) => (p.clone(), false),
                None => (VpnProfile::default(), true),
            };
            self.vpn_editor = Some(VpnEditor::new(profile, is_new, false));
        }
        if close || (m.should_close() && self.settings.pin_flow.is_none()) {
            self.settings = SettingsDialog::default();
        }
    }
}

/// Date (jj/mm/aaaa, UTC) d'un horodatage Unix ; `None` si inconnu.
fn date_fr(secs: u64) -> Option<String> {
    if secs == 0 {
        return None;
    }
    // algorithme « civil from days » (H. Hinnant)
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    Some(format!("{d:02}/{m:02}/{y}"))
}

/// Ajoute les hôtes de `other` absents de `data` (même identifiant = même hôte, conservé tel quel).
/// Les rebonds vers un hôte inconnu des deux coffres sont retirés. Renvoie (ajoutés, ignorés).
fn merge_hosts(data: &mut VaultData, other: VaultData) -> (usize, usize) {
    let (mut added, mut skipped) = (0, 0);
    for h in other.hosts.iter() {
        if data.host(h.id).is_some() {
            skipped += 1;
        } else {
            data.hosts.push(h.clone());
            added += 1;
        }
    }
    // profils VPN de la sauvegarde absents d'ici (ceux déjà présents ne sont pas écrasés)
    for v in other.vpns.iter() {
        if data.vpn(v.id).is_none() {
            data.vpns.push(v.clone());
        }
    }
    let ids: Vec<Uuid> = data.hosts.iter().map(|h| h.id).collect();
    let vpns: Vec<Uuid> = data.vpns.iter().map(|v| v.id).collect();
    for h in &mut data.hosts {
        if h.jump.is_some_and(|j| !ids.contains(&j)) {
            h.jump = None;
        }
        if h.vpn.is_some_and(|v| !vpns.contains(&v)) {
            h.vpn = None;
        }
    }
    (added, skipped)
}

// ---------------------------------------------------------------- composants spécifiques

fn setting_row(ui: &mut egui::Ui, title: &str, sub: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.label(RichText::new(title).font(bold(13.5)));
            ui.label(RichText::new(sub).size(12.0).color(MUTED));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), add);
    });
    ui.add_space(8.0);
}

// ---------------------------------------------------------------- options du bureau à distance

/// Onglets des options RDP dans l'éditeur d'hôte.
#[derive(Clone, Copy, PartialEq, Default)]
enum RdpTab {
    #[default]
    Display,
    Resources,
    Experience,
    Security,
    Advanced,
}

/// Préréglage d'expérience : graphisme, compression et effets visuels d'un coup.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Experience {
    Lan,
    Broadband,
    Low,
    /// Réglages modifiés à la main (aucun préréglage ne correspond).
    Custom,
}

impl Experience {
    /// (graphisme, compression, [fond, déplacement, animations, styles, lissage, composition])
    fn values(self) -> Option<(RdpGraphics, RdpCompression, [bool; 6])> {
        Some(match self {
            // H.264 (le plus fluide), tous les effets, pas de compression : le réseau suit
            Experience::Lan => (RdpGraphics::Auto, RdpCompression::None, [true; 6]),
            // valeurs par défaut d'un nouvel hôte
            Experience::Broadband => (RdpGraphics::Auto, RdpCompression::K64, [true, true, false, true, true, true]),
            // H.264 (le plus économe), compression maximale, sans effets
            Experience::Low => (RdpGraphics::Auto, RdpCompression::Rdp61, [false; 6]),
            Experience::Custom => return None,
        })
    }

    fn apply(self, o: &mut RdpOptions) {
        let Some((g, c, [a, b, d, e, f, k])) = self.values() else { return };
        o.graphics = g;
        o.compression = c;
        (o.wallpaper, o.full_window_drag, o.menu_animations, o.themes, o.font_smoothing, o.desktop_composition) = (a, b, d, e, f, k);
    }

    fn of(o: &RdpOptions) -> Self {
        let cur = (o.graphics, o.compression, [o.wallpaper, o.full_window_drag, o.menu_animations, o.themes, o.font_smoothing, o.desktop_composition]);
        [Experience::Lan, Experience::Broadband, Experience::Low].into_iter().find(|e| e.values() == Some(cur)).unwrap_or(Experience::Custom)
    }
}

/// Dispositions clavier courantes (identifiant Windows ; 0 = celle de cet ordinateur).
const KEYBOARD_LAYOUTS: &[(u32, &str)] = &[
    (0, "Automatique (comme cet ordinateur)"),
    (0x040C, "Français (France)"),
    (0x080C, "Français (Belgique)"),
    (0x100C, "Français (Suisse)"),
    (0x0C0C, "Français (Canada)"),
    (0x046E, "Luxembourgeois"),
    (0x0409, "Anglais (États-Unis)"),
    (0x0809, "Anglais (Royaume-Uni)"),
    (0x0407, "Allemand (Allemagne)"),
    (0x0807, "Allemand (Suisse)"),
    (0x0C07, "Allemand (Autriche)"),
    (0x040A, "Espagnol"),
    (0x0410, "Italien"),
    (0x0816, "Portugais (Portugal)"),
    (0x0416, "Portugais (Brésil)"),
    (0x0413, "Néerlandais (Pays-Bas)"),
    (0x0813, "Néerlandais (Belgique)"),
    (0x0406, "Danois"),
    (0x041D, "Suédois"),
    (0x0414, "Norvégien"),
    (0x040B, "Finnois"),
    (0x0415, "Polonais"),
    (0x0419, "Russe"),
];

const RESOLUTIONS: [(u16, u16); 6] = [(1280, 720), (1366, 768), (1600, 900), (1920, 1080), (2560, 1440), (3840, 2160)];
const SCALES: [u32; 8] = [0, 100, 125, 150, 175, 200, 250, 300];

fn scale_label(s: u32) -> String {
    if s == 0 { "Automatique (comme cet écran)".into() } else { format!("{s} %") }
}

fn layout_label(id: u32) -> String {
    KEYBOARD_LAYOUTS.iter().find(|(k, _)| *k == id).map(|(_, n)| n.to_string()).unwrap_or_else(|| format!("Personnalisée (0x{id:04X})"))
}

fn compression_label(c: RdpCompression) -> &'static str {
    match c {
        RdpCompression::None => "Aucune",
        RdpCompression::K8 => "Légère (MPPC 8 Ko)",
        RdpCompression::K64 => "Standard (MPPC 64 Ko)",
        RdpCompression::Rdp6 => "Forte (RDP 6.0)",
        RdpCompression::Rdp61 => "Maximale (RDP 6.1, XCRUSH)",
    }
}

/// Dossier local partagé avec un hôte RDP (`base` : dossier du coffre). Un chemin personnalisé
/// relatif (coffre importé, ancien format) n'est pas pris : il dépendrait du dossier de lancement.
fn share_dir_in(base: &Path, h: &Host) -> PathBuf {
    let custom = h.rdp.drive_path.trim();
    // un chemin qui contiendrait un coffre (vault.escale, vault.pin) n'est jamais partagé
    if !custom.is_empty() && Path::new(custom).is_absolute() && !exposes_vault(Path::new(custom), &crate::vault::root()) {
        return PathBuf::from(custom);
    }
    let name: String = h
        .display_name()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    base.join("Partage").join(format!("{}-{}", name.trim_matches('.'), &h.id.simple().to_string()[..8]))
}

/// Le dossier `dir` exposerait-il un coffre au serveur distant ? Vrai s'il contient le dossier des
/// données d'Escale (`root`), ou s'il est dans ce dossier hors d'un sous-dossier « Partage ».
fn exposes_vault(dir: &Path, root: &Path) -> bool {
    let norm = |p: &Path| if cfg!(windows) { PathBuf::from(p.to_string_lossy().to_lowercase()) } else { p.to_path_buf() };
    let (dir, root) = (norm(dir), norm(root));
    if root.starts_with(&dir) {
        return true;
    }
    match dir.strip_prefix(&root) {
        Ok(rel) => !rel.components().any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("partage")),
        Err(_) => false,
    }
}

/// Contenu du panneau Fichiers d'un bureau RDP : le dossier partagé par la session en cours, ou la
/// raison de son absence. Le partage est fixé à l'ouverture de la session : l'activer ensuite dans
/// l'hôte demande une reconnexion.
fn rdp_files(session_share: Option<&Path>, host_drive: bool) -> Result<PathBuf, &'static str> {
    match session_share {
        Some(dir) => Ok(dir.to_path_buf()),
        None if host_drive => Err("Le dossier partagé a été activé après l'ouverture de cette session : reconnectez-la (Ctrl+Maj+R) pour le partager."),
        None => Err("Le dossier partagé est désactivé pour cet hôte (Options du bureau à distance)."),
    }
}

/// Vérifie les options RDP avant l'enregistrement ; crée le dossier partagé personnalisé s'il manque.
fn validate_rdp(o: &RdpOptions) -> Result<(), String> {
    if o.display != RdpDisplay::Dynamic && !((200..=8192).contains(&o.width) && (200..=8192).contains(&o.height)) {
        return Err("La résolution fixe doit être comprise entre 200 et 8192 pixels.".into());
    }
    let path = o.drive_path.trim();
    if o.drive && !path.is_empty() {
        let p = std::path::Path::new(path);
        if !p.is_absolute() {
            return Err("Indiquez le chemin complet du dossier partagé (ex. C:\\Partage).".into());
        }
        if exposes_vault(p, &crate::vault::root()) {
            return Err("Ce dossier contient les coffres d'Escale : choisissez un autre dossier partagé.".into());
        }
        if p.exists() && !p.is_dir() {
            return Err(format!("« {path} » n'est pas un dossier."));
        }
        if !p.is_dir() {
            std::fs::create_dir_all(p).map_err(|e| format!("Impossible de créer le dossier partagé « {path} » : {e}"))?;
        }
    }
    Ok(())
}

/// Titre d'une option et sa description courte.
fn option_title(ui: &mut egui::Ui, title: &str, sub: &str) {
    ui.add_space(2.0);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(RichText::new(title).font(bold(13.5)));
        if !sub.is_empty() {
            ui.label(RichText::new(sub).size(12.0).color(MUTED));
        }
    });
    ui.add_space(4.0);
}

/// Case à cocher d'option (interrupteur à droite).
fn option_toggle(ui: &mut egui::Ui, title: &str, sub: &str, on: &mut bool) {
    setting_row(ui, title, sub, |ui| {
        w::toggle(ui, on);
    });
}

/// Champ numérique (largeur / hauteur).
fn number_input(ui: &mut egui::Ui, value: &mut u16, width: f32) {
    let mut s = if *value == 0 { String::new() } else { value.to_string() };
    if w::input(ui, &mut s, "", false, width).changed() {
        s.retain(|c| c.is_ascii_digit());
        *value = s.parse::<u32>().map(|v| v.min(u16::MAX as u32) as u16).unwrap_or(0);
    }
}

/// Choix des écrans d'une session sur plusieurs écrans : plan des écrans de cet ordinateur, un clic
/// ajoute ou retire un écran. `sel` vide = tous.
fn screens_picker(ui: &mut egui::Ui, sel: &mut Vec<String>, width: f32) {
    let all = crate::monitors::list();
    if all.is_empty() {
        ui.label(RichText::new("Aucun écran détecté : la session prendra la taille de la fenêtre.").size(12.0).color(MUTED));
        return;
    }
    let names: Vec<String> = all.iter().map(|s| s.name.clone()).collect();
    // aucun écran choisi n'est branché (autre ordinateur) : tous, comme à la connexion
    let any = names.iter().any(|n| sel.contains(n));
    let chosen: Vec<bool> = all.iter().map(|s| !any || sel.contains(&s.name)).collect();
    let (l, t, r, b) = crate::monitors::bounds(&all);
    let scale = (width / (r - l) as f32).min(110.0 / (b - t) as f32);
    let size = vec2((r - l) as f32, (b - t) as f32) * scale;
    let (area, _) = ui.allocate_exact_size(vec2(width, size.y), Sense::hover());
    let origin = pos2(area.center().x - size.x / 2.0, area.top());
    let mut toggled = None;
    for (n, s) in all.iter().enumerate() {
        let rect = Rect::from_min_max(
            origin + vec2((s.left - l) as f32, (s.top - t) as f32) * scale,
            origin + vec2((s.right - l) as f32, (s.bottom - t) as f32) * scale,
        )
        .shrink(3.0);
        let resp = ui.interact(rect, ui.id().with(("screen-pick", n)), Sense::click());
        let on = chosen[n];
        let (fill, stroke) = if on { (ACCENT.gamma_multiply(0.22), ACCENT) } else { (SURFACE, BORDER_STRONG) };
        let stroke = if resp.hovered() { Stroke::new(2.0, stroke) } else { Stroke::new(1.0, stroke) };
        ui.painter().rect(rect, 6.0, fill, stroke, egui::StrokeKind::Inside);
        let (w, h) = s.size();
        let text = format!("{}{}\n{w}×{h}", s.number(n + 1), if s.primary { " ★" } else { "" });
        ui.painter().text(rect.center(), Align2::CENTER_CENTER, text, egui::FontId::proportional(12.0), if on { TEXT } else { MUTED });
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.on_hover_text(if on { "Retirer cet écran" } else { "Ajouter cet écran" }).clicked() {
            toggled = Some(n);
        }
    }
    if let Some(n) = toggled {
        let mut now: Vec<String> = all.iter().zip(&chosen).filter(|(_, on)| **on).map(|(s, _)| s.name.clone()).collect();
        if let Some(p) = now.iter().position(|x| *x == all[n].name) {
            // au moins un écran
            if now.len() > 1 {
                now.remove(p);
            }
        } else {
            now.push(all[n].name.clone());
        }
        *sel = if now.len() == all.len() { Vec::new() } else { now };
    }
    let count = if toggled.is_some() { all.iter().filter(|s| sel.is_empty() || sel.contains(&s.name)).count() } else { chosen.iter().filter(|on| **on).count() };
    let summary = if count == all.len() {
        format!("Tous les écrans ({count}). Cliquez sur un écran pour le retirer ; ★ = écran principal.")
    } else {
        format!("{count} écran(s) sur {}. Cliquez sur un écran pour l'ajouter ou le retirer ; la barre des tâches distante va sur l'écran principal (★) s'il est choisi, sinon sur le plus à gauche.", all.len())
    };
    ui.add_space(4.0);
    ui.label(RichText::new(summary).size(12.0).color(MUTED));
}

/// Options du bureau à distance d'un hôte RDP, par onglets.
fn rdp_options_ui(ui: &mut egui::Ui, o: &mut RdpOptions, tab: &mut RdpTab, width: f32) {
    w::section_title(ui, "Options du bureau à distance");
    w::segmented(
        ui,
        tab,
        &[
            (RdpTab::Display, Icon::Monitor, "Affichage"),
            (RdpTab::Resources, Icon::Folder, "Ressources"),
            (RdpTab::Experience, Icon::Play, "Expérience"),
            (RdpTab::Security, Icon::Shield, "Sécurité"),
            (RdpTab::Advanced, Icon::Gear, "Avancé"),
        ],
        width,
    );
    ui.add_space(10.0);
    let combo = |id: &str, text: String| egui::ComboBox::from_id_salt(("rdp-opt", id.to_string())).selected_text(text).width(width).height(300.0);

    match *tab {
        RdpTab::Display => {
            option_toggle(
                ui,
                "Plusieurs écrans",
                "Le bureau distant s'étend sur les écrans choisis, comme mstsc /multimon ; il s'ouvre dans une fenêtre qui les couvre.",
                &mut o.multimon,
            );
            if o.multimon {
                ui.add_space(8.0);
                screens_picker(ui, &mut o.screens, width);
            }
            ui.add_space(12.0);
            // tous les écrans : la résolution est celle de leur ensemble
            if !o.multimon {
                option_title(
                    ui,
                    "Résolution",
                    match o.display {
                        RdpDisplay::Dynamic => "Suit la taille de la fenêtre : le bureau distant est redimensionné en direct.",
                        RdpDisplay::FixedFit => "Taille fixe, image agrandie ou réduite pour tenir dans la fenêtre.",
                        RdpDisplay::FixedNative => "Taille fixe, pixels 1:1 ; barres de défilement si la fenêtre est plus petite.",
                    },
                );
                w::segmented(
                    ui,
                    &mut o.display,
                    &[
                        (RdpDisplay::Dynamic, Icon::Expand, "Dynamique"),
                        (RdpDisplay::FixedFit, Icon::Shrink, "Fixe, ajustée"),
                        (RdpDisplay::FixedNative, Icon::Monitor, "Fixe, 1:1"),
                    ],
                    width,
                );
                if o.display != RdpDisplay::Dynamic {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        number_input(ui, &mut o.width, 110.0);
                        ui.label(RichText::new("×").size(15.0).color(MUTED));
                        number_input(ui, &mut o.height, 110.0);
                        ui.label(RichText::new("pixels").size(12.0).color(MUTED));
                    });
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        for (rw, rh) in RESOLUTIONS {
                            let selected = (o.width, o.height) == (rw, rh);
                            let r = w::chip(ui, None, &format!("{rw}×{rh}"), if selected { ACCENT } else { TEXT_DIM }).interact(Sense::click());
                            if r.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            }
                            if r.clicked() {
                                (o.width, o.height) = (rw, rh);
                            }
                        }
                    });
                }
                ui.add_space(12.0);
            }

            option_title(
                ui,
                "Graphisme",
                match o.graphics {
                    RdpGraphics::Auto => "H.264 si le serveur le propose, sinon RemoteFX : le plus fluide, peu de débit.",
                    RdpGraphics::RemoteFx => "Sans H.264 (RemoteFX, ClearCodec) : image plus nette, débit plus élevé.",
                    RdpGraphics::Legacy => "Ancien mode bitmap : compatible avec tous les serveurs, même anciens.",
                },
            );
            w::segmented(
                ui,
                &mut o.graphics,
                &[(RdpGraphics::Auto, Icon::Play, "Automatique"), (RdpGraphics::RemoteFx, Icon::Monitor, "RemoteFX"), (RdpGraphics::Legacy, Icon::Back, "Ancien mode")],
                width,
            );
            ui.add_space(12.0);

            option_title(ui, "Profondeur de couleur", "Utilisée en ancien mode graphique ; 16 bits allège le débit.");
            w::segmented(
                ui,
                &mut o.color_depth,
                &[(32, Icon::Monitor, "32 bits"), (24, Icon::Monitor, "24 bits"), (16, Icon::Monitor, "16 bits"), (15, Icon::Monitor, "15 bits")],
                width,
            );
            ui.add_space(12.0);

            option_title(ui, "Mise à l'échelle", "Taille du texte et des icônes sur le bureau distant.");
            combo("scale", scale_label(o.scale)).show_ui(ui, |ui| {
                for s in SCALES {
                    ui.selectable_value(&mut o.scale, s, scale_label(s));
                }
            });
            ui.add_space(12.0);

            option_toggle(ui, "Curseur du serveur", "Formes du curseur Windows (texte, attente…) ; sinon la flèche d'ici.", &mut o.server_pointer);
        }
        RdpTab::Resources => {
            option_title(
                ui,
                "Son",
                match o.audio {
                    RdpAudio::Local => "Le son du bureau distant est joué sur cet ordinateur.",
                    RdpAudio::Remote => "Le son reste sur l'ordinateur distant.",
                    RdpAudio::Off => "Aucun son.",
                },
            );
            w::segmented(
                ui,
                &mut o.audio,
                &[(RdpAudio::Local, Icon::Monitor, "Sur cet ordinateur"), (RdpAudio::Remote, Icon::Server, "À distance"), (RdpAudio::Off, Icon::Close, "Aucun son")],
                width,
            );
            ui.add_space(12.0);
            option_toggle(ui, "Microphone", "Le micro de cet ordinateur est utilisable sur le bureau distant.", &mut o.microphone);
            option_toggle(ui, "Presse-papiers partagé", "Copier-coller de texte, d'images et de fichiers dans les deux sens.", &mut o.clipboard);
            option_toggle(ui, "Dossier partagé", "Visible sur le bureau distant dans Ce PC (\\\\tsclient\\Escale).", &mut o.drive);
            if o.drive {
                ui.horizontal(|ui| {
                    let bw = 112.0;
                    w::input(ui, &mut o.drive_path, "Dossier propre à cet hôte (par défaut)", false, width - bw - 8.0);
                    if w::button_h(ui, Kind::Secondary, Some(Icon::Folder), "Parcourir…", bw, 40.0).clicked() {
                        let mut dlg = rfd::FileDialog::new().set_title("Dossier partagé avec le bureau distant");
                        if !o.drive_path.trim().is_empty() {
                            dlg = dlg.set_directory(o.drive_path.trim());
                        }
                        if let Some(p) = dlg.pick_folder() {
                            o.drive_path = p.display().to_string();
                        }
                    }
                });
                if !o.drive_path.trim().is_empty() {
                    ui.add_space(2.0);
                    if w::link(ui, "Revenir au dossier par défaut").clicked() {
                        o.drive_path.clear();
                    }
                }
                ui.add_space(8.0);
            }
            ui.add_space(4.0);
            option_title(ui, "Disposition du clavier", "Annoncée au serveur pour qu'il traduise les touches comme ici.");
            combo("keyboard", layout_label(o.keyboard_layout)).show_ui(ui, |ui| {
                for (id, name) in KEYBOARD_LAYOUTS {
                    ui.selectable_value(&mut o.keyboard_layout, *id, *name);
                }
            });
            ui.add_space(12.0);
            option_toggle(
                ui,
                "Raccourcis Windows",
                "Win (et Win+touche), Alt+Tab, Alt+F4, Ctrl+Échap, Ctrl+Maj+Échap, Impr écran vont au bureau distant quand il a le focus. Ctrl+Alt+Fin = Ctrl+Alt+Suppr.",
                &mut o.windows_keys,
            );
        }
        RdpTab::Experience => {
            let current = Experience::of(o);
            option_title(
                ui,
                "Connexion",
                match current {
                    Experience::Lan => "Qualité maximale, tous les effets : pour un réseau local rapide.",
                    Experience::Broadband => "Équilibre fluidité / débit : fibre, câble, VPN rapide.",
                    Experience::Low => "Débit minimal : 4G, VPN lent, connexion partagée.",
                    Experience::Custom => "Réglages personnalisés ; choisissez un préréglage pour tout régler d'un coup.",
                },
            );
            let mut chosen = current;
            w::segmented(
                ui,
                &mut chosen,
                &[(Experience::Lan, Icon::Server, "Réseau local"), (Experience::Broadband, Icon::Play, "Haut débit"), (Experience::Low, Icon::Hop, "Faible débit")],
                width,
            );
            if chosen != current {
                chosen.apply(o);
            }
            ui.add_space(12.0);
            option_title(ui, "Compression", "Réduit le débit au prix d'un peu de calcul ; utile sur une connexion lente.");
            combo("compression", compression_label(o.compression).into()).show_ui(ui, |ui| {
                for c in [RdpCompression::None, RdpCompression::K8, RdpCompression::K64, RdpCompression::Rdp6, RdpCompression::Rdp61] {
                    ui.selectable_value(&mut o.compression, c, compression_label(c));
                }
            });
            ui.add_space(12.0);
            option_toggle(ui, "Fond d'écran", "Image du bureau distant ; sinon fond uni.", &mut o.wallpaper);
            option_toggle(ui, "Contenu des fenêtres en déplacement", "Sinon seul le contour suit la souris.", &mut o.full_window_drag);
            option_toggle(ui, "Animations", "Menus et fenêtres animés.", &mut o.menu_animations);
            option_toggle(ui, "Styles visuels", "Apparence moderne des fenêtres et boutons.", &mut o.themes);
            option_toggle(ui, "Lissage des polices", "Texte adouci (ClearType).", &mut o.font_smoothing);
            option_toggle(ui, "Composition du bureau", "Transparence, ombres et aperçus des fenêtres.", &mut o.desktop_composition);
        }
        RdpTab::Security => {
            option_title(
                ui,
                "Authentification",
                match o.security {
                    RdpSecurity::Nla => "Identifiants vérifiés avant l'ouverture de la session (recommandé).",
                    RdpSecurity::Tls => "Pour les serveurs sans NLA : l'écran de connexion Windows s'affiche.",
                },
            );
            w::segmented(ui, &mut o.security, &[(RdpSecurity::Nla, Icon::Shield, "NLA (recommandé)"), (RdpSecurity::Tls, Icon::Lock, "TLS seul")], width);
            if o.security == RdpSecurity::Nla {
                ui.add_space(12.0);
                option_title(ui, "Kerberos (KDC)", "Vide : NTLM. Sinon le contrôleur de domaine, ex. dc01.corp.local ou tcp://dc01:88.");
                w::input(ui, &mut o.kdc, "Aucun (NTLM)", false, width);
            }
        }
        RdpTab::Advanced => {
            option_title(ui, "Programme de démarrage", "Lancé à l'ouverture de session à la place du bureau ; vide = bureau complet.");
            w::input(ui, &mut o.alternate_shell, "ex. C:\\Windows\\System32\\notepad.exe", false, width);
            ui.add_space(6.0);
            w::label(ui, "Dossier de travail");
            w::input(ui, &mut o.work_dir, "optionnel (ex. C:\\Users\\Public)", false, width);
            ui.add_space(12.0);
            option_toggle(ui, "Session administrateur", "Ouvre la session console du serveur (comme mstsc /admin).", &mut o.admin);
            option_toggle(ui, "Reconnexion automatique", "Après une coupure réseau, la session revient sans fermer l'onglet.", &mut o.auto_reconnect);
        }
    }

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let default = *o == RdpOptions::default();
        ui.add_enabled_ui(!default, |ui| {
            if w::link(ui, "Rétablir les valeurs par défaut").on_hover_text("Toutes les options du bureau à distance de cet hôte").clicked() {
                *o = RdpOptions::default();
            }
        });
    });
}

fn key_box(ui: &mut egui::Ui, h: &mut Host, show_key: &mut bool, error: &mut Option<String>, width: f32) {
    let info = if h.private_key.trim().is_empty() {
        None
    } else {
        Some(match russh::keys::ssh_key::PrivateKey::from_openssh(h.private_key.trim()) {
            Ok(k) => {
                let enc = if k.is_encrypted() { " · protégée par phrase secrète" } else { "" };
                format!("{}{enc}", k.algorithm())
            }
            Err(_) => "Format PEM / PuTTY".to_string(),
        })
    };
    egui::Frame::new()
        .fill(INPUT)
        .stroke(Stroke::new(1.0, if info.is_some() { ACCENT.gamma_multiply(0.35) } else { BORDER }))
        .corner_radius(RADIUS)
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(width - 28.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                let col = if info.is_some() { ACCENT } else { MUTED };
                ui.painter().rect_filled(r, 10.0, col.gamma_multiply(0.12));
                w::paint_icon(ui.painter(), r.shrink(9.0), Icon::Key, col);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    match &info {
                        Some(t) => {
                            ui.label(RichText::new("Clé privée chargée").font(bold(13.5)));
                            ui.label(RichText::new(t).size(12.0).color(MUTED));
                        }
                        None => {
                            ui.label(RichText::new("Aucune clé").font(bold(13.5)));
                            ui.label(RichText::new("OpenSSH, PEM ou PuTTY (.ppk)").size(12.0).color(MUTED));
                        }
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if info.is_some() && w::icon_button(ui, Icon::Trash, "Retirer la clé").clicked() {
                        h.private_key.zeroize();
                    }
                    if w::icon_button(ui, if *show_key { Icon::EyeOff } else { Icon::Edit }, "Coller / afficher le contenu").clicked() {
                        *show_key = !*show_key;
                    }
                    if w::button_h(ui, Kind::Secondary, Some(Icon::Folder), "Importer", 0.0, 34.0).clicked()
                        && let Some(p) = rfd::FileDialog::new().set_title("Clé privée SSH").pick_file()
                    {
                        match std::fs::read_to_string(&p) {
                            Ok(s) => h.private_key = s,
                            Err(e) => *error = Some(format!("Lecture impossible : {e}")),
                        }
                    }
                });
            });
            if *show_key {
                ui.add_space(8.0);
                ui.add(
                    egui::TextEdit::multiline(&mut h.private_key)
                        .hint_text(RichText::new("-----BEGIN OPENSSH PRIVATE KEY-----").color(MUTED))
                        .font(FontId::monospace(11.0))
                        .desired_rows(5)
                        .margin(Margin::same(10))
                        .desired_width(f32::INFINITY),
                );
            }
        });
}

// ---------------------------------------------------------------- éditeur de profil VPN

/// Fichier intégré d'un profil OpenVPN (`<ca>`, `<cert>`…), ouvert en édition dans le formulaire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OvpnPart {
    Ca,
    Cert,
    Key,
    TlsAuth,
    TlsCrypt,
}

/// Retire les espaces en tête et en fin sans recopier la chaîne (clés : pas de copie laissée en mémoire).
fn trim_in_place(s: &mut String) {
    let end = s.trim_end().len();
    s.truncate(end);
    let start = s.len() - s.trim_start().len();
    s.drain(..start);
}

/// Type d'un fichier de configuration VPN : extension, puis contenu.
fn detect_vpn_file(path: &Path, text: &str) -> VpnKind {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if ext == "ovpn" {
        return VpnKind::OpenVpn;
    }
    for line in text.lines() {
        let l = line.trim().to_ascii_lowercase();
        if l.starts_with("[interface]") || l.starts_with("[peer]") {
            return VpnKind::WireGuard;
        }
        let first = l.split_whitespace().next().unwrap_or("");
        if matches!(first, "client" | "remote" | "dev" | "proto" | "auth-user-pass" | "<ca>" | "tls-client" | "nobind") {
            return VpnKind::OpenVpn;
        }
    }
    VpnKind::WireGuard
}

/// Lit un élément DER : (étiquette, contenu, reste).
fn der_next(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, head) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    Some((tag, b.get(head..end)?, b.get(end..)?))
}

/// Nom commun (CN, à défaut O) du sujet d'un certificat X.509 en DER.
fn cert_subject_name(der: &[u8]) -> Option<String> {
    let (_, cert, _) = der_next(der)?;
    let (_, tbs, _) = der_next(cert)?;
    let mut rest = tbs;
    // version [0] optionnelle, puis numéro de série, algorithme, émetteur, validité, sujet
    if rest.first() == Some(&0xA0) {
        rest = der_next(rest)?.2;
    }
    for _ in 0..4 {
        rest = der_next(rest)?.2;
    }
    let (_, mut subject, _) = der_next(rest)?;
    let (mut cn, mut org) = (None, None);
    while let Some((_, set, next)) = der_next(subject) {
        subject = next;
        let Some((_, atv, _)) = der_next(set) else { continue };
        let Some((0x06, oid, value)) = der_next(atv) else { continue };
        let Some((tag, v, _)) = der_next(value) else { continue };
        let text = if tag == 0x1E {
            // BMPString : UTF-16 gros-boutiste
            let units: Vec<u16> = v.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(v).into_owned()
        };
        match oid {
            [0x55, 0x04, 0x03] => cn = Some(text),
            [0x55, 0x04, 0x0A] => org = Some(text),
            _ => {}
        }
    }
    cn.or(org).filter(|s| !s.trim().is_empty())
}

/// Résumé d'un ou plusieurs certificats PEM : « CN · n certificats ».
fn cert_summary(pem: &str) -> Result<String, String> {
    use rustls_pki_types::{CertificateDer, pem::PemObject};
    let certs: Vec<CertificateDer> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|_| "Certificat illisible (PEM attendu)".to_string())?;
    let first = certs.first().ok_or_else(|| "Aucun certificat PEM (-----BEGIN CERTIFICATE-----)".to_string())?;
    let name = cert_subject_name(first).unwrap_or_else(|| "sans nom".into());
    Ok(match certs.len() {
        1 => name,
        n => format!("{name}  ·  {n} certificats"),
    })
}

/// Résumé d'une clé privée PEM (sans jamais l'afficher).
fn key_summary(pem: &str) -> Result<String, String> {
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
    if pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED") {
        return Err("Clé protégée par mot de passe : non prise en charge, exportez-la sans phrase secrète".into());
    }
    let key = PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|_| "Clé privée illisible (PEM attendu)".to_string())?;
    Ok(match key {
        PrivateKeyDer::Pkcs1(_) => "Clé RSA".into(),
        PrivateKeyDer::Sec1(_) => "Clé EC".into(),
        PrivateKeyDer::Pkcs8(_) => "Clé PKCS#8".into(),
        _ => "Clé privée".into(),
    })
}

/// Résumé d'une clé statique OpenVPN (tls-auth / tls-crypt).
fn static_key_summary(text: &str) -> Result<String, String> {
    const BEGIN: &str = "-----BEGIN OpenVPN Static key V1-----";
    const END: &str = "-----END OpenVPN Static key V1-----";
    let start = text.find(BEGIN).ok_or_else(|| "Clé statique OpenVPN attendue (-----BEGIN OpenVPN Static key V1-----)".to_string())?;
    let body = &text[start + BEGIN.len()..];
    let body = body.find(END).map(|e| &body[..e]).ok_or_else(|| "Clé statique incomplète (ligne -----END… absente)".to_string())?;
    let hex = body.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) || hex.len() % 2 != 0 {
        return Err("Clé statique illisible (hexadécimal attendu)".into());
    }
    if hex.len() != 512 {
        return Err(format!("Clé statique de {} octets (256 attendus)", hex.len() / 2));
    }
    Ok("Clé statique  ·  2048 bits".into())
}

/// Ligne compacte d'un fichier intégré : état (chargé / absent), import, édition, retrait.
#[allow(clippy::too_many_arguments)]
fn ovpn_file_row(
    ui: &mut egui::Ui,
    part: OvpnPart,
    title: &str,
    absent: &str,
    hint: &str,
    value: &mut String,
    summary: fn(&str) -> Result<String, String>,
    open: &mut Option<OvpnPart>,
    error: &mut Option<String>,
    width: f32,
) {
    let state = if value.trim().is_empty() { None } else { Some(summary(value)) };
    let (col, icon) = match &state {
        Some(Ok(_)) => (ACCENT, Icon::Check),
        Some(Err(_)) => (DANGER, Icon::Warning),
        None => (MUTED, if matches!(part, OvpnPart::Key | OvpnPart::TlsAuth | OvpnPart::TlsCrypt) { Icon::Key } else { Icon::File }),
    };
    let editing = *open == Some(part);
    egui::Frame::new()
        .fill(INPUT)
        .stroke(Stroke::new(1.0, if state.is_some() { col.gamma_multiply(0.35) } else { BORDER }))
        .corner_radius(RADIUS)
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(width - 24.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
                ui.painter().rect_filled(r, 8.0, col.gamma_multiply(0.12));
                w::paint_icon(ui.painter(), r.shrink(7.0), icon, col);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(RichText::new(title).font(bold(13.0)));
                    match &state {
                        Some(Ok(s)) => ui.label(RichText::new(s).size(12.0).color(TEXT_DIM)),
                        Some(Err(e)) => ui.label(RichText::new(e).size(12.0).color(DANGER)),
                        None => ui.label(RichText::new(absent).size(12.0).color(MUTED)),
                    };
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if state.is_some() && w::icon_button(ui, Icon::Trash, "Retirer").clicked() {
                        value.zeroize();
                        if editing {
                            *open = None;
                        }
                    }
                    if w::icon_button(ui, if editing { Icon::EyeOff } else { Icon::Edit }, "Coller / afficher le contenu").clicked() {
                        *open = if editing { None } else { Some(part) };
                    }
                    if w::icon_button(ui, Icon::Folder, "Importer un fichier").clicked()
                        && let Some(p) = rfd::FileDialog::new().set_title(title).pick_file()
                    {
                        match std::fs::read_to_string(&p) {
                            Ok(s) => {
                                value.zeroize();
                                *value = s;
                                *error = None;
                            }
                            Err(e) => *error = Some(format!("Lecture impossible : {e}")),
                        }
                    }
                });
            });
            if editing {
                ui.add_space(8.0);
                ui.add(
                    egui::TextEdit::multiline(value)
                        .hint_text(RichText::new(hint).color(MUTED))
                        .font(FontId::monospace(11.0))
                        .desired_rows(5)
                        .margin(Margin::same(10))
                        .desired_width(f32::INFINITY),
                );
            }
        });
    ui.add_space(6.0);
}

/// Importe un fichier `.conf` (WireGuard) ou `.ovpn` (OpenVPN) dans le profil édité.
fn import_vpn_file(ve: &mut VpnEditor, path: &Path) {
    let mut text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            ve.notice = None;
            ve.error = Some(format!("Lecture impossible : {e}"));
            return;
        }
    };
    let kind = detect_vpn_file(path, &text);
    let p = &mut ve.profile;
    let result = match kind {
        VpnKind::WireGuard => crate::vpn::parse_wireguard(&text).map(|c| {
            p.wireguard.private_key.zeroize();
            p.wireguard.preshared_key.zeroize();
            p.wireguard = c;
        }),
        VpnKind::OpenVpn => crate::openvpn::config::parse_ovpn(&text, path.parent()).map(|c| {
            for s in [&mut p.openvpn.key, &mut p.openvpn.tls_auth, &mut p.openvpn.tls_crypt] {
                s.zeroize();
            }
            p.openvpn = c;
        }),
    };
    text.zeroize();
    match result {
        Ok(()) => {
            p.kind = kind;
            if p.name.trim().is_empty()
                && let Some(stem) = path.file_stem()
            {
                p.name = stem.to_string_lossy().into_owned();
            }
            ve.open_part = None;
            ve.error = None;
            ve.notice = Some(format!("« {} » importé ({}).", path.file_name().unwrap_or_default().to_string_lossy(), kind.label()));
        }
        Err(e) => {
            ve.notice = None;
            ve.error = Some(e);
        }
    }
}

/// Contenu défilant de l'éditeur de profil VPN : type, import, puis réglages du type choisi.
fn vpn_form(ui: &mut egui::Ui, ve: &mut VpnEditor, users: &[String], width: f32) {
    ui.set_width(width);
    let half = (width - 12.0) / 2.0;

    w::segmented(
        ui,
        &mut ve.profile.kind,
        &[(VpnKind::WireGuard, Icon::Shield, "WireGuard"), (VpnKind::OpenVpn, Icon::Lock, "OpenVPN")],
        width,
    );
    ui.add_space(10.0);

    // --- import d'un fichier .conf / .ovpn
    egui::Frame::new()
        .fill(INPUT)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(RADIUS)
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(width - 28.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                ui.painter().rect_filled(r, 10.0, WARN.gamma_multiply(0.12));
                w::paint_icon(ui.painter(), r.shrink(9.0), Icon::File, WARN);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(RichText::new("Fichier de configuration").font(bold(13.5)));
                    ui.label(RichText::new("WireGuard ou OpenVPN : remplit les champs, modifiables ensuite").size(12.0).color(MUTED));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if w::button_h(ui, Kind::Secondary, Some(Icon::Folder), "Importer .conf / .ovpn", 0.0, 34.0).clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .set_title("Configuration VPN")
                            .add_filter("WireGuard / OpenVPN", &["conf", "ovpn"])
                            .add_filter("Tous les fichiers", &["*"])
                            .pick_file()
                    {
                        import_vpn_file(ve, &path);
                    }
                });
            });
        });
    if let Some(n) = &ve.notice {
        ui.add_space(6.0);
        w::callout(ui, Icon::Check, ACCENT, n);
    }
    ui.add_space(10.0);

    w::section_title(ui, "Général");
    w::label(ui, "Nom");
    w::input(ui, &mut ve.profile.name, "ex. VPN Client A", false, width);
    ui.add_space(10.0);

    match ve.profile.kind {
        VpnKind::WireGuard => wireguard_form(ui, ve, width, half),
        VpnKind::OpenVpn => openvpn_form(ui, ve, width, half),
    }

    if !users.is_empty() {
        ui.add_space(12.0);
        w::section_title(ui, "Utilisé par");
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
            for u in users {
                w::chip(ui, Some(Icon::Server), u, ACCENT);
            }
        });
    }
}

fn wireguard_form(ui: &mut egui::Ui, ve: &mut VpnEditor, width: f32, half: f32) {
    let wg = &mut ve.profile.wireguard;
    w::section_title(ui, "Ce poste  ·  [Interface]");
    w::label(ui, "Clé privée");
    w::password_input(ui, &mut wg.private_key, "PrivateKey (base64)", &mut ve.show_key, width);
    ui.add_space(2.0);
    ui.horizontal(|ui| match crate::vpn::public_key(&wg.private_key) {
        Some(public) => {
            ui.label(RichText::new("Clé publique :").size(12.0).color(MUTED));
            ui.label(RichText::new(&public).monospace().size(11.5).color(TEXT_DIM));
            if w::link(ui, "Copier").clicked() {
                ui.ctx().copy_text(public);
            }
        }
        None if wg.private_key.trim().is_empty() => {
            ui.label(RichText::new("Pas encore de clé :").size(12.0).color(MUTED));
            if w::link(ui, "En générer une").clicked() {
                wg.private_key = crate::vpn::generate_private_key();
            }
        }
        None => {
            ui.label(RichText::new("Clé privée illisible (44 caractères base64 attendus)").size(12.0).color(DANGER));
        }
    });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width(half);
            w::label(ui, "Adresse dans le VPN");
            w::input(ui, &mut wg.address, "ex. 10.8.0.2/32", false, half);
        });
        ui.vertical(|ui| {
            ui.set_width(half);
            w::label(ui, "DNS");
            w::input(ui, &mut wg.dns, "optionnel (ex. 10.8.0.1, corp.local)", false, half);
        });
    });
    ui.add_space(4.0);
    w::label(ui, "MTU");
    let mut mtu = if wg.mtu == 0 { String::new() } else { wg.mtu.to_string() };
    if w::input(ui, &mut mtu, "1420 (automatique)", false, 160.0).changed() {
        mtu.retain(|c| c.is_ascii_digit());
        wg.mtu = mtu.parse().unwrap_or(0);
    }
    ui.add_space(10.0);

    w::section_title(ui, "Serveur  ·  [Peer]");
    ui.horizontal(|ui| {
        let host_w = width - 160.0 - 12.0;
        ui.vertical(|ui| {
            ui.set_width(host_w);
            w::label(ui, "Adresse du serveur");
            w::input(ui, &mut wg.endpoint, "Endpoint (ex. vpn.exemple.fr:51820)", false, host_w);
        });
        ui.vertical(|ui| {
            ui.set_width(160.0);
            w::label(ui, "Keepalive (s)");
            let mut ka = if wg.keepalive == 0 { String::new() } else { wg.keepalive.to_string() };
            if w::input(ui, &mut ka, "aucun", false, 160.0).changed() {
                ka.retain(|c| c.is_ascii_digit());
                wg.keepalive = ka.parse().unwrap_or(0);
            }
        });
    });
    ui.add_space(4.0);
    w::label(ui, "Clé publique du serveur");
    w::input(ui, &mut wg.peer_public_key, "PublicKey (base64)", false, width);
    ui.add_space(4.0);
    w::label(ui, "Clé partagée");
    w::password_input(ui, &mut wg.preshared_key, "PresharedKey, optionnelle", &mut ve.show_psk, width);
    ui.add_space(4.0);
    w::label(ui, "Réseaux joignables");
    w::input(ui, &mut wg.allowed_ips, "AllowedIPs (ex. 10.8.0.0/24, 192.168.1.0/24) — vide = tout", false, width);
}

fn openvpn_form(ui: &mut egui::Ui, ve: &mut VpnEditor, width: f32, half: f32) {
    let p = &mut ve.profile;
    let o = &mut p.openvpn;

    w::section_title(ui, "Serveur");
    ui.horizontal(|ui| {
        let host_w = width - 110.0 - 12.0;
        ui.vertical(|ui| {
            ui.set_width(host_w);
            w::label(ui, "Adresse du serveur");
            w::input(ui, &mut o.remote, "remote (ex. vpn.exemple.fr)", false, host_w);
        });
        ui.vertical(|ui| {
            ui.set_width(110.0);
            w::label(ui, "Port");
            let mut port = if o.port == 0 { String::new() } else { o.port.to_string() };
            if w::input(ui, &mut port, "1194", false, 110.0).changed() {
                port.retain(|c| c.is_ascii_digit());
                o.port = port.parse::<u32>().map(|v| v.min(u16::MAX as u32) as u16).unwrap_or(0);
            }
        });
    });
    ui.add_space(4.0);
    w::label(ui, "Transport");
    w::segmented(ui, &mut o.proto, &[(OpenVpnProto::Udp, Icon::Forward, "UDP"), (OpenVpnProto::Tcp, Icon::Hop, "TCP")], half);
    ui.add_space(10.0);

    w::section_title(ui, "Authentification");
    option_toggle(ui, "Le serveur demande un identifiant", "auth-user-pass : envoyés à chaque connexion (WatchGuard, AD…)", &mut o.auth_user_pass);
    if o.auth_user_pass {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(half);
                w::label(ui, "Identifiant");
                w::input(ui, &mut p.username, "ex. jdupont", false, half);
            });
            ui.vertical(|ui| {
                ui.set_width(half);
                w::label(ui, "Mot de passe");
                w::password_input(ui, &mut p.password, "", &mut ve.show_password, half);
            });
        });
        ui.add_space(8.0);
    }

    w::section_title(ui, "Certificats et clés");
    let (open, error) = (&mut ve.open_part, &mut ve.error);
    const PEM_CERT: &str = "-----BEGIN CERTIFICATE-----";
    const PEM_STATIC: &str = "-----BEGIN OpenVPN Static key V1-----";
    ovpn_file_row(ui, OvpnPart::Ca, "Autorité du serveur (CA)", "Absent : obligatoire", PEM_CERT, &mut o.ca, cert_summary, open, error, width);
    ovpn_file_row(ui, OvpnPart::Cert, "Certificat client", "Absent (inutile si identifiant seul)", PEM_CERT, &mut o.cert, cert_summary, open, error, width);
    ovpn_file_row(ui, OvpnPart::Key, "Clé client", "Absente", "-----BEGIN PRIVATE KEY-----", &mut o.key, key_summary, open, error, width);
    ovpn_file_row(ui, OvpnPart::TlsAuth, "tls-auth", "Absente", PEM_STATIC, &mut o.tls_auth, static_key_summary, open, error, width);
    if !o.tls_auth.trim().is_empty() {
        setting_row(ui, "Direction de la clé", "key-direction : 1 côté client en général", |ui| {
            let mut dir = match o.key_direction.trim() {
                "0" => 0u8,
                "1" => 1,
                _ => 2,
            };
            if w::segmented(ui, &mut dir, &[(2u8, Icon::Refresh, "Aucune"), (0u8, Icon::Up, "0"), (1u8, Icon::Download, "1")], 230.0) {
                o.key_direction = match dir {
                    0 => "0".into(),
                    1 => "1".into(),
                    _ => String::new(),
                };
            }
        });
    }
    ovpn_file_row(ui, OvpnPart::TlsCrypt, "tls-crypt", "Absente", PEM_STATIC, &mut o.tls_crypt, static_key_summary, open, error, width);
    ui.add_space(4.0);

    w::section_title(ui, "Chiffrement");
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width(half);
            w::label(ui, "cipher");
            w::input(ui, &mut o.cipher, "ex. AES-256-CBC (si non négocié)", false, half);
        });
        ui.vertical(|ui| {
            ui.set_width(half);
            w::label(ui, "auth");
            w::input(ui, &mut o.auth, "SHA1 par défaut (SHA256, SHA512)", false, half);
        });
    });
    ui.add_space(4.0);
    w::label(ui, "data-ciphers");
    w::input(ui, &mut o.data_ciphers, "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305 (défaut)", false, width);
    ui.add_space(4.0);
    w::label(ui, "verify-x509-name");
    w::input(ui, &mut o.verify_x509_name, "Nom attendu dans le certificat du serveur, optionnel", false, width);
    ui.add_space(10.0);
    option_toggle(ui, "Vérifier le rôle du serveur", "remote-cert-tls server : refuse un certificat client présenté comme serveur", &mut o.remote_cert_tls);
    ui.add_space(4.0);
    w::label(ui, "Compression (comp-lzo, compress, compress stub-v2)");
    w::input(ui, &mut o.compression, "Aucune — rien n'est compressé, seul l'octet d'en-tête est géré", false, width);
    ui.add_space(4.0);
    w::label(ui, "Routes du profil");
    w::input(ui, &mut o.routes, "Réseaux en plus de ceux du serveur, ex. 192.168.1.0/24 10.0.0.0/8", false, width);
    ui.add_space(10.0);
    option_toggle(ui, "Tout passer par le VPN", "redirect-gateway : aucun hôte n'est refusé faute de route", &mut o.redirect_gateway);
    option_toggle(ui, "Ignorer les routes du serveur", "route-nopull : seules les routes du profil comptent", &mut o.route_nopull);
}

/// Fondu PANEL → transparent sur un bord de la zone d'onglets (signale du contenu masqué).
fn fade_edge(p: &egui::Painter, r: Rect, left: bool) {
    let wd = 28.0;
    let (x0, x1) = if left { (r.left(), r.left() + wd) } else { (r.right(), r.right() - wd) };
    let mut mesh = egui::Mesh::default();
    let clear = Color32::TRANSPARENT;
    mesh.colored_vertex(pos2(x0, r.top()), PANEL);
    mesh.colored_vertex(pos2(x0, r.bottom()), PANEL);
    mesh.colored_vertex(pos2(x1, r.top()), clear);
    mesh.colored_vertex(pos2(x1, r.bottom()), clear);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(1, 2, 3);
    p.add(egui::Shape::mesh(mesh));
}

fn tab_pill(ui: &mut egui::Ui, icon: Option<Icon>, title: &str, selected: bool, dot: Option<Color32>, closable: bool) -> (egui::Response, bool) {
    let t: String = if title.chars().count() > 24 { title.chars().take(23).chain(['…']).collect() } else { title.to_string() };
    let font = if selected { bold(13.0) } else { FontId::proportional(13.0) };
    let galley = ui.painter().layout_no_wrap(t, font, if selected { TEXT } else { TEXT_DIM });
    let lead = if icon.is_some() || dot.is_some() { 20.0 } else { 0.0 };
    let tail = if closable { 24.0 } else { 0.0 };
    let size = vec2(galley.size().x + lead + tail + 26.0, 34.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let hover = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    if selected {
        ui.painter().rect(rect, 9.0, ELEVATED, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
    } else if hover > 0.0 {
        ui.painter().rect_filled(rect, 9.0, HOVER.gamma_multiply(0.6 * hover));
    }
    let mut x = rect.left() + 13.0;
    if let Some(i) = icon {
        w::paint_icon(ui.painter(), Rect::from_center_size(pos2(x + 7.0, rect.center().y), Vec2::splat(15.0)), i, if selected { ACCENT } else { MUTED });
        x += lead;
    } else if let Some(c) = dot {
        ui.painter().circle_filled(pos2(x + 4.0, rect.center().y), 4.0, c);
        if selected {
            ui.painter().circle_filled(pos2(x + 4.0, rect.center().y), 7.0, c.gamma_multiply(0.18));
        }
        x += lead - 4.0;
    }
    ui.painter().galley(pos2(x, rect.center().y - galley.size().y / 2.0), galley, TEXT);
    let mut closed = false;
    if closable {
        let cr = Rect::from_center_size(pos2(rect.right() - 17.0, rect.center().y), Vec2::splat(20.0));
        let c = ui.interact(cr, resp.id.with("close"), Sense::click());
        if c.hovered() {
            ui.painter().rect_filled(cr, 5.0, HOVER);
        }
        if selected || hover > 0.0 || c.hovered() {
            w::paint_icon(ui.painter(), cr.shrink(5.0), Icon::Close, if c.hovered() { TEXT } else { MUTED });
        }
        closed = c.clicked();
    }
    (resp, closed)
}

/// Recherche : nom, adresse, groupe, utilisateur ou protocole (`q` en minuscules).
fn host_matches(h: &Host, q: &str) -> bool {
    [&h.label, &h.hostname, &h.group, &h.username].iter().any(|s| s.to_lowercase().contains(q)) || h.protocol.label().to_lowercase() == q
}

fn protocol_color(p: Protocol) -> Color32 {
    match p {
        Protocol::Ssh => ACCENT,
        Protocol::Rdp => ACCENT_2,
        Protocol::Vnc => Color32::from_rgb(0xC0, 0x84, 0xFC),
    }
}

fn protocol_icon(p: Protocol) -> Icon {
    if p.is_graphical() { Icon::Monitor } else { Icon::Terminal }
}

/// Petite étiquette de protocole peinte à `pos` (coin droit-centre). Renvoie sa largeur.
fn paint_protocol_badge(p: &egui::Painter, right_center: egui::Pos2, proto: Protocol) -> f32 {
    let col = protocol_color(proto);
    let galley = p.layout_no_wrap(proto.label().to_string(), bold(9.5), col);
    let r = Rect::from_min_size(
        pos2(right_center.x - galley.size().x - 10.0, right_center.y - 8.0),
        vec2(galley.size().x + 10.0, 16.0),
    );
    p.rect_filled(r, 5.0, col.gamma_multiply(0.14));
    p.galley(pos2(r.left() + 5.0, r.center().y - galley.size().y / 2.0), galley, col);
    r.width()
}

fn host_row(ui: &mut egui::Ui, h: &Host, connected: bool, active: bool, jump: Option<String>, actions: &mut Vec<Action>) {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 52.0), Sense::click());
    let hover = ui.ctx().animate_bool_with_time(resp.id, ui.rect_contains_pointer(rect), 0.1);
    if active {
        ui.painter().rect_filled(rect, 10.0, ELEVATED);
    } else if hover > 0.0 {
        ui.painter().rect_filled(rect, 10.0, HOVER.gamma_multiply(0.55 * hover));
    }
    let p = ui.painter();
    let av = Rect::from_min_size(rect.min + vec2(8.0, 9.0), Vec2::splat(34.0));
    w::paint_avatar(p, av, h.display_name());
    if connected {
        let c = av.right_bottom() - vec2(2.0, 2.0);
        p.circle_filled(c, 5.5, PANEL);
        p.circle_filled(c, 3.8, ACCENT);
    }
    // zone de texte fixe : rien ne bouge au survol
    let badge_w = if h.protocol.is_graphical() { paint_protocol_badge(p, pos2(rect.right() - 8.0, rect.top() + 17.0), h.protocol) + 6.0 } else { 0.0 };
    let clip = Rect::from_min_max(rect.min + vec2(52.0, 0.0), rect.right_bottom() - vec2(8.0, 0.0));
    let pc = p.with_clip_rect(clip);
    p.with_clip_rect(Rect::from_min_max(clip.min, pos2(clip.right() - badge_w, clip.bottom())))
        .text(rect.min + vec2(52.0, 9.0), Align2::LEFT_TOP, h.display_name(), bold(13.5), TEXT);
    let sub = match &jump {
        Some(j) => format!("{}  ·  via {j}", h.address()),
        None => h.address(),
    };
    pc.text(rect.min + vec2(52.0, 28.0), Align2::LEFT_TOP, sub, FontId::proportional(11.5), MUTED);

    // boutons superposés en fondu (pas d'allocation dans la mise en page)
    let b1 = Rect::from_center_size(pos2(rect.right() - 22.0, rect.center().y), Vec2::splat(28.0));
    let b2 = Rect::from_center_size(pos2(rect.right() - 54.0, rect.center().y), Vec2::splat(28.0));
    let r1 = ui.interact(b1, resp.id.with("go"), Sense::click());
    let r2 = ui.interact(b2, resp.id.with("edit"), Sense::click());
    if hover > 0.01 {
        let row_bg = if active { ELEVATED } else { w::lerp_color(PANEL, HOVER, 0.55) };
        let cover = Rect::from_min_max(pos2(b2.left() - 10.0, rect.top() + 4.0), pos2(rect.right() - 4.0, rect.bottom() - 4.0));
        let p = ui.painter();
        p.rect_filled(cover, 8.0, row_bg.gamma_multiply(hover));
        for (b, r, icon) in [(b1, &r1, Icon::Play), (b2, &r2, Icon::Edit)] {
            if r.hovered() {
                p.rect_filled(b, 8.0, HOVER.gamma_multiply(hover));
            }
            let col = if r.hovered() { TEXT } else { TEXT_DIM };
            w::paint_icon(p, b.shrink(7.0), icon, col.gamma_multiply(hover));
        }
    }
    if hover > 0.5 {
        if r1.on_hover_text("Se connecter").clicked() {
            actions.push(Action::Connect(h.id));
            return;
        }
        if r2.on_hover_text("Modifier").clicked() {
            actions.push(Action::Edit(h.id));
            return;
        }
    }
    if resp.double_clicked() {
        actions.push(Action::Connect(h.id));
    }
    host_context_menu(&resp, h.id, actions);
}

fn host_context_menu(resp: &egui::Response, id: Uuid, actions: &mut Vec<Action>) {
    resp.context_menu(|ui| {
        ui.set_min_width(170.0);
        if ui.button("Se connecter").clicked() {
            actions.push(Action::Connect(id));
            ui.close();
        }
        if ui.button("Modifier").clicked() {
            actions.push(Action::Edit(id));
            ui.close();
        }
        ui.separator();
        if ui.button(RichText::new("Supprimer").color(DANGER)).clicked() {
            actions.push(Action::Delete(id));
            ui.close();
        }
    });
}

fn host_card(ui: &mut egui::Ui, rect: Rect, h: &Host, connected: bool, actions: &mut Vec<Action>) {
    let resp = ui.interact(rect, egui::Id::new(("host-card", h.id)), Sense::click());
    let hover = ui.ctx().animate_bool_with_time(resp.id, ui.rect_contains_pointer(rect), 0.14);
    let p = ui.painter();
    let r = rect.translate(vec2(0.0, -2.0 * hover));
    if hover > 0.0 {
        p.rect_filled(r.translate(vec2(0.0, 6.0)).shrink(6.0), 14.0, Color32::from_black_alpha((60.0 * hover) as u8));
    }
    p.rect(
        r,
        14.0,
        w::lerp_color(SURFACE, ELEVATED, hover),
        Stroke::new(1.0, w::lerp_color(BORDER, ACCENT.gamma_multiply(0.45), hover)),
        egui::StrokeKind::Inside,
    );
    let av = Rect::from_min_size(pos2(r.left() + 16.0, r.center().y - 21.0), Vec2::splat(42.0));
    w::paint_avatar(p, av, h.display_name());
    if connected {
        let c = av.right_bottom() - vec2(3.0, 3.0);
        p.circle_filled(c, 6.5, w::lerp_color(SURFACE, ELEVATED, hover));
        p.circle_filled(c, 4.5, ACCENT);
    }
    let clip = p.with_clip_rect(Rect::from_min_max(r.min + vec2(70.0, 0.0), r.right_bottom() - vec2(56.0, 0.0)));
    clip.text(pos2(r.left() + 70.0, r.center().y - 2.0), Align2::LEFT_BOTTOM, h.display_name(), bold(15.0), TEXT);
    clip.text(pos2(r.left() + 70.0, r.center().y + 3.0), Align2::LEFT_TOP, h.address(), FontId::monospace(12.0), MUTED);
    paint_protocol_badge(p, pos2(r.right() - 12.0, r.bottom() - 14.0), h.protocol);

    // bouton connexion au survol
    let br = Rect::from_center_size(pos2(r.right() - 30.0, r.center().y), Vec2::splat(34.0));
    let b = ui.interact(br, resp.id.with("go"), Sense::click());
    if hover > 0.01 {
        let col = if b.hovered() { Color32::from_rgb(0x5E, 0xEA, 0xD4) } else { ACCENT };
        ui.painter().circle_filled(br.center(), 17.0, col.gamma_multiply(hover));
        w::paint_icon(ui.painter(), br.shrink(10.0).translate(vec2(1.5, 0.0)), Icon::Play, ON_ACCENT.gamma_multiply(hover));
    }
    if b.clicked() || resp.double_clicked() {
        actions.push(Action::Connect(h.id));
    }
    if resp.hovered() || b.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    host_context_menu(&resp, h.id, actions);
}

/// Puce de filtre : icône, libellé, nombre d'hôtes.
fn filter_chip(ui: &mut egui::Ui, icon: Option<Icon>, label: &str, count: usize, selected: bool, tint: Color32) -> egui::Response {
    let font = if selected { bold(13.0) } else { FontId::proportional(13.0) };
    let text = ui.painter().layout_no_wrap(label.to_string(), font, if selected { TEXT } else { TEXT_DIM });
    let num = ui.painter().layout_no_wrap(count.to_string(), bold(11.0), if selected { tint } else { MUTED });
    let lead = if icon.is_some() { 20.0 } else { 0.0 };
    let size = vec2(12.0 + lead + text.size().x + 7.0 + num.size().x + 12.0, 30.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let hover = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    let (fill, stroke) = if selected {
        (tint.gamma_multiply(0.14), Stroke::new(1.0, tint.gamma_multiply(0.55)))
    } else {
        (w::lerp_color(SURFACE, HOVER, hover), Stroke::new(1.0, BORDER))
    };
    ui.painter().rect(rect, 15.0, fill, stroke, egui::StrokeKind::Inside);
    let mut x = rect.left() + 12.0;
    if let Some(i) = icon {
        w::paint_icon(ui.painter(), Rect::from_center_size(pos2(x + 7.0, rect.center().y), Vec2::splat(14.0)), i, if selected { tint } else { MUTED });
        x += lead;
    }
    let tw = text.size();
    ui.painter().galley(pos2(x, rect.center().y - tw.y / 2.0), text, TEXT);
    x += tw.x + 7.0;
    let nh = num.size().y;
    ui.painter().galley(pos2(x, rect.center().y - nh / 2.0), num, MUTED);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn empty_state(ui: &mut egui::Ui, actions: &mut Vec<Action>) {
    ui.add_space(50.0);
    ui.vertical_centered(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::splat(120.0), Sense::hover());
        w::glow(ui.painter(), r.center(), 90.0, ACCENT.gamma_multiply(0.18));
        ui.painter().rect(r.shrink(26.0), 18.0, SURFACE, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
        w::paint_icon(ui.painter(), r.shrink(44.0), Icon::Terminal, ACCENT);
        ui.add_space(14.0);
        ui.label(RichText::new("Ajoutez votre premier serveur").font(bold(20.0)));
        ui.add_space(2.0);
        ui.label(RichText::new("Mot de passe ou clé SSH, rebonds en chaîne : tout est chiffré localement dans votre coffre.").color(MUTED));
        ui.add_space(18.0);
        if w::button_h(ui, Kind::Primary, Some(Icon::Plus), "Nouvel hôte", 0.0, 42.0).clicked() {
            actions.push(Action::New);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space((ui.available_width() - 150.0) / 2.0);
            ui.label(RichText::new("ou").size(12.0).color(MUTED));
            w::shortcut(ui, "Ctrl+Maj+N");
        });
    });
}

/// Bouton de la barre de session : icône et petit libellé dessous. Sélectionné : trait d'accent sur le
/// bord, icône et libellé colorés, sans fond.
fn rail_button(ui: &mut egui::Ui, icon: Icon, label: &str, selected: bool, tint: Color32, tooltip: &str) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 52.0), Sense::click());
    let hover = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    let sel = ui.ctx().animate_bool_with_time(resp.id.with("sel"), selected, 0.15);
    if sel > 0.0 {
        let h = 26.0 * sel;
        let bar = Rect::from_center_size(pos2(rect.left() + 1.5, rect.center().y), vec2(3.0, h));
        ui.painter().rect_filled(bar, 1.5, tint);
    }
    let base = w::lerp_color(MUTED, TEXT, hover);
    let col = w::lerp_color(base, tint, sel);
    w::paint_icon(ui.painter(), Rect::from_center_size(pos2(rect.center().x + 1.0, rect.top() + 19.0), Vec2::splat(19.0)), icon, col);
    let font = if selected { bold(10.0) } else { FontId::proportional(10.0) };
    ui.painter().text(pos2(rect.center().x + 1.0, rect.bottom() - 10.0), Align2::CENTER_CENTER, label, font, col);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp.on_hover_text(tooltip)
}

/// Transferts vus depuis la console : anneau de progression autour de l'icône « Fichiers » pendant
/// le lot, puis pastille (bleue, rouge en cas d'échec) jusqu'à l'ouverture de la vue Fichiers.
fn files_indicator(ui: &egui::Ui, r: &egui::Response, f: &crate::files::FileManager) {
    let center = pos2(r.rect.center().x + 1.0, r.rect.top() + 19.0);
    let p = ui.painter();
    let id = r.id.with("transfer-ring");
    if f.busy() {
        let radius = 15.0;
        p.circle_stroke(center, radius, Stroke::new(2.5, BORDER));
        let (start, sweep) = match f.progress() {
            // avance lissée : l'anneau ne saute pas d'un relevé à l'autre
            Some(frac) => (0.0, ui.ctx().animate_value_with_time(id, frac, 0.25) * std::f32::consts::TAU),
            // taille inconnue : arc qui tourne
            None => ((ui.input(|i| i.time) as f32 * 4.0) % std::f32::consts::TAU, std::f32::consts::FRAC_PI_2),
        };
        if sweep > 0.0 {
            let steps = ((sweep / std::f32::consts::TAU) * 64.0).ceil().max(2.0) as usize;
            let pts: Vec<_> = (0..=steps)
                .map(|k| {
                    // départ en haut, sens horaire
                    let a = start + sweep * k as f32 / steps as f32 - std::f32::consts::FRAC_PI_2;
                    center + radius * vec2(a.cos(), a.sin())
                })
                .collect();
            p.add(egui::Shape::line(pts, Stroke::new(2.5, ACCENT_2)));
        }
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(50));
    } else {
        // l'anneau repartira de zéro au prochain lot
        ui.ctx().animate_value_with_time(id, 0.0, 0.0);
        if let Some(done) = f.unseen() {
            let col = if done == crate::files::Finished::Failed { DANGER } else { ACCENT_2 };
            let c = r.rect.center_top() + vec2(12.0, 9.0);
            p.circle_filled(c, 5.0, PANEL);
            p.circle_filled(c, 3.5, col);
        }
    }
}

/// Barre latérale droite d'une session : console (terminal ou bureau) ou fichiers, à la place l'un de l'autre.
/// `has_key` : l'hôte se connecte déjà par clé (pas de bouton « Clé »).
fn session_rail(ui: &mut egui::Ui, tab: &Tab, i: usize, has_key: bool, actions: &mut Vec<Action>) {
    ui.add_space(4.0);
    let tip = if tab.protocol.is_graphical() { "Bureau distant" } else { "Terminal" };
    if rail_button(ui, protocol_icon(tab.protocol), "Console", !tab.show_files, ACCENT, tip).clicked() {
        actions.push(Action::Console(i));
    }
    ui.add_space(4.0);
    let tip = match tab.protocol {
        Protocol::Ssh => "Fichiers : ce PC et l'hôte (SFTP)  ·  Ctrl+Maj+E",
        Protocol::Rdp => "Fichiers : ce PC et le dossier partagé du bureau distant  ·  Ctrl+Maj+E",
        Protocol::Vnc => "Fichiers (indisponible en VNC)",
    };
    let tint = if tab.protocol == Protocol::Vnc { MUTED } else { ACCENT };
    let r = rail_button(ui, Icon::Folder, "Fichiers", tab.show_files, tint, tip);
    if let Some(f) = &tab.files {
        files_indicator(ui, &r, f);
    }
    if r.clicked() {
        actions.push(Action::Files(i));
    }
    if tab.protocol == Protocol::Ssh && !has_key && matches!(tab.state, TabState::Connected) {
        ui.add_space(4.0);
        let tip = "Configurer une clé : génère une clé, l'enregistre dans le coffre, l'ajoute au serveur par cette session et passe l'hôte en connexion par clé (mot de passe en secours)";
        if rail_button(ui, Icon::Key, "Clé", false, ACCENT_2, tip).clicked() {
            actions.push(Action::SetupKey(i));
        }
    }

    // affichage de la session : fenêtre séparée, plein écran
    ui.add_space(8.0);
    let y = ui.cursor().top();
    ui.painter().hline(ui.max_rect().x_range().shrink(10.0), y, Stroke::new(1.0, BORDER));
    ui.add_space(8.0);
    let (tip, action) = if tab.popped {
        ("Ramener la session dans cette fenêtre", Action::PopIn(i))
    } else {
        ("Ouvrir la session dans une fenêtre séparée", Action::PopOut(i))
    };
    if rail_button(ui, Icon::External, "Fenêtre", tab.popped, ACCENT_2, tip).clicked() {
        actions.push(action);
    }
    ui.add_space(4.0);
    if rail_button(ui, Icon::Expand, "Plein écran", false, ACCENT, "Session en plein écran  ·  Ctrl+Maj+Entrée").clicked() {
        actions.push(if tab.popped { Action::PopupFullscreen(i, true) } else { Action::Immersive(true) });
    }
    // Ctrl+Alt+Suppr est toujours intercepté par cet ordinateur : envoyé par un bouton
    if tab.protocol.is_graphical() && matches!(tab.state, TabState::Connected) {
        ui.add_space(4.0);
        if rail_button(ui, Icon::Keyboard, "Sécurité", false, ACCENT_2, "Envoyer Ctrl+Alt+Suppr au bureau distant (écran de sécurité Windows)")
            .clicked()
        {
            actions.push(Action::CtrlAltDel(i));
        }
        // Ctrl+Maj+Échap : retenu par le crochet clavier si l'hôte accepte les raccourcis Windows
        // (RDP) ou en VNC ; ce bouton l'envoie dans tous les cas
        ui.add_space(4.0);
        if rail_button(ui, Icon::Monitor, "Tâches", false, ACCENT_2, "Envoyer Ctrl+Maj+Échap au bureau distant (gestionnaire des tâches)")
            .clicked()
        {
            actions.push(Action::TaskManager(i));
        }
    }
}

/// Pendant la connexion d'un bureau graphique : indicateur et dernière étape.
fn desktop_placeholder(ui: &mut egui::Ui, proto: Protocol, status: &str) {
    let rect = ui.max_rect();
    let c = rect.center();
    let r = Rect::from_center_size(c - vec2(0.0, 30.0), Vec2::splat(64.0));
    w::glow(ui.painter(), r.center(), 70.0, protocol_color(proto).gamma_multiply(0.12));
    ui.painter().rect(r, 16.0, SURFACE, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
    w::paint_icon(ui.painter(), r.shrink(18.0), Icon::Monitor, protocol_color(proto));
    let t = ui.input(|i| i.time) as f32;
    for k in 0..3 {
        let a = ((t * 3.0 - k as f32 * 0.6).sin() * 0.5 + 0.5).powf(2.0);
        ui.painter().circle_filled(pos2(c.x - 12.0 + 12.0 * k as f32, r.bottom() + 20.0), 3.0, TEXT_DIM.gamma_multiply(0.3 + 0.7 * a));
    }
    ui.painter().text(pos2(c.x, r.bottom() + 44.0), Align2::CENTER_CENTER, status, FontId::proportional(13.0), TEXT_DIM);
    ui.ctx().request_repaint_after(std::time::Duration::from_millis(33));
}

/// Bureau en cours de reconnexion : image assombrie et pastille d'état en haut.
fn reconnect_banner(ui: &mut egui::Ui, status: &str) {
    let rect = ui.max_rect();
    let p = ui.painter();
    p.rect_filled(rect, 0.0, BG.gamma_multiply(0.45));
    let galley = p.layout_no_wrap(status.to_owned(), bold(13.0), TEXT);
    let pill = Rect::from_center_size(pos2(rect.center().x, rect.top() + 34.0), vec2(galley.size().x + 52.0, 34.0));
    p.rect(pill, 17.0, SURFACE, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
    let t = ui.input(|i| i.time) as f32;
    let a = (t * 4.0).sin() * 0.5 + 0.5;
    p.circle_filled(pos2(pill.left() + 20.0, pill.center().y), 4.0, WARN.gamma_multiply(0.4 + 0.6 * a));
    p.galley(pos2(pill.left() + 34.0, pill.center().y - galley.size().y / 2.0), galley, TEXT);
    ui.ctx().request_repaint_after(std::time::Duration::from_millis(50));
}

/// Fichiers survolés au-dessus de la fenêtre : où ils iront une fois déposés.
fn drop_overlay(ctx: &egui::Context, rect: Rect, tab: &Tab) {
    let (text, sub) = match tab.protocol {
        Protocol::Ssh => ("Déposer pour envoyer par SFTP", "dans le dossier distant ouvert dans Fichiers"),
        Protocol::Rdp => ("Déposer dans le dossier partagé", "accessible depuis le bureau distant (\\\\tsclient\\Escale)"),
        Protocol::Vnc => ("Transfert indisponible en VNC", "ajoutez cet hôte en SSH pour utiliser SFTP"),
    };
    let col = if tab.protocol == Protocol::Vnc { WARN } else { ACCENT };
    let p = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop-overlay")));
    p.rect(rect.shrink(6.0), 12.0, BG.gamma_multiply(0.82), Stroke::new(2.0, col.gamma_multiply(0.8)), egui::StrokeKind::Inside);
    let c = rect.center();
    w::paint_icon(&p, Rect::from_center_size(c - vec2(0.0, 34.0), Vec2::splat(40.0)), Icon::Upload, col);
    p.text(c + vec2(0.0, 6.0), Align2::CENTER_CENTER, text, bold(17.0), TEXT);
    p.text(c + vec2(0.0, 30.0), Align2::CENTER_CENTER, sub, FontId::proportional(12.5), MUTED);
}

/// Étape de connexion, ouverture ou fermeture d'une session.
fn session_state(tab: &mut Tab, ev: Event) {
    match ev {
        Event::Status(s) => {
            tab.session.note(&format!("\x1b[90m\u{203a} {s}\x1b[0m\r\n"));
            // bureau déjà ouvert qui se reconnecte de lui-même (coupure réseau) : l'onglet et
            // la dernière image restent, les entrées attendent le retour de la session
            if matches!(tab.session, Session::Desktop { .. }) && matches!(tab.state, TabState::Connected) {
                tab.state = TabState::Connecting;
            }
            tab.status = s;
        }
        Event::Connected => {
            if let Session::Desktop { view, handle } = &mut tab.session
                && tab.was_connected
            {
                // session rétablie : taille, modificateurs et souris renvoyés ; rien ne reste enfoncé
                // de ce qui a été tapé pendant la coupure
                view.resume();
                let _ = handle.tx.send(DesktopCmd::Input(vec![desktop::Input::ReleaseAll]));
            }
            // plusieurs écrans : la fenêtre qui les couvre s'ouvre à la première connexion
            if tab.multimon && !tab.was_connected {
                tab.popped = true;
                tab.show_files = false;
                tab.toolbar_until = 0.0;
            }
            tab.was_connected = true;
            tab.state = TabState::Connected;
        }
        Event::Closed(err) => {
            let msg = match &err {
                Some(e) => format!("\r\n\x1b[31m\u{00d7} {e}\x1b[0m\r\n"),
                None => "\r\n\x1b[90m\u{203a} Session terminée\x1b[0m\r\n".to_string(),
            };
            tab.session.note(&msg);
            tab.state = TabState::Closed(err);
        }
        Event::Output(_) | Event::VerifyHostKey { .. } => {}
    }
}

/// Terminal ou bureau distant d'un onglet, dans toute la zone disponible (fenêtre principale,
/// plein écran ou fenêtre séparée).
fn render_session(
    ui: &mut egui::Ui,
    tab: &mut Tab,
    i: usize,
    settings: &crate::model::Settings,
    active: bool,
    primary: &mut String,
    paste_confirm: &mut Option<(usize, String)>,
) {
    let connected = matches!(tab.state, TabState::Connected);
    let (has_password, pw_sent) = (tab.has_password, tab.pw_sent);
    // fenêtre séparée d'une session sur tous les écrans : image 1:1 sur toute la fenêtre
    let span = tab.multimon && tab.popped;
    let mut pw_request = false;
    match &mut tab.session {
        Session::Term { term, handle } => {
            let area = ui.max_rect();
            let out = term.show(ui, settings, active, primary);
            if let Some((c, r)) = out.resize {
                let _ = handle.tx.send(Cmd::Resize(c as u32, r as u32));
            }
            if connected && !out.bytes.is_empty() {
                // nouvelle commande validée (pas une saisie à une invite de mot de passe) :
                // la prochaine invite sudo pourra de nouveau recevoir le mot de passe automatiquement
                if out.bytes.contains(&b'\r') && !term.password_prompt() {
                    tab.pw_auto = false;
                }
                let _ = handle.tx.send(Cmd::Data(out.bytes));
            }
            if let Some(text) = out.paste_request {
                *paste_confirm = Some((i, text));
            }
            // invite sudo / su : le mot de passe enregistré de l'hôte en un clic
            if connected && !pw_sent && term.password_prompt() {
                pw_request = password_button(ui, area, has_password);
            }
        }
        Session::Desktop { view, handle } => {
            view.set_span(span);
            let out = view.show(ui, &handle.frame, active);
            if connected && !out.input.is_empty() {
                let _ = handle.tx.send(DesktopCmd::Input(out.input));
            }
            // mis en file pendant la connexion : appliqué dès la session ouverte
            if let Some((w, h)) = out.resize {
                let _ = handle.tx.send(DesktopCmd::Resize(w, h));
            }
            let empty = handle.frame.lock().map(|f| f.width == 0).unwrap_or(true);
            if matches!(tab.state, TabState::Connecting) {
                if empty {
                    desktop_placeholder(ui, tab.protocol, &tab.status);
                } else {
                    // reconnexion automatique : la dernière image reste affichée, assombrie
                    reconnect_banner(ui, &tab.status);
                }
            }
        }
    }
    if pw_request {
        tab.pw_request = true;
        ui.ctx().request_repaint();
    }
}

/// Bouton flottant en bas à droite du terminal quand une invite de mot de passe est affichée.
/// Vrai s'il est cliqué (et que l'hôte a un mot de passe).
fn password_button(ui: &mut egui::Ui, area: Rect, has_password: bool) -> bool {
    let r = Rect::from_min_max(area.right_bottom() - vec2(420.0, 58.0), area.right_bottom() - vec2(18.0, 16.0));
    let mut clicked = false;
    ui.scope_builder(egui::UiBuilder::new().max_rect(r).layout(egui::Layout::right_to_left(egui::Align::Center)), |ui| {
        if has_password {
            let resp = w::button(ui, Kind::Primary, Some(Icon::Key), "Saisir le mot de passe", 0.0)
                .on_hover_text("Envoie le mot de passe enregistré pour cet hôte  ·  Ctrl+Maj+M");
            clicked = resp.clicked();
        } else {
            w::button(ui, Kind::Secondary, Some(Icon::Key), "Aucun mot de passe enregistré", 0.0)
                .on_hover_text("Ajoutez-le dans l'hôte (Modifier › Mot de passe) pour le saisir en un clic");
        }
    });
    clicked
}

#[derive(Clone, Copy, PartialEq)]
enum ToolbarMode {
    /// Plein écran dans la fenêtre principale.
    Immersive,
    /// Fenêtre séparée (en plein écran ou non).
    Popup { fullscreen: bool },
    /// Fenêtre sur tous les écrans.
    Span,
}

/// Barre flottante en haut de la session, comme la barre de connexion de mstsc : visible quelques
/// secondes à l'ouverture, puis seulement quand la souris survole sa languette (petite poignée au
/// milieu du bord haut) ou la barre elle-même : le haut du bureau distant reste utilisable.
fn session_toolbar(ui: &mut egui::Ui, area: Rect, tab: &mut Tab, i: usize, mode: ToolbarMode, actions: &mut Vec<Action>) {
    let now = ui.input(|t| t.time);
    if tab.toolbar_until == 0.0 {
        tab.toolbar_until = now + 3.0;
    }
    let hover = ui.input(|t| t.pointer.hover_pos());
    let handle = Rect::from_center_size(pos2(area.center().x, area.top() + 4.0), vec2(120.0, 8.0));
    let bar_id = egui::Id::new(("session-toolbar-rect", tab.uid));
    let anim_id = egui::Id::new(("session-toolbar", tab.uid));
    // barre affichée à l'image précédente : la survoler la garde ouverte
    let shown_before = ui.ctx().data(|d| d.get_temp::<bool>(anim_id.with("on"))).unwrap_or(false);
    let bar: Option<Rect> = ui.ctx().data(|d| d.get_temp(bar_id));
    let on_handle = hover.is_some_and(|p| handle.contains(p));
    let on_bar = shown_before && hover.is_some_and(|p| bar.is_some_and(|r| r.expand(10.0).contains(p)));
    let closed = matches!(tab.state, TabState::Closed(_));
    if on_handle || on_bar {
        tab.toolbar_until = tab.toolbar_until.max(now + 0.5);
    }
    let visible = on_handle || on_bar || closed || now < tab.toolbar_until;
    ui.ctx().data_mut(|d| d.insert_temp(anim_id.with("on"), visible));
    let t = ui.ctx().animate_bool_with_time(anim_id, visible, 0.15);
    if now < tab.toolbar_until {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
    }
    // languette discrète, seule zone qui fait apparaître la barre
    if t < 1.0 {
        let pill = Rect::from_center_size(pos2(area.center().x, area.top() + 3.0), vec2(if on_handle { 72.0 } else { 48.0 }, 4.0));
        let alpha = if on_handle { 0.85 } else { 0.35 } * (1.0 - t);
        ui.ctx()
            .layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new(("session-toolbar-handle", tab.uid))))
            .rect_filled(pill, 2.0, Color32::WHITE.gamma_multiply(alpha));
    }
    if t <= 0.0 {
        return;
    }
    let shown = egui::Area::new(egui::Id::new(("session-toolbar-area", tab.uid)))
        .fixed_pos(pos2(area.center().x, area.top() + 10.0 - 50.0 * (1.0 - t)))
        .pivot(Align2::CENTER_TOP)
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            ui.set_opacity(t);
            w::modal_frame().inner_margin(Margin::symmetric(10, 6)).corner_radius(12).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let dot = match tab.state {
                        TabState::Connecting => WARN,
                        TabState::Connected => ACCENT,
                        TabState::Closed(Some(_)) => DANGER,
                        TabState::Closed(None) => MUTED,
                    };
                    let (r, _) = ui.allocate_exact_size(vec2(14.0, 28.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.0, dot);
                    ui.label(RichText::new(tab.title()).font(bold(13.0)));
                    // plein écran, fenêtre séparée : pas de bandeau d'erreur, la cause s'affiche ici
                    if let TabState::Closed(Some(e)) = &tab.state {
                        ui.add_space(4.0);
                        ui.allocate_ui(vec2(420.0, 28.0), |ui| {
                            ui.add(egui::Label::new(RichText::new(e).size(12.5).color(DANGER)).truncate()).on_hover_text(e);
                        });
                    }
                    ui.add_space(8.0);
                    if closed {
                        if w::button_h(ui, Kind::Primary, Some(Icon::Refresh), "Reconnecter", 0.0, 28.0).clicked() {
                            actions.push(Action::Reconnect(i));
                        }
                    } else if tab.protocol.is_graphical()
                        && matches!(tab.state, TabState::Connected)
                        && w::button_h(ui, Kind::Ghost, Some(Icon::Keyboard), "Ctrl+Alt+Suppr", 0.0, 28.0).clicked()
                    {
                        actions.push(Action::CtrlAltDel(i));
                    }
                    if !closed
                        && tab.protocol.is_graphical()
                        && matches!(tab.state, TabState::Connected)
                        && w::button_h(ui, Kind::Ghost, Some(Icon::Monitor), "Ctrl+Maj+Échap", 0.0, 28.0)
                            .on_hover_text("Gestionnaire des tâches du bureau distant")
                            .clicked()
                    {
                        actions.push(Action::TaskManager(i));
                    }
                    match mode {
                        ToolbarMode::Immersive => {
                            if w::icon_button_sized(ui, Icon::External, 28.0, "Ouvrir dans une fenêtre séparée").clicked() {
                                actions.push(Action::Immersive(false));
                                actions.push(Action::PopOut(i));
                            }
                            if w::button_h(ui, Kind::Secondary, Some(Icon::Shrink), "Quitter le plein écran", 0.0, 28.0)
                                .on_hover_text("Ctrl+Maj+Entrée")
                                .clicked()
                            {
                                actions.push(Action::Immersive(false));
                            }
                        }
                        ToolbarMode::Span => {
                            if w::button_h(ui, Kind::Ghost, None, "Réduire", 0.0, 28.0).on_hover_text("Réduit la fenêtre dans la barre des tâches").clicked() {
                                actions.push(Action::Minimize(i));
                            }
                            if w::button_h(ui, Kind::Secondary, Some(Icon::Back), "Ramener dans Escale", 0.0, 28.0)
                                .on_hover_text("Affiche le bureau, réduit, dans la fenêtre Escale")
                                .clicked()
                            {
                                actions.push(Action::PopIn(i));
                            }
                            if w::button_h(ui, Kind::Danger, Some(Icon::Close), "Fermer la session", 0.0, 28.0)
                                .on_hover_text("Déconnecte le bureau distant et ferme l'onglet")
                                .clicked()
                            {
                                actions.push(Action::CloseTab(i));
                            }
                        }
                        ToolbarMode::Popup { fullscreen } => {
                            let (icon, label) = if fullscreen { (Icon::Shrink, "Quitter le plein écran") } else { (Icon::Expand, "Plein écran") };
                            if w::button_h(ui, Kind::Secondary, Some(icon), label, 0.0, 28.0).clicked() {
                                actions.push(Action::PopupFullscreen(i, !fullscreen));
                            }
                            if w::icon_button_sized(ui, Icon::Back, 28.0, "Ramener dans la fenêtre Escale").clicked() {
                                actions.push(Action::PopIn(i));
                            }
                        }
                    }
                });
            });
        });
    ui.ctx().data_mut(|d| d.insert_temp(bar_id, shown.response.rect));
}

/// À la place d'une session ouverte dans sa propre fenêtre.
fn popped_placeholder(ui: &mut egui::Ui, tab: &Tab, i: usize, actions: &mut Vec<Action>) {
    ui.add_space((ui.available_height() / 2.0 - 90.0).max(20.0));
    ui.vertical_centered(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::splat(64.0), Sense::hover());
        ui.painter().rect(r, 16.0, SURFACE, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
        w::paint_icon(ui.painter(), r.shrink(18.0), Icon::External, ACCENT);
        ui.add_space(12.0);
        ui.label(RichText::new(format!("« {} » est ouvert dans une fenêtre séparée", tab.title())).font(bold(16.0)));
        ui.label(RichText::new("La session continue dans cette fenêtre ; fermez-la pour la ramener ici.").color(MUTED));
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.add_space((ui.available_width() - 330.0) / 2.0);
            if w::button(ui, Kind::Primary, Some(Icon::External), "Afficher la fenêtre", 0.0).clicked() {
                actions.push(Action::FocusPopup(i));
            }
            if w::button(ui, Kind::Secondary, Some(Icon::Back), "Ramener ici", 0.0).clicked() {
                actions.push(Action::PopIn(i));
            }
        });
    });
}

/// Combinaison de touches pour un bureau distant : (code physique RDP, keysym VNC) enfoncées dans
/// l'ordre puis relâchées dans l'ordre inverse.
fn key_chord(rdp: bool, keys: &[(u16, u32)]) -> Vec<desktop::Input> {
    let key = |&(code, sym): &(u16, u32), down: bool| if rdp { desktop::Input::Scancode { code, down } } else { desktop::Input::Keysym { sym, down } };
    keys.iter().map(|k| key(k, true)).chain(keys.iter().rev().map(|k| key(k, false))).collect()
}

/// Ctrl+Maj+Échap : gestionnaire des tâches du bureau distant (Windows le garde sinon pour cet ordinateur).
fn task_manager_chord(rdp: bool) -> Vec<desktop::Input> {
    key_chord(rdp, &[(0x1D, 0xFFE3), (0x2A, 0xFFE1), (0x01, 0xFF1B)])
}

/// Nom d'un coffre ouvert : son propriétaire, sinon son dossier (« Coffre1 »).
fn vault_title(owner: &str, vault_path: &Path) -> String {
    if !owner.trim().is_empty() {
        return owner.trim().to_string();
    }
    vault_path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Hôte RDP ouvert sur tous les écrans (option de l'hôte, écrans détectés).
fn uses_all_screens(h: &Host) -> bool {
    h.protocol == Protocol::Rdp && h.rdp.multimon && crate::monitors::layout(&h.rdp.screens).is_some()
}

fn popup_viewport_id(tab: &Tab) -> egui::ViewportId {
    egui::ViewportId::from_hash_of(("escale-session", tab.uid))
}

// ---------------------------------------------------------------- boucle principale

impl eframe::App for EscaleApp {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        #[cfg(windows)]
        crate::winput::fix_events(&mut raw_input.events, terminal::FOCUSED.load(std::sync::atomic::Ordering::Relaxed));
        #[cfg(not(windows))]
        let _ = raw_input;
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        // codes physiques des touches : conservés seulement si un bureau distant avait le focus ;
        // le bureau qui a le focus se signale de nouveau pendant l'image (écran verrouillé : aucun)
        #[cfg(windows)]
        if !crate::winput::begin_frame() {
            let _ = crate::winput::take_scancodes();
        }
        // une erreur interne de l'interface ne ferme pas Escale (détails dans crash.log)
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.frame_ui(ui, frame))).is_err() {
            if let Some(st) = &mut self.state {
                st.error = Some("Une erreur interne est survenue ; Escale a pu continuer. Les détails sont dans crash.log, dans le dossier d'Escale (%APPDATA%).".into());
            }
            ui.ctx().request_repaint();
        }
        // raccourcis Windows retenus par le crochet clavier seulement d'après une image complète
        #[cfg(windows)]
        crate::winput::end_frame();
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        #[cfg(windows)]
        crate::winput::uninstall_keyboard_hook();
    }
}

impl EscaleApp {
    fn frame_ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // état de l'image précédente ; le terminal le repositionne s'il garde le focus
        let term_focus = terminal::FOCUSED.swap(false, std::sync::atomic::Ordering::Relaxed);
        let f11_to_server = term_focus && self.state.as_ref().is_some_and(|s| s.data.settings.keys_to_server);
        if !f11_to_server && take(&ctx, false, false, false, egui::Key::F11) {
            self.fullscreen = !self.fullscreen;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.fullscreen));
        }
        // « Escale - <coffre> » : deux Escale ouverts se distinguent dans la barre des tâches
        let vault_name = match &self.state {
            Some(st) => Some(vault_title(&st.data.owner, st.vault.path())),
            None => self.lock.vault_name(),
        };
        let title = match vault_name.as_deref().map(str::trim) {
            Some(n) if !n.is_empty() => format!("Escale - {n}"),
            _ => "Escale".to_string(),
        };
        if title != self.window_title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
            self.window_title = title;
        }
        let Some(st) = &mut self.state else {
            if let Some((vault, data)) = self.lock.show(ui, &self.logo) {
                self.state = Some(Unlocked::new(vault, data));
                self.lock = LockScreen::new();
            }
            w::window_frame(&ctx);
            return;
        };
        st.pump_events(&ctx);
        st.send_passwords();
        // remis par la vue du bureau distant tant que la souris le survole
        #[cfg(windows)]
        crate::winput::CURSOR_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
        let mut actions = Vec::new();
        st.shortcuts(&ctx, term_focus, &mut actions);

        // fichiers déposés sur la fenêtre : envoyés vers l'hôte de l'onglet actif
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect());
        if !dropped.is_empty()
            && let Some(i) = st.active
        {
            actions.push(Action::Upload(i, dropped));
        }
        let hovering_files = ctx.input(|i| !i.raw.hovered_files.is_empty());

        let modal_open = st.modal_open();
        let settings = st.data.settings.clone();
        let ppp = ctx.pixels_per_point();
        // plein écran : seulement pour une session affichée dans cette fenêtre
        let immersive_tab = st.active.filter(|&i| st.immersive && i < st.tabs.len() && !st.tabs[i].popped);
        if st.immersive && immersive_tab.is_none() {
            actions.push(Action::Immersive(false));
        }

        if let Some(i) = immersive_tab {
            // --- session seule, sans barres ; barre flottante en haut
            st.tabs[i].activity = false;
            st.tabs[i].show_files = false;
            egui::CentralPanel::default().frame(egui::Frame::new().fill(terminal::BG)).show(ui, |ui| {
                let area = ui.max_rect();
                render_session(ui, &mut st.tabs[i], i, &settings, !modal_open && !hovering_files, &mut st.primary, &mut st.paste_confirm);
                session_toolbar(ui, area, &mut st.tabs[i], i, ToolbarMode::Immersive, &mut actions);
                st.view_px = area.size() * ppp;
            });
        } else {
            if st.data.settings.sidebar_collapsed {
                egui::Panel::left("sidebar-rail")
                    .resizable(false)
                    .exact_size(64.0)
                    .show_separator_line(false)
                    .frame(egui::Frame::new().fill(PANEL).inner_margin(Margin::symmetric(8, 0)))
                    .show(ui, |ui| st.sidebar_rail(ui, &self.logo, &mut actions));
            } else {
                egui::Panel::left("sidebar")
                    .resizable(true)
                    .default_size(280.0)
                    .size_range(230.0..=420.0)
                    .show_separator_line(false)
                    .frame(egui::Frame::new().fill(PANEL).inner_margin(Margin::symmetric(14, 0)))
                    .show(ui, |ui| st.sidebar(ui, &self.logo, &mut actions));
            }

            egui::Panel::top("tabs")
                .exact_size(52.0)
                .show_separator_line(false)
                .frame(egui::Frame::new().fill(PANEL).inner_margin(Margin { left: 6, right: 6, top: 0, bottom: 0 }))
                .show(ui, |ui| st.tab_bar(ui, &mut actions));

            // transferts des vues Fichiers cachées (console affichée, autre onglet) : ils se terminent
            // et l'indicateur du bouton « Fichiers » suit
            let now = ctx.input(|i| i.time);
            for t in &mut st.tabs {
                if let Some(f) = &mut t.files {
                    f.tick(now);
                }
            }

            match st.active {
                Some(i) if i < st.tabs.len() => {
                    st.tabs[i].activity = false;

                    // barre latérale droite : console / fichiers / clé / affichage
                    let has_key = st.data.host(st.tabs[i].host_id).is_some_and(|h| h.auth == Auth::Key && !h.private_key.is_empty());
                    egui::Panel::right("session-rail")
                        .resizable(false)
                        .exact_size(58.0)
                        .show_separator_line(false)
                        .frame(egui::Frame::new().fill(PANEL).inner_margin(Margin { left: 6, right: 8, top: 0, bottom: 10 }))
                        .show(ui, |ui| session_rail(ui, &st.tabs[i], i, has_key, &mut actions));

                    let mut panel_rect = Rect::NOTHING;
                    let popped = st.tabs[i].popped;
                    egui::CentralPanel::default()
                        .frame(egui::Frame::new().fill(PANEL).inner_margin(Margin { left: 0, right: 4, top: 0, bottom: 10 }))
                        .show(ui, |ui| {
                            // vue Fichiers : remplace la console (la session continue en arrière-plan)
                            if st.tabs[i].show_files {
                                panel_rect = ui.max_rect();
                                if let Some(f) = &mut st.tabs[i].files {
                                    f.show(ui);
                                }
                                return;
                            }
                            egui::Frame::new().fill(terminal::BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(12).show(ui, |ui| {
                                ui.set_min_size(ui.available_size());
                                panel_rect = ui.max_rect();
                                if popped {
                                    popped_placeholder(ui, &st.tabs[i], i, &mut actions);
                                } else {
                                    render_session(ui, &mut st.tabs[i], i, &settings, !modal_open && !hovering_files, &mut st.primary, &mut st.paste_confirm);
                                }
                            });
                        });
                    if !st.tabs[i].show_files && !popped {
                        st.view_px = panel_rect.size() * ppp;
                    }
                    if hovering_files {
                        drop_overlay(&ctx, panel_rect, &st.tabs[i]);
                    }
                    if let (TabState::Closed(err), false, false) = (&st.tabs[i].state, st.tabs[i].show_files, popped) {
                        let err = err.clone();
                        let idle_icon = protocol_icon(st.tabs[i].protocol);
                        egui::Area::new(egui::Id::new(("closed-banner", i)))
                            .fixed_pos(pos2(panel_rect.center().x, panel_rect.bottom() - 22.0))
                            .pivot(Align2::CENTER_BOTTOM)
                            .order(egui::Order::Foreground)
                            .show(&ctx, |ui| {
                                w::modal_frame().inner_margin(Margin::symmetric(16, 12)).corner_radius(14).show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        match &err {
                                            Some(e) => {
                                                w::icon_size(ui, Icon::Warning, 16.0, DANGER);
                                                ui.label(RichText::new(e).color(TEXT));
                                            }
                                            None => {
                                                w::icon_size(ui, idle_icon, 16.0, MUTED);
                                                ui.label(RichText::new("Session terminée").color(TEXT));
                                            }
                                        }
                                        ui.add_space(10.0);
                                        if w::button_h(ui, Kind::Primary, Some(Icon::Refresh), "Reconnecter", 0.0, 32.0)
                                            .on_hover_text("Ctrl+Maj+R")
                                            .clicked()
                                        {
                                            actions.push(Action::Reconnect(i));
                                        }
                                        if w::button_h(ui, Kind::Ghost, None, "Fermer", 0.0, 32.0).on_hover_text("Ctrl+Maj+W").clicked() {
                                            actions.push(Action::CloseTab(i));
                                        }
                                    });
                                });
                            });
                    }
                }
                _ => {
                    st.active = None;
                    let r = egui::CentralPanel::default()
                        .frame(egui::Frame::new().fill(BG).inner_margin(Margin { left: 32, right: 32, top: 26, bottom: 10 }))
                        .show(ui, |ui| st.home(ui, &mut actions))
                        .response
                        .rect;
                    // zone de session estimée (sans la barre de droite) pour la résolution RDP initiale
                    st.view_px = (r.size() - vec2(70.0, 12.0)).max(vec2(320.0, 240.0)) * ppp;
                }
            }
        }

        // --- sessions ouvertes dans leur propre fenêtre
        for i in 0..st.tabs.len() {
            if !st.tabs[i].popped {
                continue;
            }
            let vid = popup_viewport_id(&st.tabs[i]);
            // tous les écrans : fenêtre sans bordure sur leur rectangle englobant (pixels physiques)
            let span = if st.tabs[i].multimon { crate::monitors::layout(&st.tabs[i].screens) } else { None };
            let title = match span {
                Some(_) => format!("{} — Escale (plusieurs écrans)", st.tabs[i].title),
                None => format!("{} — Escale", st.tabs[i].title),
            };
            let mut builder = egui::ViewportBuilder::default().with_title(title.clone()).with_icon(self.icon.clone());
            builder = match &span {
                Some(l) => {
                    let (left, top, right, bottom) = l.bounds();
                    // position et taille approchées à la création, recalées en pixels juste après
                    builder
                        .with_decorations(false)
                        .with_position(pos2(left as f32, top as f32) / ppp)
                        .with_inner_size(vec2((right - left) as f32, (bottom - top) as f32) / ppp)
                }
                None => builder.with_inner_size([1280.0, 800.0]).with_min_inner_size([480.0, 320.0]),
            };
            let fullscreen = st.tabs[i].popup_fullscreen;
            let (tabs, primary, paste) = (&mut st.tabs, &mut st.primary, &mut st.paste_confirm);
            ctx.show_viewport_immediate(vid, builder, |ui, _class| {
                egui::CentralPanel::default().frame(egui::Frame::new().fill(terminal::BG)).show(ui, |ui| {
                    let area = ui.max_rect();
                    render_session(ui, &mut tabs[i], i, &settings, !modal_open, primary, paste);
                    match &span {
                        // barre flottante en haut de l'écran principal
                        Some(l) => {
                            let (left, top, ..) = l.bounds();
                            let p = l.primary();
                            let px = ui.ctx().pixels_per_point();
                            let screen = Rect::from_min_size(
                                area.min + vec2((p.left - left) as f32, (p.top - top) as f32) / px,
                                vec2((p.right - p.left) as f32, (p.bottom - p.top) as f32) / px,
                            );
                            session_toolbar(ui, screen, &mut tabs[i], i, ToolbarMode::Span, &mut actions);
                        }
                        None => session_toolbar(ui, area, &mut tabs[i], i, ToolbarMode::Popup { fullscreen }, &mut actions),
                    }
                });
                // fermer la fenêtre la ramène dans Escale (la session continue)
                if ui.input(|inp| inp.viewport().close_requested()) {
                    actions.push(Action::PopIn(i));
                }
                if span.is_none() && ui.input(|inp| inp.key_pressed(egui::Key::F11)) {
                    actions.push(Action::PopupFullscreen(i, !fullscreen));
                }
            });
            #[cfg(windows)]
            if let Some(l) = &span {
                let screens: Vec<[i32; 4]> = l.screens.iter().map(|s| s.rect()).collect();
                if !crate::winput::span_window(&title, &screens) {
                    // fenêtre pas encore créée par winit : nouvel essai à l'image suivante
                    ctx.request_repaint_after(std::time::Duration::from_millis(30));
                }
            }
        }

        st.palette_modal(&ctx, &mut actions);
        st.editor_modal(&ctx);
        st.host_key_modal(&ctx);
        st.delete_modal(&ctx);
        st.settings_modal(&ctx);
        st.vpn_modal(&ctx);
        st.shortcuts_modal(&ctx);
        st.paste_modal(&ctx);
        st.key_setup_modal(&ctx);
        st.error_modal(&ctx);
        w::window_frame(&ctx);

        let mut lock = false;
        if !actions.is_empty() {
            ctx.request_repaint();
        }
        for a in actions {
            match a {
                Action::Connect(id) => st.connect(&self.rt, &ctx, id),
                Action::Edit(id) => {
                    if let Some(h) = st.data.host(id) {
                        st.editor = Some(Editor {
                            host: h.clone(),
                            is_new: false,
                            show_password: false,
                            show_passphrase: false,
                            show_key: false,
                            rdp_tab: RdpTab::default(),
                            error: None,
                        });
                    }
                }
                Action::New => {
                    st.editor = Some(Editor {
                        host: Host::default(),
                        is_new: true,
                        show_password: false,
                        show_passphrase: false,
                        show_key: false,
                        rdp_tab: RdpTab::default(),
                        error: None,
                    });
                }
                Action::Delete(id) => st.confirm_delete = Some(id),
                Action::Lock => lock = true,
                Action::Settings => st.settings = SettingsDialog { open: true, ..Default::default() },
                Action::Shortcuts => st.show_shortcuts = true,
                Action::Palette => st.palette = Some(Palette::default()),
                Action::Home => st.active = None,
                Action::Select(i) => st.active = Some(i),
                Action::CloseTab(i) => st.close_tab(i),
                Action::Reconnect(i) => st.reconnect(&self.rt, &ctx, i),
                Action::Zoom(d) => {
                    let s = &mut st.data.settings.font_size;
                    *s = match d {
                        0 => 14.0,
                        d => (*s + d as f32).clamp(10.0, 24.0),
                    };
                    st.save();
                }
                Action::Console(i) => {
                    if let Some(t) = st.tabs.get_mut(i) {
                        t.show_files = false;
                    }
                }
                Action::Files(i) => {
                    if st.tabs.get(i).is_some_and(|t| t.show_files) {
                        st.tabs[i].show_files = false;
                    } else {
                        st.open_files(&self.rt, &ctx, i);
                    }
                }
                Action::Upload(i, files) => {
                    // fichiers déposés sur la console : envoi en arrière-plan, on reste sur la session
                    // (progression autour du bouton « Fichiers »)
                    let shown = st.tabs.get(i).is_some_and(|t| t.show_files);
                    st.open_files(&self.rt, &ctx, i);
                    if let Some(t) = st.tabs.get_mut(i) {
                        t.show_files = shown;
                        if let Some(f) = t.files.as_mut() {
                            f.upload(files);
                        }
                    }
                }
                Action::Minimize(i) => {
                    if let Some(t) = st.tabs.get(i) {
                        ctx.send_viewport_cmd_to(popup_viewport_id(t), egui::ViewportCommand::Minimized(true));
                    }
                }
                Action::PopOut(i) => {
                    if let Some(t) = st.tabs.get_mut(i) {
                        t.popped = true;
                        t.show_files = false;
                        t.toolbar_until = 0.0;
                        st.immersive = false;
                    }
                }
                Action::PopIn(i) => {
                    if let Some(t) = st.tabs.get_mut(i) {
                        t.popped = false;
                        t.popup_fullscreen = false;
                        st.active = Some(i);
                    }
                }
                // tous les écrans : la fenêtre les couvre déjà, elle est seulement ramenée devant
                Action::PopupFullscreen(i, _) if st.tabs.get(i).is_some_and(|t| t.multimon) => {
                    ctx.send_viewport_cmd_to(popup_viewport_id(&st.tabs[i]), egui::ViewportCommand::Focus);
                }
                Action::PopupFullscreen(i, on) => {
                    if let Some(t) = st.tabs.get_mut(i) {
                        t.popup_fullscreen = on;
                        t.toolbar_until = 0.0;
                        ctx.send_viewport_cmd_to(popup_viewport_id(t), egui::ViewportCommand::Fullscreen(on));
                    }
                }
                Action::FocusPopup(i) => {
                    if let Some(t) = st.tabs.get(i) {
                        ctx.send_viewport_cmd_to(popup_viewport_id(t), egui::ViewportCommand::Focus);
                    }
                }
                // plein écran d'une session sur tous les écrans : sa fenêtre qui les couvre
                Action::Immersive(true) if st.active.and_then(|i| st.tabs.get(i)).is_some_and(|t| t.multimon) => {
                    if let Some(t) = st.active.and_then(|i| st.tabs.get_mut(i)) {
                        t.popped = true;
                        t.show_files = false;
                        t.toolbar_until = 0.0;
                    }
                }
                Action::Immersive(on) => {
                    let on = on && st.active.is_some_and(|i| i < st.tabs.len());
                    if on != st.immersive {
                        st.immersive = on;
                        if let Some(t) = st.active.and_then(|i| st.tabs.get_mut(i)) {
                            t.toolbar_until = 0.0;
                        }
                        self.fullscreen = on;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(on));
                    }
                }
                Action::CtrlAltDel(i) => {
                    if let Some(Session::Desktop { handle, .. }) = st.tabs.get(i).map(|t| &t.session) {
                        let rdp = st.tabs[i].protocol == Protocol::Rdp;
                        // Ctrl, Alt, Suppr
                        let _ = handle.tx.send(DesktopCmd::Input(key_chord(rdp, &[(0x1D, 0xFFE3), (0x38, 0xFFE9), (0xE053, 0xFFFF)])));
                    }
                }
                Action::TaskManager(i) => {
                    if let Some(Session::Desktop { handle, .. }) = st.tabs.get(i).map(|t| &t.session) {
                        let rdp = st.tabs[i].protocol == Protocol::Rdp;
                        let _ = handle.tx.send(DesktopCmd::Input(task_manager_chord(rdp)));
                    }
                }
                Action::SetupKey(i) => st.setup_key(i),
                Action::ToggleSidebar => {
                    st.data.settings.sidebar_collapsed = !st.data.settings.sidebar_collapsed;
                    st.save();
                }
            }
        }
        if lock {
            for t in &st.tabs {
                t.session.close();
            }
            self.state = None;
            self.lock = LockScreen::new();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn task_manager_chord_for_rdp_and_vnc() {
        use super::desktop::Input;
        let rdp = super::task_manager_chord(true);
        let codes: Vec<(u16, bool)> = rdp.iter().map(|i| match i {
            Input::Scancode { code, down } => (*code, *down),
            _ => panic!("RDP : codes physiques"),
        }).collect();
        assert_eq!(codes, [(0x1D, true), (0x2A, true), (0x01, true), (0x01, false), (0x2A, false), (0x1D, false)]);
        let vnc = super::task_manager_chord(false);
        assert_eq!(vnc[2], Input::Keysym { sym: 0xFF1B, down: true });
        assert_eq!(vnc[5], Input::Keysym { sym: 0xFFE3, down: false });
    }

    use super::*;

    #[test]
    fn import_adds_only_new_hosts_and_keeps_jumps_valid() {
        let mut a = Host::default();
        a.label = "a".into();
        let mut mine = VaultData { hosts: vec![a.clone()], ..Default::default() };

        let mut b = Host::default();
        b.label = "b".into();
        b.jump = Some(a.id); // rebond vers un hôte déjà présent : conservé
        let mut c = Host::default();
        c.jump = Some(Uuid::new_v4()); // rebond inconnu : retiré
        let mut a_changed = a.clone();
        a_changed.label = "a modifié".into();
        let theirs = VaultData { hosts: vec![a_changed, b.clone(), c.clone()], ..Default::default() };

        assert_eq!(merge_hosts(&mut mine, theirs), (2, 1));
        assert_eq!(mine.hosts.len(), 3);
        assert_eq!(mine.host(a.id).unwrap().label, "a", "l'hôte existant n'est pas écrasé");
        assert_eq!(mine.host(b.id).unwrap().jump, Some(a.id));
        assert_eq!(mine.host(c.id).unwrap().jump, None);
    }

    #[test]
    fn import_brings_vpn_profiles_without_overwriting() {
        let mut mine_vpn = VpnProfile::default();
        mine_vpn.name = "le mien".into();
        let mut mine = VaultData { vpns: vec![mine_vpn.clone()], ..Default::default() };
        let mut changed = mine_vpn.clone();
        changed.name = "modifié".into();
        let new_vpn = VpnProfile::default();
        let mut h = Host::default();
        h.vpn = Some(new_vpn.id);
        let mut orphan = Host::default();
        orphan.vpn = Some(Uuid::new_v4());
        let theirs = VaultData { hosts: vec![h.clone(), orphan.clone()], vpns: vec![changed, new_vpn.clone()], ..Default::default() };
        assert_eq!(merge_hosts(&mut mine, theirs), (2, 0));
        assert_eq!(mine.vpns.len(), 2);
        assert_eq!(mine.vpn(mine_vpn.id).unwrap().name, "le mien");
        assert_eq!(mine.host(h.id).unwrap().vpn, Some(new_vpn.id));
        assert_eq!(mine.host(orphan.id).unwrap().vpn, None);
    }

    #[test]
    fn old_vault_without_rdp_options_loads_with_defaults() {
        // coffre enregistré avant les options RDP par hôte
        let json = r#"{"hosts":[{"id":"67e55044-10b1-426f-9247-bb680e5fe0c8","label":"srv","protocol":"Rdp","hostname":"h","port":3389,"username":"u"}]}"#;
        let data: VaultData = serde_json::from_str(json).unwrap();
        assert_eq!(data.hosts[0].rdp, RdpOptions::default());
        // options partielles : les champs absents prennent leur valeur par défaut
        let json = r#"{"id":"67e55044-10b1-426f-9247-bb680e5fe0c8","label":"x","hostname":"h","port":3389,"username":"u","rdp":{"display":"FixedNative","width":1600}}"#;
        let h: Host = serde_json::from_str(json).unwrap();
        assert_eq!(h.rdp.display, RdpDisplay::FixedNative);
        assert_eq!((h.rdp.width, h.rdp.height), (1600, 1080));
        assert!(h.rdp.clipboard && h.rdp.auto_reconnect);
    }

    #[test]
    fn rdp_options_serde_roundtrip() {
        let o = RdpOptions {
            graphics: RdpGraphics::Legacy,
            display: RdpDisplay::FixedFit,
            multimon: true,
            screens: vec!["\\\\.\\DISPLAY2".into()],
            width: 2560,
            height: 1440,
            scale: 150,
            color_depth: 16,
            server_pointer: false,
            security: RdpSecurity::Tls,
            kdc: "tcp://dc01:88".into(),
            audio: RdpAudio::Off,
            microphone: true,
            clipboard: false,
            drive: false,
            drive_path: "D:\\Partage".into(),
            keyboard_layout: 0x080C,
            windows_keys: false,
            compression: RdpCompression::Rdp61,
            wallpaper: false,
            full_window_drag: false,
            menu_animations: true,
            themes: false,
            font_smoothing: false,
            desktop_composition: false,
            alternate_shell: "notepad.exe".into(),
            work_dir: "C:\\Temp".into(),
            admin: true,
            auto_reconnect: false,
        };
        let back: RdpOptions = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(back, o);
        let mut h = Host::default();
        h.rdp = o.clone();
        let back: Host = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(back.rdp, o);
    }

    #[test]
    fn experience_presets_and_validation() {
        let mut o = RdpOptions::default();
        assert_eq!(Experience::of(&o), Experience::Broadband, "valeurs par défaut = haut débit");
        for e in [Experience::Lan, Experience::Low, Experience::Broadband] {
            e.apply(&mut o);
            assert_eq!(Experience::of(&o), e);
        }
        o.wallpaper = !o.wallpaper;
        assert_eq!(Experience::of(&o), Experience::Custom);

        let mut o = RdpOptions { display: RdpDisplay::FixedFit, width: 100, ..Default::default() };
        assert!(validate_rdp(&o).is_err());
        o.width = 8192;
        assert!(validate_rdp(&o).is_ok());
        o.display = RdpDisplay::Dynamic;
        o.width = 0;
        assert!(validate_rdp(&o).is_ok(), "taille ignorée en mode dynamique");
        // dossier partagé : relatif refusé, absent créé, fichier refusé
        o.drive_path = "relatif".into();
        assert!(validate_rdp(&o).is_err());
        let dir = std::env::temp_dir().join(format!("escale-share-{}", Uuid::new_v4())).join("sous");
        o.drive_path = dir.display().to_string();
        assert!(validate_rdp(&o).is_ok());
        assert!(dir.is_dir());
        let file = dir.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        o.drive_path = file.display().to_string();
        assert!(validate_rdp(&o).is_err());
        o.drive = false;
        assert!(validate_rdp(&o).is_ok(), "chemin ignoré quand le partage est désactivé");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }
}

#[cfg(test)]
mod resize_tests {
    use super::*;
    use crate::desktop::{Frame, SharedFrame};
    use std::sync::{Arc, Mutex};

    const SIZES: [(f32, f32); 12] = [
        (1400.0, 860.0),
        (60.0, 40.0),
        (720.0, 420.0),
        (2560.0, 1440.0),
        (200.0, 900.0),
        (1900.0, 120.0),
        (0.0, 0.0),
        (333.3, 222.7),
        (1280.0, 800.0),
        (1.0, 1.0),
        (900.0, 600.0),
        (1600.0, 1000.0),
    ];

    fn frames(ctx: &egui::Context, mut draw: impl FnMut(&mut egui::Ui)) {
        for (w, h) in SIZES.iter().chain(SIZES.iter().rev()) {
            let input = egui::RawInput { screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(*w, *h))), ..Default::default() };
            let mut out = ctx.run_ui(input, |ui_root| {
                egui::CentralPanel::default().show(ui_root, |ui| draw(ui));
            });
            out.textures_delta.clear();
        }
    }

    #[test]
    fn terminal_survives_resizing_with_content() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let mut term = Terminal::new(2000);
        for i in 0..400 {
            let _ = term.feed(format!("ligne {i} \x1b[31mrouge\x1b[0m {}\r\n", "x".repeat(i % 180)).as_bytes());
        }
        // écran alternatif + curseur loin dans l'écran
        let _ = term.feed(b"\x1b[?1049h\x1b[200;300Htexte\x1b[999;999H");
        let settings = crate::model::Settings::default();
        let mut primary = String::new();
        frames(&ctx, |ui| {
            let _ = term.show(ui, &settings, true, &mut primary);
            let _ = term.feed(b"suite\r\n");
        });
    }

    #[test]
    fn desktop_view_survives_resizing() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let modes = [
            (Protocol::Rdp, RdpDisplay::Dynamic),
            (Protocol::Rdp, RdpDisplay::FixedFit),
            (Protocol::Rdp, RdpDisplay::FixedNative),
            (Protocol::Vnc, RdpDisplay::Dynamic),
        ];
        for (proto, display) in modes {
            let opts = desktop::ViewOptions { display, server_pointer: false, windows_keys: false };
            let mut view = DesktopView::new(proto).with_options(opts);
            let mut n = 0usize;
            frames(&ctx, |ui| {
                // le serveur change aussi de résolution pendant ce temps
                n += 1;
                let (w, h) = [(1280, 720), (8, 4), (1920, 1080), (640, 480)][n % 4];
                if let Ok(mut f) = frame.lock() {
                    f.resize(w, h);
                    f.mark(0, 0, w + 10, h + 10);
                }
                let _ = view.show(ui, &frame, true);
            });
        }
    }

    #[test]
    fn rdp_options_form_renders_every_tab() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let mut o = RdpOptions { display: RdpDisplay::FixedFit, drive_path: "C:\\Partage".into(), ..Default::default() };
        for tab in [RdpTab::Display, RdpTab::Resources, RdpTab::Experience, RdpTab::Security, RdpTab::Advanced] {
            let mut t = tab;
            frames(&ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| rdp_options_ui(ui, &mut o, &mut t, 560.0));
            });
            assert!(t == tab, "aucun clic : l'onglet ne change pas");
        }
        assert_eq!(o.display, RdpDisplay::FixedFit, "aucun clic : rien ne change");
    }

    #[test]
    fn vpn_editor_renders_both_kinds() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let users = vec!["srv-1".to_string(), "srv-2".to_string()];
        let mut wg = VpnProfile::default();
        wg.wireguard.private_key = crate::vpn::generate_private_key();
        let mut ve = VpnEditor::new(wg, true, false);
        frames(&ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| vpn_form(ui, &mut ve, &users, 560.0));
        });
        assert_eq!(ve.profile.kind, VpnKind::WireGuard, "aucun clic : le type ne change pas");

        // OpenVPN : identifiant demandé, fichiers valides, illisibles ou absents, chacun ouvert en édition
        let ck = rcgen::generate_simple_self_signed(vec!["vpn.exemple.fr".into()]).unwrap();
        let mut p = VpnProfile::default();
        p.kind = VpnKind::OpenVpn;
        p.openvpn.auth_user_pass = true;
        p.openvpn.ca = ck.cert.pem();
        p.openvpn.key = ck.signing_key.serialize_pem();
        p.openvpn.cert = "pas un certificat".into();
        p.openvpn.tls_auth = "-----BEGIN OpenVPN Static key V1-----\nzz\n".into();
        let mut ve = VpnEditor::new(p, false, true);
        for part in [None, Some(OvpnPart::Ca), Some(OvpnPart::Cert), Some(OvpnPart::Key), Some(OvpnPart::TlsAuth), Some(OvpnPart::TlsCrypt)] {
            ve.open_part = part;
            frames(&ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| vpn_form(ui, &mut ve, &users, 560.0));
            });
            assert_eq!(ve.open_part, part);
        }
        assert_eq!(ve.profile.kind, VpnKind::OpenVpn);
        assert!(ve.profile.openvpn.ca.contains("BEGIN CERTIFICATE"), "aucun clic : rien n'est retiré");
    }

    #[test]
    fn openvpn_files_are_summarised() {
        let ck = rcgen::generate_simple_self_signed(vec!["vpn.exemple.fr".into()]).unwrap();
        let pem = ck.cert.pem();
        assert_eq!(cert_summary(&pem).unwrap(), "rcgen self signed cert");
        assert!(cert_summary(&format!("{pem}{pem}")).unwrap().ends_with("2 certificats"));
        assert!(cert_summary("rien").is_err());
        assert!(cert_summary("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n").is_err());
        // DER tronqué ou mal formé : jamais de panique
        let der = ck.cert.der().to_vec();
        for n in 0..der.len() {
            let _ = cert_subject_name(&der[..n]);
        }
        assert_eq!(cert_subject_name(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), None);

        assert_eq!(key_summary(&ck.signing_key.serialize_pem()).unwrap(), "Clé PKCS#8");
        assert!(key_summary("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----").unwrap_err().contains("mot de passe"));

        let hex: String = (0..256).map(|i| format!("{:02x}", i as u8)).collect();
        let lines: Vec<&str> = (0..16).map(|i| &hex[i * 32..i * 32 + 32]).collect();
        let key = format!("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n", lines.join("\n"));
        assert!(static_key_summary(&key).unwrap().contains("2048"));
        assert!(static_key_summary(&key.replace(&lines[3].to_string(), "")).is_err());
        assert!(static_key_summary("-----BEGIN OpenVPN Static key V1-----\nabcd").is_err());

        let p = Path::new;
        assert_eq!(detect_vpn_file(p("a.ovpn"), ""), VpnKind::OpenVpn);
        assert_eq!(detect_vpn_file(p("a.conf"), "[Interface]\nPrivateKey = x\n"), VpnKind::WireGuard);
        assert_eq!(detect_vpn_file(p("a.conf"), "# WatchGuard\nclient\ndev tun\nproto tcp\nremote fw.exemple.fr 443\n"), VpnKind::OpenVpn);
        assert_eq!(detect_vpn_file(p("a.txt"), ""), VpnKind::WireGuard);

        let mut s = "  \tclé \n".to_string();
        trim_in_place(&mut s);
        assert_eq!(s, "clé");
    }

    /// Onglet de bureau RDP relié à des canaux de test : (onglet, commandes envoyées à la session).
    fn desktop_tab(display: RdpDisplay) -> (Tab, tokio::sync::mpsc::UnboundedReceiver<DesktopCmd>) {
        let (tx, cmds) = tokio::sync::mpsc::unbounded_channel();
        let (_etx, rx) = std::sync::mpsc::channel();
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let opts = desktop::ViewOptions { display, server_pointer: false, windows_keys: false };
        let tab = Tab {
            host_id: Uuid::new_v4(),
            title: "Bureau".into(),
            protocol: Protocol::Rdp,
            session: Session::Desktop { view: DesktopView::new(Protocol::Rdp).with_options(opts), handle: DesktopHandle { tx, rx, frame, drive: None } },
            state: TabState::Connecting,
            status: "Connexion…".into(),
            activity: false,
            files: None,
            show_files: false,
            uid: Uuid::new_v4(),
            popped: false,
            popup_fullscreen: false,
            multimon: false,
            screens: Vec::new(),
            toolbar_until: 0.0,
            was_connected: false,
            share: None,
            files_for: None,
            has_password: false,
            pw_request: false,
            pw_sent: false,
            pw_auto: false,
        };
        (tab, cmds)
    }

    /// Textes peints pendant une image.
    fn painted_text(out: &egui::FullOutput) -> String {
        let mut all = String::new();
        for s in &out.shapes {
            if let egui::Shape::Text(t) = &s.shape {
                all.push_str(t.galley.text());
                all.push('\n');
            }
        }
        all
    }

    #[test]
    fn sudo_prompt_shows_the_password_button() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let (tx, _cmds) = tokio::sync::mpsc::unbounded_channel();
        let (_etx, rx) = std::sync::mpsc::channel();
        let (mut tab, _) = desktop_tab(RdpDisplay::Dynamic);
        tab.protocol = Protocol::Ssh;
        tab.session = Session::Term { term: Terminal::new(100), handle: SessionHandle { tx, rx } };
        tab.state = TabState::Connected;
        tab.has_password = true;
        let settings = crate::model::Settings::default();
        let (mut primary, mut paste) = (String::new(), None);
        let mut frame = |tab: &mut Tab| painted_text(&one_frame(&ctx, |ui| render_session(ui, tab, 0, &settings, true, &mut primary, &mut paste)));

        assert!(!frame(&mut tab).contains("Saisir le mot de passe"), "pas d'invite : pas de bouton");
        tab.session.note("theo@srv:~$ sudo -i\r\n[sudo] password for theo: ");
        assert!(frame(&mut tab).contains("Saisir le mot de passe"));
        // déjà envoyé : masqué jusqu'à la prochaine sortie du serveur
        tab.pw_sent = true;
        assert!(!frame(&mut tab).contains("Saisir le mot de passe"));
        tab.pw_sent = false;
        tab.has_password = false;
        assert!(frame(&mut tab).contains("Aucun mot de passe enregistré"));
        // terminal déconnecté : rien
        tab.has_password = true;
        tab.state = TabState::Closed(None);
        assert!(!frame(&mut tab).contains("Saisir le mot de passe"));
    }

    fn one_frame(ctx: &egui::Context, draw: impl FnMut(&mut egui::Ui)) -> egui::FullOutput {
        let mut draw = draw;
        let input = egui::RawInput { screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1200.0, 800.0))), ..Default::default() };
        let mut out = ctx.run_ui(input, |root| {
            egui::CentralPanel::default().show(root, |ui| draw(ui));
        });
        out.textures_delta.clear();
        out
    }

    #[test]
    fn auto_reconnect_keeps_the_tab_and_resumes_inputs() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let (mut tab, mut cmds) = desktop_tab(RdpDisplay::FixedFit);
        session_state(&mut tab, Event::Connected);
        assert!(matches!(tab.state, TabState::Connected));
        assert!(cmds.try_recv().is_err(), "première ouverture : rien à relâcher");
        if let Session::Desktop { handle, .. } = &tab.session {
            handle.frame.lock().unwrap().resize(640, 400);
        }

        // coupure : l'onglet reste, l'image aussi, le statut de la session est affiché
        let status = "Reconnexion… (connexion réinitialisée) — tentative 2/5";
        session_state(&mut tab, Event::Status(status.into()));
        assert!(matches!(tab.state, TabState::Connecting));
        let settings = crate::model::Settings::default();
        let (mut primary, mut paste) = (String::new(), None);
        let out = one_frame(&ctx, |ui| render_session(ui, &mut tab, 0, &settings, true, &mut primary, &mut paste));
        assert!(painted_text(&out).contains(status), "statut visible : {}", painted_text(&out));
        // entrées suspendues pendant la coupure
        let ev = egui::Event::PointerButton { pos: pos2(600.0, 400.0), button: egui::PointerButton::Primary, pressed: true, modifiers: Default::default() };
        let input = egui::RawInput { screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1200.0, 800.0))), events: vec![ev], ..Default::default() };
        let mut out = ctx.run_ui(input, |root| {
            egui::CentralPanel::default().show(root, |ui| render_session(ui, &mut tab, 0, &settings, true, &mut primary, &mut paste));
        });
        out.textures_delta.clear();
        while let Ok(c) = cmds.try_recv() {
            assert!(!matches!(c, DesktopCmd::Input(_)), "aucune entrée envoyée pendant la reconnexion");
            assert!(!matches!(c, DesktopCmd::Resize(..)), "jamais de redimensionnement en résolution fixe");
        }

        // retour : reprise, avec tout relâché d'abord
        session_state(&mut tab, Event::Connected);
        assert!(matches!(tab.state, TabState::Connected));
        assert!(matches!(cmds.try_recv(), Ok(DesktopCmd::Input(v)) if v == vec![desktop::Input::ReleaseAll]));
        assert!(cmds.try_recv().is_err(), "pas de redimensionnement en résolution fixe après reconnexion");

        // nouvelle coupure, puis échec définitif : l'erreur est gardée et affichée
        session_state(&mut tab, Event::Status("Reconnexion… (x) — tentative 5/5".into()));
        session_state(&mut tab, Event::Closed(Some("Hôte injoignable".into())));
        assert!(matches!(&tab.state, TabState::Closed(Some(e)) if e == "Hôte injoignable"));
        // plein écran / fenêtre séparée : la barre flottante montre la cause
        let mut actions = Vec::new();
        let _ = one_frame(&ctx, |ui| session_toolbar(ui, ui.max_rect(), &mut tab, 0, ToolbarMode::Popup { fullscreen: true }, &mut actions));
        let out = one_frame(&ctx, |ui| session_toolbar(ui, ui.max_rect(), &mut tab, 0, ToolbarMode::Popup { fullscreen: true }, &mut actions));
        assert!(painted_text(&out).contains("Hôte injoignable"), "{}", painted_text(&out));
    }

    #[test]
    fn rdp_files_panel_follows_the_session_share() {
        let dir = std::path::Path::new("C:\\Partage");
        assert_eq!(rdp_files(Some(dir), true), Ok(dir.to_path_buf()));
        assert_eq!(rdp_files(Some(dir), false), Ok(dir.to_path_buf()), "désactivé pendant la session : partagé jusqu'à la reconnexion");
        assert!(rdp_files(None, true).unwrap_err().contains("reconnectez"), "activé pendant la session");
        assert!(rdp_files(None, false).unwrap_err().contains("désactivé"));

        // chemin personnalisé relatif (coffre importé) : dossier par défaut, pas le dossier de lancement
        let base = std::path::Path::new("C:\\Coffre");
        let mut h = Host::default();
        h.label = "srv".into();
        let default = share_dir_in(base, &h);
        assert!(default.starts_with(base.join("Partage")));
        h.rdp.drive_path = "relatif\\dossier".into();
        assert_eq!(share_dir_in(base, &h), default);
        h.rdp.drive_path = "  D:\\Echange  ".into();
        assert_eq!(share_dir_in(base, &h), PathBuf::from("D:\\Echange"));
        // un dossier qui contient les coffres n'est jamais partagé
        h.rdp.drive_path = crate::vault::root().to_string_lossy().into_owned();
        assert_eq!(share_dir_in(base, &h), default);
    }

    #[test]
    fn shared_folder_never_exposes_the_vault() {
        let root = Path::new("C:\\Users\\a\\AppData\\Roaming\\Escale");
        assert!(exposes_vault(root, root));
        assert!(exposes_vault(Path::new("C:\\Users\\a"), root), "dossier parent des coffres");
        assert!(exposes_vault(&root.join("Coffre1"), root));
        assert!(exposes_vault(Path::new("c:\\users\\A\\appdata\\roaming\\escale\\coffre2"), root), "casse ignorée");
        assert!(!exposes_vault(&root.join("Coffre1").join("Partage").join("srv"), root));
        assert!(!exposes_vault(Path::new("D:\\Echange"), root));
    }

    #[test]
    fn file_manager_survives_resizing() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let root = std::env::temp_dir().join(format!("escale-resize-{}", Uuid::new_v4()));
        let mut fm = FileManager::shared(root.clone(), Some(Default::default()), "Hôte", rt.handle().clone(), ctx.clone());
        frames(&ctx, |ui| fm.show(ui));
        let mut un = FileManager::unavailable("indisponible", "Hôte", rt.handle().clone(), ctx.clone());
        frames(&ctx, |ui| un.show(ui));
        let _ = std::fs::remove_dir_all(&root);
    }
}
