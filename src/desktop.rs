//! Bureau distant (RDP, VNC) : image partagée avec la session, affichage mis à l'échelle,
//! souris et clavier convertis en événements neutres que chaque protocole traduit.

use crate::model::{Protocol, RdpDisplay};
use crate::ssh::Event;
use eframe::egui::{self, Color32, ColorImage, Pos2, Rect, Sense, TextureHandle, TextureOptions, Vec2, pos2, vec2};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// ---------------------------------------------------------------- image partagée

pub struct CursorImage {
    pub size: [usize; 2],
    pub hotspot: [u16; 2],
    pub pixels: Vec<Color32>,
}

#[derive(Clone)]
pub enum CursorShape {
    Default,
    Hidden,
    Bitmap(Arc<CursorImage>),
}

/// Image du bureau distant, écrite par la session et lue par l'interface.
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<Color32>,
    /// Zones modifiées depuis le dernier affichage : x0, y0, x1, y1 (exclusifs), disjointes.
    dirty: Vec<[usize; 4]>,
    resized: bool,
    cursor: CursorShape,
    cursor_serial: u64,
}

impl Frame {
    pub fn new() -> Self {
        Self { width: 0, height: 0, pixels: Vec::new(), dirty: Vec::new(), resized: false, cursor: CursorShape::Default, cursor_serial: 0 }
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        if (width, height) != (self.width, self.height) {
            self.width = width;
            self.height = height;
            self.pixels = vec![Color32::BLACK; width * height];
            self.resized = true;
            self.dirty.clear();
        }
    }

    /// Signale une zone modifiée (coordonnées exclusives, bornées à l'image). Les zones sont gardées
    /// séparées (chacune téléversée seule : deux petites zones dans des coins opposés ne coûtent pas
    /// tout l'écran) ; elles ne sont réunies que si elles se touchent ou deviennent trop nombreuses.
    pub fn mark(&mut self, x0: usize, y0: usize, x1: usize, y1: usize) {
        let (x1, y1) = (x1.min(self.width), y1.min(self.height));
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let union = |a: [usize; 4], b: [usize; 4]| [a[0].min(b[0]), a[1].min(b[1]), a[2].max(b[2]), a[3].max(b[3])];
        let area = |a: [usize; 4]| (a[2] - a[0]) * (a[3] - a[1]);
        let mut r = [x0, y0, x1, y1];
        loop {
            // chevauchement ou bord commun : une seule zone
            if let Some(i) = self.dirty.iter().position(|d| d[0] <= r[2] && r[0] <= d[2] && d[1] <= r[3] && r[1] <= d[3]) {
                r = union(self.dirty.swap_remove(i), r);
                continue;
            }
            if self.dirty.len() < MAX_DIRTY {
                break;
            }
            // trop de zones : réunie à celle dont l'englobant grandit le moins
            let i = (0..self.dirty.len()).min_by_key(|&i| area(union(self.dirty[i], r)) - area(self.dirty[i])).unwrap_or(0);
            r = union(self.dirty.swap_remove(i), r);
        }
        self.dirty.push(r);
    }

    pub fn set_cursor(&mut self, cursor: CursorShape) {
        self.cursor = cursor;
        self.cursor_serial += 1;
    }
}

/// Zones modifiées gardées séparées au plus (au-delà, réunies).
const MAX_DIRTY: usize = 16;

pub type SharedFrame = Arc<Mutex<Frame>>;

// ---------------------------------------------------------------- événements

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum MouseBtn {
    Left,
    Middle,
    Right,
    X1,
    X2,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    Mouse { x: u16, y: u16 },
    Button { button: MouseBtn, down: bool },
    /// Molette : 120 unités par cran ; positif = vers le haut / la droite.
    Wheel { vertical: bool, units: i16 },
    /// Code de touche physique (jeu 1, 0xE0xx pour les touches étendues) : RDP.
    Scancode { code: u16, down: bool },
    /// Symbole X11 : VNC.
    Keysym { sym: u32, down: bool },
    /// Texte tapé tel quel (collage) : RDP en Unicode, VNC en keysyms.
    Text(String),
    /// Le bureau perd le focus : relâcher les touches et boutons enfoncés.
    ReleaseAll,
    /// État des verrous de cet ordinateur (événement de synchronisation RDP) : sans lui, le serveur
    /// garde les siens (Verr. Num souvent éteint) et le pavé numérique devient un pavé de direction.
    Locks(LockKeys),
}

/// Verrous du clavier (Verr. Num, Verr. Maj, Arrêt défil.).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LockKeys {
    pub num: bool,
    pub caps: bool,
    pub scroll: bool,
}

impl Default for LockKeys {
    /// Verr. Num allumé par défaut (comme le clavier de la plupart des postes).
    fn default() -> Self {
        Self { num: true, caps: false, scroll: false }
    }
}

impl LockKeys {
    fn bits(self) -> u8 {
        self.num as u8 | (self.caps as u8) << 1 | (self.scroll as u8) << 2
    }

    fn from_bits(b: u8) -> Self {
        Self { num: b & 1 != 0, caps: b & 2 != 0, scroll: b & 4 != 0 }
    }
}

/// Verrous de cet ordinateur vus par la dernière image où un bureau avait le focus : la session RDP
/// les annonce dès son ouverture (et à chaque reconnexion), avant même que le bureau ait le focus.
static LOCKS: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

/// Verrous à annoncer au serveur à l'ouverture de la session.
pub fn current_locks() -> LockKeys {
    LockKeys::from_bits(LOCKS.load(std::sync::atomic::Ordering::Relaxed))
}

/// Verrous de cet ordinateur : lus sous Windows, Verr. Num allumé ailleurs (egui ne les connaît pas).
fn local_locks() -> LockKeys {
    #[cfg(windows)]
    {
        crate::winput::lock_keys()
    }
    #[cfg(not(windows))]
    {
        LockKeys::default()
    }
}

/// Code de la touche Pause (préfixe E1, sans relâchement) : la session RDP l'envoie en Ctrl + Verr. Num.
#[cfg_attr(not(windows), allow(dead_code))]
pub const PAUSE: u16 = 0xE11D;

pub enum DesktopCmd {
    Input(Vec<Input>),
    /// Nouvelle taille souhaitée en pixels (redimensionnement dynamique RDP).
    Resize(u16, u16),
    Close,
}

/// Côté UI d'une session graphique.
pub struct DesktopHandle {
    pub tx: mpsc::UnboundedSender<DesktopCmd>,
    pub rx: std::sync::mpsc::Receiver<Event>,
    pub frame: SharedFrame,
    /// État du lecteur partagé (RDP uniquement).
    pub drive: Option<Arc<crate::rdpdr::DriveStatus>>,
}

/// Copie d'une zone (x0, y0, x1, y1 exclusifs) d'une image large de `w` pixels.
fn region(pixels: &[Color32], w: usize, [x0, y0, x1, y1]: [usize; 4]) -> Vec<Color32> {
    let mut px = Vec::with_capacity((x1 - x0) * (y1 - y0));
    for y in y0..y1 {
        px.extend_from_slice(&pixels[y * w + x0..y * w + x1]);
    }
    px
}

/// Taille de bureau acceptée par les serveurs : largeur paire, 200 à 8192 pixels (bornes du
/// redimensionnement dynamique, les mêmes que celles de la session et de la validation des options).
pub fn clamp_size(w: f32, h: f32) -> (u16, u16) {
    let w = (w.round() as i32).clamp(MIN_SIZE, MAX_SIZE) as u16 & !1;
    let h = (h.round() as i32).clamp(MIN_SIZE, MAX_SIZE) as u16;
    (w, h)
}

pub const MIN_SIZE: i32 = 200;
pub const MAX_SIZE: i32 = 8192;

// ---------------------------------------------------------------- placement de l'image

/// Placement de l'image distante (`w`×`h` pixels) dans la zone `view` (points) : rectangle de l'image
/// à l'écran et échelle (points par pixel distant). `offset` : défilement (mode 1:1 uniquement).
pub fn place(view: Rect, offset: Vec2, w: usize, h: usize, ppp: f32, display: RdpDisplay) -> (Rect, f32) {
    let (wf, hf) = (w.max(1) as f32, h.max(1) as f32);
    let fit = (view.width() / wf).min(view.height() / hf).max(0.0);
    let scale = match display {
        // jamais d'agrandissement au-delà de la taille réelle (flou), réduction si nécessaire
        RdpDisplay::Dynamic => fit.min(1.0 / ppp),
        // résolution fixe ajustée : agrandie ou réduite pour occuper la zone, proportions gardées
        RdpDisplay::FixedFit => fit,
        // pixels 1:1
        RdpDisplay::FixedNative => 1.0 / ppp,
    };
    let size = vec2(wf, hf) * scale;
    if display != RdpDisplay::FixedNative {
        return (Rect::from_center_size(view.center(), size), scale);
    }
    // 1:1 : centrée sur chaque axe où elle tient, sinon décalée du défilement
    let axis = |min: f32, len: f32, content: f32, off: f32| {
        if content <= len { min + (len - content) / 2.0 } else { min - off.clamp(0.0, content - len) }
    };
    let x = axis(view.left(), view.width(), size.x, offset.x);
    let y = axis(view.top(), view.height(), size.y, offset.y);
    (Rect::from_min_size(pos2(x, y), size), scale)
}

/// Position à l'écran -> pixel distant (borné à l'image).
pub fn to_remote(p: Pos2, img: Rect, scale: f32, w: usize, h: usize) -> (u16, u16) {
    let v = (p - img.min) / scale.max(f32::EPSILON);
    ((v.x.max(0.0) as usize).min(w.saturating_sub(1)) as u16, (v.y.max(0.0) as usize).min(h.saturating_sub(1)) as u16)
}

// ---------------------------------------------------------------- vue

/// Options d'affichage d'un bureau RDP (VNC : valeurs par défaut, comportement historique).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ViewOptions {
    pub display: RdpDisplay,
    /// Formes de curseur envoyées par le serveur ; sinon la flèche locale.
    pub server_pointer: bool,
    /// Win, Alt+Tab, Ctrl+Échap… envoyés au bureau distant quand il a le focus.
    pub windows_keys: bool,
}

impl Default for ViewOptions {
    fn default() -> Self {
        Self { display: RdpDisplay::Dynamic, server_pointer: true, windows_keys: true }
    }
}

impl ViewOptions {
    pub fn from_rdp(o: &crate::model::RdpOptions) -> Self {
        // tous les écrans : ramenée dans la fenêtre d'Escale, l'image est mise à l'échelle
        let display = if o.multimon { RdpDisplay::FixedFit } else { o.display };
        Self { display, server_pointer: o.server_pointer, windows_keys: o.windows_keys }
    }
}

#[derive(Default)]
pub struct ViewOutput {
    pub input: Vec<Input>,
    pub resize: Option<(u16, u16)>,
}

pub struct DesktopView {
    protocol: Protocol,
    opts: ViewOptions,
    texture: Option<TextureHandle>,
    /// Filtrage de la texture : au plus proche à 1:1 (net), linéaire sinon.
    filter: TextureOptions,
    cursor_tex: Option<(TextureHandle, [u16; 2], [usize; 2])>,
    cursor: CursorShape,
    cursor_serial: u64,
    /// Forme appliquée au curseur système (Windows), d'après `cursor_serial`.
    hw_cursor: Option<u64>,
    focused: bool,
    /// Modificateurs envoyés au serveur (hors Windows / VNC).
    sent_mods: egui::Modifiers,
    last_pos: Option<(u16, u16)>,
    wheel_acc: Vec2,
    /// Taille souhaitée (pixels) et depuis quand elle est stable.
    want: Option<((u16, u16), f64)>,
    sent_size: Option<(u16, u16)>,
    /// Boutons de souris enfoncés sur le bureau (bits de `button_bit`) : le glisser continue hors de l'image.
    buttons: u8,
    /// Fenêtre étendue à tous les écrans : l'image, de la taille de leur ensemble, part du coin
    /// haut-gauche de la zone, pixels 1:1.
    span: bool,
    /// Modificateurs enfoncés d'après les codes physiques envoyés (bits de `modifier_bit`).
    held_mods: u8,
    /// Fin enfoncée avec Ctrl+Alt : envoyée comme Suppr jusqu'à son relâchement.
    end_as_delete: bool,
    /// Verrous annoncés au serveur depuis la prise du focus (`None` : à renvoyer).
    sent_locks: Option<LockKeys>,
}

fn button_bit(b: MouseBtn) -> u8 {
    match b {
        MouseBtn::Left => 1,
        MouseBtn::Middle => 2,
        MouseBtn::Right => 4,
        MouseBtn::X1 => 8,
        MouseBtn::X2 => 16,
    }
}

impl DesktopView {
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            opts: ViewOptions::default(),
            texture: None,
            filter: TextureOptions::LINEAR,
            cursor_tex: None,
            cursor: CursorShape::Default,
            cursor_serial: 0,
            hw_cursor: None,
            focused: false,
            sent_mods: egui::Modifiers::default(),
            last_pos: None,
            wheel_acc: Vec2::ZERO,
            want: None,
            sent_size: None,
            buttons: 0,
            span: false,
            held_mods: 0,
            end_as_delete: false,
            sent_locks: None,
        }
    }

    /// Fenêtre étendue à tous les écrans (image 1:1 depuis le coin haut-gauche) ou non.
    pub fn set_span(&mut self, on: bool) {
        self.span = on;
    }

    /// Options d'affichage propres à l'hôte (RDP uniquement ; VNC garde le comportement historique).
    pub fn with_options(mut self, opts: ViewOptions) -> Self {
        if self.protocol == Protocol::Rdp {
            self.opts = opts;
        }
        self
    }

    fn display(&self) -> RdpDisplay {
        if self.protocol == Protocol::Rdp { self.opts.display } else { RdpDisplay::Dynamic }
    }

    /// Session rétablie (reconnexion automatique) : le nouveau serveur ne connaît ni la taille souhaitée
    /// (renvoyée en mode dynamique), ni les modificateurs, ni la position de la souris : tout est renvoyé.
    pub fn resume(&mut self) {
        self.sent_size = None;
        self.want = None;
        self.sent_mods = egui::Modifiers::default();
        self.last_pos = None;
        self.buttons = 0;
        self.wheel_acc = Vec2::ZERO;
        self.sent_locks = None;
    }

    fn sync_texture(&mut self, ctx: &egui::Context, frame: &SharedFrame) -> (usize, usize) {
        let Ok(mut f) = frame.lock() else { return (0, 0) };
        let (w, h) = (f.width, f.height);
        if w == 0 || h == 0 {
            return (0, 0);
        }
        let opts = self.filter;
        let full = f.resized || self.texture.as_ref().is_none_or(|t| t.size() != [w, h]);
        if full {
            let img = ColorImage::new([w, h], f.pixels.clone());
            match &mut self.texture {
                Some(t) => t.set(img, opts),
                None => self.texture = Some(ctx.load_texture("remote-desktop", img, opts)),
            }
        } else if let Some(t) = &mut self.texture {
            // chaque zone modifiée seule (glTexSubImage2D), jamais l'englobant de zones éloignées
            for &[x0, y0, x1, y1] in &f.dirty {
                t.set_partial([x0, y0], ColorImage::new([x1 - x0, y1 - y0], region(&f.pixels, w, [x0, y0, x1, y1])), opts);
            }
        }
        f.resized = false;
        f.dirty.clear();
        if f.cursor_serial != self.cursor_serial {
            self.cursor_serial = f.cursor_serial;
            // curseur du serveur désactivé pour cet hôte : flèche locale
            self.cursor = if self.opts.server_pointer { f.cursor.clone() } else { CursorShape::Default };
            self.cursor_tex = match &self.cursor {
                CursorShape::Bitmap(c) if c.size[0] > 0 && c.size[1] > 0 => {
                    let img = ColorImage::new(c.size, c.pixels.clone());
                    Some((ctx.load_texture("remote-cursor", img, TextureOptions::NEAREST), c.hotspot, c.size))
                }
                _ => None,
            };
        }
        (w, h)
    }

    /// Affiche le bureau dans toute la zone disponible et traduit les entrées.
    /// `active` : aucune fenêtre modale ne bloque le clavier.
    pub fn show(&mut self, ui: &mut egui::Ui, frame: &SharedFrame, active: bool) -> ViewOutput {
        let mut out = ViewOutput::default();
        let rect = ui.available_rect_before_wrap();
        let ppp = ui.ctx().pixels_per_point();
        let id = ui.id().with("escale-desktop");
        let resp = ui.interact(rect, id, Sense::click_and_drag());

        // --- taille souhaitée (RDP dynamique) : envoyée une fois stable, pour ne pas inonder le serveur ;
        // en résolution fixe, le serveur garde la taille choisie
        // fenêtre réduite : sa zone n'a plus de taille, le bureau garde la sienne
        let minimized = ui.input(|i| i.viewport().minimized == Some(true)) || rect.width() < 1.0 || rect.height() < 1.0;
        if self.protocol == Protocol::Rdp && self.display() == RdpDisplay::Dynamic && !minimized {
            let now = ui.input(|i| i.time);
            let size = clamp_size(rect.width() * ppp, rect.height() * ppp);
            if self.sent_size != Some(size) {
                match self.want {
                    Some((s, since)) if s == size => {
                        if now - since > 0.6 {
                            out.resize = Some(size);
                            self.sent_size = Some(size);
                            self.want = None;
                        } else {
                            ui.ctx().request_repaint_after(std::time::Duration::from_millis(150));
                        }
                    }
                    _ => {
                        self.want = Some((size, now));
                        ui.ctx().request_repaint_after(std::time::Duration::from_millis(650));
                    }
                }
            }
        }

        let (w, h) = self.sync_texture(ui.ctx(), frame);
        if w == 0 {
            return out;
        }
        let display = self.display();
        // `clip` : partie visible de la zone (sans les barres de défilement du mode 1:1)
        let (img, scale, clip) = if self.span {
            (Rect::from_min_size(rect.min, vec2(w as f32, h as f32) / ppp), 1.0 / ppp, rect)
        } else if display == RdpDisplay::FixedNative {
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rect));
            // barres pleines, à côté de l'image ; la molette reste au bureau distant
            child.spacing_mut().scroll = egui::style::ScrollStyle::solid();
            let content = vec2(w as f32, h as f32) / ppp;
            let so = egui::ScrollArea::both()
                .id_salt(id.with("scroll"))
                .auto_shrink(false)
                .scroll_source(egui::scroll_area::ScrollSource::SCROLL_BAR)
                .show(&mut child, |ui| {
                    ui.allocate_exact_size(content, Sense::hover());
                });
            let (img, scale) = place(so.inner_rect, so.state.offset, w, h, ppp, display);
            (img, scale, so.inner_rect)
        } else {
            let (img, scale) = place(rect, Vec2::ZERO, w, h, ppp, display);
            (img, scale, rect)
        };
        // à 1:1, l'image commence sur un pixel physique entier et la texture est filtrée au plus
        // proche : chaque pixel distant tombe exactement sur un pixel de l'écran (net, sans flou)
        let native = (scale * ppp - 1.0).abs() < 1e-4;
        let img = if native { Rect::from_min_size(((img.min.to_vec2() * ppp).round() / ppp).to_pos2(), img.size()) } else { img };
        let filter = if native { TextureOptions::NEAREST } else { TextureOptions::LINEAR };
        if filter != self.filter {
            self.filter = filter;
            // le filtrage accompagne chaque téléversement : un pixel suffit à le changer
            if let (Some(t), Ok(f)) = (&mut self.texture, frame.lock())
                && t.size() == [f.width, f.height]
                && let Some(&p) = f.pixels.first()
            {
                t.set_partial([0, 0], ColorImage::new([1, 1], vec![p]), filter);
            }
        }
        let vis = img.intersect(clip);
        if let Some(t) = &self.texture {
            ui.painter_at(clip).image(t.id(), img, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
        }
        let to_remote = |p: Pos2| to_remote(p, img, scale, w, h);

        // --- focus clavier
        if resp.clicked() || resp.drag_started() || (active && !ui.memory(|m| m.has_focus(id)) && !ui.ctx().egui_wants_keyboard_input()) {
            ui.memory_mut(|m| m.request_focus(id));
        }
        // egui garde le focus d'un élément quand sa fenêtre perd le focus : seul le bureau de la
        // fenêtre active (principale ou séparée) reçoit le clavier
        let window_focused = ui.input(|i| i.viewport().focused != Some(false));
        let focused = active && window_focused && ui.memory(|m| m.has_focus(id));
        if focused {
            crate::terminal::FOCUSED.store(true, std::sync::atomic::Ordering::Relaxed);
            #[cfg(windows)]
            {
                crate::winput::CAPTURE.store(true, std::sync::atomic::Ordering::Relaxed);
                // raccourcis Windows (Win, Alt+Tab…) : interceptés seulement pour un bureau RDP qui les accepte
                if self.protocol == Protocol::Rdp && self.opts.windows_keys {
                    crate::winput::WIN_KEYS.store(true, std::sync::atomic::Ordering::Relaxed);
                    crate::winput::install_keyboard_hook(ui.ctx());
                }
                // VNC : Ctrl+Maj+Échap (gestionnaire des tâches) va au bureau distant
                if self.protocol == Protocol::Vnc {
                    crate::winput::TASK_KEYS.store(true, std::sync::atomic::Ordering::Relaxed);
                    crate::winput::install_keyboard_hook(ui.ctx());
                }
            }
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true })
            });
        }
        if self.focused && !focused {
            out.input.push(Input::ReleaseAll);
            self.sent_mods = egui::Modifiers::default();
            self.buttons = 0;
            self.held_mods = 0;
            self.end_as_delete = false;
            // verrous changés ailleurs entre-temps : renvoyés au retour du focus (comme mstsc)
            self.sent_locks = None;
        }
        self.focused = focused;

        let (events, mods, hover) = ui.input(|i| (i.events.clone(), i.modifiers, i.pointer.hover_pos()));
        let hovered = hover.is_some_and(|p| vis.contains(p)) && ui.rect_contains_pointer(rect);

        // --- souris
        if active {
            for ev in &events {
                match ev {
                    // bouton enfoncé : le glisser suit la souris hors de l'image (position bornée au bord)
                    egui::Event::PointerMoved(p) if (vis.contains(*p) && ui.rect_contains_pointer(rect)) || self.buttons != 0 => {
                        let pos = to_remote(*p);
                        if self.last_pos != Some(pos) {
                            self.last_pos = Some(pos);
                            out.input.push(Input::Mouse { x: pos.0, y: pos.1 });
                        }
                    }
                    egui::Event::PointerButton { pos, button, pressed, .. } if vis.contains(*pos) || !pressed => {
                        if *pressed && !ui.rect_contains_pointer(rect) {
                            continue;
                        }
                        let button = match button {
                            egui::PointerButton::Primary => MouseBtn::Left,
                            egui::PointerButton::Secondary => MouseBtn::Right,
                            egui::PointerButton::Middle => MouseBtn::Middle,
                            egui::PointerButton::Extra1 => MouseBtn::X1,
                            egui::PointerButton::Extra2 => MouseBtn::X2,
                        };
                        let p = to_remote(*pos);
                        if self.last_pos != Some(p) {
                            self.last_pos = Some(p);
                            out.input.push(Input::Mouse { x: p.0, y: p.1 });
                        }
                        if *pressed {
                            self.buttons |= button_bit(button);
                        } else {
                            self.buttons &= !button_bit(button);
                        }
                        out.input.push(Input::Button { button, down: *pressed });
                    }
                    egui::Event::MouseWheel { unit, delta, .. } if hovered => {
                        let k = match unit {
                            egui::MouseWheelUnit::Point => 1.0 / 50.0,
                            egui::MouseWheelUnit::Line => 1.0,
                            egui::MouseWheelUnit::Page => 3.0,
                        };
                        self.wheel_acc += *delta * k * 120.0;
                        for (vertical, v) in [(true, self.wheel_acc.y), (false, -self.wheel_acc.x)] {
                            let units = v.clamp(-240.0, 240.0) as i16;
                            // VNC ne connaît que des crans entiers
                            let step = if self.protocol == Protocol::Vnc { units / 120 * 120 } else { units };
                            if step != 0 {
                                out.input.push(Input::Wheel { vertical, units: step });
                                if vertical {
                                    self.wheel_acc.y -= step as f32;
                                } else {
                                    self.wheel_acc.x += step as f32;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // --- clavier
        if focused {
            self.keyboard(&events, mods, &mut out.input);
            if self.protocol == Protocol::Rdp {
                self.sync_locks(local_locks(), &mut out.input);
            }
        }

        // --- curseur distant : vrai curseur Windows (sans latence), dessiné ailleurs
        #[cfg(windows)]
        {
            if hovered {
                crate::winput::CURSOR_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
                if self.hw_cursor != Some(self.cursor_serial) {
                    self.hw_cursor = Some(self.cursor_serial);
                    match &self.cursor {
                        CursorShape::Default => crate::winput::set_remote_cursor(None),
                        CursorShape::Hidden => crate::winput::set_remote_cursor(Some((&[], 0, 0, 0, 0))),
                        CursorShape::Bitmap(c) => {
                            let px: Vec<[u8; 4]> = c.pixels.iter().map(|p| p.to_srgba_unmultiplied()).collect();
                            crate::winput::set_remote_cursor(Some((&px, c.size[0], c.size[1], c.hotspot[0], c.hotspot[1])));
                        }
                    }
                }
                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
            } else {
                // reprise à l'entrée suivante (un autre bureau a pu changer le curseur entre-temps)
                self.hw_cursor = None;
            }
        }
        #[cfg(not(windows))]
        if hovered {
            match &self.cursor {
                CursorShape::Default => ui.ctx().set_cursor_icon(egui::CursorIcon::Default),
                CursorShape::Hidden => ui.ctx().set_cursor_icon(egui::CursorIcon::None),
                CursorShape::Bitmap(_) => {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::None);
                    if let (Some((t, hot, size)), Some(p)) = (&self.cursor_tex, hover) {
                        // le curseur garde sa taille réelle, quel que soit le zoom de l'image
                        let px = 1.0 / ppp;
                        let r = Rect::from_min_size(
                            p - vec2(hot[0] as f32, hot[1] as f32) * px,
                            vec2(size[0] as f32, size[1] as f32) * px,
                        );
                        ui.ctx()
                            .layer_painter(egui::LayerId::new(egui::Order::Tooltip, id.with("cursor")))
                            .with_clip_rect(vis)
                            .image(t.id(), r, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
                    }
                }
            }
        }
        out
    }

    fn keyboard(&mut self, events: &[egui::Event], mods: egui::Modifiers, out: &mut Vec<Input>) {
        // collage explicite (Ctrl+Maj+V, Maj+Inser) : tapé tel quel, après les touches de l'image
        let pastes: Vec<Input> = events
            .iter()
            .filter_map(|ev| match ev {
                egui::Event::Paste(t) if !t.is_empty() => Some(Input::Text(t.clone())),
                _ => None,
            })
            .collect();
        // RDP sous Windows : codes physiques relevés dans la boucle de messages (cf. winput)
        #[cfg(windows)]
        if self.protocol == Protocol::Rdp {
            let pasted = !pastes.is_empty();
            let win_keys = self.opts.windows_keys;
            // la frappe du raccourci de collage (V, Inser) n'est pas transmise en plus du texte ;
            // touches Windows gardées sur cet ordinateur si l'hôte ne les accepte pas
            for (code, down) in crate::winput::take_scancodes() {
                if (pasted && down && (code == 0x2F || code == 0xE052)) || (!win_keys && is_windows_key(code)) {
                    continue;
                }
                // modificateur déjà enfoncé : répétition automatique, ou renvoyé par le crochet
                // avant une touche retenue (Ctrl+Maj+Échap) puis relevé dans la file de messages
                if down && self.modifier_held(code) {
                    continue;
                }
                let code = self.remap_key(code, down);
                out.push(Input::Scancode { code, down });
            }
            out.extend(pastes);
            return;
        }
        // VNC : touches lues dans egui, les codes physiques relevés ne servent pas
        #[cfg(windows)]
        let _ = crate::winput::take_scancodes();

        let rdp = self.protocol == Protocol::Rdp;
        for ev in events {
            match ev {
                // touche du raccourci de collage : remplacée par le texte collé
                egui::Event::Key { key: egui::Key::V | egui::Key::Insert, .. } if !pastes.is_empty() => {}
                egui::Event::Key { key, physical_key, pressed, modifiers, .. } => {
                    self.sync_mods(*modifiers, rdp, out);
                    if rdp {
                        if let Some(code) = scancode(physical_key.unwrap_or(*key)).filter(|&c| self.opts.windows_keys || !is_windows_key(c)) {
                            out.push(Input::Scancode { code, down: *pressed });
                        }
                    } else if let Some(sym) = special_keysym(*key) {
                        out.push(Input::Keysym { sym, down: *pressed });
                    } else if *pressed && modifiers.ctrl {
                        // Ctrl+lettre ne produit pas de texte : on envoie la lettre
                        if let Some(c) = key_char(*key) {
                            out.push(Input::Keysym { sym: c as u32, down: true });
                            out.push(Input::Keysym { sym: c as u32, down: false });
                        }
                    }
                }
                egui::Event::Text(t) if !rdp => {
                    for c in t.chars() {
                        let sym = char_keysym(c);
                        out.push(Input::Keysym { sym, down: true });
                        out.push(Input::Keysym { sym, down: false });
                    }
                }
                _ => {}
            }
        }
        self.sync_mods(mods, rdp, out);
        if !pastes.is_empty() {
            // la session relâche les modificateurs avant le texte : à renvoyer s'ils restent enfoncés
            self.sent_mods = egui::Modifiers::default();
            out.extend(pastes);
        }
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    fn modifier_held(&self, code: u16) -> bool {
        let bit = modifier_bit(code);
        bit != 0 && self.held_mods & bit != 0
    }

    /// Aligne les verrous du serveur sur ceux de cet ordinateur : à la prise du focus, puis à chaque
    /// changement. Après les touches de l'image : un appui sur Verr. Num déjà transmis a basculé le
    /// verrou du serveur, la synchronisation confirme le même état.
    fn sync_locks(&mut self, now: LockKeys, out: &mut Vec<Input>) {
        LOCKS.store(now.bits(), std::sync::atomic::Ordering::Relaxed);
        if self.sent_locks != Some(now) {
            self.sent_locks = Some(now);
            out.push(Input::Locks(now));
        }
    }

    /// Ctrl+Alt+Fin devient Ctrl+Alt+Suppr sur le bureau distant, comme dans mstsc : Windows garde
    /// Ctrl+Alt+Suppr pour cet ordinateur.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn remap_key(&mut self, code: u16, down: bool) -> u16 {
        let bit = modifier_bit(code);
        if bit != 0 {
            if down {
                self.held_mods |= bit;
            } else {
                self.held_mods &= !bit;
            }
            return code;
        }
        if code != 0xE04F {
            return code;
        }
        if down && self.held_mods & 3 != 0 && self.held_mods & 12 != 0 {
            self.end_as_delete = true;
        }
        let code = if self.end_as_delete { 0xE053 } else { code };
        if !down {
            self.end_as_delete = false;
        }
        code
    }

    /// Aligne les modificateurs du serveur sur l'état local.
    fn sync_mods(&mut self, m: egui::Modifiers, rdp: bool, out: &mut Vec<Input>) {
        // (scancode, keysym)
        let keys = [(m.shift, self.sent_mods.shift, 0x2A, 0xFFE1), (m.ctrl, self.sent_mods.ctrl, 0x1D, 0xFFE3), (m.alt, self.sent_mods.alt, 0x38, 0xFFE9)];
        for (now, before, code, sym) in keys {
            if now != before {
                out.push(if rdp { Input::Scancode { code, down: now } } else { Input::Keysym { sym, down: now } });
            }
        }
        self.sent_mods = egui::Modifiers { shift: m.shift, ctrl: m.ctrl, alt: m.alt, ..Default::default() };
    }
}

// ---------------------------------------------------------------- tables de touches

/// Bit de suivi d'un modificateur (codes physiques) : Ctrl g., Ctrl d., Alt g., Alt d., Maj g., Maj d.
#[cfg_attr(not(windows), allow(dead_code))]
fn modifier_bit(code: u16) -> u8 {
    match code {
        0x1D => 1,
        0xE01D => 2,
        0x38 => 4,
        0xE038 => 8,
        0x2A => 16,
        0x36 => 32,
        _ => 0,
    }
}

/// Touches Windows gauche / droite (codes physiques étendus).
fn is_windows_key(code: u16) -> bool {
    matches!(code, 0xE05B | 0xE05C)
}

/// Code de touche physique (jeu 1) pour une touche egui en position QWERTY.
pub fn scancode(key: egui::Key) -> Option<u16> {
    use egui::Key as K;
    const LETTERS: [u16; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F,
        0x11, 0x2D, 0x15, 0x2C,
    ];
    let letters = [
        K::A, K::B, K::C, K::D, K::E, K::F, K::G, K::H, K::I, K::J, K::K, K::L, K::M, K::N, K::O, K::P, K::Q, K::R, K::S, K::T, K::U, K::V, K::W,
        K::X, K::Y, K::Z,
    ];
    if let Some(i) = letters.iter().position(|k| *k == key) {
        return Some(LETTERS[i]);
    }
    let digits = [K::Num1, K::Num2, K::Num3, K::Num4, K::Num5, K::Num6, K::Num7, K::Num8, K::Num9, K::Num0];
    if let Some(i) = digits.iter().position(|k| *k == key) {
        return Some(0x02 + i as u16);
    }
    let fkeys = [K::F1, K::F2, K::F3, K::F4, K::F5, K::F6, K::F7, K::F8, K::F9, K::F10];
    if let Some(i) = fkeys.iter().position(|k| *k == key) {
        return Some(0x3B + i as u16);
    }
    Some(match key {
        K::F11 => 0x57,
        K::F12 => 0x58,
        K::Escape => 0x01,
        K::Minus => 0x0C,
        K::Equals | K::Plus => 0x0D,
        K::Backspace => 0x0E,
        K::Tab => 0x0F,
        K::OpenBracket | K::OpenCurlyBracket => 0x1A,
        K::CloseBracket | K::CloseCurlyBracket => 0x1B,
        K::Enter => 0x1C,
        K::ControlLeft => 0x1D,
        K::Semicolon | K::Colon => 0x27,
        K::Quote => 0x28,
        K::Backtick => 0x29,
        K::ShiftLeft => 0x2A,
        K::Backslash | K::Pipe => 0x2B,
        K::Comma => 0x33,
        K::Period => 0x34,
        K::Slash | K::Questionmark => 0x35,
        K::ShiftRight => 0x36,
        K::AltLeft => 0x38,
        K::Space => 0x39,
        K::IntlBackslash => 0x56,
        K::ControlRight => 0xE01D,
        K::AltRight => 0xE038,
        K::Home => 0xE047,
        K::ArrowUp => 0xE048,
        K::PageUp => 0xE049,
        K::ArrowLeft => 0xE04B,
        K::ArrowRight => 0xE04D,
        K::End => 0xE04F,
        K::ArrowDown => 0xE050,
        K::PageDown => 0xE051,
        K::Insert => 0xE052,
        K::Delete => 0xE053,
        K::SuperLeft => 0xE05B,
        K::SuperRight => 0xE05C,
        _ => return None,
    })
}

/// Keysym X11 des touches qui ne produisent pas de texte.
pub fn special_keysym(key: egui::Key) -> Option<u32> {
    use egui::Key as K;
    let fkeys = [K::F1, K::F2, K::F3, K::F4, K::F5, K::F6, K::F7, K::F8, K::F9, K::F10, K::F11, K::F12];
    if let Some(i) = fkeys.iter().position(|k| *k == key) {
        return Some(0xFFBE + i as u32);
    }
    Some(match key {
        K::Escape => 0xFF1B,
        K::Tab => 0xFF09,
        K::Backspace => 0xFF08,
        K::Enter => 0xFF0D,
        K::Insert => 0xFF63,
        K::Delete => 0xFFFF,
        K::Home => 0xFF50,
        K::End => 0xFF57,
        K::PageUp => 0xFF55,
        K::PageDown => 0xFF56,
        K::ArrowLeft => 0xFF51,
        K::ArrowUp => 0xFF52,
        K::ArrowRight => 0xFF53,
        K::ArrowDown => 0xFF54,
        K::SuperLeft => 0xFFEB,
        K::SuperRight => 0xFFEC,
        _ => return None,
    })
}

/// Caractère de base d'une touche lettre / chiffre (pour Ctrl+touche).
fn key_char(key: egui::Key) -> Option<char> {
    let name = key.name();
    let mut chars = name.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii_alphanumeric() => Some(c.to_ascii_lowercase()),
        _ => None,
    }
}

/// Keysym X11 d'un caractère : Latin-1 tel quel, le reste en Unicode (0x01000000 + code).
pub fn char_keysym(c: char) -> u32 {
    match c {
        '\n' | '\r' => 0xFF0D,
        '\t' => 0xFF09,
        c if (' '..='~').contains(&c) || ('\u{a0}'..='\u{ff}').contains(&c) => c as u32,
        c => 0x0100_0000 + c as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keysyms_and_scancodes() {
        assert_eq!(char_keysym('a'), 0x61);
        assert_eq!(char_keysym('é'), 0xE9);
        assert_eq!(char_keysym('€'), 0x0100_20AC);
        assert_eq!(char_keysym('\n'), 0xFF0D);
        assert_eq!(scancode(egui::Key::A), Some(0x1E));
        assert_eq!(scancode(egui::Key::Num0), Some(0x0B));
        assert_eq!(scancode(egui::Key::F10), Some(0x44));
        assert_eq!(scancode(egui::Key::ArrowUp), Some(0xE048));
        assert_eq!(key_char(egui::Key::C), Some('c'));
        assert_eq!(key_char(egui::Key::Enter), None);
    }

    #[test]
    fn fixed_fit_scales_and_centers_with_correct_mouse_mapping() {
        // bureau 1920×1080 dans une zone 1000×1000 points (écran à 100 %)
        let view = Rect::from_min_size(pos2(100.0, 50.0), vec2(1000.0, 1000.0));
        let (img, scale) = place(view, Vec2::ZERO, 1920, 1080, 1.0, RdpDisplay::FixedFit);
        assert!((scale - 1000.0 / 1920.0).abs() < 1e-6);
        assert!((img.width() - 1000.0).abs() < 0.01 && (img.height() - 562.5).abs() < 0.01);
        assert!((img.center().y - view.center().y).abs() < 0.01, "centrée verticalement");
        assert_eq!(to_remote(img.min, img, scale, 1920, 1080), (0, 0));
        assert_eq!(to_remote(img.center(), img, scale, 1920, 1080), (960, 540));
        // hors de l'image : borné aux bords
        assert_eq!(to_remote(img.max + vec2(50.0, 50.0), img, scale, 1920, 1080), (1919, 1079));
        assert_eq!(to_remote(img.min - vec2(50.0, 50.0), img, scale, 1920, 1080), (0, 0));
        // petite résolution : agrandie (contrairement au mode dynamique, jamais au-delà de 1:1)
        let (img, scale) = place(view, Vec2::ZERO, 800, 600, 1.0, RdpDisplay::FixedFit);
        assert!((scale - 1000.0 / 800.0).abs() < 1e-6 && (img.width() - 1000.0).abs() < 0.01);
        assert_eq!(to_remote(img.min + vec2(500.0, 375.0), img, scale, 800, 600), (400, 300));
        let (_, dyn_scale) = place(view, Vec2::ZERO, 800, 600, 1.0, RdpDisplay::Dynamic);
        assert_eq!(dyn_scale, 1.0);
    }

    #[test]
    fn fixed_native_is_one_to_one_and_follows_scrolling() {
        // écran à 150 % : un pixel distant = 1/1.5 point
        let ppp = 1.5;
        let view = Rect::from_min_size(pos2(0.0, 0.0), vec2(800.0, 600.0));
        // 1920×1080 px = 1280×720 points : défile dans les deux sens
        let (img, scale) = place(view, vec2(200.0, 50.0), 1920, 1080, ppp, RdpDisplay::FixedNative);
        assert!((scale - 1.0 / ppp).abs() < 1e-6);
        assert_eq!(img.min, pos2(-200.0, -50.0));
        // le coin haut gauche visible correspond au pixel (300, 75)
        assert_eq!(to_remote(view.min, img, scale, 1920, 1080), (300, 75));
        assert_eq!(to_remote(pos2(100.0, 100.0), img, scale, 1920, 1080), (450, 225));
        // défilement au-delà de la fin : borné
        let (img, _) = place(view, vec2(5000.0, 5000.0), 1920, 1080, ppp, RdpDisplay::FixedNative);
        assert_eq!(img.max, view.max);
        // plus petit que la zone : centré, sans défilement
        let (img, scale) = place(view, vec2(30.0, 30.0), 600, 300, 1.0, RdpDisplay::FixedNative);
        assert_eq!(img, Rect::from_min_size(pos2(100.0, 150.0), vec2(600.0, 300.0)));
        assert_eq!(to_remote(pos2(110.0, 160.0), img, scale, 600, 300), (10, 10));
    }

    #[test]
    fn windows_keys_are_recognized() {
        assert!(is_windows_key(0xE05B) && is_windows_key(0xE05C));
        assert!(!is_windows_key(0x5B) && !is_windows_key(0x1D));
    }

    #[test]
    fn lock_keys_synced_on_focus_and_on_change() {
        let mut v = DesktopView::new(Protocol::Rdp);
        let on = LockKeys::default();
        assert!(on.num && !on.caps && !on.scroll, "Verr. Num allumé par défaut");
        let mut out = Vec::new();
        v.sync_locks(on, &mut out);
        assert_eq!(out, vec![Input::Locks(on)], "annoncés à la prise du focus");
        out.clear();
        v.sync_locks(on, &mut out);
        assert!(out.is_empty(), "une seule fois tant que rien ne change");
        let off = LockKeys { num: false, ..on };
        v.sync_locks(off, &mut out);
        assert_eq!(out, vec![Input::Locks(off)], "Verr. Num éteint ici : éteint là-bas");
        // reconnexion : le nouveau serveur ne les connaît pas
        v.resume();
        out.clear();
        v.sync_locks(off, &mut out);
        assert_eq!(out.len(), 1);
        v.sync_locks(on, &mut Vec::new());
        assert_eq!(LockKeys::from_bits(on.bits()), on);
        assert_eq!(LockKeys::from_bits(LockKeys { num: false, caps: true, scroll: true }.bits()), LockKeys { num: false, caps: true, scroll: true });
    }

    #[test]
    fn repeated_modifier_presses_are_recognized() {
        let mut v = DesktopView::new(Protocol::Rdp);
        assert!(!v.modifier_held(0x1D) && !v.modifier_held(0x2A));
        v.remap_key(0x1D, true);
        v.remap_key(0x2A, true);
        // Ctrl+Maj+Échap : Ctrl et Maj renvoyés par le crochet avant Échap, puis relevés ici
        assert!(v.modifier_held(0x1D) && v.modifier_held(0x2A) && !v.modifier_held(0x36));
        assert!(!v.modifier_held(0x01), "Échap n'est pas un modificateur");
        v.remap_key(0x2A, false);
        assert!(!v.modifier_held(0x2A));
    }

    #[test]
    fn ctrl_alt_end_becomes_ctrl_alt_delete() {
        let mut v = DesktopView::new(Protocol::Rdp);
        assert_eq!(v.remap_key(0xE04F, true), 0xE04F, "Fin seule");
        assert_eq!(v.remap_key(0xE04F, false), 0xE04F);
        v.remap_key(0x1D, true);
        v.remap_key(0x38, true);
        assert_eq!(v.remap_key(0xE04F, true), 0xE053);
        assert_eq!(v.remap_key(0xE04F, true), 0xE053, "répétition");
        // Alt relâché avant Fin : le relâchement suit l'appui
        v.remap_key(0x38, false);
        assert_eq!(v.remap_key(0xE04F, false), 0xE053);
        assert_eq!(v.remap_key(0xE04F, true), 0xE04F, "Ctrl+Fin");
    }

    #[test]
    fn frame_dirty_union_and_bounds() {
        let mut f = Frame::new();
        f.resize(100, 50);
        assert!(f.resized);
        f.mark(10, 10, 20, 20);
        f.mark(5, 15, 12, 80);
        assert_eq!(f.dirty, vec![[5, 10, 20, 50]]);
        f.mark(30, 30, 30, 40);
        assert_eq!(f.dirty, vec![[5, 10, 20, 50]], "zone vide ignorée");
        // zone éloignée : gardée à part (pas d'englobant de tout l'écran)
        f.mark(90, 0, 100, 5);
        assert_eq!(f.dirty, vec![[5, 10, 20, 50], [90, 0, 100, 5]]);
        // bord commun : réunies
        f.mark(80, 0, 90, 5);
        assert_eq!(f.dirty, vec![[5, 10, 20, 50], [80, 0, 100, 5]]);
        // trop de zones : réunies, la couverture reste complète
        for i in 0..40 {
            f.mark(i * 2, 30 + i % 3 * 6, i * 2 + 1, 31 + i % 3 * 6);
        }
        assert!(f.dirty.len() <= MAX_DIRTY);
        for i in 0..40 {
            let (x, y) = (i * 2, 30 + i % 3 * 6);
            assert!(f.dirty.iter().any(|d| d[0] <= x && x < d[2] && d[1] <= y && y < d[3]), "({x}, {y}) perdu : {:?}", f.dirty);
        }
        assert_eq!(clamp_size(1001.4, 300.0), (1000, 300));
    }

    #[test]
    fn size_bounds_match_the_session_and_the_validation() {
        // la validation accepte une résolution de 200 pixels : elle ne doit pas devenir 640×480
        assert_eq!(clamp_size(200.0, 200.0), (200, 200));
        assert_eq!(clamp_size(301.0, 250.0), (300, 250), "largeur paire");
        assert_eq!(clamp_size(50.0, 0.0), (200, 200));
        assert_eq!(clamp_size(9000.0, 9000.0), (8192, 8192));
    }

    struct Run {
        time: f64,
        ppp: f32,
        focused: Option<bool>,
        minimized: Option<bool>,
    }

    /// Une image headless de 800×600 points contenant uniquement le bureau.
    fn show(ctx: &egui::Context, view: &mut DesktopView, frame: &SharedFrame, r: &Run, events: Vec<egui::Event>) -> ViewOutput {
        let mut input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(800.0, 600.0))),
            time: Some(r.time),
            events,
            ..Default::default()
        };
        let vp = input.viewports.entry(egui::ViewportId::ROOT).or_default();
        vp.native_pixels_per_point = Some(r.ppp);
        vp.focused = r.focused;
        vp.minimized = r.minimized;
        let mut out = ViewOutput::default();
        let mut full = ctx.run_ui(input, |root| {
            egui::CentralPanel::default().frame(egui::Frame::NONE).show(root, |ui| {
                out = view.show(ui, frame, true);
            });
        });
        full.textures_delta.clear();
        out
    }

    fn shared(w: usize, h: usize) -> SharedFrame {
        let f: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        f.lock().unwrap().resize(w, h);
        f
    }

    fn rdp(display: RdpDisplay) -> DesktopView {
        DesktopView::new(Protocol::Rdp).with_options(ViewOptions { display, server_pointer: false, windows_keys: false })
    }

    #[test]
    fn keyboard_released_when_the_window_loses_focus() {
        let ctx = egui::Context::default();
        let frame = shared(400, 300);
        let mut view = rdp(RdpDisplay::FixedFit);
        let mut r = Run { time: 0.0, ppp: 1.0, focused: Some(true), minimized: None };
        for _ in 0..2 {
            let out = show(&ctx, &mut view, &frame, &r, vec![]);
            assert!(!out.input.contains(&Input::ReleaseAll));
            r.time += 0.1;
        }
        // Alt+Tab vers une autre application : egui garde le focus de l'élément, pas le bureau
        r.focused = Some(false);
        let out = show(&ctx, &mut view, &frame, &r, vec![]);
        assert!(out.input.contains(&Input::ReleaseAll), "touches relâchées à la perte du focus : {:?}", out.input);
        assert!(!view.focused);
        r.focused = Some(true);
        let _ = show(&ctx, &mut view, &frame, &r, vec![]);
        assert!(view.focused, "focus repris au retour");
    }

    #[test]
    fn drag_follows_the_mouse_outside_the_image() {
        let ctx = egui::Context::default();
        // 400×400 ajusté dans 800×600 : image de 600×600 points, de x = 100 à 700
        let frame = shared(400, 400);
        let mut view = rdp(RdpDisplay::FixedFit);
        let r = Run { time: 0.0, ppp: 1.0, focused: Some(true), minimized: None };
        let _ = show(&ctx, &mut view, &frame, &r, vec![egui::Event::PointerMoved(pos2(400.0, 300.0))]);
        let press = |pressed, p| egui::Event::PointerButton { pos: p, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        let out = show(&ctx, &mut view, &frame, &r, vec![press(true, pos2(400.0, 300.0))]);
        assert!(out.input.contains(&Input::Button { button: MouseBtn::Left, down: true }));
        // bande noire à droite, puis hors de la fenêtre : la position reste bornée au bord
        let out = show(&ctx, &mut view, &frame, &r, vec![egui::Event::PointerMoved(pos2(750.0, 300.0))]);
        assert_eq!(out.input, vec![Input::Mouse { x: 399, y: 200 }]);
        let out = show(&ctx, &mut view, &frame, &r, vec![egui::Event::PointerMoved(pos2(-50.0, 900.0))]);
        assert_eq!(out.input, vec![Input::Mouse { x: 0, y: 399 }]);
        let out = show(&ctx, &mut view, &frame, &r, vec![press(false, pos2(-50.0, 900.0))]);
        assert_eq!(out.input, vec![Input::Button { button: MouseBtn::Left, down: false }]);
        // bouton relâché : plus rien hors de l'image
        let out = show(&ctx, &mut view, &frame, &r, vec![egui::Event::PointerMoved(pos2(750.0, 100.0))]);
        assert!(out.input.is_empty(), "{:?}", out.input);
    }

    #[test]
    fn native_mode_maps_the_mouse_with_a_dpi_zoom() {
        let ctx = egui::Context::default();
        // écran à 150 % : 300×300 pixels = 200×200 points, centrés dans 800×600 points
        let frame = shared(300, 300);
        let mut view = rdp(RdpDisplay::FixedNative);
        let r = Run { time: 0.0, ppp: 1.5, focused: Some(true), minimized: None };
        let _ = show(&ctx, &mut view, &frame, &r, vec![]);
        let out = show(&ctx, &mut view, &frame, &r, vec![egui::Event::PointerMoved(pos2(400.0, 250.0))]);
        assert_eq!(out.input, vec![Input::Mouse { x: 150, y: 75 }]);
        // molette : au bureau distant (la zone 1:1 ne défile qu'avec ses barres)
        let wheel = egui::Event::MouseWheel { unit: egui::MouseWheelUnit::Line, delta: vec2(0.0, -1.0), modifiers: Default::default(), phase: egui::TouchPhase::Move };
        let out = show(&ctx, &mut view, &frame, &r, vec![wheel]);
        assert_eq!(out.input, vec![Input::Wheel { vertical: true, units: -120 }]);
    }

    #[test]
    fn no_resize_in_fixed_modes_nor_when_minimized() {
        for display in [RdpDisplay::FixedFit, RdpDisplay::FixedNative, RdpDisplay::Dynamic] {
            let ctx = egui::Context::default();
            let frame = shared(1024, 768);
            let mut view = rdp(display);
            let mut sent = Vec::new();
            let mut r = Run { time: 0.0, ppp: 1.25, focused: Some(true), minimized: None };
            for step in 0..40 {
                // reconnexion automatique au milieu, et fenêtre réduite un moment
                if step == 20 {
                    view.resume();
                }
                r.minimized = Some((25..32).contains(&step));
                if let Some(s) = show(&ctx, &mut view, &frame, &r, vec![]).resize {
                    sent.push((step, s));
                }
                r.time += 0.2;
            }
            if display == RdpDisplay::Dynamic {
                // 800×600 points à 125 % ; envoyée une fois stable, puis de nouveau après la reconnexion
                assert_eq!(sent.len(), 2, "{sent:?}");
                assert!(sent.iter().all(|(_, s)| *s == (1000, 750)));
                assert!(sent[1].0 >= 20);
            } else {
                assert!(sent.is_empty(), "{display:?} : {sent:?}");
            }
        }
    }

    /// Une image headless qui renvoie les mises à jour de textures produites.
    fn show_deltas(ctx: &egui::Context, view: &mut DesktopView, frame: &SharedFrame, ppp: f32) -> egui::TexturesDelta {
        let mut input = egui::RawInput { screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(800.0, 600.0))), ..Default::default() };
        input.viewports.entry(egui::ViewportId::ROOT).or_default().native_pixels_per_point = Some(ppp);
        ctx.run_ui(input, |root| {
            egui::CentralPanel::default().frame(egui::Frame::NONE).show(root, |ui| {
                let _ = view.show(ui, frame, true);
            });
        })
        .textures_delta
    }

    /// Texture simulée : les mises à jour d'egui appliquées comme le ferait le moteur de rendu.
    #[derive(Default)]
    struct Gpu {
        size: [usize; 2],
        pixels: Vec<Color32>,
        options: Option<TextureOptions>,
        /// Pixels téléversés (hors changements de filtrage).
        uploaded: usize,
    }

    impl Gpu {
        fn apply(&mut self, mut delta: egui::TexturesDelta) {
            for (id, list) in &delta.set {
                if *id == egui::TextureId::default() {
                    continue; // police d'egui
                }
                for d in list {
                    let egui::ImageData::Color(img) = &d.image;
                    let filter_only = img.size == [1, 1] && d.pos == Some([0, 0]) && self.pixels.first() == img.pixels.first();
                    if !filter_only {
                        self.uploaded += img.pixels.len();
                    }
                    self.options = Some(d.options);
                    match d.pos {
                        None => {
                            self.size = img.size;
                            self.pixels = img.pixels.to_vec();
                        }
                        Some([x, y]) => {
                            assert!(x + img.size[0] <= self.size[0] && y + img.size[1] <= self.size[1], "hors texture");
                            for r in 0..img.size[1] {
                                let dst = (y + r) * self.size[0] + x;
                                self.pixels[dst..dst + img.size[0]].copy_from_slice(&img.pixels[r * img.size[0]..][..img.size[0]]);
                            }
                        }
                    }
                }
            }
            delta.clear();
        }

        fn check(&self, frame: &SharedFrame, what: &str) {
            let f = frame.lock().unwrap();
            assert_eq!(self.size, [f.width, f.height], "{what} : taille");
            if let Some(i) = (0..f.pixels.len()).find(|&i| f.pixels[i] != self.pixels[i]) {
                panic!("{what} : pixel ({}, {}) périmé à l'écran", i % f.width, i / f.width);
            }
        }
    }

    /// Écrit des pixels distincts dans une zone, comme une mise à jour du serveur.
    fn paint(frame: &SharedFrame, [x0, y0, x1, y1]: [usize; 4], seed: u8) {
        let mut f = frame.lock().unwrap();
        let w = f.width;
        for y in y0..y1 {
            for x in x0..x1 {
                f.pixels[y * w + x] = Color32::from_rgb(seed, x as u8, y as u8);
            }
        }
        f.mark(x0, y0, x1, y1);
    }

    #[test]
    fn texture_follows_scattered_updates_resize_and_reconnection() {
        let ctx = egui::Context::default();
        let frame = shared(64, 48);
        let mut view = rdp(RdpDisplay::Dynamic);
        let mut gpu = Gpu::default();
        paint(&frame, [0, 0, 64, 48], 1);
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.0));
        gpu.check(&frame, "première image");
        // 1:1 : image nette
        assert_eq!(gpu.options, Some(TextureOptions::NEAREST));

        // petites zones dans des coins opposés : seules elles sont envoyées
        gpu.uploaded = 0;
        paint(&frame, [0, 0, 3, 2], 2);
        paint(&frame, [61, 45, 64, 48], 3);
        paint(&frame, [62, 0, 64, 1], 4);
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.0));
        gpu.check(&frame, "coins opposés");
        assert_eq!(gpu.uploaded, 3 * 2 + 3 * 3 + 2, "seulement les zones modifiées");

        // nombreuses zones éparses (au-delà de la limite) puis zones qui se recouvrent
        for i in 0..50usize {
            paint(&frame, [(i * 7) % 60, (i * 11) % 44, (i * 7) % 60 + 3, (i * 11) % 44 + 2], 5 + i as u8);
        }
        paint(&frame, [10, 10, 30, 20], 60);
        paint(&frame, [20, 15, 40, 30], 61);
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.0));
        gpu.check(&frame, "zones éparses");

        // rien de nouveau : rien d'envoyé
        gpu.uploaded = 0;
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.0));
        assert_eq!(gpu.uploaded, 0);

        // redimensionnement (zones marquées avant puis après)
        paint(&frame, [0, 0, 5, 5], 70);
        frame.lock().unwrap().resize(80, 40);
        paint(&frame, [70, 30, 80, 40], 71);
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.0));
        gpu.check(&frame, "après redimensionnement");
        paint(&frame, [0, 39, 80, 40], 72);
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.0));
        gpu.check(&frame, "dernière ligne");

        // reconnexion : même taille, le nouveau serveur repeint tout puis des morceaux
        view.resume();
        frame.lock().unwrap().resize(80, 40);
        paint(&frame, [0, 0, 80, 40], 80);
        paint(&frame, [79, 0, 80, 40], 81);
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.0));
        gpu.check(&frame, "reconnexion");

        // écran à 125 % : toujours 1:1 (pixels physiques), puis vue mise à l'échelle : linéaire
        paint(&frame, [5, 5, 6, 6], 90);
        gpu.apply(show_deltas(&ctx, &mut view, &frame, 1.25));
        gpu.check(&frame, "125 %");
        assert_eq!(gpu.options, Some(TextureOptions::NEAREST));
        let mut fit = rdp(RdpDisplay::FixedFit);
        let mut gpu2 = Gpu::default();
        gpu2.apply(show_deltas(&ctx, &mut fit, &frame, 1.25));
        gpu2.check(&frame, "ajustée");
        assert_eq!(gpu2.options, Some(TextureOptions::LINEAR));
    }

    #[test]
    fn native_image_is_aligned_on_physical_pixels() {
        // image centrée à une position non entière en pixels physiques
        for (display, ppp) in [(RdpDisplay::Dynamic, 1.25), (RdpDisplay::FixedNative, 1.5), (RdpDisplay::Dynamic, 1.0)] {
            let ctx = egui::Context::default();
            let frame = shared(333, 201);
            let mut view = rdp(display);
            let mut input = egui::RawInput { screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(800.0, 600.0))), ..Default::default() };
            input.viewports.entry(egui::ViewportId::ROOT).or_default().native_pixels_per_point = Some(ppp);
            let mut full = ctx.run_ui(input, |root| {
                egui::CentralPanel::default().frame(egui::Frame::NONE).show(root, |ui| {
                    let _ = view.show(ui, &frame, true);
                });
            });
            full.textures_delta.clear();
            let tex = view.texture.as_ref().unwrap().id();
            let rect = full
                .shapes
                .iter()
                .find_map(|c| match &c.shape {
                    egui::Shape::Rect(r) if r.fill_texture_id() == tex => Some(r.rect),
                    egui::Shape::Mesh(m) if m.texture_id == tex => Some(Rect::from_points(&m.vertices.iter().map(|v| v.pos).collect::<Vec<_>>())),
                    _ => None,
                })
                .expect("image dessinée");
            for c in [rect.min.x, rect.min.y, rect.max.x, rect.max.y] {
                let px = c * ppp;
                assert!((px - px.round()).abs() < 1e-3, "{display:?} à {ppp} : bord à {px} pixels physiques");
            }
        }
    }

    /// Mesure (ignorée par défaut) : 60 images/s de petites mises à jour RDPGFX sur un écran
    /// 1920×1080, du compositeur jusqu'à la préparation de la texture.
    /// `cargo test --release perf_small_updates -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn perf_small_updates_1080p() {
        use ironrdp_dvc::DvcProcessor as _;
        use ironrdp_egfx::pdu::*;
        let (w, h) = (1920u16, 1080u16);
        let wire = |pdus: Vec<GfxPdu>| {
            let mut raw = Vec::new();
            for p in &pdus {
                raw.extend(ironrdp_core::encode_vec(p).unwrap());
            }
            ironrdp_graphics::zgfx::wrap_uncompressed(&raw)
        };
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (events, _rx) = crate::ssh::Events::new(egui::Context::default());
        let mut c = crate::gfx::client(frame.clone(), events, Default::default(), crate::gfx::Codecs::NoAvc);
        c.start(1).unwrap();
        let cap = CapabilitySet::V10_7 { flags: CapabilitiesV107Flags::AVC_DISABLED };
        c.process(
            1,
            &wire(vec![
                GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&cap)),
                GfxPdu::ResetGraphics(ResetGraphicsPdu { width: w.into(), height: h.into(), monitors: vec![] }),
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 1, width: w, height: h, pixel_format: PixelFormat::XRgb }),
                GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 1, output_origin_x: 0, output_origin_y: 0 }),
            ]),
        )
        .unwrap();
        let ctx = egui::Context::default();
        let mut view = rdp(RdpDisplay::Dynamic);
        show_deltas(&ctx, &mut view, &frame, 1.0).clear();
        // par image : frappe au clavier (haut gauche), horloge (bas droite), curseur de texte qui se déplace
        let tile = |x: u16, y: u16, tw: u16, th: u16, v: u8| GfxPdu::WireToSurface1(WireToSurface1Pdu {
            surface_id: 1,
            codec_id: Codec1Type::Uncompressed,
            pixel_format: PixelFormat::XRgb,
            destination_rectangle: ironrdp_pdu::geometry::ExclusiveRectangle { left: x, top: y, right: x + tw, bottom: y + th },
            bitmap_data: vec![v; tw as usize * th as usize * 4],
        });
        const N: u32 = 600;
        let (mut t_comp, mut t_tex, mut bytes) = (std::time::Duration::ZERO, std::time::Duration::ZERO, 0usize);
        for n in 0..N {
            let v = n as u8;
            let k = n as u16;
            let pdus = vec![
                GfxPdu::StartFrame(StartFramePdu { timestamp: Timestamp { milliseconds: 0, seconds: 0, minutes: 0, hours: 0 }, frame_id: n }),
                tile(40 + (k * 8) % 600, 60, 16, 24, v),
                tile(1840, 1050, 64, 24, v),
                tile(200 + (k * 37) % 1500, 200 + (k * 53) % 800, 64, 64, v),
                GfxPdu::EndFrame(EndFramePdu { frame_id: n }),
            ];
            let msg = wire(pdus);
            let t0 = std::time::Instant::now();
            c.process(1, &msg).unwrap();
            let t1 = std::time::Instant::now();
            let mut d = show_deltas(&ctx, &mut view, &frame, 1.0);
            t_tex += t1.elapsed();
            t_comp += t1 - t0;
            bytes += d.set.values().flatten().map(|d| d.image.width() * d.image.height() * 4).sum::<usize>();
            d.clear();
        }
        let per = |t: std::time::Duration| t.as_secs_f64() * 1e6 / N as f64;
        println!(
            "1920×1080, {N} images : compositeur {:.1} µs/image, interface + texture {:.1} µs/image, {:.1} Ko téléversés/image, CPU à 60 i/s ≈ {:.2} %",
            per(t_comp),
            per(t_tex),
            bytes as f64 / N as f64 / 1024.0,
            (per(t_comp) + per(t_tex)) * 60.0 / 1e6 * 100.0
        );
    }
}
