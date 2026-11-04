//! Émulateur de terminal : parsing vt100 + rendu egui + saisie clavier/souris, au comportement
//! d'une vraie console Linux (sélection, presse-papiers, souris pour les applis, recherche, liens…).

use crate::model::Settings;
use crate::theme::{self, mono_bold};
use crate::widgets::{self as w, Icon};
use eframe::egui::{self, Color32, FontId, Key, Pos2, Rect, Sense, Stroke, Vec2, vec2};
use std::sync::atomic::{AtomicBool, Ordering};
use vt100::{MouseProtocolEncoding, MouseProtocolMode};

pub const BG: Color32 = Color32::from_rgb(0x0A, 0x0D, 0x13);
const FG: Color32 = Color32::from_rgb(0xD8, 0xDE, 0xE9);
const CURSOR: Color32 = Color32::from_rgb(0x2D, 0xD4, 0xBF);
const SELECTION: Color32 = Color32::from_rgba_premultiplied(0x1E, 0x55, 0x60, 0xA0);
const MATCH: Color32 = Color32::from_rgba_premultiplied(0x6E, 0x55, 0x10, 0x90);
const LINK: Color32 = Color32::from_rgb(0x38, 0xBD, 0xF8);
const PAD: f32 = 10.0;

/// Un terminal a le focus clavier : ses touches passent avant les raccourcis d'egui et d'Escale.
pub static FOCUSED: AtomicBool = AtomicBool::new(false);

const ANSI: [Color32; 16] = [
    Color32::from_rgb(0x1C, 0x21, 0x2B),
    Color32::from_rgb(0xF0, 0x71, 0x78),
    Color32::from_rgb(0x8B, 0xD5, 0x8B),
    Color32::from_rgb(0xF2, 0xC8, 0x6B),
    Color32::from_rgb(0x6C, 0xA8, 0xF0),
    Color32::from_rgb(0xC5, 0x92, 0xE8),
    Color32::from_rgb(0x4F, 0xD6, 0xC6),
    Color32::from_rgb(0xC8, 0xCE, 0xD8),
    Color32::from_rgb(0x55, 0x5E, 0x6E),
    Color32::from_rgb(0xFF, 0x8F, 0x95),
    Color32::from_rgb(0xA6, 0xE8, 0xA0),
    Color32::from_rgb(0xFF, 0xDB, 0x8A),
    Color32::from_rgb(0x8E, 0xC2, 0xFF),
    Color32::from_rgb(0xDB, 0xB0, 0xFA),
    Color32::from_rgb(0x7F, 0xEC, 0xDD),
    Color32::from_rgb(0xF4, 0xF6, 0xFA),
];

fn color(c: vt100::Color, default: Color32) -> Color32 {
    match c {
        vt100::Color::Default => default,
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(i) if i < 16 => ANSI[i as usize],
        vt100::Color::Idx(i) if i < 232 => {
            let i = i - 16;
            let v = |n: u8| if n == 0 { 0 } else { 55 + n * 40 };
            Color32::from_rgb(v(i / 36), v((i / 6) % 6), v(i % 6))
        }
        vt100::Color::Idx(i) => {
            let g = 8 + (i - 232) * 10;
            Color32::from_rgb(g, g, g)
        }
    }
}

// ---------------------------------------------------------------- séquences hors écran

#[derive(Clone, Copy, PartialEq)]
enum CursorShape {
    Block,
    Underline,
    Bar,
}

/// Reçoit du parseur les séquences qui ne modifient pas l'écran (titre, cloche, requêtes…).
struct Callbacks {
    title: Option<String>,
    bell: bool,
    replies: Vec<u8>,
    clipboard: Option<String>,
    cursor_shape: CursorShape,
    cursor_blink: bool,
    focus_reporting: bool,
}

impl Default for Callbacks {
    fn default() -> Self {
        Self {
            title: None,
            bell: false,
            replies: Vec::new(),
            clipboard: None,
            cursor_shape: CursorShape::Block,
            cursor_blink: true,
            focus_reporting: false,
        }
    }
}

fn first_param(params: &[&[u16]]) -> u16 {
    params.first().and_then(|p| p.first()).copied().unwrap_or(0)
}

impl vt100::Callbacks for Callbacks {
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.bell = true;
    }

    fn visual_bell(&mut self, _: &mut vt100::Screen) {
        self.bell = true;
    }

    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        let t = String::from_utf8_lossy(title).trim().to_string();
        self.title = (!t.is_empty()).then_some(t);
    }

    fn set_window_icon_name(&mut self, s: &mut vt100::Screen, name: &[u8]) {
        if self.title.is_none() {
            self.set_window_title(s, name);
        }
    }

    fn copy_to_clipboard(&mut self, _: &mut vt100::Screen, _ty: &[u8], data: &[u8]) {
        if let Some(bytes) = base64_decode(data) {
            self.clipboard = Some(String::from_utf8_lossy(&bytes).into_owned());
        }
    }

    fn unhandled_csi(&mut self, screen: &mut vt100::Screen, i1: Option<u8>, _i2: Option<u8>, params: &[&[u16]], c: char) {
        match (i1, c) {
            // DSR : état du terminal / position du curseur
            (None, 'n') => match first_param(params) {
                5 => self.replies.extend_from_slice(b"\x1b[0n"),
                6 => {
                    let (r, c) = screen.cursor_position();
                    self.replies.extend_from_slice(format!("\x1b[{};{}R", r + 1, c + 1).as_bytes());
                }
                _ => {}
            },
            // DA1 / DA2 : identification du terminal
            (None, 'c') => self.replies.extend_from_slice(b"\x1b[?62;22c"),
            (Some(b'>'), 'c') => self.replies.extend_from_slice(b"\x1b[>1;10;0c"),
            // DECSCUSR : forme du curseur
            (Some(b' '), 'q') => {
                let p = first_param(params);
                self.cursor_shape = match p {
                    3 | 4 => CursorShape::Underline,
                    5 | 6 => CursorShape::Bar,
                    _ => CursorShape::Block,
                };
                self.cursor_blink = p == 0 || p % 2 == 1;
            }
            // mode 1004 : signalement du focus
            (Some(b'?'), 'h' | 'l') if params.iter().any(|p| p.first() == Some(&1004)) => {
                self.focus_reporting = c == 'h';
            }
            // taille de la zone de texte
            (None, 't') if first_param(params) == 18 => {
                let (rows, cols) = screen.size();
                self.replies.extend_from_slice(format!("\x1b[8;{rows};{cols}t").as_bytes());
            }
            _ => {}
        }
    }

    fn unhandled_osc(&mut self, _: &mut vt100::Screen, params: &[&[u8]]) {
        // requêtes de couleur (vim, fzf… s'adaptent au fond)
        if params.len() >= 2 && params[1] == b"?" {
            let rgb = match params[0] {
                b"10" => "d8d8/dede/e9e9",
                b"11" => "0a0a/0d0d/1313",
                b"12" => "2d2d/d4d4/bfbf",
                _ => return,
            };
            let n = String::from_utf8_lossy(params[0]);
            self.replies.extend_from_slice(format!("\x1b]{n};rgb:{rgb}\x1b\\").as_bytes());
        }
    }
}

fn base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let clean: Vec<u8> = data.iter().copied().filter(|c| !c.is_ascii_whitespace() && *c != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c)? << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

// ---------------------------------------------------------------- sélection & recherche

/// Position absolue : `line` = 0 pour la première ligne de l'écran, négative dans l'historique.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Pos {
    line: i64,
    col: u16,
}

#[derive(Clone, Copy, PartialEq)]
enum SelMode {
    Char,
    Word,
    Line,
}

#[derive(Clone, Copy)]
struct Selection {
    anchor: Pos,
    head: Pos,
    mode: SelMode,
    /// Plage calculée [début, fin[ (mise à jour à chaque modification).
    range: Option<(Pos, Pos)>,
}

struct Search {
    query: String,
    searched: String,
    generation: u64,
    matches: Vec<(i64, u16, u16)>,
    current: Option<usize>,
    focus: bool,
}

enum MenuAction {
    Copy,
    Paste,
    PastePrimary,
    SelectAll,
    Find,
    ClearScrollback,
    Reset,
    OpenLink(String),
    CopyLink(String),
}

/// Résultat d'une frame : octets à envoyer au serveur, etc.
#[derive(Default)]
pub struct Output {
    pub bytes: Vec<u8>,
    pub resize: Option<(u16, u16)>,
    /// Collage de plusieurs lignes à confirmer par l'utilisateur.
    pub paste_request: Option<String>,
}

/// Effets d'un bloc de données reçu du serveur.
#[derive(Default)]
pub struct Feed {
    pub reply: Vec<u8>,
    pub bell: bool,
    pub clipboard: Option<String>,
}

/// Ligne qui demande le mot de passe du compte (`[sudo] password for theo:`, `Mot de passe :`…).
/// Les phrases secrètes de clé et les nouveaux mots de passe (passwd) sont exclus : le mot de passe
/// enregistré n'y a pas sa place.
fn is_password_prompt(line: &str) -> bool {
    let l = line.trim_end().to_lowercase();
    if !l.ends_with(':') || l.chars().count() > 120 {
        return false;
    }
    let asks = ["password", "mot de passe", "passwort", "contraseña", "senha", "wachtwoord"].iter().any(|w| l.contains(w));
    let other = ["passphrase", "new ", "nouveau", "retype", "confirm", "again", "encore", "vault", "verification code", "otp"]
        .iter()
        .any(|w| l.contains(w));
    asks && !other
}

/// Invite de sudo parmi les invites de mot de passe : préfixe `[sudo]`, ou `Password:` seul
/// lorsque la ligne au-dessus (`above`) lance `sudo`. Les autres invites (su, ssh…) sont exclues.
fn is_sudo_prompt(line: &str, above: &str) -> bool {
    if !is_password_prompt(line) {
        return false;
    }
    let l = line.trim().to_lowercase();
    l.starts_with("[sudo]") || (l == "password:" && above.split_whitespace().any(|w| w == "sudo"))
}

pub struct Terminal {
    parser: vt100::Parser<Callbacks>,
    scrollback_len: usize,
    rows: u16,
    cols: u16,
    sel: Option<Selection>,
    search: Option<Search>,
    generation: u64,
    wheel_acc: f32,
    mouse_button: Option<u8>,
    last_mouse_cell: (u16, u16),
    bell_at: Option<f64>,
    blink_epoch: f64,
    was_focused: bool,
}

impl Terminal {
    pub fn new(scrollback: usize) -> Self {
        Self {
            parser: vt100::Parser::new_with_callbacks(24, 80, scrollback, Callbacks::default()),
            scrollback_len: scrollback,
            rows: 24,
            cols: 80,
            sel: None,
            search: None,
            generation: 0,
            wheel_acc: 0.0,
            mouse_button: None,
            last_mouse_cell: (u16::MAX, u16::MAX),
            bell_at: None,
            blink_epoch: 0.0,
            was_focused: false,
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// Invite de mot de passe (sudo, su, doas…) sur la ligne du curseur, à l'écran principal et
    /// sans défilement de l'historique.
    pub fn password_prompt(&self) -> bool {
        let s = self.parser.screen();
        if s.alternate_screen() || s.scrollback() != 0 {
            return false;
        }
        let (row, col) = s.cursor_position();
        is_password_prompt(&s.contents_between(row, 0, row, col))
    }

    /// Invite de mot de passe de sudo uniquement (envoi automatique) : `[sudo] password for theo:`,
    /// ou un simple `Password:` (sudo de macOS / BSD) juste sous une ligne de commande `sudo …`.
    pub fn sudo_prompt(&self) -> bool {
        if !self.password_prompt() {
            return false;
        }
        let s = self.parser.screen();
        let (row, col) = s.cursor_position();
        let line = s.contents_between(row, 0, row, col);
        let above = if row > 0 { s.contents_between(row - 1, 0, row - 1, self.cols) } else { String::new() };
        is_sudo_prompt(&line, &above)
    }

    /// Titre défini par l'application distante (OSC 0/2).
    pub fn title(&self) -> Option<&str> {
        self.parser.callbacks().title.as_deref()
    }

    fn history_len(&mut self) -> usize {
        let cur = self.parser.screen().scrollback();
        self.parser.screen_mut().set_scrollback(usize::MAX);
        let n = self.parser.screen().scrollback();
        self.parser.screen_mut().set_scrollback(cur);
        n
    }

    /// Traite des données reçues ; renvoie les réponses à transmettre et les effets.
    pub fn feed(&mut self, data: &[u8]) -> Feed {
        let before = self.history_len();
        let view = self.parser.screen().scrollback();
        self.guarded(|p| p.process(data));
        self.generation += 1;
        let after = self.history_len();
        let delta = after.saturating_sub(before) as i64;
        if delta > 0 {
            // l'écran a défilé : on garde la sélection et la vue sur le même contenu
            if let Some(s) = &mut self.sel {
                s.anchor.line -= delta;
                s.head.line -= delta;
                if let Some((a, b)) = &mut s.range {
                    a.line -= delta;
                    b.line -= delta;
                }
            }
            if view > 0 {
                self.parser.screen_mut().set_scrollback(view + delta as usize);
            }
        } else if after >= self.scrollback_len && data.contains(&b'\n') {
            // historique plein : impossible de suivre le contenu, on abandonne la sélection
            self.sel = None;
        }
        let cb = self.parser.callbacks_mut();
        Feed { reply: std::mem::take(&mut cb.replies), bell: std::mem::take(&mut cb.bell), clipboard: cb.clipboard.take() }
    }

    /// Octets à envoyer pour coller `text` (gère le mode « bracketed paste »).
    pub fn paste_payload(&self, text: &str) -> Vec<u8> {
        let t = text.replace("\r\n", "\r").replace('\n', "\r");
        let mut buf = Vec::with_capacity(t.len() + 12);
        if self.parser.screen().bracketed_paste() {
            buf.extend_from_slice(b"\x1b[200~");
            buf.extend_from_slice(t.as_bytes());
            buf.extend_from_slice(b"\x1b[201~");
        } else {
            buf.extend_from_slice(t.as_bytes());
        }
        buf
    }

    fn paste(&mut self, text: String, cfg: &Settings, out: &mut Output) {
        if text.is_empty() {
            return;
        }
        self.sel = None;
        if cfg.confirm_multiline_paste && text.trim_end_matches(['\r', '\n']).contains('\n') {
            out.paste_request = Some(text);
        } else {
            out.bytes.extend(self.paste_payload(&text));
        }
    }

    fn scroll_by(&mut self, lines: i64) {
        let cur = self.parser.screen().scrollback() as i64;
        self.parser.screen_mut().set_scrollback((cur + lines).max(0) as usize);
    }

    fn clear_scrollback(&mut self) {
        let state = self.parser.screen().state_formatted();
        let title = self.parser.callbacks().title.clone();
        let mut p = vt100::Parser::new_with_callbacks(self.rows, self.cols, self.scrollback_len, Callbacks::default());
        p.process(&state);
        p.callbacks_mut().title = title;
        self.parser = p;
        self.sel = None;
        self.generation += 1;
    }

    /// Opération sur l'émulateur protégée contre ses paniques internes : l'écran est réinitialisé
    /// (l'historique est perdu) plutôt que de fermer Escale.
    fn guarded(&mut self, op: impl FnOnce(&mut vt100::Parser<Callbacks>)) {
        let parser = &mut self.parser;
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| op(parser))).is_err() {
            let title = self.parser.callbacks().title.clone();
            let mut p = vt100::Parser::new_with_callbacks(self.rows.max(3), self.cols.max(10), self.scrollback_len, Callbacks::default());
            p.process("\x1b[90m\u{203a} Affichage réinitialisé après une erreur de l'émulateur\x1b[0m\r\n".as_bytes());
            p.callbacks_mut().title = title;
            self.parser = p;
            self.sel = None;
        }
    }

    fn reset(&mut self) {
        self.parser.process(b"\x1bc");
        self.clear_scrollback();
    }

    // ---- accès aux lignes (écran + historique)

    /// Contenu d'une ligne absolue : une chaîne par colonne + indicateur de retour à la ligne automatique.
    fn line_cells(&mut self, abs: i64) -> (Vec<String>, bool) {
        let cur = self.parser.screen().scrollback();
        let want = if abs < 0 { (-abs) as usize } else { 0 };
        self.parser.screen_mut().set_scrollback(want);
        let real = self.parser.screen().scrollback() as i64;
        let r = abs + real;
        let mut cells = Vec::with_capacity(self.cols as usize);
        let mut wrapped = false;
        if (0..self.rows as i64).contains(&r) && (abs >= 0 || real as i64 >= -abs) {
            let scr = self.parser.screen();
            for c in 0..self.cols {
                cells.push(match scr.cell(r as u16, c) {
                    Some(cl) if cl.is_wide_continuation() => String::new(),
                    Some(cl) if cl.has_contents() => cl.contents().to_string(),
                    _ => " ".to_string(),
                });
            }
            wrapped = scr.row_wrapped(r as u16);
        } else {
            cells.resize(self.cols as usize, " ".to_string());
        }
        self.parser.screen_mut().set_scrollback(cur);
        (cells, wrapped)
    }

    fn text_range(&mut self, start: Pos, end: Pos) -> String {
        let mut out = String::new();
        let cols = self.cols;
        for line in start.line..=end.line {
            let (cells, wrapped) = self.line_cells(line);
            let c0 = if line == start.line { start.col.min(cols) } else { 0 } as usize;
            let c1 = if line == end.line { end.col.min(cols) } else { cols } as usize;
            let last = line == end.line;
            let mut s: String = if c1 > c0 { cells[c0..c1].concat() } else { String::new() };
            if !wrapped || last {
                s.truncate(s.trim_end().len());
            }
            out.push_str(&s);
            if !last && !wrapped {
                out.push('\n');
            }
        }
        out
    }

    fn word_bounds(&mut self, p: Pos) -> (Pos, Pos) {
        let (cells, _) = self.line_cells(p.line);
        let is_word = |c: usize| {
            cells.get(c).is_some_and(|s| !s.is_empty() && s.chars().all(|ch| ch.is_alphanumeric() || "-_./~:@%+=?&#,".contains(ch)))
        };
        let c = (p.col as usize).min(cells.len().saturating_sub(1));
        if !is_word(c) {
            return (Pos { line: p.line, col: c as u16 }, Pos { line: p.line, col: c as u16 + 1 });
        }
        let (mut a, mut b) = (c, c);
        while a > 0 && is_word(a - 1) {
            a -= 1;
        }
        while b + 1 < cells.len() && is_word(b + 1) {
            b += 1;
        }
        (Pos { line: p.line, col: a as u16 }, Pos { line: p.line, col: b as u16 + 1 })
    }

    fn update_selection(&mut self) {
        let Some(s) = self.sel else { return };
        let (a, b) = if s.anchor <= s.head { (s.anchor, s.head) } else { (s.head, s.anchor) };
        let range = match s.mode {
            SelMode::Char => (a != b).then_some((a, b)),
            SelMode::Word => {
                let (ws, _) = self.word_bounds(a);
                let (_, we) = self.word_bounds(b);
                Some((ws, we))
            }
            SelMode::Line => Some((Pos { line: a.line, col: 0 }, Pos { line: b.line, col: self.cols })),
        };
        if let Some(sel) = &mut self.sel {
            sel.range = range;
        }
    }

    fn selected_text(&mut self) -> Option<String> {
        let (a, b) = self.sel?.range?;
        let t = self.text_range(a, b);
        (!t.is_empty()).then_some(t)
    }

    fn select_all(&mut self) {
        let hist = self.history_len() as i64;
        let (cr, _) = self.parser.screen().cursor_position();
        let last = (cr as i64).max(0);
        self.sel = Some(Selection {
            anchor: Pos { line: -hist, col: 0 },
            head: Pos { line: last, col: self.cols },
            mode: SelMode::Char,
            range: None,
        });
        self.update_selection();
    }

    fn url_at(&mut self, p: Pos) -> Option<(String, u16, u16)> {
        let (cells, _) = self.line_cells(p.line);
        let chars: Vec<char> = cells.iter().map(|s| s.chars().next().unwrap_or(' ')).collect();
        let line: String = chars.iter().collect();
        for scheme in ["https://", "http://"] {
            let mut from = 0;
            while let Some(i) = line[from..].find(scheme) {
                let start_byte = from + i;
                let start = line[..start_byte].chars().count();
                let mut end = start;
                while end < chars.len() && !chars[end].is_whitespace() && !"\"'<>`{}|\\^".contains(chars[end]) {
                    end += 1;
                }
                while end > start && ".,;:!?)]".contains(chars[end - 1]) {
                    end -= 1;
                }
                if (start..end).contains(&(p.col as usize)) {
                    return Some((chars[start..end].iter().collect(), start as u16, end as u16));
                }
                from = start_byte + scheme.len();
            }
        }
        None
    }

    fn run_search(&mut self) {
        let Some(s) = &self.search else { return };
        let q: Vec<char> = s.query.to_lowercase().chars().collect();
        let hist = self.history_len() as i64;
        let mut matches = Vec::new();
        if !q.is_empty() {
            for line in -hist..self.rows as i64 {
                let (cells, _) = self.line_cells(line);
                let chars: Vec<char> = cells.iter().map(|s| s.chars().next().unwrap_or(' ').to_lowercase().next().unwrap_or(' ')).collect();
                let mut c = 0;
                while c + q.len() <= chars.len() {
                    if chars[c..c + q.len()] == q[..] {
                        matches.push((line, c as u16, (c + q.len()) as u16));
                        c += q.len();
                    } else {
                        c += 1;
                    }
                }
            }
        }
        let generation = self.generation;
        if let Some(s) = &mut self.search {
            s.current = (!matches.is_empty()).then(|| matches.len() - 1);
            s.matches = matches;
            s.searched = s.query.clone();
            s.generation = generation;
        }
        self.reveal_current_match();
    }

    fn step_search(&mut self, older: bool) {
        let stale = self.search.as_ref().is_some_and(|s| s.searched != s.query || s.generation != self.generation);
        if stale {
            self.run_search();
            return;
        }
        if let Some(s) = &mut self.search {
            let n = s.matches.len();
            if n == 0 {
                return;
            }
            s.current = Some(match (s.current, older) {
                (Some(0), true) => n - 1,
                (Some(i), true) => i - 1,
                (Some(i), false) => (i + 1) % n,
                (None, _) => n - 1,
            });
        }
        self.reveal_current_match();
    }

    fn reveal_current_match(&mut self) {
        let Some((line, ..)) = self.search.as_ref().and_then(|s| s.current.map(|i| s.matches[i])) else { return };
        let sb = self.parser.screen().scrollback() as i64;
        let row = line + sb;
        if !(0..self.rows as i64).contains(&row) {
            let target = if line >= 0 { 0 } else { -line + self.rows as i64 / 2 };
            self.parser.screen_mut().set_scrollback(target.max(0) as usize);
        }
    }

    // ---- souris pour les applications (vim, htop, mc…)

    fn mouse_report(&self, code: u8, col: u16, row: u16, release: bool, mods: egui::Modifiers) -> Vec<u8> {
        let code = code + if mods.alt { 8 } else { 0 } + if mods.ctrl { 16 } else { 0 };
        let (x, y) = (col as u32 + 1, row as u32 + 1);
        match self.parser.screen().mouse_protocol_encoding() {
            MouseProtocolEncoding::Sgr => format!("\x1b[<{code};{x};{y}{}", if release { 'm' } else { 'M' }).into_bytes(),
            enc => {
                let c = if release { 3 + (code & !3) } else { code };
                let mut v = vec![0x1b, b'[', b'M', 32 + c];
                for n in [x, y] {
                    if enc == MouseProtocolEncoding::Utf8 {
                        let ch = char::from_u32(32 + n).unwrap_or(' ');
                        let mut b = [0; 4];
                        v.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                    } else {
                        v.push((32 + n.min(223)) as u8);
                    }
                }
                v
            }
        }
    }

    // ---------------------------------------------------------------- affichage + entrées

    /// Affiche le terminal dans toute la zone disponible et traite les entrées.
    /// `primary` : sélection « primaire » façon X11 (collée au clic molette).
    pub fn show(&mut self, ui: &mut egui::Ui, cfg: &Settings, active: bool, primary: &mut String) -> Output {
        let mut out = Output::default();
        let font = FontId::monospace(cfg.font_size);
        let rect = ui.available_rect_before_wrap();
        let cw = ui.fonts_mut(|f| f.glyph_width(&font, 'M')).max(1.0);
        let ch = ui.fonts_mut(|f| f.row_height(&font)).max(1.0) + 1.0;
        let cell = Vec2::new(cw, ch);
        let cols = ((rect.width() - 2.0 * PAD) / cell.x).floor().max(10.0) as u16;
        let rows = ((rect.height() - 2.0 * PAD) / cell.y).floor().max(3.0) as u16;
        if (cols, rows) != (self.cols, self.rows) {
            self.cols = cols;
            self.rows = rows;
            self.guarded(|p| p.screen_mut().set_size(rows, cols));
            self.sel = None;
            out.resize = Some((cols, rows));
        }
        let now = ui.input(|i| i.time);

        let id = ui.id().with("escale-term");
        let resp = ui.interact(rect, id, Sense::click_and_drag());
        let search_focus = self.search.as_ref().is_some_and(|s| s.focus);
        if !search_focus
            && (resp.clicked() || resp.drag_started() || (active && !ui.memory(|m| m.has_focus(id)) && !ui.ctx().egui_wants_keyboard_input()))
        {
            ui.memory_mut(|m| m.request_focus(id));
        }
        let focused = active && ui.memory(|m| m.has_focus(id));
        if focused {
            FOCUSED.store(true, Ordering::Relaxed);
            // « Tous les raccourcis au serveur » : Ctrl+Maj+Échap n'ouvre plus le gestionnaire des
            // tâches de cet ordinateur, le terminal reçoit Échap
            #[cfg(windows)]
            if cfg.keys_to_server {
                crate::winput::TASK_KEYS.store(true, Ordering::Relaxed);
                crate::winput::install_keyboard_hook(ui.ctx());
            }
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true })
            });
        }
        if focused != self.was_focused {
            if self.parser.callbacks().focus_reporting {
                out.bytes.extend_from_slice(if focused { b"\x1b[I" } else { b"\x1b[O" });
            }
            self.was_focused = focused;
        }

        let origin = rect.min + Vec2::splat(PAD);
        let sb = self.parser.screen().scrollback() as i64;
        let cell_at = |p: Pos2| -> (u16, u16, u16) {
            let v = p - origin;
            let row = ((v.y / cell.y).floor().max(0.0) as u16).min(rows - 1);
            let col = ((v.x / cell.x).floor().max(0.0) as u16).min(cols - 1);
            let col_round = ((v.x / cell.x).round().max(0.0) as u16).min(cols);
            (row, col, col_round)
        };
        let (mods, events, hover_pos) = ui.input(|i| (i.modifiers, i.events.clone(), i.pointer.hover_pos()));

        // ---------- souris
        let mouse_mode = self.parser.screen().mouse_protocol_mode();
        let report = mouse_mode != MouseProtocolMode::None && !mods.shift && active;
        if report {
            for ev in &events {
                match ev {
                    egui::Event::PointerButton { pos, button, pressed, modifiers } if rect.contains(*pos) => {
                        let b = match button {
                            egui::PointerButton::Primary => 0,
                            egui::PointerButton::Middle => 1,
                            egui::PointerButton::Secondary => 2,
                            _ => continue,
                        };
                        let (r, c, _) = cell_at(*pos);
                        if *pressed {
                            self.mouse_button = Some(b);
                            out.bytes.extend(self.mouse_report(b, c, r, false, *modifiers));
                        } else if mouse_mode != MouseProtocolMode::Press {
                            self.mouse_button = None;
                            out.bytes.extend(self.mouse_report(b, c, r, true, *modifiers));
                        }
                    }
                    egui::Event::PointerMoved(pos) if rect.contains(*pos) => {
                        let (r, c, _) = cell_at(*pos);
                        let moving = match mouse_mode {
                            MouseProtocolMode::AnyMotion => true,
                            MouseProtocolMode::ButtonMotion => self.mouse_button.is_some(),
                            _ => false,
                        };
                        if moving && (r, c) != self.last_mouse_cell {
                            self.last_mouse_cell = (r, c);
                            out.bytes.extend(self.mouse_report(32 + self.mouse_button.unwrap_or(3), c, r, false, mods));
                        }
                    }
                    egui::Event::MouseWheel { delta, .. } if hover_pos.is_some_and(|p| rect.contains(p)) && delta.y != 0.0 => {
                        let (r, c, _) = cell_at(hover_pos.unwrap());
                        let code = if delta.y > 0.0 { 64 } else { 65 };
                        out.bytes.extend(self.mouse_report(code, c, r, false, mods));
                    }
                    _ => {}
                }
            }
        } else {
            let to_pos = |p: Pos2, round: bool| {
                let (r, c, cr) = cell_at(p);
                Pos { line: r as i64 - sb, col: if round { cr } else { c } }
            };
            let mut finalize = false;
            if let Some(p) = resp.interact_pointer_pos() {
                if resp.triple_clicked() {
                    let at = to_pos(p, false);
                    self.sel = Some(Selection { anchor: at, head: at, mode: SelMode::Line, range: None });
                    finalize = true;
                } else if resp.double_clicked() {
                    let at = to_pos(p, false);
                    self.sel = Some(Selection { anchor: at, head: at, mode: SelMode::Word, range: None });
                    finalize = true;
                } else if resp.clicked() {
                    if mods.ctrl {
                        if let Some((url, ..)) = self.url_at(to_pos(p, false)) {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                        }
                    } else if mods.shift && self.sel.is_some() {
                        if let Some(s) = &mut self.sel {
                            s.head = to_pos(p, true);
                        }
                        finalize = true;
                    } else {
                        self.sel = None;
                    }
                } else if resp.drag_started() {
                    let at = to_pos(p, true);
                    if mods.shift && self.sel.is_some() {
                        if let Some(s) = &mut self.sel {
                            s.head = at;
                        }
                    } else {
                        self.sel = Some(Selection { anchor: at, head: at, mode: SelMode::Char, range: None });
                    }
                } else if resp.dragged() {
                    // défilement automatique quand on sort de la zone en sélectionnant
                    if p.y < rect.top() + PAD {
                        self.scroll_by(1);
                        ui.ctx().request_repaint();
                    } else if p.y > rect.bottom() - PAD {
                        self.scroll_by(-1);
                        ui.ctx().request_repaint();
                    }
                    let sb_now = self.parser.screen().scrollback() as i64;
                    let (r, _, cr) = cell_at(p);
                    if let Some(s) = &mut self.sel {
                        s.head = Pos { line: r as i64 - sb_now, col: cr };
                    }
                }
                if resp.dragged() || resp.drag_started() || finalize {
                    self.update_selection();
                }
            }
            if resp.drag_stopped() {
                finalize = true;
            }
            if finalize {
                if let Some(t) = self.selected_text() {
                    if cfg.copy_on_select {
                        ui.ctx().copy_text(t.clone());
                    }
                    *primary = t;
                }
            }
            if resp.middle_clicked() {
                let t = if primary.is_empty() { read_clipboard() } else { Some(primary.clone()) };
                if let Some(t) = t {
                    self.paste(t, cfg, &mut out);
                }
            }
            if resp.hovered() {
                let dy = ui.input(|i| i.smooth_scroll_delta.y);
                if dy != 0.0 {
                    self.wheel_acc += dy / cell.y;
                    let lines = self.wheel_acc.trunc() as i64;
                    self.wheel_acc -= lines as f32;
                    if lines != 0 {
                        if self.parser.screen().alternate_screen() {
                            let seq: &[u8] = if lines > 0 { b"\x1b[A" } else { b"\x1b[B" };
                            for _ in 0..lines.abs() * 3 {
                                out.bytes.extend_from_slice(seq);
                            }
                        } else {
                            self.scroll_by(lines * 3);
                        }
                    }
                }
            }
        }

        // lien sous le pointeur (Ctrl enfoncé)
        let mut hover_link = None;
        if let Some(p) = hover_pos.filter(|p| rect.contains(*p) && mods.ctrl) {
            let (r, c, _) = cell_at(p);
            let sb_now = self.parser.screen().scrollback() as i64;
            if let Some((url, a, b)) = self.url_at(Pos { line: r as i64 - sb_now, col: c }) {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                hover_link = Some((r, a, b, url));
            }
        } else if resp.hovered() && !report {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Text);
        }

        // clic droit : menu contextuel ou collage direct (style PuTTY)
        let mut menu: Option<MenuAction> = None;
        if !report {
            if cfg.right_click_paste {
                if resp.secondary_clicked() {
                    menu = Some(MenuAction::Paste);
                }
            } else {
                let has_sel = self.sel.and_then(|s| s.range).is_some();
                let link = resp.interact_pointer_pos().or(hover_pos).and_then(|p| {
                    let (r, c, _) = cell_at(p);
                    self.url_at(Pos { line: r as i64 - sb, col: c }).map(|u| u.0)
                });
                resp.context_menu(|ui| {
                    ui.set_min_width(230.0);
                    if let Some(url) = &link {
                        if menu_item(ui, "Ouvrir le lien", "Ctrl+clic", true) {
                            menu = Some(MenuAction::OpenLink(url.clone()));
                        }
                        if menu_item(ui, "Copier l'adresse du lien", "", true) {
                            menu = Some(MenuAction::CopyLink(url.clone()));
                        }
                        ui.separator();
                    }
                    if menu_item(ui, "Copier", "Ctrl+Maj+C", has_sel) {
                        menu = Some(MenuAction::Copy);
                    }
                    if menu_item(ui, "Coller", "Ctrl+Maj+V", true) {
                        menu = Some(MenuAction::Paste);
                    }
                    if menu_item(ui, "Coller la sélection", "Clic molette", !primary.is_empty()) {
                        menu = Some(MenuAction::PastePrimary);
                    }
                    if menu_item(ui, "Tout sélectionner", "Ctrl+Maj+A", true) {
                        menu = Some(MenuAction::SelectAll);
                    }
                    ui.separator();
                    if menu_item(ui, "Rechercher…", "Ctrl+Maj+F", true) {
                        menu = Some(MenuAction::Find);
                    }
                    if menu_item(ui, "Effacer l'historique", "Ctrl+Maj+K", true) {
                        menu = Some(MenuAction::ClearScrollback);
                    }
                    if menu_item(ui, "Réinitialiser le terminal", "", true) {
                        menu = Some(MenuAction::Reset);
                    }
                    if menu.is_some() {
                        ui.close();
                    }
                });
            }
        }

        // ---------- clavier
        if focused {
            let mut paste_event: Option<String> = None;
            let mut paste_key = false;
            // Alt+touche : ESC + caractère produit, envoyé avec l'événement texte qui suit la touche
            // (respecte la disposition du clavier) ; à défaut de texte, ESC + lettre de la touche.
            let mut alt_pending: Option<u8> = None;
            for ev in events {
                let key_event = match &ev {
                    egui::Event::Key { key, pressed: true, modifiers, .. } => Some((*key, *modifiers)),
                    // egui-winit remplace Ctrl+C / Ctrl+X par Copier/Couper (sous Windows, winput
                    // rétablit déjà la touche exacte, Ctrl+Inser et Maj+Suppr compris)
                    egui::Event::Copy => Some((Key::C, mods)),
                    egui::Event::Cut => Some((Key::X, mods)),
                    _ => None,
                };
                if key_event.is_some() || matches!(ev, egui::Event::Paste(_)) {
                    if let Some(c) = alt_pending.take() {
                        out.bytes.extend_from_slice(&[0x1b, c]);
                    }
                }
                if let Some((key, modifiers)) = key_event {
                    let ctrl = modifiers.ctrl && !modifiers.alt;
                    let cs = ctrl && modifiers.shift;
                    match key {
                        Key::C if cs => menu = Some(MenuAction::Copy),
                        Key::Insert if ctrl && !modifiers.shift => menu = Some(MenuAction::Copy),
                        Key::V if cs => paste_key = true,
                        Key::Insert if modifiers.shift && !modifiers.ctrl => paste_key = true,
                        Key::A if cs => menu = Some(MenuAction::SelectAll),
                        Key::F if cs => menu = Some(MenuAction::Find),
                        Key::K if cs => menu = Some(MenuAction::ClearScrollback),
                        _ if modifiers.alt && !modifiers.ctrl && alt_char(key, modifiers.shift).is_some() => {
                            self.sel = None;
                            alt_pending = alt_char(key, modifiers.shift);
                        }
                        _ => self.handle_key(key, modifiers, &mut out.bytes),
                    }
                    continue;
                }
                match ev {
                    egui::Event::Paste(t) => {
                        // Ctrl+V seul = caractère littéral ^V (comme sous Linux)
                        if mods.ctrl && !mods.shift {
                            out.bytes.push(0x16);
                        } else {
                            paste_event = Some(t);
                        }
                    }
                    egui::Event::Text(t) => {
                        self.sel = None;
                        if alt_pending.take().is_some() || (mods.alt && !mods.ctrl) {
                            out.bytes.push(0x1b);
                        }
                        out.bytes.extend_from_slice(t.as_bytes());
                    }
                    _ => {}
                }
            }
            if let Some(c) = alt_pending {
                out.bytes.extend_from_slice(&[0x1b, c]);
            }
            if let Some(t) = paste_event {
                self.paste(t, cfg, &mut out);
            } else if paste_key {
                if let Some(t) = read_clipboard() {
                    self.paste(t, cfg, &mut out);
                }
            }
        }

        // actions du menu / des raccourcis
        if let Some(a) = menu {
            match a {
                MenuAction::Copy => {
                    if let Some(t) = self.selected_text() {
                        *primary = t.clone();
                        ui.ctx().copy_text(t);
                    }
                }
                MenuAction::Paste => {
                    if let Some(t) = read_clipboard() {
                        self.paste(t, cfg, &mut out);
                    }
                }
                MenuAction::PastePrimary => {
                    let t = primary.clone();
                    self.paste(t, cfg, &mut out);
                }
                MenuAction::SelectAll => {
                    self.select_all();
                    if let Some(t) = self.selected_text() {
                        *primary = t;
                    }
                }
                MenuAction::Find => {
                    let query = self.sel.and_then(|s| s.range).filter(|(a, b)| a.line == b.line).and_then(|_| self.selected_text()).unwrap_or_default();
                    let had = self.search.is_some();
                    self.search = Some(Search {
                        query: if had { self.search.take().map(|s| s.query).unwrap_or_default() } else { query },
                        searched: String::new(),
                        generation: 0,
                        matches: Vec::new(),
                        current: None,
                        focus: true,
                    });
                    self.run_search();
                }
                MenuAction::ClearScrollback => self.clear_scrollback(),
                MenuAction::Reset => {
                    self.reset();
                    out.bytes.extend_from_slice(b"\x0c");
                }
                MenuAction::OpenLink(u) => ui.ctx().open_url(egui::OpenUrl::new_tab(u)),
                MenuAction::CopyLink(u) => ui.ctx().copy_text(u),
            }
            ui.ctx().request_repaint();
        }

        if !out.bytes.is_empty() {
            self.parser.screen_mut().set_scrollback(0);
            self.blink_epoch = now;
        }

        self.paint(ui, rect, origin, cell, &font, focused, cfg, now, hover_link.as_ref());
        self.search_bar(ui, rect);
        out
    }

    fn handle_key(&mut self, key: Key, modifiers: egui::Modifiers, buf: &mut Vec<u8>) {
        let app_cursor = self.parser.screen().application_cursor();
        let ctrl = modifiers.ctrl && !modifiers.alt;
        // Défilement de l'historique
        let half = (self.rows / 2) as i64;
        match key {
            Key::PageUp if modifiers.shift && !ctrl => return self.scroll_by(half),
            Key::PageDown if modifiers.shift && !ctrl => return self.scroll_by(-half),
            Key::Home if modifiers.shift && !ctrl => return self.scroll_by(i64::MAX / 4),
            Key::End if modifiers.shift && !ctrl => return self.parser.screen_mut().set_scrollback(0),
            Key::ArrowUp if ctrl && modifiers.shift => return self.scroll_by(1),
            Key::ArrowDown if ctrl && modifiers.shift => return self.scroll_by(-1),
            _ => {}
        }
        // Modificateurs xterm : 2=Maj 3=Alt 4=Maj+Alt 5=Ctrl 6=Ctrl+Maj 7=Ctrl+Alt 8=tous
        let m = 1 + modifiers.shift as u8 + 2 * modifiers.alt as u8 + 4 * modifiers.ctrl as u8;
        let csi = |c: u8| -> Vec<u8> {
            if m > 1 {
                format!("\x1b[1;{m}{}", c as char).into_bytes()
            } else if app_cursor {
                vec![0x1b, b'O', c]
            } else {
                vec![0x1b, b'[', c]
            }
        };
        let tilde = |n: u8| -> Vec<u8> { if m > 1 { format!("\x1b[{n};{m}~").into_bytes() } else { format!("\x1b[{n}~").into_bytes() } };
        let ss3 = |c: char| -> Vec<u8> { if m > 1 { format!("\x1b[1;{m}{c}").into_bytes() } else { format!("\x1bO{c}").into_bytes() } };
        let seq: Option<Vec<u8>> = match key {
            Key::Enter => Some(if modifiers.alt { b"\x1b\r".to_vec() } else { b"\r".to_vec() }),
            Key::Backspace => Some(match (ctrl, modifiers.alt) {
                (true, _) => vec![0x08],
                (_, true) => vec![0x1b, 0x7f],
                _ => vec![0x7f],
            }),
            Key::Tab => Some(if modifiers.shift { b"\x1b[Z".to_vec() } else { b"\t".to_vec() }),
            Key::Escape => Some(vec![0x1b]),
            Key::ArrowUp => Some(csi(b'A')),
            Key::ArrowDown => Some(csi(b'B')),
            Key::ArrowRight => Some(csi(b'C')),
            Key::ArrowLeft => Some(csi(b'D')),
            Key::Home => Some(csi(b'H')),
            Key::End => Some(csi(b'F')),
            Key::PageUp => Some(tilde(5)),
            Key::PageDown => Some(tilde(6)),
            Key::Insert => Some(tilde(2)),
            Key::Delete => Some(tilde(3)),
            Key::F1 => Some(ss3('P')),
            Key::F2 => Some(ss3('Q')),
            Key::F3 => Some(ss3('R')),
            Key::F4 => Some(ss3('S')),
            Key::F5 => Some(tilde(15)),
            Key::F6 => Some(tilde(17)),
            Key::F7 => Some(tilde(18)),
            Key::F8 => Some(tilde(19)),
            Key::F9 => Some(tilde(20)),
            Key::F10 => Some(tilde(21)),
            Key::F11 => Some(tilde(23)),
            Key::F12 => Some(tilde(24)),
            // Ctrl+lettre : caractère de contrôle (Ctrl+C = interruption, Ctrl+D = EOF, Ctrl+L = effacer…)
            _ if ctrl => ctrl_byte(key).map(|b| vec![b]),
            // Ctrl+Alt+lettre : ESC + caractère de contrôle (Emacs C-M-…)
            _ if modifiers.ctrl && modifiers.alt => ctrl_byte(key).map(|b| vec![0x1b, b]),
            _ => None,
        };
        if let Some(s) = seq {
            self.sel = None;
            buf.extend_from_slice(&s);
        }
    }

    fn search_bar(&mut self, ui: &mut egui::Ui, rect: Rect) {
        let Some(s) = &mut self.search else { return };
        let bar = Rect::from_min_size(egui::pos2(rect.right() - 392.0, rect.top() + 10.0), vec2(380.0, 44.0));
        let mut close = false;
        let mut step: Option<bool> = None;
        ui.scope_builder(egui::UiBuilder::new().max_rect(bar), |ui| {
            egui::Frame::new()
                .fill(theme::ELEVATED)
                .stroke(Stroke::new(1.0, theme::BORDER_STRONG))
                .corner_radius(12)
                .inner_margin(egui::Margin::symmetric(8, 5))
                .shadow(egui::Shadow { offset: [0, 6], blur: 18, spread: 0, color: Color32::from_black_alpha(120) })
                .show(ui, |ui| {
                    ui.horizontal_centered(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        w::icon_size(ui, Icon::Search, 14.0, theme::MUTED);
                        let te = ui.add(
                            egui::TextEdit::singleline(&mut s.query)
                                .id(egui::Id::new("term-search"))
                                .hint_text(egui::RichText::new("Rechercher dans le terminal").color(theme::MUTED))
                                .frame(egui::Frame::NONE)
                                .desired_width(190.0),
                        );
                        if s.focus {
                            te.request_focus();
                            s.focus = false;
                        }
                        if te.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                            step = Some(!ui.input(|i| i.modifiers.shift));
                            te.request_focus();
                        }
                        if te.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)) {
                            close = true;
                        }
                        let count = match (s.current, s.matches.len()) {
                            (_, 0) if s.query.is_empty() => String::new(),
                            (_, 0) => "0".into(),
                            (Some(i), n) => format!("{}/{n}", n - i),
                            (None, n) => n.to_string(),
                        };
                        ui.label(egui::RichText::new(count).size(12.0).color(theme::TEXT_DIM));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            if w::icon_button_sized(ui, Icon::Close, 28.0, "Fermer  (Échap)").clicked() {
                                close = true;
                            }
                            if arrow_button(ui, false, "Suivant (plus récent)  Maj+Entrée").clicked() {
                                step = Some(false);
                            }
                            if arrow_button(ui, true, "Précédent (plus ancien)  Entrée").clicked() {
                                step = Some(true);
                            }
                        });
                    });
                });
        });
        if s.query != s.searched && step.is_none() {
            self.run_search();
        }
        if let Some(older) = step {
            self.step_search(older);
        }
        if close {
            self.search = None;
            ui.ctx().request_repaint();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn paint(
        &mut self,
        ui: &egui::Ui,
        rect: Rect,
        origin: Pos2,
        cell: Vec2,
        font: &FontId,
        focused: bool,
        cfg: &Settings,
        now: f64,
        hover_link: Option<&(u16, u16, u16, String)>,
    ) {
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, BG);
        let bold_font = mono_bold(font.size);
        let screen = self.parser.screen();
        let sb = screen.scrollback() as i64;
        let sel = self.sel.and_then(|s| s.range);
        let in_sel = |r: u16, c: u16| match sel {
            Some((a, b)) => {
                let p = Pos { line: r as i64 - sb, col: c };
                p >= a && p < b
            }
            None => false,
        };
        let (matches, current) = match &self.search {
            Some(s) => (s.matches.as_slice(), s.current.map(|i| s.matches[i])),
            None => (&[][..], None),
        };
        let text_y = (cell.y - ui.fonts_mut(|f| f.row_height(font))) / 2.0;

        for r in 0..self.rows {
            let y = origin.y + r as f32 * cell.y;
            let abs = r as i64 - sb;
            // résultats de recherche
            for m in matches.iter().filter(|m| m.0 == abs) {
                let mr = Rect::from_min_size(Pos2::new(origin.x + m.1 as f32 * cell.x, y), Vec2::new((m.2 - m.1) as f32 * cell.x, cell.y));
                if Some(*m) == current {
                    painter.rect(mr, 2.0, CURSOR.gamma_multiply(0.45), Stroke::new(1.0, CURSOR), egui::StrokeKind::Inside);
                } else {
                    painter.rect_filled(mr, 2.0, MATCH);
                }
            }

            let mut run = String::new();
            let mut run_start = 0u16;
            let mut run_style = (FG, false);
            let flush = |run: &mut String, start: u16, (fg, bold): (Color32, bool)| {
                if !run.trim_end().is_empty() {
                    painter.text(
                        Pos2::new(origin.x + start as f32 * cell.x, y + text_y),
                        egui::Align2::LEFT_TOP,
                        run.as_str(),
                        if bold { bold_font.clone() } else { font.clone() },
                        fg,
                    );
                }
                run.clear();
            };

            let mut c = 0u16;
            while c < self.cols {
                let Some(cl) = screen.cell(r, c) else { break };
                if cl.is_wide_continuation() {
                    c += 1;
                    continue;
                }
                let (mut fg, mut bg) = (color(cl.fgcolor(), FG), color(cl.bgcolor(), BG));
                if cl.bold() {
                    if let vt100::Color::Idx(i) = cl.fgcolor() {
                        if i < 8 {
                            fg = ANSI[i as usize + 8];
                        }
                    }
                }
                if cl.inverse() {
                    std::mem::swap(&mut fg, &mut bg);
                }
                if cl.dim() {
                    fg = fg.gamma_multiply(0.6);
                }
                let wd = if cl.is_wide() { 2 } else { 1 };
                let x = origin.x + c as f32 * cell.x;
                let cell_rect = Rect::from_min_size(Pos2::new(x, y), Vec2::new(cell.x * wd as f32, cell.y));
                if bg != BG {
                    painter.rect_filled(cell_rect, 0.0, bg);
                }
                if in_sel(r, c) {
                    painter.rect_filled(cell_rect, 0.0, SELECTION);
                }
                let on_link = hover_link.is_some_and(|l| l.0 == r && (l.1..l.2).contains(&c));
                if on_link {
                    fg = LINK;
                }
                if cl.underline() || on_link {
                    painter.hline(cell_rect.x_range(), cell_rect.bottom() - 1.5, (1.0, fg));
                }

                let style = (fg, cl.bold());
                let txt = if cl.has_contents() { cl.contents() } else { " " };
                if wd == 2 || !txt.is_ascii() {
                    // caractère large/non ASCII : dessiné seul pour préserver l'alignement de la grille
                    flush(&mut run, run_start, run_style);
                    painter.text(Pos2::new(x, y + text_y), egui::Align2::LEFT_TOP, txt, if style.1 { bold_font.clone() } else { font.clone() }, fg);
                    run_start = c + wd;
                } else {
                    if style != run_style && !run.is_empty() {
                        flush(&mut run, run_start, run_style);
                    }
                    if run.is_empty() {
                        run_start = c;
                    }
                    run_style = style;
                    run.push_str(txt);
                }
                c += wd;
            }
            flush(&mut run, run_start, run_style);
        }

        // curseur (forme et clignotement pilotés par l'application, DECSCUSR)
        let cb = self.parser.callbacks();
        if !screen.hide_cursor() && sb == 0 {
            let (cr, cc) = screen.cursor_position();
            let r = Rect::from_min_size(Pos2::new(origin.x + cc as f32 * cell.x, origin.y + cr as f32 * cell.y), cell);
            let blink = focused && cfg.cursor_blink && cb.cursor_blink;
            let phase = ((now - self.blink_epoch) / 0.55) as i64;
            let visible = !blink || phase % 2 == 0;
            if blink {
                let next = 0.55 - ((now - self.blink_epoch) % 0.55);
                ui.ctx().request_repaint_after(std::time::Duration::from_secs_f64(next.max(0.02)));
            }
            if !focused {
                painter.rect_stroke(r, 2.0, (1.0, CURSOR.gamma_multiply(0.7)), egui::StrokeKind::Inside);
            } else if visible {
                match cb.cursor_shape {
                    CursorShape::Block => {
                        painter.rect_filled(r, 2.0, CURSOR);
                        if let Some(cl) = screen.cell(cr, cc) {
                            if cl.has_contents() {
                                painter.text(r.min + Vec2::new(0.0, text_y), egui::Align2::LEFT_TOP, cl.contents(), font.clone(), BG);
                            }
                        }
                    }
                    CursorShape::Underline => {
                        painter.rect_filled(Rect::from_min_max(egui::pos2(r.left(), r.bottom() - 2.5), r.max), 0.0, CURSOR);
                    }
                    CursorShape::Bar => {
                        painter.rect_filled(Rect::from_min_max(r.min, egui::pos2(r.left() + 2.0, r.bottom())), 0.0, CURSOR);
                    }
                }
            }
        }

        // cloche visuelle
        if let Some(t0) = self.bell_at {
            let t = (now - t0) as f32;
            if t < 0.3 && cfg.visual_bell {
                let a = 1.0 - t / 0.3;
                painter.rect_filled(rect, 0.0, Color32::from_white_alpha((14.0 * a) as u8));
                painter.rect_stroke(rect.shrink(1.0), 12.0, Stroke::new(2.0, CURSOR.gamma_multiply(a)), egui::StrokeKind::Inside);
                ui.ctx().request_repaint();
            } else {
                self.bell_at = None;
            }
        }

        // indicateur de défilement
        if sb > 0 {
            let label = format!("↑ {sb} lignes  ·  Maj+Fin pour revenir");
            let galley = painter.layout_no_wrap(label, FontId::proportional(12.0), Color32::WHITE);
            let top = if self.search.is_some() { rect.top() + 62.0 } else { rect.top() + 12.0 };
            let pill = Rect::from_min_size(Pos2::new(rect.right() - galley.size().x - 34.0, top), galley.size() + Vec2::new(22.0, 10.0));
            painter.rect_filled(pill, 12.0, Color32::from_rgba_unmultiplied(0x1A, 0x20, 0x2C, 235));
            painter.rect_stroke(pill, 12.0, (1.0, CURSOR.gamma_multiply(0.5)), egui::StrokeKind::Inside);
            painter.galley(pill.min + Vec2::new(11.0, 5.0), galley, Color32::WHITE);
        }
    }

    /// Déclenche la cloche visuelle.
    pub fn ring(&mut self, now: f64) {
        self.bell_at = Some(now);
    }
}

fn read_clipboard() -> Option<String> {
    arboard::Clipboard::new().and_then(|mut c| c.get_text()).ok().filter(|t| !t.is_empty())
}

fn menu_item(ui: &mut egui::Ui, label: &str, shortcut: &str, enabled: bool) -> bool {
    let resp = ui.add_enabled(enabled, egui::Button::new(label).shortcut_text(shortcut).min_size(vec2(220.0, 0.0)));
    resp.clicked()
}

fn arrow_button(ui: &mut egui::Ui, up: bool, tip: &str) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(r, 7.0, theme::HOVER);
    }
    let c = r.center();
    let d = if up { -1.0 } else { 1.0 };
    let col = if resp.hovered() { theme::TEXT } else { theme::MUTED };
    ui.painter().add(egui::Shape::line(
        vec![c + vec2(-5.0, -2.5 * d), c + vec2(0.0, 2.5 * d), c + vec2(5.0, -2.5 * d)],
        Stroke::new(1.6, col),
    ));
    resp.on_hover_text(tip)
}

fn letter(key: Key) -> Option<u8> {
    let b = key.name().as_bytes();
    (b.len() == 1 && b[0].is_ascii_alphanumeric()).then(|| b[0])
}

fn ctrl_byte(key: Key) -> Option<u8> {
    if let Some(b) = letter(key).filter(|b| b.is_ascii_alphabetic()) {
        return Some(b.to_ascii_uppercase() - b'A' + 1);
    }
    // mêmes codes que xterm (Ctrl+/ = ^_ : « aller à la ligne » dans nano)
    match key {
        Key::Space | Key::Num2 | Key::Backtick => Some(0x00),
        Key::OpenBracket | Key::Num3 => Some(0x1b),
        Key::Backslash | Key::Num4 => Some(0x1c),
        Key::CloseBracket | Key::Num5 => Some(0x1d),
        Key::Num6 => Some(0x1e),
        Key::Minus | Key::Slash | Key::Num7 => Some(0x1f),
        Key::Num8 | Key::Questionmark => Some(0x7f),
        _ => None,
    }
}

fn alt_char(key: Key, shift: bool) -> Option<u8> {
    let b = letter(key)?;
    Some(if shift { b.to_ascii_uppercase() } else { b.to_ascii_lowercase() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_prompts_are_recognized() {
        for p in ["[sudo] password for theo: ", "Password:", "[sudo] Mot de passe de theo : ", "theo@srv's password:", "Passwort:", "(current) UNIX password:"] {
            assert!(is_password_prompt(p), "{p}");
        }
        for p in ["Enter passphrase for key '/home/theo/.ssh/id_ed25519':", "New password:", "Retype new password:", "Nouveau mot de passe :", "theo@srv:~$ ", "password", "echo password:x"] {
            assert!(!is_password_prompt(p), "{p}");
        }
        let mut t = Terminal::new(100);
        let _ = t.feed(b"theo@srv:~$ sudo apt update\r\n[sudo] password for theo: ");
        assert!(t.password_prompt());
        let _ = t.feed(b"\r\n");
        assert!(!t.password_prompt());
        // invite dans vim (écran alternatif) : ignorée
        let _ = t.feed(b"\x1b[?1049hPassword:");
        assert!(!t.password_prompt());
    }

    #[test]
    fn sudo_prompts_are_recognized() {
        assert!(is_sudo_prompt("[sudo] password for theo: ", ""));
        assert!(is_sudo_prompt("[sudo] Mot de passe de theo : ", ""));
        assert!(is_sudo_prompt("Password:", "theo@mac ~ % sudo ls"));
        assert!(!is_sudo_prompt("Password:", "theo@srv:~$ su -"));
        assert!(!is_sudo_prompt("Password:", "Sorry, try again."));
        assert!(!is_sudo_prompt("theo@srv's password:", ""));
        assert!(!is_sudo_prompt("[sudo] ", ""));
        let mut t = Terminal::new(100);
        let _ = t.feed(b"theo@srv:~$ sudo apt update\r\n[sudo] password for theo: ");
        assert!(t.sudo_prompt());
        let _ = t.feed(b"\r\ntheo@srv:~$ su -\r\nPassword: ");
        assert!(t.password_prompt() && !t.sudo_prompt());
    }

    fn keys(key: Key, ctrl: bool, shift: bool, alt: bool) -> Vec<u8> {
        let mut t = Terminal::new(100);
        let mut buf = Vec::new();
        t.handle_key(key, egui::Modifiers { alt, ctrl, shift, mac_cmd: false, command: ctrl }, &mut buf);
        buf
    }

    #[test]
    fn key_sequences_match_xterm() {
        assert_eq!(keys(Key::X, true, false, false), [0x18]);
        assert_eq!(keys(Key::C, true, false, false), [0x03]);
        assert_eq!(keys(Key::V, true, false, false), [0x16]);
        assert_eq!(keys(Key::Slash, true, false, false), [0x1f]);
        assert_eq!(keys(Key::Num6, true, false, false), [0x1e]);
        assert_eq!(keys(Key::Space, true, false, false), [0x00]);
        assert_eq!(keys(Key::A, true, false, true), [0x1b, 0x01]);
        assert_eq!(keys(Key::Delete, false, true, false), b"\x1b[3;2~");
        assert_eq!(keys(Key::F1, false, false, false), b"\x1bOP");
        assert_eq!(keys(Key::F1, false, true, false), b"\x1b[1;2P");
        assert_eq!(keys(Key::ArrowLeft, true, false, false), b"\x1b[1;5D");
        assert_eq!(keys(Key::Backspace, false, false, true), [0x1b, 0x7f]);
    }
}

#[cfg(test)]
mod resize_fuzz {
    /// Séquences variées (zones de défilement, écran alternatif, insertions…) entrecoupées de
    /// redimensionnements aléatoires : rien ne doit paniquer.
    #[test]
    fn vt100_survives_random_resizes() {
        let seqs: [&[u8]; 16] = [
            b"\x1b[5;40r",
            b"\x1b[?1049h",
            b"\x1b[?1049l",
            b"\x1b[999;999H",
            b"\x1b[2J",
            b"\x1b[10L",
            b"\x1b[10M",
            b"\x1b[50@",
            b"\x1b[50P",
            b"\x1bM\x1bM\x1bM",
            b"\x1b[?6h\x1b[3;1H",
            b"\x1b[r",
            b"\x1b[200S\x1b[200T",
            b"ligne de texte assez longue pour boucler sur plusieurs colonnes ................................\r\n",
            b"\xe4\xb8\xad\xe6\x96\x87\xf0\x9f\x98\x80\t\t\x08\x08",
            b"\x1b[?25l\x1b[1;1H\x1b[K\x1b[J",
        ];
        let seeds: u64 = if cfg!(debug_assertions) { 6 } else { 40 };
        for start in 1..=seeds {
        let mut seed: u64 = 0x5eed ^ start.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut rnd = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let mut p = vt100::Parser::new(24, 80, 1000);
        for _ in 0..20_000 {
            if rnd(6) == 0 {
                let rows = 3 + rnd(120) as u16;
                let cols = 10 + rnd(300) as u16;
                p.screen_mut().set_size(rows, cols);
            } else {
                p.process(seqs[rnd(seqs.len() as u64) as usize]);
            }
            if rnd(50) == 0 {
                p.screen_mut().set_scrollback(rnd(2000) as usize);
            }
        }
        }
    }
}
