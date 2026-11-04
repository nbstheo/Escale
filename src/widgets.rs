//! Composants d'interface : icônes vectorielles, boutons, champs, code PIN, puces…

use crate::theme::*;
use eframe::egui::{self, Align2, Color32, FontId, Margin, Pos2, Rect, Response, RichText, Sense, Shape, Stroke, Vec2, pos2, vec2};
use std::f32::consts::PI;

// ---------------------------------------------------------------- icônes

#[derive(Clone, Copy, PartialEq)]
pub enum Icon {
    Plus,
    Close,
    Search,
    Lock,
    Gear,
    Keyboard,
    Edit,
    Trash,
    Play,
    Key,
    Eye,
    EyeOff,
    Folder,
    Back,
    Shield,
    Warning,
    Hop,
    Terminal,
    Home,
    Refresh,
    Check,
    Server,
    Forward,
    Up,
    Upload,
    Download,
    File,
    FolderPlus,
    External,
    Monitor,
    Expand,
    Shrink,
}

fn arc(c: Pos2, r: f32, a0: f32, a1: f32) -> Vec<Pos2> {
    let n = 20;
    (0..=n).map(|i| {
        let a = a0 + (a1 - a0) * i as f32 / n as f32;
        pos2(c.x + r * a.cos(), c.y + r * a.sin())
    })
    .collect()
}

/// Dessine une icône dans `rect` (carré conseillé).
pub fn paint_icon(p: &egui::Painter, rect: Rect, icon: Icon, color: Color32) {
    let s = rect.width().min(rect.height());
    let o = rect.center() - vec2(s / 2.0, s / 2.0);
    let at = |x: f32, y: f32| pos2(o.x + x * s, o.y + y * s);
    let st = Stroke::new((s * 0.085).max(1.4), color);
    let line = |pts: Vec<Pos2>| {
        p.add(Shape::line(pts, st));
    };
    match icon {
        Icon::Plus => {
            line(vec![at(0.5, 0.2), at(0.5, 0.8)]);
            line(vec![at(0.2, 0.5), at(0.8, 0.5)]);
        }
        Icon::Close => {
            line(vec![at(0.27, 0.27), at(0.73, 0.73)]);
            line(vec![at(0.73, 0.27), at(0.27, 0.73)]);
        }
        Icon::Search => {
            p.circle_stroke(at(0.44, 0.44), s * 0.24, st);
            line(vec![at(0.62, 0.62), at(0.84, 0.84)]);
        }
        Icon::Lock => {
            p.rect_stroke(Rect::from_min_max(at(0.2, 0.46), at(0.8, 0.86)), s * 0.08, st, egui::StrokeKind::Middle);
            let mut sh = vec![at(0.32, 0.46)];
            sh.extend(arc(at(0.5, 0.34), s * 0.18, PI, 2.0 * PI));
            sh.push(at(0.68, 0.46));
            line(sh);
            p.circle_filled(at(0.5, 0.64), s * 0.05, color);
        }
        Icon::Gear => {
            p.circle_stroke(rect.center(), s * 0.24, st);
            p.circle_stroke(rect.center(), s * 0.08, st);
            for i in 0..8 {
                let a = i as f32 * PI / 4.0;
                let (c, d) = (a.cos(), a.sin());
                p.line_segment(
                    [rect.center() + vec2(c, d) * s * 0.26, rect.center() + vec2(c, d) * s * 0.40],
                    Stroke::new(st.width * 1.5, color),
                );
            }
        }
        Icon::Keyboard => {
            p.rect_stroke(Rect::from_min_max(at(0.1, 0.27), at(0.9, 0.73)), s * 0.08, st, egui::StrokeKind::Middle);
            for i in 0..4 {
                let x = 0.27 + i as f32 * 0.153;
                p.circle_filled(at(x, 0.42), s * 0.035, color);
            }
            line(vec![at(0.32, 0.58), at(0.68, 0.58)]);
        }
        Icon::Edit => {
            line(vec![at(0.24, 0.76), at(0.3, 0.58), at(0.66, 0.22), at(0.78, 0.34), at(0.42, 0.7), at(0.24, 0.76)]);
            line(vec![at(0.58, 0.3), at(0.7, 0.42)]);
        }
        Icon::Trash => {
            line(vec![at(0.2, 0.3), at(0.8, 0.3)]);
            line(vec![at(0.4, 0.3), at(0.42, 0.18), at(0.58, 0.18), at(0.6, 0.3)]);
            line(vec![at(0.28, 0.3), at(0.32, 0.84), at(0.68, 0.84), at(0.72, 0.3)]);
            line(vec![at(0.44, 0.44), at(0.44, 0.7)]);
            line(vec![at(0.56, 0.44), at(0.56, 0.7)]);
        }
        Icon::Play => {
            p.add(Shape::convex_polygon(vec![at(0.32, 0.2), at(0.8, 0.5), at(0.32, 0.8)], color, Stroke::NONE));
        }
        Icon::Key => {
            p.circle_stroke(at(0.3, 0.5), s * 0.15, st);
            line(vec![at(0.45, 0.5), at(0.86, 0.5)]);
            line(vec![at(0.72, 0.5), at(0.72, 0.66)]);
            line(vec![at(0.84, 0.5), at(0.84, 0.62)]);
        }
        Icon::Eye | Icon::EyeOff => {
            let n = 16;
            let mut pts: Vec<Pos2> = (0..=n).map(|i| {
                let t = i as f32 / n as f32;
                at(0.08 + 0.84 * t, 0.5 - 0.3 * (PI * t).sin())
            }).collect();
            pts.extend((1..n).rev().map(|i| {
                let t = i as f32 / n as f32;
                at(0.08 + 0.84 * t, 0.5 + 0.3 * (PI * t).sin())
            }));
            pts.push(pts[0]);
            line(pts);
            p.circle_stroke(rect.center(), s * 0.13, st);
            if icon == Icon::EyeOff {
                line(vec![at(0.18, 0.18), at(0.82, 0.82)]);
            }
        }
        Icon::Folder => {
            line(vec![
                at(0.14, 0.78),
                at(0.14, 0.24),
                at(0.4, 0.24),
                at(0.48, 0.34),
                at(0.86, 0.34),
                at(0.86, 0.78),
                at(0.14, 0.78),
            ]);
        }
        Icon::Back => line(vec![at(0.6, 0.22), at(0.32, 0.5), at(0.6, 0.78)]),
        Icon::Shield => {
            line(vec![
                at(0.5, 0.12),
                at(0.82, 0.24),
                at(0.8, 0.52),
                at(0.5, 0.88),
                at(0.2, 0.52),
                at(0.18, 0.24),
                at(0.5, 0.12),
            ]);
            line(vec![at(0.36, 0.5), at(0.47, 0.61), at(0.66, 0.4)]);
        }
        Icon::Warning => {
            line(vec![at(0.5, 0.14), at(0.88, 0.82), at(0.12, 0.82), at(0.5, 0.14)]);
            line(vec![at(0.5, 0.4), at(0.5, 0.6)]);
            p.circle_filled(at(0.5, 0.71), s * 0.045, color);
        }
        Icon::Hop => {
            line(vec![at(0.2, 0.78), at(0.2, 0.5), at(0.8, 0.5)]);
            line(vec![at(0.64, 0.34), at(0.8, 0.5), at(0.64, 0.66)]);
        }
        Icon::Terminal => {
            p.rect_stroke(Rect::from_min_max(at(0.1, 0.18), at(0.9, 0.82)), s * 0.1, st, egui::StrokeKind::Middle);
            line(vec![at(0.28, 0.38), at(0.42, 0.5), at(0.28, 0.62)]);
            line(vec![at(0.5, 0.64), at(0.7, 0.64)]);
        }
        Icon::Home => {
            line(vec![at(0.16, 0.48), at(0.5, 0.18), at(0.84, 0.48)]);
            line(vec![at(0.26, 0.4), at(0.26, 0.82), at(0.74, 0.82), at(0.74, 0.4)]);
        }
        Icon::Refresh => {
            line(arc(rect.center(), s * 0.3, -PI * 0.35, PI * 1.35));
            let tip = rect.center() + vec2((-PI * 0.35).cos(), (-PI * 0.35).sin()) * s * 0.3;
            line(vec![tip + vec2(-s * 0.16, -s * 0.02), tip, tip + vec2(-s * 0.02, s * 0.16)]);
        }
        Icon::Check => line(vec![at(0.22, 0.52), at(0.42, 0.72), at(0.8, 0.3)]),
        Icon::Server => {
            for y in [0.18, 0.54] {
                p.rect_stroke(Rect::from_min_max(at(0.14, y), at(0.86, y + 0.28)), s * 0.06, st, egui::StrokeKind::Middle);
                p.circle_filled(at(0.3, y + 0.14), s * 0.04, color);
            }
        }
        Icon::Forward => line(vec![at(0.4, 0.22), at(0.68, 0.5), at(0.4, 0.78)]),
        Icon::Up => {
            line(vec![at(0.5, 0.8), at(0.5, 0.22)]);
            line(vec![at(0.26, 0.44), at(0.5, 0.2), at(0.74, 0.44)]);
        }
        Icon::Upload | Icon::Download => {
            line(vec![at(0.18, 0.62), at(0.18, 0.82), at(0.82, 0.82), at(0.82, 0.62)]);
            line(vec![at(0.5, 0.16), at(0.5, 0.64)]);
            if icon == Icon::Upload {
                line(vec![at(0.32, 0.34), at(0.5, 0.16), at(0.68, 0.34)]);
            } else {
                line(vec![at(0.32, 0.46), at(0.5, 0.64), at(0.68, 0.46)]);
            }
        }
        Icon::File => {
            line(vec![at(0.24, 0.12), at(0.58, 0.12), at(0.78, 0.32), at(0.78, 0.88), at(0.24, 0.88), at(0.24, 0.12)]);
            line(vec![at(0.58, 0.12), at(0.58, 0.32), at(0.78, 0.32)]);
        }
        Icon::FolderPlus => {
            line(vec![
                at(0.14, 0.78),
                at(0.14, 0.24),
                at(0.4, 0.24),
                at(0.48, 0.34),
                at(0.86, 0.34),
                at(0.86, 0.78),
                at(0.14, 0.78),
            ]);
            line(vec![at(0.5, 0.45), at(0.5, 0.69)]);
            line(vec![at(0.38, 0.57), at(0.62, 0.57)]);
        }
        Icon::External => {
            line(vec![at(0.46, 0.2), at(0.2, 0.2), at(0.2, 0.8), at(0.8, 0.8), at(0.8, 0.54)]);
            line(vec![at(0.48, 0.52), at(0.82, 0.18)]);
            line(vec![at(0.58, 0.18), at(0.82, 0.18), at(0.82, 0.42)]);
        }
        Icon::Expand | Icon::Shrink => {
            // quatre coins, vers l'extérieur (agrandir) ou vers l'intérieur (réduire)
            let out = icon == Icon::Expand;
            for (cx, cy) in [(0.2, 0.2), (0.8, 0.2), (0.2, 0.8), (0.8, 0.8)] {
                let (dx, dy) = (if cx < 0.5 { 1.0 } else { -1.0 }, if cy < 0.5 { 1.0 } else { -1.0 });
                let (ox, oy) = if out { (cx, cy) } else { (cx + dx * 0.22, cy + dy * 0.22) };
                let (sx, sy) = if out { (dx, dy) } else { (-dx, -dy) };
                line(vec![at(ox + sx * 0.2, oy), at(ox, oy), at(ox, oy + sy * 0.2)]);
            }
        }
        Icon::Monitor => {
            p.rect_stroke(Rect::from_min_max(at(0.1, 0.18), at(0.9, 0.7)), s * 0.07, st, egui::StrokeKind::Middle);
            line(vec![at(0.5, 0.7), at(0.5, 0.84)]);
            line(vec![at(0.32, 0.84), at(0.68, 0.84)]);
        }
    }
}

pub fn icon_size(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint_icon(ui.painter(), rect, icon, color);
    resp
}

/// Bouton icône carré, discret.
pub fn icon_button(ui: &mut egui::Ui, icon: Icon, tooltip: &str) -> Response {
    icon_button_sized(ui, icon, 32.0, tooltip)
}

pub fn icon_button_sized(ui: &mut egui::Ui, icon: Icon, size: f32, tooltip: &str) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let t = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    if t > 0.0 {
        ui.painter().rect_filled(rect, 8.0, HOVER.gamma_multiply(t));
    }
    let col = lerp_color(MUTED, TEXT, t);
    paint_icon(ui.painter(), rect.shrink(size * 0.24), icon, col);
    if tooltip.is_empty() { resp } else { resp.on_hover_text(tooltip) }
}

pub fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgba_unmultiplied(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()), l(a.a(), b.a()))
}

// ---------------------------------------------------------------- boutons

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Primary,
    Secondary,
    Ghost,
    Danger,
}

/// Bouton moderne avec icône optionnelle. `width` = 0 → largeur du contenu.
pub fn button(ui: &mut egui::Ui, kind: Kind, icon: Option<Icon>, text: &str, width: f32) -> Response {
    button_h(ui, kind, icon, text, width, 38.0)
}

pub fn button_h(ui: &mut egui::Ui, kind: Kind, icon: Option<Icon>, text: &str, width: f32, h: f32) -> Response {
    let font = bold(14.0);
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, TEXT);
    let icon_w = if icon.is_some() { 16.0 + 8.0 } else { 0.0 };
    let content_w = galley.size().x + icon_w;
    let w = if width > 0.0 { width } else { content_w + 32.0 };
    let (rect, resp) = ui.allocate_exact_size(vec2(w, h), Sense::click());
    let hover = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    let pressed = resp.is_pointer_button_down_on();
    let (fill, fg, stroke) = match kind {
        Kind::Primary => (
            lerp_color(ACCENT, Color32::from_rgb(0x5E, 0xEA, 0xD4), hover * 0.6),
            ON_ACCENT,
            Stroke::NONE,
        ),
        Kind::Secondary => (lerp_color(ELEVATED, HOVER, hover), TEXT, Stroke::new(1.0, BORDER_STRONG)),
        Kind::Ghost => (HOVER.gamma_multiply(hover), lerp_color(TEXT_DIM, TEXT, hover), Stroke::NONE),
        Kind::Danger => (
            lerp_color(DANGER.gamma_multiply(0.14), DANGER.gamma_multiply(0.24), hover),
            DANGER,
            Stroke::new(1.0, DANGER.gamma_multiply(0.4)),
        ),
    };
    let r = if pressed { rect.shrink(0.5) } else { rect };
    ui.painter().rect(r, RADIUS, fill, stroke, egui::StrokeKind::Inside);
    let start = r.center().x - content_w / 2.0;
    if let Some(i) = icon {
        paint_icon(ui.painter(), Rect::from_center_size(pos2(start + 8.0, r.center().y), Vec2::splat(16.0)), i, fg);
    }
    let galley = ui.painter().layout_no_wrap(text.to_owned(), bold(14.0), fg);
    ui.painter().galley(pos2(start + icon_w, r.center().y - galley.size().y / 2.0), galley, fg);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Lien textuel discret.
pub fn link(ui: &mut egui::Ui, text: &str) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), FontId::proportional(13.0), MUTED);
    let (rect, resp) = ui.allocate_exact_size(galley.size() + vec2(4.0, 6.0), Sense::click());
    let col = if resp.hovered() { ACCENT } else { TEXT_DIM };
    let galley = ui.painter().layout_no_wrap(text.to_owned(), FontId::proportional(13.0), col);
    ui.painter().galley(rect.min + vec2(2.0, 3.0), galley, col);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

// ---------------------------------------------------------------- champs

pub fn label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).font(bold(12.5)).color(TEXT_DIM));
}

/// Champ texte moderne (hauteur 40).
pub fn input(ui: &mut egui::Ui, value: &mut String, placeholder: &str, password: bool, width: f32) -> Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .password(password)
            .hint_text(RichText::new(placeholder).color(MUTED))
            .margin(Margin::symmetric(12, 10))
            .desired_width(width),
    )
}

/// Champ mot de passe avec bouton œil intégré.
pub fn password_input(ui: &mut egui::Ui, value: &mut String, placeholder: &str, visible: &mut bool, width: f32) -> Response {
    let resp = ui.add(
        egui::TextEdit::singleline(value)
            .password(!*visible)
            .hint_text(RichText::new(placeholder).color(MUTED))
            .margin(Margin { left: 12, right: 40, top: 10, bottom: 10 })
            .desired_width(width),
    );
    let r = Rect::from_center_size(pos2(resp.rect.right() - 20.0, resp.rect.center().y), Vec2::splat(28.0));
    let b = ui.interact(r, resp.id.with("eye"), Sense::CLICK);
    paint_icon(
        ui.painter(),
        r.shrink(6.0),
        if *visible { Icon::EyeOff } else { Icon::Eye },
        if b.hovered() { TEXT } else { MUTED },
    );
    if b.clicked() {
        *visible = !*visible;
    }
    resp
}

/// Champ de recherche avec loupe.
pub fn search_input(ui: &mut egui::Ui, value: &mut String, placeholder: &str) -> Response {
    let resp = ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(RichText::new(placeholder).color(MUTED))
            .margin(Margin { left: 34, right: 10, top: 9, bottom: 9 })
            .desired_width(f32::INFINITY),
    );
    let r = Rect::from_center_size(pos2(resp.rect.left() + 18.0, resp.rect.center().y), Vec2::splat(15.0));
    paint_icon(ui.painter(), r, Icon::Search, MUTED);
    resp
}

/// Contrôle segmenté.
pub fn segmented<T: PartialEq + Clone>(ui: &mut egui::Ui, value: &mut T, options: &[(T, Icon, &str)], width: f32) -> bool {
    let h = 40.0;
    let (rect, _) = ui.allocate_exact_size(vec2(width, h), Sense::hover());
    ui.painter().rect(rect, RADIUS, INPUT, Stroke::new(1.0, BORDER), egui::StrokeKind::Inside);
    let seg_w = (width - 8.0) / options.len() as f32;
    let mut changed = false;
    for (i, (v, icon, text)) in options.iter().enumerate() {
        let r = Rect::from_min_size(rect.min + vec2(4.0 + i as f32 * seg_w, 4.0), vec2(seg_w, h - 8.0));
        let resp = ui.interact(r, ui.id().with(("seg", i, text)), Sense::click());
        let selected = value == v;
        if selected {
            ui.painter().rect_filled(r, RADIUS - 3, ELEVATED);
            ui.painter().rect_stroke(r, RADIUS - 3, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
        } else if resp.hovered() {
            ui.painter().rect_filled(r, RADIUS - 3, HOVER.gamma_multiply(0.5));
        }
        let col = if selected { TEXT } else { TEXT_DIM };
        let galley = ui.painter().layout_no_wrap(text.to_string(), bold(13.0), col);
        let total = galley.size().x + 22.0;
        let x0 = r.center().x - total / 2.0;
        paint_icon(ui.painter(), Rect::from_center_size(pos2(x0 + 7.0, r.center().y), Vec2::splat(14.0)), *icon, if selected { ACCENT } else { MUTED });
        ui.painter().galley(pos2(x0 + 22.0, r.center().y - galley.size().y / 2.0), galley, col);
        if resp.clicked() && !selected {
            *value = v.clone();
            changed = true;
        }
    }
    changed
}

// ---------------------------------------------------------------- fenêtre sans bordure

fn maximized(ctx: &egui::Context) -> bool {
    ctx.input(|i| i.viewport().maximized.unwrap_or(false))
}

/// Zone de déplacement de la fenêtre (glisser) ; double-clic = agrandir/restaurer.
/// À appeler avant les widgets de la zone pour qu'ils restent cliquables.
pub fn drag_area(ui: &mut egui::Ui, rect: Rect, id: &str) {
    let resp = ui.interact(rect, egui::Id::new(("drag-area", id)), Sense::click_and_drag());
    if resp.drag_started_by(egui::PointerButton::Primary) {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    if resp.double_clicked() {
        let m = maximized(ui.ctx());
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Maximized(!m));
    }
}

/// Largeur totale des boutons de fenêtre (3 × 42 + 2 espacements de 2).
pub const WINDOW_CONTROLS_W: f32 = 3.0 * 42.0 + 2.0 * 2.0;

/// Boutons réduire / agrandir / fermer (à placer dans une mise en page de droite à gauche).
pub fn window_controls(ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    let max = maximized(&ctx);
    ui.spacing_mut().item_spacing.x = 2.0;
    for kind in [2u8, 1, 0] {
        let (r, resp) = ui.allocate_exact_size(vec2(42.0, 32.0), Sense::click());
        let hov = resp.hovered();
        if hov {
            let bg = if kind == 2 { Color32::from_rgb(0xE5, 0x48, 0x4D) } else { HOVER };
            ui.painter().rect_filled(r, 8.0, bg);
        }
        let col = if hov && kind == 2 { Color32::WHITE } else if hov { TEXT } else { TEXT_DIM };
        let st = Stroke::new(1.3, col);
        let c = r.center();
        let p = ui.painter();
        match kind {
            0 => {
                p.line_segment([c + vec2(-5.5, 0.0), c + vec2(5.5, 0.0)], st);
            }
            1 if max => {
                p.rect_stroke(Rect::from_center_size(c + vec2(-1.5, 1.5), Vec2::splat(8.0)), 1.5, st, egui::StrokeKind::Middle);
                p.add(Shape::line(vec![c + vec2(-2.5, -3.5), c + vec2(-2.5, -5.5), c + vec2(5.5, -5.5), c + vec2(5.5, 2.5), c + vec2(3.5, 2.5)], st));
            }
            1 => {
                p.rect_stroke(Rect::from_center_size(c, Vec2::splat(10.0)), 1.5, st, egui::StrokeKind::Middle);
            }
            _ => {
                p.line_segment([c + vec2(-5.0, -5.0), c + vec2(5.0, 5.0)], st);
                p.line_segment([c + vec2(5.0, -5.0), c + vec2(-5.0, 5.0)], st);
            }
        }
        let tip = match kind {
            0 => "Réduire",
            1 if max => "Restaurer",
            1 => "Agrandir",
            _ => "Fermer",
        };
        if resp.on_hover_text(tip).clicked() {
            ctx.send_viewport_cmd(match kind {
                0 => egui::ViewportCommand::Minimized(true),
                1 => egui::ViewportCommand::Maximized(!max),
                _ => egui::ViewportCommand::Close,
            });
        }
    }
}

/// Changement d'écran (autre échelle) : la fenêtre garde sa taille logique, bornée à l'écran.
fn keep_size_across_monitors(ctx: &egui::Context) {
    let (ppp, inner, monitor, max, full, pressed) = ctx.input(|i| {
        let v = i.viewport();
        (v.native_pixels_per_point, v.inner_rect, v.monitor_size, v.maximized.unwrap_or(false), v.fullscreen.unwrap_or(false), i.pointer.any_down())
    });
    let (Some(ppp), Some(inner)) = (ppp, inner) else { return };
    let id = egui::Id::new(("window-scale", ctx.viewport_id()));
    let prev: Option<(f32, Vec2)> = ctx.data(|d| d.get_temp(id));
    let Some((prev_ppp, prev_size)) = prev else {
        ctx.data_mut(|d| d.insert_temp(id, (ppp, inner.size())));
        return;
    };
    if (prev_ppp - ppp).abs() < 1e-3 {
        if !max && !full {
            ctx.data_mut(|d| d.insert_temp(id, (ppp, inner.size())));
        }
        return;
    }
    // attendre la fin du déplacement à la souris
    if pressed || full {
        return;
    }
    // fenêtre agrandie : déjà bornée à son écran par winit
    let mut size = prev_size;
    if !max {
        let limit = monitor.map_or(Vec2::INFINITY, |m| m * 0.95);
        size = prev_size.min(limit).max(vec2(720.0, 420.0));
        if (size - inner.size()).abs().max_elem() > 1.0 {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
        }
    }
    ctx.data_mut(|d| d.insert_temp(id, (ppp, size)));
    ctx.request_repaint();
}

/// Redimensionnement par les bords de la fenêtre + fine bordure (fenêtre sans décorations).
pub fn window_frame(ctx: &egui::Context) {
    keep_size_across_monitors(ctx);
    let r = ctx.content_rect();
    if !maximized(ctx) {
        ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("window-border")))
            .rect_stroke(r, 0.0, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
        let m = 5.0;
        if let Some(p) = ctx.input(|i| i.pointer.hover_pos()) {
            let (l, rt, t, b) = (p.x <= r.left() + m, p.x >= r.right() - m, p.y <= r.top() + m, p.y >= r.bottom() - m);
            use egui::ResizeDirection as D;
            let dir = match (l, rt, t, b) {
                (true, _, true, _) => D::NorthWest,
                (_, true, true, _) => D::NorthEast,
                (true, _, _, true) => D::SouthWest,
                (_, true, _, true) => D::SouthEast,
                (true, ..) => D::West,
                (_, true, ..) => D::East,
                (_, _, true, _) => D::North,
                (_, _, _, true) => D::South,
                _ => return,
            };
            ctx.set_cursor_icon(match dir {
                D::West | D::East => egui::CursorIcon::ResizeHorizontal,
                D::North | D::South => egui::CursorIcon::ResizeVertical,
                D::NorthWest | D::SouthEast => egui::CursorIcon::ResizeNwSe,
                D::NorthEast | D::SouthWest => egui::CursorIcon::ResizeNeSw,
            });
            if ctx.input(|i| i.pointer.primary_pressed()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
            }
        }
    }
}

/// Interrupteur on/off.
pub fn toggle(ui: &mut egui::Ui, on: &mut bool) -> Response {
    let (rect, mut resp) = ui.allocate_exact_size(vec2(42.0, 24.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_with_time(resp.id, *on, 0.15);
    ui.painter().rect_filled(rect, 12.0, lerp_color(BORDER_STRONG, ACCENT, t));
    let x = rect.left() + 12.0 + t * (rect.width() - 24.0);
    ui.painter().circle_filled(pos2(x, rect.center().y), 9.0, lerp_color(TEXT_DIM, Color32::WHITE, t));
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

// ---------------------------------------------------------------- décor

pub fn card() -> egui::Frame {
    egui::Frame::new().fill(SURFACE).stroke(Stroke::new(1.0, BORDER)).corner_radius(14).inner_margin(Margin::same(18))
}

pub fn modal_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER_STRONG))
        .corner_radius(18)
        .inner_margin(Margin::same(26))
        .shadow(egui::Shadow { offset: [0, 20], blur: 60, spread: 0, color: Color32::from_black_alpha(170) })
}

pub fn modal(id: &str) -> egui::Modal {
    egui::Modal::new(egui::Id::new(id)).frame(modal_frame()).backdrop_color(Color32::from_black_alpha(170))
}

/// En-tête de modale : pastille icône + titre + sous-titre.
pub fn modal_header(ui: &mut egui::Ui, icon: Icon, tint: Color32, title: &str, subtitle: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
        ui.painter().rect_filled(r, 12.0, tint.gamma_multiply(0.14));
        paint_icon(ui.painter(), r.shrink(11.0), icon, tint);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(RichText::new(title).font(bold(18.0)));
            if !subtitle.is_empty() {
                ui.label(RichText::new(subtitle).size(13.0).color(MUTED));
            }
        });
    });
}

pub fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.add_space(4.0);
    ui.label(RichText::new(text.to_uppercase()).font(bold(11.0)).color(MUTED));
    ui.add_space(2.0);
}

pub fn divider(ui: &mut egui::Ui) {
    let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(r, 0.0, BORDER);
}

/// Pastille d'information.
pub fn chip(ui: &mut egui::Ui, icon: Option<Icon>, text: &str, color: Color32) -> Response {
    let font = FontId::proportional(12.0);
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, color);
    let iw = if icon.is_some() { 16.0 } else { 0.0 };
    let (rect, resp) = ui.allocate_exact_size(vec2(galley.size().x + iw + 16.0, 22.0), Sense::hover());
    ui.painter().rect_filled(rect, 11.0, color.gamma_multiply(0.12));
    if let Some(i) = icon {
        paint_icon(ui.painter(), Rect::from_center_size(pos2(rect.left() + 14.0, rect.center().y), Vec2::splat(11.0)), i, color);
    }
    ui.painter().galley(pos2(rect.left() + 8.0 + iw, rect.center().y - galley.size().y / 2.0), galley, color);
    resp
}

/// Touche de clavier.
pub fn keycap(ui: &mut egui::Ui, text: &str) {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), mono_bold(11.5), TEXT_DIM);
    let (rect, _) = ui.allocate_exact_size(vec2(galley.size().x.max(14.0) + 12.0, 22.0), Sense::hover());
    ui.painter().rect(rect, 6.0, ELEVATED, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
    ui.painter().line_segment(
        [pos2(rect.left() + 3.0, rect.bottom() - 1.5), pos2(rect.right() - 3.0, rect.bottom() - 1.5)],
        Stroke::new(1.0, BORDER_STRONG),
    );
    ui.painter().galley(rect.center() - galley.size() / 2.0 - vec2(0.0, 1.0), galley, TEXT_DIM);
}

pub fn shortcut(ui: &mut egui::Ui, keys: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for (i, k) in keys.split('+').enumerate() {
            if i > 0 {
                ui.label(RichText::new("+").size(11.0).color(MUTED));
            }
            keycap(ui, k);
        }
    });
}

const AVATAR_COLORS: [Color32; 8] = [
    Color32::from_rgb(0x2D, 0xD4, 0xBF),
    Color32::from_rgb(0x38, 0xBD, 0xF8),
    Color32::from_rgb(0xA7, 0x8B, 0xFA),
    Color32::from_rgb(0xF4, 0x72, 0xB6),
    Color32::from_rgb(0xFB, 0xBF, 0x24),
    Color32::from_rgb(0x4A, 0xDE, 0x80),
    Color32::from_rgb(0xFB, 0x92, 0x3C),
    Color32::from_rgb(0x81, 0x8C, 0xF8),
];

pub fn avatar_color(name: &str) -> Color32 {
    let h = name.bytes().fold(5381u32, |h, b| h.wrapping_mul(33) ^ b as u32);
    AVATAR_COLORS[(h % AVATAR_COLORS.len() as u32) as usize]
}

pub fn paint_avatar(p: &egui::Painter, rect: Rect, name: &str) {
    let c = avatar_color(name);
    p.rect_filled(rect, rect.width() * 0.3, c.gamma_multiply(0.16));
    let initials: String = name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();
    let initials = if initials.is_empty() { "?".into() } else { initials };
    p.text(rect.center(), Align2::CENTER_CENTER, initials, bold(rect.height() * 0.38), c);
}

/// Halo lumineux radial (dégradé) pour les fonds.
pub fn glow(p: &egui::Painter, center: Pos2, radius: f32, color: Color32) {
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(center, color);
    let n = 64;
    for i in 0..=n {
        let a = i as f32 / n as f32 * 2.0 * PI;
        mesh.colored_vertex(center + vec2(a.cos(), a.sin()) * radius, Color32::TRANSPARENT);
    }
    for i in 1..=n as u32 {
        mesh.add_triangle(0, i, i + 1);
    }
    p.add(Shape::mesh(mesh));
}

// ---------------------------------------------------------------- code PIN

/// Lit les chiffres tapés au clavier (et retour arrière) en les retirant de la file d'événements.
pub fn read_digits(ctx: &egui::Context, value: &mut String, max: usize) {
    ctx.input_mut(|i| {
        i.events.retain(|ev| match ev {
            egui::Event::Text(t) if t.chars().all(|c| c.is_ascii_digit()) => {
                for c in t.chars() {
                    if value.len() < max {
                        value.push(c);
                    }
                }
                false
            }
            egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => {
                value.pop();
                false
            }
            _ => true,
        })
    });
}

/// Six cases de code PIN. `error_at` : instant d'une erreur (déclenche la secousse).
pub fn pin_boxes(ui: &mut egui::Ui, value: &str, error_at: Option<f64>, focused: bool) {
    let (bw, bh, gap) = (50.0, 60.0, 10.0);
    let total = 6.0 * bw + 5.0 * gap;
    let (rect, _) = ui.allocate_exact_size(vec2(total, bh), Sense::hover());
    let now = ui.input(|i| i.time);
    let mut dx = 0.0;
    let mut err = false;
    if let Some(t0) = error_at {
        let t = (now - t0) as f32;
        if t < 0.45 {
            dx = (t * 55.0).sin() * 9.0 * (1.0 - t / 0.45);
            ui.ctx().request_repaint();
        }
        err = t < 1.2;
        if err {
            ui.ctx().request_repaint();
        }
    }
    let blink = ((now * 2.0).fract() < 0.6) as u8 as f32;
    if focused {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
    }
    for i in 0..6 {
        let r = Rect::from_min_size(pos2(rect.left() + dx + i as f32 * (bw + gap), rect.top()), vec2(bw, bh));
        let filled = i < value.len();
        let current = focused && i == value.len();
        let border = if err {
            DANGER
        } else if current {
            ACCENT
        } else if filled {
            BORDER_STRONG
        } else {
            BORDER
        };
        ui.painter().rect(r, 12.0, if filled { ELEVATED } else { INPUT }, Stroke::new(if current || err { 1.6 } else { 1.0 }, border), egui::StrokeKind::Inside);
        if current {
            // halo de focus
            ui.painter().rect_stroke(r.expand(3.0), 15.0, Stroke::new(3.0, ACCENT.gamma_multiply(0.15)), egui::StrokeKind::Outside);
            ui.painter().line_segment(
                [pos2(r.center().x, r.center().y - 11.0), pos2(r.center().x, r.center().y + 11.0)],
                Stroke::new(2.0, ACCENT.gamma_multiply(blink)),
            );
        }
        if filled {
            ui.painter().circle_filled(r.center(), 7.0, if err { DANGER } else { TEXT });
        }
    }
}

/// Indicateur de progression des étapes.
pub fn steps(ui: &mut egui::Ui, current: usize, total: usize, width: f32) {
    let gap = 6.0;
    let w = (width - gap * (total - 1) as f32) / total as f32;
    let (rect, _) = ui.allocate_exact_size(vec2(width, 4.0), Sense::hover());
    for i in 0..total {
        let r = Rect::from_min_size(pos2(rect.left() + i as f32 * (w + gap), rect.top()), vec2(w, 4.0));
        ui.painter().rect_filled(r, 2.0, if i <= current { ACCENT } else { BORDER_STRONG });
    }
}

/// Jauge de robustesse d'un mot de passe : (score 0..4, libellé, couleur).
pub fn password_strength(pw: &str) -> (usize, &'static str, Color32) {
    if pw.is_empty() {
        return (0, "", MUTED);
    }
    let len = pw.chars().count();
    let classes = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    let score = match (len, classes) {
        (0..=7, _) => 1,
        (8..=11, 0..=2) => 2,
        (8..=11, _) | (12..=15, 0..=2) => 3,
        _ => 4,
    };
    match score {
        1 => (1, "Trop court", DANGER),
        2 => (2, "Moyen", WARN),
        3 => (3, "Bon", ACCENT_2),
        _ => (4, "Excellent", ACCENT),
    }
}

pub fn strength_meter(ui: &mut egui::Ui, pw: &str, width: f32) {
    let (score, txt, col) = password_strength(pw);
    ui.horizontal(|ui| {
        let gap = 4.0;
        let bar_w = (width - 90.0 - gap * 3.0) / 4.0;
        let (rect, _) = ui.allocate_exact_size(vec2(width - 90.0, 4.0), Sense::hover());
        for i in 0..4 {
            let r = Rect::from_min_size(pos2(rect.left() + i as f32 * (bar_w + gap), rect.top()), vec2(bar_w, 4.0));
            ui.painter().rect_filled(r, 2.0, if i < score { col } else { BORDER_STRONG });
        }
        ui.label(RichText::new(txt).size(12.0).color(col));
    });
}

/// Encadré d'information / d'alerte.
pub fn callout(ui: &mut egui::Ui, icon: Icon, color: Color32, text: &str) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.08))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.25)))
        .corner_radius(RADIUS)
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                icon_size(ui, icon, 16.0, color);
                ui.add(egui::Label::new(RichText::new(text).size(13.0).color(TEXT_DIM)).wrap());
            });
        });
}
