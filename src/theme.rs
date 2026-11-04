//! Système de design : palette, typographie, style egui global.

use eframe::egui::{self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke, TextStyle, Vec2};
use std::sync::Arc;

pub const BG: Color32 = Color32::from_rgb(0x0A, 0x0D, 0x13);
pub const PANEL: Color32 = Color32::from_rgb(0x0E, 0x12, 0x1A);
pub const SURFACE: Color32 = Color32::from_rgb(0x14, 0x19, 0x23);
pub const ELEVATED: Color32 = Color32::from_rgb(0x1A, 0x20, 0x2C);
pub const HOVER: Color32 = Color32::from_rgb(0x21, 0x29, 0x38);
pub const INPUT: Color32 = Color32::from_rgb(0x0C, 0x10, 0x17);
pub const BORDER: Color32 = Color32::from_rgb(0x22, 0x2A, 0x38);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x30, 0x3A, 0x4C);
pub const TEXT: Color32 = Color32::from_rgb(0xE7, 0xEB, 0xF3);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0xA6, 0xB0, 0xC2);
pub const MUTED: Color32 = Color32::from_rgb(0x6F, 0x7A, 0x8E);
pub const ACCENT: Color32 = Color32::from_rgb(0x2D, 0xD4, 0xBF);
pub const ACCENT_2: Color32 = Color32::from_rgb(0x38, 0xBD, 0xF8);
pub const ON_ACCENT: Color32 = Color32::from_rgb(0x03, 0x1F, 0x1B);
pub const DANGER: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
pub const WARN: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);

pub const RADIUS: u8 = 10;

pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("bold".into()))
}

pub fn mono_bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("mono-bold".into()))
}

fn install_fonts(ctx: &egui::Context) {
    let mut f = FontDefinitions::default();
    let mut add = |name: &str, bytes: &'static [u8]| {
        f.font_data.insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    };
    add("inter", include_bytes!("../assets/fonts/Inter-Regular.ttf"));
    add("inter-ext", include_bytes!("../assets/fonts/Inter-RegularExt.ttf"));
    add("inter-sb", include_bytes!("../assets/fonts/Inter-SemiBold.ttf"));
    add("inter-sb-ext", include_bytes!("../assets/fonts/Inter-SemiBoldExt.ttf"));
    add("jbm", include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf"));
    add("jbm-bold", include_bytes!("../assets/fonts/JetBrainsMono-Bold.ttf"));

    let prop_fallback = f.families[&FontFamily::Proportional].clone();
    let mono_fallback = f.families[&FontFamily::Monospace].clone();
    let with = |first: &[&str], rest: &[String]| -> Vec<String> {
        first.iter().map(|s| s.to_string()).chain(rest.iter().cloned()).collect()
    };
    f.families.insert(FontFamily::Proportional, with(&["inter", "inter-ext"], &prop_fallback));
    f.families.insert(FontFamily::Monospace, with(&["jbm"], &mono_fallback));
    f.families.insert(FontFamily::Name("bold".into()), with(&["inter-sb", "inter-sb-ext"], &prop_fallback));
    f.families.insert(FontFamily::Name("mono-bold".into()), with(&["jbm-bold"], &mono_fallback));
    ctx.set_fonts(f);
}

pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);

    let mut v = egui::Visuals::dark();
    v.panel_fill = PANEL;
    v.window_fill = SURFACE;
    v.extreme_bg_color = INPUT;
    v.faint_bg_color = SURFACE;
    v.code_bg_color = ELEVATED;
    v.window_stroke = Stroke::new(1.0, BORDER);
    v.window_corner_radius = CornerRadius::same(16);
    v.menu_corner_radius = CornerRadius::same(RADIUS);
    v.selection.bg_fill = ACCENT.gamma_multiply(0.30);
    v.selection.stroke = Stroke::new(1.5, ACCENT);
    v.hyperlink_color = ACCENT;
    v.override_text_color = Some(TEXT);
    v.text_cursor.stroke = Stroke::new(2.0, ACCENT);
    v.popup_shadow = egui::Shadow { offset: [0, 8], blur: 24, spread: 0, color: Color32::from_black_alpha(120) };
    v.window_shadow = egui::Shadow { offset: [0, 16], blur: 48, spread: 0, color: Color32::from_black_alpha(150) };

    let r = CornerRadius::same(RADIUS);
    let w = &mut v.widgets;
    w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
    w.noninteractive.corner_radius = r;
    w.inactive.bg_fill = ELEVATED;
    w.inactive.weak_bg_fill = ELEVATED;
    w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    w.inactive.corner_radius = r;
    w.hovered.bg_fill = HOVER;
    w.hovered.weak_bg_fill = HOVER;
    w.hovered.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    w.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    w.hovered.corner_radius = r;
    w.hovered.expansion = 0.0;
    w.active.bg_fill = ACCENT.gamma_multiply(0.25);
    w.active.weak_bg_fill = ACCENT.gamma_multiply(0.25);
    w.active.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.fg_stroke = Stroke::new(1.0, TEXT);
    w.active.corner_radius = r;
    w.active.expansion = 0.0;
    w.open.corner_radius = r;
    w.open.bg_fill = HOVER;
    w.open.weak_bg_fill = HOVER;
    ctx.set_visuals(v);

    ctx.all_styles_mut(|s| {
        s.text_styles = [
            (TextStyle::Heading, bold(22.0)),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Small, FontId::proportional(12.0)),
            (TextStyle::Monospace, FontId::monospace(13.0)),
        ]
        .into();
        s.spacing.item_spacing = Vec2::new(10.0, 8.0);
        s.spacing.button_padding = Vec2::new(14.0, 8.0);
        s.spacing.interact_size.y = 34.0;
        s.spacing.menu_margin = Margin::same(6);
        s.spacing.combo_height = 320.0;
        s.spacing.scroll.bar_width = 6.0;
        s.spacing.scroll.floating = true;
        s.interaction.selectable_labels = false;
    });
}
