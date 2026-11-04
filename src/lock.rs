//! Choix du coffre, création (mot de passe → PIN → confirmation) et déverrouillage.

use crate::model::VaultData;
use crate::pin;
use crate::theme::*;
use crate::vault::{self, Vault, VaultInfo};
use crate::widgets::{self as w, Icon, Kind};
use eframe::egui::{self, RichText, Vec2, vec2};
use std::sync::mpsc::{Receiver, channel};
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Choose,
    CreatePassword,
    CreatePin,
    ConfirmPin,
    UnlockPin,
    UnlockPassword,
}

type Outcome = Result<(Vault, VaultData), Failure>;

enum Failure {
    Message(String),
    WrongPin,
}

pub struct LockScreen {
    step: Step,
    pw: String,
    pw2: String,
    show_pw: bool,
    pin1: String,
    pin2: String,
    error: Option<String>,
    shake_at: Option<f64>,
    busy: Option<(Receiver<Outcome>, &'static str)>,
    focus_pw: bool,
    /// Information (non erreur) affichée sous le formulaire.
    notice: Option<String>,
    /// Coffres présents sur l'appareil.
    vaults: Vec<VaultInfo>,
    /// Coffre à déverrouiller.
    current: Option<VaultInfo>,
    /// Propriétaire du coffre en cours de création.
    owner: String,
}

const W: f32 = 380.0;

impl LockScreen {
    pub fn new() -> Self {
        let vaults = vault::list();
        let current = vault::last_used(&vaults);
        let step = Self::unlock_step(current.as_ref());
        Self {
            step,
            pw: String::new(),
            pw2: String::new(),
            show_pw: false,
            pin1: String::new(),
            pin2: String::new(),
            error: None,
            shake_at: None,
            busy: None,
            focus_pw: true,
            notice: None,
            vaults,
            current,
            owner: vault::windows_user(),
        }
    }

    fn unlock_step(v: Option<&VaultInfo>) -> Step {
        match v {
            None => Step::CreatePassword,
            Some(v) if pin::is_enabled(&v.path) => Step::UnlockPin,
            Some(_) => Step::UnlockPassword,
        }
    }

    fn select(&mut self, v: VaultInfo) {
        self.pin1.zeroize();
        self.pw.zeroize();
        self.error = None;
        self.notice = None;
        self.step = Self::unlock_step(Some(&v));
        self.focus_pw = true;
        vault::set_last_used(&v.path);
        self.current = Some(v);
    }

    fn start_create(&mut self) {
        self.pin1.zeroize();
        self.pw.zeroize();
        self.pw2.zeroize();
        self.error = None;
        self.notice = None;
        self.owner = if self.vaults.is_empty() { vault::windows_user() } else { String::new() };
        self.focus_pw = true;
        self.step = Step::CreatePassword;
    }

    fn current_path(&self) -> std::path::PathBuf {
        self.current.as_ref().map(|v| v.path.clone()).unwrap_or_else(vault::new_slot)
    }

    fn fail(&mut self, ui: &egui::Ui, msg: impl Into<String>) {
        self.error = Some(msg.into());
        self.shake_at = Some(ui.input(|i| i.time));
    }

    fn run(&mut self, ctx: &egui::Context, label: &'static str, job: impl FnOnce() -> Outcome + Send + 'static) {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(job());
            ctx.request_repaint();
        });
        self.busy = Some((rx, label));
    }

    /// Affiche l'écran ; renvoie le coffre ouvert une fois déverrouillé.
    pub fn show(&mut self, ui: &mut egui::Ui, logo: &egui::TextureHandle) -> Option<(Vault, VaultData)> {
        let before = (self.step, self.error.clone(), self.busy.is_some());
        let opened = self.show_inner(ui, logo);
        // un changement d'état après le dessin doit être affiché immédiatement
        if before != (self.step, self.error.clone(), self.busy.is_some()) || opened.is_some() {
            ui.ctx().request_repaint();
        }
        opened
    }

    fn show_inner(&mut self, ui: &mut egui::Ui, logo: &egui::TextureHandle) -> Option<(Vault, VaultData)> {
        let mut opened = None;
        if let Some((rx, _)) = &self.busy {
            if let Ok(res) = rx.try_recv() {
                self.busy = None;
                match res {
                    Ok(v) => opened = Some(v),
                    Err(Failure::WrongPin) => {
                        self.pin1.zeroize();
                        self.step = Step::UnlockPassword;
                        self.focus_pw = true;
                        self.fail(ui, "Code PIN incorrect. Confirmez votre identité avec le mot de passe maître.");
                    }
                    Err(Failure::Message(m)) => {
                        self.pin1.zeroize();
                        if self.step == Step::UnlockPin {
                            self.step = Step::UnlockPassword;
                            self.focus_pw = true;
                        }
                        self.fail(ui, m);
                    }
                }
            }
        }

        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ui, |ui| {
            let full = ui.max_rect();
            let p = ui.painter();
            w::glow(p, full.center_top() + vec2(-full.width() * 0.25, full.height() * 0.15), full.width() * 0.55, ACCENT.gamma_multiply(0.07));
            w::glow(p, full.right_bottom() + vec2(-full.width() * 0.15, -full.height() * 0.1), full.width() * 0.5, ACCENT_2.gamma_multiply(0.06));

            // barre de titre invisible : déplacement + boutons de fenêtre
            let bar = egui::Rect::from_min_size(full.min, vec2(full.width(), 44.0));
            w::drag_area(ui, bar, "lock");
            let mut controls = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(bar.shrink2(vec2(8.0, 6.0)))
                    .layout(egui::Layout::right_to_left(egui::Align::Center)),
            );
            w::window_controls(&mut controls);

            let content_h = 520.0;
            ui.add_space(((full.height() - content_h) / 2.0).max(24.0));
            ui.vertical_centered(|ui| {
                ui.set_max_width(W);
                ui.add(egui::Image::from_texture(logo).fit_to_exact_size(Vec2::splat(64.0)));
                ui.add_space(18.0);
                self.body(ui);
            });
        });
        opened
    }

    fn title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
        ui.label(RichText::new(title).font(bold(26.0)));
        ui.add_space(2.0);
        ui.label(RichText::new(subtitle).size(14.0).color(TEXT_DIM));
        ui.add_space(22.0);
    }

    fn body(&mut self, ui: &mut egui::Ui) {
        if let Some((_, label)) = &self.busy {
            ui.add_space(40.0);
            ui.add(egui::Spinner::new().size(28.0).color(ACCENT));
            ui.add_space(12.0);
            ui.label(RichText::new(*label).color(TEXT_DIM));
            ui.add_space(80.0);
            return;
        }
        match self.step {
            Step::Choose => self.choose(ui),
            Step::CreatePassword => self.create_password(ui),
            Step::CreatePin => self.create_pin(ui, false),
            Step::ConfirmPin => self.create_pin(ui, true),
            Step::UnlockPin => self.unlock_pin(ui),
            Step::UnlockPassword => self.unlock_password(ui),
        }
    }

    fn error_line(&self, ui: &mut egui::Ui) {
        if let (Some(n), None) = (&self.notice, &self.error) {
            ui.add_space(4.0);
            w::callout(ui, Icon::Check, ACCENT, n);
        }
        if let Some(e) = &self.error {
            ui.add_space(4.0);
            w::callout(ui, Icon::Warning, DANGER, e);
        }
    }

    // ---- création : étape 1
    fn create_password(&mut self, ui: &mut egui::Ui) {
        w::steps(ui, 0, 3, W);
        ui.add_space(22.0);
        if self.vaults.is_empty() {
            Self::title(ui, "Bienvenue sur Escale", "Créez le mot de passe maître qui chiffre votre coffre.");
        } else {
            Self::title(ui, "Nouveau coffre", "Un coffre séparé, avec son propre mot de passe et son propre PIN.");
        }
        let mut submit = false;
        let mut restore = false;
        let mut back = false;
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            w::label(ui, "Propriétaire");
            w::input(ui, &mut self.owner, "Nom de la personne à qui appartient ce coffre", false, W);
            ui.add_space(10.0);
            w::label(ui, "Mot de passe maître");
            let r = w::password_input(ui, &mut self.pw, "Au moins 8 caractères", &mut self.show_pw, W);
            if self.focus_pw {
                r.request_focus();
                self.focus_pw = false;
            }
            submit |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.add_space(2.0);
            w::strength_meter(ui, &self.pw, W);
            ui.add_space(10.0);
            w::label(ui, "Confirmation");
            let r2 = w::password_input(ui, &mut self.pw2, "Retapez le mot de passe", &mut self.show_pw, W);
            submit |= r2.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.add_space(12.0);
            w::callout(ui, Icon::Lock, ACCENT_2, "Ce mot de passe n'est jamais stocké et ne peut pas être récupéré. Gardez-le précieusement.");
            self.error_line(ui);
            ui.add_space(14.0);
            submit |= w::button_h(ui, Kind::Primary, None, "Continuer", W, 44.0).clicked();
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_space((W - 230.0) / 2.0);
                ui.label(RichText::new("Déjà un coffre ?").size(12.5).color(MUTED));
                if w::link(ui, "Restaurer une sauvegarde…").clicked() {
                    restore = true;
                }
            });
            if !self.vaults.is_empty() {
                ui.add_space(6.0);
                ui.vertical_centered(|ui| back = w::link(ui, "Revenir aux coffres existants").clicked());
            }
        });
        if back {
            self.pw.zeroize();
            self.pw2.zeroize();
            self.error = None;
            self.step = Step::Choose;
            return;
        }
        if restore {
            match restore_backup() {
                Ok(Some(info)) => {
                    self.vaults = vault::list();
                    self.select(info);
                    self.pw2.zeroize();
                    self.notice = Some("Sauvegarde restaurée dans un nouveau coffre. Saisissez son mot de passe maître.".into());
                }
                Ok(None) => {}
                Err(e) => self.fail(ui, e),
            }
            return;
        }
        if submit {
            if self.owner.trim().is_empty() {
                self.fail(ui, "Indiquez à qui appartient ce coffre.");
            } else if self.pw.chars().count() < 8 {
                self.fail(ui, "Le mot de passe doit contenir au moins 8 caractères.");
            } else if self.pw != self.pw2 {
                self.fail(ui, "Les deux mots de passe ne correspondent pas.");
            } else {
                self.error = None;
                self.step = Step::CreatePin;
            }
        }
    }

    // ---- création : étapes 2 et 3
    fn create_pin(&mut self, ui: &mut egui::Ui, confirm: bool) {
        w::steps(ui, if confirm { 2 } else { 1 }, 3, W);
        ui.add_space(22.0);
        if confirm {
            Self::title(ui, "Confirmez votre code PIN", "Saisissez à nouveau les 6 chiffres.");
        } else {
            Self::title(ui, "Choisissez un code PIN", "6 chiffres pour déverrouiller Escale en un instant.");
        }
        let target = if confirm { &mut self.pin2 } else { &mut self.pin1 };
        w::read_digits(ui.ctx(), target, 6);
        w::pin_boxes(ui, target, self.shake_at, true);
        ui.add_space(16.0);
        if let Some(e) = &self.error {
            ui.label(RichText::new(e).size(13.0).color(DANGER));
        } else {
            ui.label(RichText::new("Tapez les chiffres au clavier").size(12.5).color(MUTED));
        }
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.add_space((W - 230.0) / 2.0);
            if w::button(ui, Kind::Ghost, Some(Icon::Back), "Retour", 110.0).clicked() {
                self.error = None;
                if confirm {
                    self.pin1.zeroize();
                    self.pin2.zeroize();
                    self.step = Step::CreatePin;
                } else {
                    self.pin1.zeroize();
                    self.step = Step::CreatePassword;
                }
            }
            if !confirm && w::button(ui, Kind::Ghost, None, "Passer", 110.0).on_hover_text("Créer le coffre sans code PIN").clicked() {
                self.pin1.zeroize();
                self.finish_create(ui.ctx());
            }
        });

        if !confirm && self.pin1.len() == 6 {
            self.error = None;
            self.step = Step::ConfirmPin;
        } else if confirm && self.pin2.len() == 6 {
            if self.pin1 == self.pin2 {
                self.finish_create(ui.ctx());
            } else {
                self.pin1.zeroize();
                self.pin2.zeroize();
                self.step = Step::CreatePin;
                self.fail(ui, "Les codes ne correspondent pas. Recommencez.");
            }
        }
    }

    fn finish_create(&mut self, ctx: &egui::Context) {
        let pw = std::mem::take(&mut self.pw);
        self.pw2.zeroize();
        let chosen = (self.pin1.len() == 6).then(|| self.pin1.clone());
        self.pin1.zeroize();
        self.pin2.zeroize();
        let owner = self.owner.trim().to_string();
        self.run(ctx, "Création du coffre chiffré…", move || {
            let mut pw = pw;
            let path = vault::new_slot();
            let vault = Vault::create_at(path.clone(), &pw).map_err(Failure::Message);
            pw.zeroize();
            let vault = vault?;
            let profile = vault::Profile { owner: owner.clone(), windows_user: vault::windows_user(), created: vault::now() };
            vault::write_profile(&path, &profile).map_err(Failure::Message)?;
            vault::set_last_used(&path);
            let data = VaultData { owner, pin: chosen.clone(), ..Default::default() };
            vault.save(&data).map_err(Failure::Message)?;
            if let Some(p) = chosen {
                pin::enable(&vault, &p).map_err(Failure::Message)?;
            }
            Ok((vault, data))
        });
    }

    // ---- déverrouillage par PIN
    fn unlock_pin(&mut self, ui: &mut egui::Ui) {
        Self::title(ui, "Bon retour", "Entrez votre code PIN pour déverrouiller le coffre.");
        self.vault_badge(ui);
        if self.step != Step::UnlockPin {
            return;
        }
        w::read_digits(ui.ctx(), &mut self.pin1, 6);
        w::pin_boxes(ui, &self.pin1, self.shake_at, true);
        ui.add_space(22.0);
        if w::link(ui, "Utiliser le mot de passe maître").clicked() {
            self.pin1.zeroize();
            self.error = None;
            self.step = Step::UnlockPassword;
            self.focus_pw = true;
        }
        if self.pin1.len() == 6 {
            let pin = std::mem::take(&mut self.pin1);
            let path = self.current_path();
            self.run(ui.ctx(), "Vérification…", move || {
                let mut pin = pin;
                let r = pin::unlock(path, &pin);
                pin.zeroize();
                r.map_err(|e| match e {
                    pin::PinError::Wrong => Failure::WrongPin,
                    pin::PinError::Unavailable(m) => Failure::Message(format!("{m}. Mot de passe maître requis.")),
                })
            });
        }
    }

    // ---- déverrouillage par mot de passe
    fn unlock_password(&mut self, ui: &mut egui::Ui) {
        Self::title(ui, "Déverrouiller Escale", "Entrez votre mot de passe maître.");
        self.vault_badge(ui);
        if self.step != Step::UnlockPassword {
            return;
        }
        let mut submit = false;
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            w::label(ui, "Mot de passe maître");
            let r = w::password_input(ui, &mut self.pw, "••••••••", &mut self.show_pw, W);
            if self.focus_pw {
                r.request_focus();
                self.focus_pw = false;
            }
            submit |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            self.error_line(ui);
            ui.add_space(16.0);
            submit |= w::button_h(ui, Kind::Primary, Some(Icon::Lock), "Déverrouiller", W, 44.0).clicked();
        });
        if pin::is_enabled(&self.current_path()) {
            ui.add_space(14.0);
            if w::link(ui, "Utiliser le code PIN").clicked() {
                self.error = None;
                self.step = Step::UnlockPin;
            }
        }
        if submit && !self.pw.is_empty() {
            let pw = std::mem::take(&mut self.pw);
            self.error = None;
            let path = self.current_path();
            self.run(ui.ctx(), "Déverrouillage…", move || {
                let mut pw = pw;
                let r = Vault::open_at(path, &pw).map_err(Failure::Message);
                pw.zeroize();
                r
            });
        }
    }

    /// Nom du coffre à déverrouiller (propriétaire, sinon dossier).
    pub fn vault_name(&self) -> Option<String> {
        self.current.as_ref().map(|v| v.owner().to_string())
    }

    /// Coffre sélectionné, avec accès au choix d'un autre coffre.
    fn vault_badge(&mut self, ui: &mut egui::Ui) {
        let Some(v) = &self.current else { return };
        let owner = v.owner().to_string();
        let several = self.vaults.len() > 1 || vault::can_add();
        let mut open = false;
        egui::Frame::new()
            .fill(ELEVATED)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(12.0)
            .inner_margin(egui::Margin::symmetric(10, 8))
            .show(ui, |ui| {
                ui.set_width(W - 20.0);
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(30.0), egui::Sense::hover());
                    w::paint_avatar(ui.painter(), r, &owner);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        ui.label(RichText::new(&owner).font(bold(13.5)));
                        ui.label(RichText::new(&v.folder).size(11.5).color(MUTED));
                    });
                    if several {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            open = w::link(ui, "Changer de coffre").clicked();
                        });
                    }
                });
            });
        ui.add_space(18.0);
        if open {
            self.pin1.zeroize();
            self.pw.zeroize();
            self.error = None;
            self.notice = None;
            self.vaults = vault::list();
            self.step = Step::Choose;
        }
    }

    // ---- choix du coffre
    fn choose(&mut self, ui: &mut egui::Ui) {
        Self::title(ui, "Choisir un coffre", "Chaque coffre a son propre mot de passe maître et son propre PIN.");
        let mut picked = None;
        let mut create = false;
        let current = self.current.as_ref().map(|v| v.path.clone());
        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            for v in &self.vaults {
                let selected = current.as_ref() == Some(&v.path);
                let r = egui::Frame::new()
                    .fill(if selected { ACCENT.gamma_multiply(0.08) } else { ELEVATED })
                    .stroke(egui::Stroke::new(1.0, if selected { ACCENT.gamma_multiply(0.6) } else { BORDER }))
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.set_width(W - 24.0);
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(Vec2::splat(34.0), egui::Sense::hover());
                            w::paint_avatar(ui.painter(), r, v.owner());
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 1.0;
                                ui.label(RichText::new(v.owner()).font(bold(14.0)));
                                let mut sub = v.folder.clone();
                                if !v.profile.windows_user.is_empty() {
                                    sub.push_str(&format!(" · session {}", v.profile.windows_user));
                                }
                                ui.label(RichText::new(sub).size(11.5).color(MUTED));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if pin::is_enabled(&v.path) {
                                    w::chip(ui, Some(Icon::Lock), "PIN", ACCENT);
                                }
                            });
                        });
                    })
                    .response;
                if r.interact(egui::Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    picked = Some(v.clone());
                }
                ui.add_space(8.0);
            }
        });
        ui.add_space(8.0);
        if vault::can_add() && w::button_h(ui, Kind::Secondary, Some(Icon::Plus), "Créer un nouveau coffre", W, 40.0).clicked() {
            create = true;
        }
        if let Some(v) = picked {
            self.select(v);
        } else if create {
            self.start_create();
        }
    }
}

/// Copie une sauvegarde choisie par l'utilisateur dans un nouveau dossier de coffre (les coffres
/// existants ne sont jamais écrasés). `Ok(None)` : annulé.
fn restore_backup() -> Result<Option<VaultInfo>, String> {
    let Some(src) = rfd::FileDialog::new().set_title("Restaurer une sauvegarde").add_filter("Coffre Escale", &["escale"]).pick_file() else {
        return Ok(None);
    };
    // en-tête valide : c'est bien un coffre Escale
    Vault::header_on_disk(&src).map_err(|_| "Ce fichier n'est pas un coffre Escale.".to_string())?;
    let dest = vault::new_slot();
    if dest.exists() {
        return Err("Un coffre existe déjà à cet emplacement.".into());
    }
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Restauration impossible : {e}"))?;
    }
    std::fs::copy(&src, &dest).map_err(|e| format!("Restauration impossible : {e}"))?;
    let profile = vault::Profile { owner: String::new(), windows_user: vault::windows_user(), created: vault::now() };
    let _ = vault::write_profile(&dest, &profile);
    Ok(vault::list().into_iter().find(|v| v.path == dest))
}
