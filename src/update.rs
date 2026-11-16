//! Mises à jour depuis les releases GitHub (dernière version publiée de `REPO`).
//!
//! - Vérification au démarrage, en arrière-plan, puis à la demande (Paramètres > À propos).
//! - Installation : si Escale a été installé (désinstalleur présent à côté de l'exe) et que la
//!   release fournit `Escale-Setup-<version>.exe`, l'installateur est lancé en silencieux ;
//!   sinon l'exe portable (`Escale.exe`) remplace l'exe courant (renommé en `.old`, effacé au
//!   lancement suivant).
//! - Le fichier téléchargé est vérifié par son empreinte SHA-256 (`digest` de l'API GitHub).

use eframe::egui::{self, Align2, Margin, RichText, vec2};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::theme::*;
use crate::widgets::{self as w, Icon, Kind};

const REPO: &str = "nbstheo/Escale";
const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct Release {
    pub version: String,
    pub page: String,
    asset_url: String,
    asset_name: String,
    sha256: String,
    installer: bool,
}

#[derive(Clone)]
enum State {
    Idle,
    Checking,
    UpToDate,
    Available(Release),
    Downloading { release: Release, done: u64, total: u64 },
    /// Nouvelle version en place : Escale se ferme (et l'installateur / le nouvel exe démarre).
    Restarting,
    Failed { msg: String, page: Option<String>, manual: bool },
}

struct Shared {
    state: State,
    /// Bandeau « mise à jour disponible » fermé par l'utilisateur.
    dismissed: bool,
}

static SHARED: Mutex<Shared> = Mutex::new(Shared { state: State::Idle, dismissed: false });

fn get() -> std::sync::MutexGuard<'static, Shared> {
    SHARED.lock().unwrap_or_else(|e| e.into_inner())
}

fn set(ctx: &egui::Context, s: State) {
    get().state = s;
    ctx.request_repaint();
}

/// Au démarrage : nettoyage de l'ancien exe puis vérification silencieuse.
pub fn startup(ctx: &egui::Context) {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(old_path(&exe));
        let _ = std::fs::remove_file(new_path(&exe));
    }
    check(ctx, false);
}

/// Lance une vérification en arrière-plan (`manual` : erreurs affichées dans les paramètres).
pub fn check(ctx: &egui::Context, manual: bool) {
    {
        let mut g = get();
        if matches!(g.state, State::Checking | State::Downloading { .. } | State::Restarting) {
            return;
        }
        g.state = State::Checking;
        if manual {
            g.dismissed = false;
        }
    }
    let ctx = ctx.clone();
    std::thread::Builder::new()
        .name("maj-verif".into())
        .spawn(move || {
            let s = match latest() {
                Ok(Some(r)) => State::Available(r),
                Ok(None) => State::UpToDate,
                Err(msg) => State::Failed { msg, page: None, manual },
            };
            set(&ctx, s);
        })
        .ok();
}

/// Télécharge et applique la mise à jour, puis ferme Escale.
fn install(ctx: &egui::Context, release: Release) {
    set(ctx, State::Downloading { release: release.clone(), done: 0, total: 0 });
    let ctx = ctx.clone();
    std::thread::Builder::new()
        .name("maj-install".into())
        .spawn(move || match apply(&ctx, &release) {
            Ok(()) => {
                set(&ctx, State::Restarting);
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(msg) => set(&ctx, State::Failed { msg, page: Some(release.page.clone()), manual: true }),
        })
        .ok();
}

// ---------------------------------------------------------------- interface

/// Bandeau flottant en bas à droite (écran verrouillé compris).
pub fn banner(ctx: &egui::Context) {
    let (state, dismissed) = {
        let g = get();
        (g.state.clone(), g.dismissed)
    };
    let show = match &state {
        State::Available(_) => !dismissed,
        State::Downloading { .. } | State::Restarting => true,
        State::Failed { page: Some(_), .. } => !dismissed,
        _ => false,
    };
    if !show {
        return;
    }
    egui::Area::new(egui::Id::new("update-banner"))
        .anchor(Align2::RIGHT_BOTTOM, vec2(-18.0, -18.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            w::card().inner_margin(Margin::same(14)).show(ui, |ui| {
                ui.set_width(320.0);
                ui.horizontal(|ui| {
                    w::icon_size(ui, Icon::Download, 16.0, ACCENT);
                    let title = match &state {
                        State::Available(r) => format!("Escale {} est disponible", r.version),
                        State::Downloading { release, .. } => format!("Mise à jour vers {}…", release.version),
                        State::Restarting => "Redémarrage d'Escale…".into(),
                        _ => "Échec de la mise à jour".into(),
                    };
                    ui.label(RichText::new(title).font(bold(14.0)));
                });
                ui.add_space(4.0);
                body(ui, &state);
            });
        });
}

/// Section « À propos » des paramètres.
pub fn about(ui: &mut egui::Ui) {
    let state = get().state.clone();
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("Escale {CURRENT}")).color(TEXT_DIM));
        ui.add_space(8.0);
        match &state {
            State::Checking => {
                ui.spinner();
                ui.label(RichText::new("Recherche de mises à jour…").size(12.5).color(MUTED));
            }
            State::UpToDate => {
                ui.label(RichText::new("À jour").size(12.5).color(ACCENT));
            }
            _ => {}
        }
    });
    ui.add_space(6.0);
    match &state {
        State::Available(_) | State::Downloading { .. } | State::Restarting | State::Failed { manual: true, .. } => body(ui, &state),
        _ => {
            if w::button(ui, Kind::Secondary, Some(Icon::Refresh), "Rechercher des mises à jour", 0.0).clicked() {
                check(ui.ctx(), true);
            }
        }
    }
}

fn body(ui: &mut egui::Ui, state: &State) {
    match state {
        State::Available(r) => {
            ui.label(RichText::new(format!("Version installée : {CURRENT}. Escale redémarrera ; les sessions ouvertes seront fermées.")).size(12.0).color(MUTED));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if w::button(ui, Kind::Primary, Some(Icon::Download), "Installer", 0.0).clicked() {
                    install(ui.ctx(), r.clone());
                }
                if w::button(ui, Kind::Ghost, Some(Icon::External), "Nouveautés", 0.0).clicked() {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(&r.page));
                }
                if w::button(ui, Kind::Ghost, None, "Plus tard", 0.0).clicked() {
                    get().dismissed = true;
                }
            });
        }
        State::Downloading { done, total, .. } => {
            let frac = if *total > 0 { *done as f32 / *total as f32 } else { 0.0 };
            ui.add(egui::ProgressBar::new(frac).desired_width(ui.available_width()).text(format!("{:.1} / {:.1} Mo", *done as f64 / 1e6, *total as f64 / 1e6)));
        }
        State::Restarting => {
            ui.spinner();
        }
        State::Failed { msg, page, .. } => {
            ui.label(RichText::new(msg).size(12.5).color(DANGER));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if w::button(ui, Kind::Secondary, Some(Icon::Refresh), "Réessayer", 0.0).clicked() {
                    check(ui.ctx(), true);
                }
                if let Some(p) = page
                    && w::button(ui, Kind::Ghost, Some(Icon::External), "Page de téléchargement", 0.0).clicked()
                {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(p));
                }
                if w::button(ui, Kind::Ghost, None, "Fermer", 0.0).clicked() {
                    let mut g = get();
                    g.dismissed = true;
                    g.state = State::Idle;
                }
            });
        }
        _ => {}
    }
}

// ---------------------------------------------------------------- logique

/// Version « 1.2.3 » (préfixe `v` toléré, suffixe `-beta` ignoré) → triplet comparable.
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>());
    let major = it.next()?.ok()?;
    let minor = it.next().unwrap_or(Ok(0)).ok()?;
    let patch = it.next().unwrap_or(Ok(0)).ok()?;
    Some((major, minor, patch))
}

fn is_newer(remote: &str, current: &str) -> bool {
    matches!((parse_version(remote), parse_version(current)), (Some(r), Some(c)) if r > c)
}

/// Escale installé par l'installateur Inno Setup (désinstalleur à côté de l'exe).
fn installed() -> bool {
    std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("unins000.exe").exists())).unwrap_or(false)
}

fn old_path(exe: &Path) -> PathBuf {
    exe.with_extension("old")
}
fn new_path(exe: &Path) -> PathBuf {
    exe.with_extension("new")
}

/// Dernière release publiée, si elle est plus récente que la version courante.
fn latest() -> Result<Option<Release>, String> {
    let mut body = Vec::new();
    http::get(&format!("https://api.github.com/repos/{REPO}/releases/latest"), "application/vnd.github+json", &mut |chunk, _| {
        body.extend_from_slice(chunk);
        Ok(())
    })?;
    let json: serde_json::Value = serde_json::from_slice(&body).map_err(|_| "Réponse de GitHub illisible.".to_string())?;
    let tag = json["tag_name"].as_str().ok_or("Aucune version publiée.")?;
    if !is_newer(tag, CURRENT) {
        return Ok(None);
    }
    let version = tag.trim_start_matches(['v', 'V']).to_string();
    let page = json["html_url"].as_str().unwrap_or("").to_string();
    let assets = json["assets"].as_array().cloned().unwrap_or_default();
    let exe = |setup: bool| {
        assets.iter().find(|a| {
            let n = a["name"].as_str().unwrap_or("").to_ascii_lowercase();
            n.ends_with(".exe") && n.contains("setup") == setup
        })
    };
    let (asset, installer) = match (installed(), exe(true), exe(false)) {
        (true, Some(a), _) => (a, true),
        (_, _, Some(a)) => (a, false),
        (false, Some(a), None) => (a, true),
        _ => {
            return Err(format!("Escale {version} est disponible, mais la release ne contient pas d'exécutable Windows."));
        }
    };
    let sha256 = asset["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")).unwrap_or("").to_ascii_lowercase();
    Ok(Some(Release {
        version,
        page,
        asset_url: asset["browser_download_url"].as_str().unwrap_or("").to_string(),
        asset_name: asset["name"].as_str().unwrap_or("Escale.exe").to_string(),
        sha256,
        installer,
    }))
}

/// Télécharge `r` dans `dest` en vérifiant son SHA-256.
fn download(ctx: &egui::Context, r: &Release, dest: &Path) -> Result<(), String> {
    if r.sha256.len() != 64 {
        return Err("Empreinte SHA-256 absente de la release : mise à jour refusée.".into());
    }
    let mut file = std::fs::File::create(dest).map_err(|e| format!("Écriture impossible ({}) : {e}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut done = 0u64;
    let mut last = std::time::Instant::now();
    let res = http::get(&r.asset_url, "application/octet-stream", &mut |chunk, total| {
        file.write_all(chunk).map_err(|e| format!("Écriture impossible : {e}"))?;
        hasher.update(chunk);
        done += chunk.len() as u64;
        if last.elapsed().as_millis() > 100 {
            last = std::time::Instant::now();
            set(ctx, State::Downloading { release: r.clone(), done, total });
        }
        Ok(())
    });
    let res = res.and_then(|()| file.flush().map_err(|e| e.to_string()));
    drop(file);
    let ok = res.and_then(|()| {
        let hex: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if hex == r.sha256 { Ok(()) } else { Err("Le fichier téléchargé est corrompu (SHA-256 différent).".into()) }
    });
    if ok.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    ok
}

fn apply(ctx: &egui::Context, r: &Release) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if r.installer {
        let dest = std::env::temp_dir().join(&r.asset_name);
        download(ctx, r, &dest)?;
        // /RELAUNCH : l'installateur relance Escale une fois la copie terminée (cf. escale.iss)
        std::process::Command::new(&dest)
            .args(["/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS", "/RELAUNCH"])
            .spawn()
            .map_err(|e| format!("Impossible de lancer l'installateur : {e}"))?;
        return Ok(());
    }
    // exe portable : l'exe en cours peut être renommé (pas supprimé) sous Windows
    let new = new_path(&exe);
    let old = old_path(&exe);
    download(ctx, r, &new).map_err(|e| {
        if e.starts_with("Écriture impossible") { format!("{e}\nLe dossier d'Escale est protégé : téléchargez la mise à jour depuis la page.") } else { e }
    })?;
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old).map_err(|e| {
        let _ = std::fs::remove_file(&new);
        format!("Remplacement impossible : {e}")
    })?;
    if let Err(e) = std::fs::rename(&new, &exe) {
        let _ = std::fs::rename(&old, &exe);
        let _ = std::fs::remove_file(&new);
        return Err(format!("Remplacement impossible : {e}"));
    }
    std::process::Command::new(&exe).spawn().map_err(|e| format!("Mise à jour installée, mais le redémarrage a échoué : {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------- HTTP (WinHTTP : proxy et certificats du système)

#[cfg(windows)]
mod http {
    use windows_sys::Win32::Networking::WinHttp::*;

    struct Handle(*mut core::ffi::c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WinHttpCloseHandle(self.0) };
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error(what: &str) -> String {
        let e = std::io::Error::last_os_error();
        format!("Connexion à GitHub impossible ({what} : {e}).")
    }

    /// GET HTTPS ; `sink(morceau, taille totale ou 0)` reçoit le corps au fil de l'eau.
    pub fn get(url: &str, accept: &str, sink: &mut dyn FnMut(&[u8], u64) -> Result<(), String>) -> Result<(), String> {
        let rest = url.strip_prefix("https://").ok_or("URL non HTTPS refusée.")?;
        let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
        let agent = wide(concat!("Escale/", env!("CARGO_PKG_VERSION")));
        unsafe {
            let session = Handle(WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, std::ptr::null(), std::ptr::null(), 0));
            if session.0.is_null() {
                return Err(last_error("ouverture"));
            }
            WinHttpSetTimeouts(session.0, 15_000, 15_000, 30_000, 30_000);
            let host_w = wide(host);
            let conn = Handle(WinHttpConnect(session.0, host_w.as_ptr(), INTERNET_DEFAULT_HTTPS_PORT, 0));
            if conn.0.is_null() {
                return Err(last_error("connexion"));
            }
            let (verb, path_w) = (wide("GET"), wide(&path));
            let req = Handle(WinHttpOpenRequest(conn.0, verb.as_ptr(), path_w.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), WINHTTP_FLAG_SECURE));
            if req.0.is_null() {
                return Err(last_error("requête"));
            }
            let headers: Vec<u16> = format!("Accept: {accept}\r\nX-GitHub-Api-Version: 2022-11-28\r\n").encode_utf16().collect();
            if WinHttpSendRequest(req.0, headers.as_ptr(), headers.len() as u32, std::ptr::null(), 0, 0, 0) == 0 || WinHttpReceiveResponse(req.0, std::ptr::null_mut()) == 0 {
                return Err(last_error("envoi"));
            }
            let number = |level: u32| -> Option<u32> {
                let mut v = 0u32;
                let mut len = 4u32;
                let ok = WinHttpQueryHeaders(req.0, level | WINHTTP_QUERY_FLAG_NUMBER, std::ptr::null(), (&mut v as *mut u32).cast(), &mut len, std::ptr::null_mut());
                (ok != 0).then_some(v)
            };
            match number(WINHTTP_QUERY_STATUS_CODE) {
                Some(200) => {}
                Some(404) => return Err("Aucune version publiée sur GitHub.".into()),
                Some(403 | 429) => return Err("GitHub limite les requêtes : réessayez dans quelques minutes.".into()),
                Some(c) => return Err(format!("GitHub a répondu {c}.")),
                None => return Err(last_error("statut")),
            }
            let total = number(WINHTTP_QUERY_CONTENT_LENGTH).unwrap_or(0) as u64;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let mut read = 0u32;
                if WinHttpReadData(req.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read) == 0 {
                    return Err(last_error("lecture"));
                }
                if read == 0 {
                    return Ok(());
                }
                sink(&buf[..read as usize], total)?;
            }
        }
    }
}

#[cfg(not(windows))]
mod http {
    pub fn get(_: &str, _: &str, _: &mut dyn FnMut(&[u8], u64) -> Result<(), String>) -> Result<(), String> {
        Err("Mises à jour disponibles sous Windows uniquement.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(is_newer("v0.2.3", "0.2.2"));
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("v1", "0.9.9"));
        assert!(!is_newer("v0.2.2", "0.2.2"));
        assert!(!is_newer("v0.2.1", "0.2.2"));
        assert!(!is_newer("nimporte", "0.2.2"));
        assert_eq!(parse_version("v1.2.3-beta.1"), Some((1, 2, 3)));
    }

    /// Réseau requis : `cargo test github_latest -- --ignored`
    #[test]
    #[ignore]
    fn github_latest() {
        assert!(latest().is_ok(), "{:?}", latest().err());
    }
}
