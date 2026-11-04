#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod audin;
mod clearcodec;
mod desktop;
mod files;
mod gfx;
mod lock;
mod logo;
mod model;
mod monitors;
mod openvpn;
mod pin;
mod rdp;
mod rdpclip;
mod rdpdr;
mod rdpsnd;
mod rfb;
mod ssh;
mod terminal;
mod theme;
#[cfg(test)]
mod tests;
mod vault;
mod vpn;
mod widgets;
#[cfg(windows)]
mod winput;

use eframe::egui;
use std::sync::Arc;

/// Toute panique est consignée dans `crash.log`, dans le dossier d'Escale (jamais de contenu du coffre).
fn install_crash_log() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let path = vault::root().join("crash.log");
        // premier lancement : le dossier d'Escale n'existe pas encore
        let _ = std::fs::create_dir_all(vault::root());
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let thread = std::thread::current().name().unwrap_or("?").to_string();
        let entry = format!(
            "--- {secs} (secondes Unix) · Escale {} · fil « {thread} »
{info}
{}

",
            env!("CARGO_PKG_VERSION"),
            std::backtrace::Backtrace::force_capture()
        );
        // journal borné : on repart de zéro au-delà de 1 Mo
        let append = std::fs::metadata(&path).map(|m| m.len() < 1 << 20).unwrap_or(true);
        let file = std::fs::OpenOptions::new().create(true).append(append).write(true).truncate(!append).open(&path);
        if let Ok(mut f) = file {
            use std::io::Write;
            let _ = f.write_all(entry.as_bytes());
        }
        default(info);
    }));
}

/// Journalise une erreur de démarrage (le dossier d'Escale peut ne pas exister encore).
fn log_startup(msg: &str) {
    let root = vault::root();
    let _ = std::fs::create_dir_all(&root);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(root.join("crash.log")) {
        use std::io::Write;
        let _ = writeln!(f, "--- démarrage · Escale {} : {msg}", env!("CARGO_PKG_VERSION"));
    }
}

/// Le binaire est en sous-système « windows » : sans cela, un échec au démarrage est invisible.
#[cfg(windows)]
fn show_error(msg: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    unsafe { MessageBoxW(std::ptr::null_mut(), wide(msg).as_ptr(), wide("Escale").as_ptr(), MB_OK | MB_ICONERROR) };
}
#[cfg(not(windows))]
fn show_error(msg: &str) {
    eprintln!("{msg}");
}

fn run(renderer: eframe::Renderer) -> eframe::Result {
    let icon = egui::IconData { rgba: logo::render(128), width: 128, height: 128 };
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_title("Escale")
            .with_inner_size([1180.0, 740.0])
            .with_min_inner_size([720.0, 420.0])
            .with_decorations(false)
            .with_icon(Arc::new(icon)),
        #[cfg(windows)]
        event_loop_builder: Some(Box::new(|b: &mut eframe::EventLoopBuilder<eframe::UserEvent>| {
            use winit::platform::windows::EventLoopBuilderExtWindows;
            // relevé des frappes avant egui-winit, qui en transforme ou perd certaines (cf. winput)
            b.with_msg_hook(|msg| {
                winput::on_message(unsafe { &*(msg as *const windows_sys::Win32::UI::WindowsAndMessaging::MSG) });
                false
            });
        })),
        ..Default::default()
    };
    eframe::run_native("Escale", options, Box::new(|cc| Ok(Box::new(app::EscaleApp::new(cc)))))
}

fn main() {
    install_crash_log();
    // Sur un PC neuf (pilote graphique générique, machine virtuelle), OpenGL peut être absent ou
    // inutilisable : la fenêtre s'ouvre puis disparaît. On retente alors en wgpu (DirectX 12 / Vulkan,
    // y compris le rendu logiciel WARP) dans un nouveau processus, la boucle d'événements ne pouvant
    // pas être recréée proprement.
    let wgpu = std::env::var_os("ESCALE_RENDERER").is_some_and(|v| v == "wgpu");
    let renderer = if wgpu { eframe::Renderer::Wgpu } else { eframe::Renderer::Glow };
    let outcome = std::panic::catch_unwind(|| run(renderer));
    let error = match outcome {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e.to_string(),
        Err(_) => "panique pendant l'initialisation graphique".to_string(),
    };
    log_startup(&format!("{} : {error}", if wgpu { "wgpu" } else { "OpenGL" }));
    if !wgpu
        && let Ok(exe) = std::env::current_exe()
        && std::process::Command::new(exe).env("ESCALE_RENDERER", "wgpu").spawn().is_ok()
    {
        return;
    }
    show_error(&format!(
        "Escale n'a pas pu démarrer (affichage indisponible).

{error}

Mettez à jour le pilote de la carte graphique ou installez les derniers pilotes Windows."
    ));
}
