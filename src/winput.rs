//! Windows : relevé des frappes dans la boucle de messages, pour rendre au terminal ce qu'egui-winit
//! transforme ou jette (Ctrl+C / Ctrl+X / Ctrl+V devenus Copier/Couper/Coller, Ctrl+V perdu quand le
//! presse-papiers est vide, caractères Ctrl+Alt comme « € » ignorés).
//! Relève aussi les codes physiques des touches pour le bureau distant RDP.

use eframe::egui::{Event, Key, Modifiers};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, MAPVK_VK_TO_VSC_EX, MapVirtualKeyW, VK_CAPITAL, VK_CONTROL, VK_DELETE, VK_INSERT, VK_LCONTROL, VK_LWIN, VK_MENU,
    VK_RMENU, VK_RSHIFT, VK_RWIN, VK_SHIFT,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MSG, WM_CHAR, WM_KEYDOWN, WM_KEYUP, WM_SYSCHAR, WM_SYSKEYDOWN, WM_SYSKEYUP};

/// Un bureau distant a le focus : les touches sont relevées en codes physiques.
pub static CAPTURE: AtomicBool = AtomicBool::new(false);
/// (code physique, 0xE0xx si étendu ; enfoncée)
static SCANCODES: Mutex<Vec<(u16, bool)>> = Mutex::new(Vec::new());
/// Le bureau qui a le focus accepte les raccourcis Windows (option RDP de l'hôte).
pub static WIN_KEYS: AtomicBool = AtomicBool::new(false);
/// Le crochet retient les raccourcis Windows : état de la dernière image complète (un bureau RDP
/// qui les accepte avait le focus). Lu par le fil du crochet, jamais à mi-image.
static HOOK_ARMED: AtomicBool = AtomicBool::new(false);
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
/// Fil du crochet (identifiant Windows, 0 tant qu'il démarre) et sa poignée, pour l'arrêter.
static HOOK_TID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static HOOK_THREAD: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);
/// Touches dont l'appui a été retenu (bits de `chord_bit`) : leur relâchement l'est aussi, quel que
/// soit l'état au moment du relâchement. Écrit seulement par le fil du crochet.
static HELD: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
/// Réveil de l'interface après une touche retenue (aucun message n'arrive à la fenêtre).
static WAKE: AtomicBool = AtomicBool::new(false);
static WAKER: std::sync::OnceLock<std::thread::Thread> = std::sync::OnceLock::new();
static WAKE_CTX: Mutex<Option<eframe::egui::Context>> = Mutex::new(None);
/// Le terminal (réglage « Tous les raccourcis au serveur ») ou le bureau VNC qui a le focus veut
/// Ctrl+Maj+Échap : signalé pendant l'image, comme `WIN_KEYS`.
pub static TASK_KEYS: AtomicBool = AtomicBool::new(false);
/// État de `TASK_KEYS` à la dernière image complète, lu par le fil du crochet.
static HOOK_TASK_ARMED: AtomicBool = AtomicBool::new(false);
/// Touches retenues (bits de `chord_bit`) à rendre à egui plutôt qu'en codes physiques RDP.
static HELD_EGUI: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
/// Échap retenu pour le terminal / VNC (Ctrl+Maj+Échap) : appuis et relâchements à rejouer dans egui.
static TASK_ESC: Mutex<Vec<bool>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------- raccourcis Windows

/// Début d'image : le bureau distant qui a le focus se signale à nouveau pendant l'image.
/// Renvoie si un bureau avait le focus à l'image précédente (ses touches relevées restent à lire).
pub fn begin_frame() -> bool {
    WIN_KEYS.store(false, Ordering::Relaxed);
    TASK_KEYS.store(false, Ordering::Relaxed);
    CAPTURE.swap(false, Ordering::Relaxed)
}

/// Fin d'image : le crochet retient les raccourcis Windows seulement si un bureau RDP qui les accepte
/// a gardé le focus pendant toute l'image.
pub fn end_frame() {
    HOOK_ARMED.store(CAPTURE.load(Ordering::Relaxed) && WIN_KEYS.load(Ordering::Relaxed), Ordering::Relaxed);
    HOOK_TASK_ARMED.store(TASK_KEYS.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Crochet clavier bas niveau : Windows traite Win, Alt+Tab, Ctrl+Échap, Alt+Échap et Impr écran
/// avant toute fenêtre, et Alt+F4 / Alt+Espace ferment Escale ou ouvrent son menu système ; quand un bureau RDP a le focus (et que l'hôte l'accepte), ils sont retenus ici et
/// transmis au bureau distant, comme le fait mstsc. Installé à la première utilisation sur un fil
/// dédié qui ne fait que tourner sa boucle de messages : un crochet bas niveau est appelé par la
/// boucle du fil qui l'a installé, et une interface occupée (grosse image, dialogue) ferait sinon
/// ramer le clavier de tout l'ordinateur, puis Windows retirerait le crochet.
pub fn install_keyboard_hook(ctx: &eframe::egui::Context) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetMessageW, PM_NOREMOVE, PeekMessageW, SetWindowsHookExW, UnhookWindowsHookEx, WH_KEYBOARD_LL,
    };
    if HOOK_INSTALLED.swap(true, Ordering::Relaxed) {
        return;
    }
    if let Ok(mut c) = WAKE_CTX.lock() {
        *c = Some(ctx.clone());
    }
    WAKER.get_or_init(|| {
        std::thread::Builder::new()
            .name("escale-clavier-réveil".into())
            .spawn(|| {
                loop {
                    std::thread::park();
                    if WAKE.swap(false, Ordering::Relaxed) {
                        let ctx = WAKE_CTX.lock().ok().and_then(|c| c.clone());
                        if let Some(ctx) = ctx {
                            ctx.request_repaint();
                        }
                    }
                }
            })
            .map(|h| h.thread().clone())
            .unwrap_or_else(|_| std::thread::current())
    });
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut core::ffi::c_void;
        fn GetCurrentThreadId() -> u32;
    }
    let spawned = std::thread::Builder::new().name("escale-crochet-clavier".into()).spawn(|| unsafe {
        let mut msg: MSG = std::mem::zeroed();
        // file de messages créée avant d'annoncer le fil (PostThreadMessageW échouerait sinon)
        PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_NOREMOVE);
        let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_ll), GetModuleHandleW(std::ptr::null()) as _, 0);
        HOOK_TID.store(GetCurrentThreadId(), Ordering::Release);
        if hook.is_null() {
            eprintln!("escale: crochet clavier indisponible, les raccourcis Windows restent locaux");
            return;
        }
        // boucle de messages : c'est elle qui appelle le crochet ; WM_QUIT l'arrête
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {}
        UnhookWindowsHookEx(hook);
    });
    match spawned {
        Ok(h) => {
            if let Ok(mut t) = HOOK_THREAD.lock() {
                *t = Some(h);
            }
        }
        Err(_) => HOOK_INSTALLED.store(false, Ordering::Relaxed),
    }
}

/// Retire le crochet (fermeture d'Escale) : plus aucune touche n'est retenue.
pub fn uninstall_keyboard_hook() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_QUIT};
    HOOK_ARMED.store(false, Ordering::Relaxed);
    HOOK_TASK_ARMED.store(false, Ordering::Relaxed);
    let Some(handle) = HOOK_THREAD.lock().ok().and_then(|mut t| t.take()) else { return };
    // le fil annonce son identifiant dès que sa file existe (quelques millisecondes au plus)
    let start = std::time::Instant::now();
    while HOOK_TID.load(Ordering::Acquire) == 0 && start.elapsed() < std::time::Duration::from_secs(1) {
        std::thread::yield_now();
    }
    let tid = HOOK_TID.swap(0, Ordering::AcqRel);
    if tid != 0 && unsafe { PostThreadMessageW(tid, WM_QUIT, 0, 0) } != 0 {
        let _ = handle.join();
    }
    HOOK_INSTALLED.store(false, Ordering::Relaxed);
}

/// Bit de suivi des touches que le crochet peut retenir.
fn chord_bit(vk: u16) -> u8 {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_ESCAPE, VK_F4, VK_SNAPSHOT, VK_SPACE, VK_TAB};
    match vk {
        VK_LWIN => 1,
        VK_RWIN => 2,
        VK_TAB => 4,
        VK_ESCAPE => 8,
        VK_F4 => 16,
        VK_SPACE => 32,
        VK_SNAPSHOT => 64,
        _ => 0,
    }
}

/// Décision du crochet pour une frappe : (retenir, nouvel état des touches retenues).
/// `armed` : Escale au premier plan, bureau RDP au focus, hôte qui accepte les raccourcis Windows.
/// Un appui n'est retenu que si `armed` ; un relâchement l'est si et seulement si l'appui l'a été
/// (sinon Windows croirait la touche toujours enfoncée, ou le bureau distant ne la verrait jamais
/// relâchée).
fn intercept(held: u8, vk: u16, down: bool, alt: bool, ctrl: bool, armed: bool) -> (bool, u8) {
    let bit = chord_bit(vk);
    if bit == 0 {
        return (false, held);
    }
    if held & bit != 0 {
        return (true, if down { held } else { held & !bit });
    }
    if down && armed && is_system_chord(vk, alt, ctrl) {
        return (true, held | bit);
    }
    (false, held)
}

/// La fenêtre au premier plan appartient à Escale (fenêtre principale ou séparée).
fn foreground_is_ours() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(GetForegroundWindow(), &mut pid) };
    pid == std::process::id()
}

/// Combinaison réservée par Windows à retenir pour le bureau distant.
fn is_system_chord(vk: u16, alt: bool, ctrl: bool) -> bool {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_ESCAPE, VK_F4, VK_SNAPSHOT, VK_SPACE, VK_TAB};
    match vk {
        VK_LWIN | VK_RWIN | VK_SNAPSHOT => true,
        // Alt+F4 ferme la fenêtre distante, pas Escale ; Alt+Espace : menu système distant
        VK_TAB | VK_F4 | VK_SPACE => alt,
        VK_ESCAPE => alt || ctrl,
        _ => false,
    }
}

/// Ctrl+Maj+Échap (gestionnaire des tâches de Windows), seul raccourci retenu pour un terminal ou un
/// bureau VNC : Windows l'ouvrirait sur cet ordinateur avant toute fenêtre.
fn is_task_manager_chord(vk: u16, alt: bool, ctrl: bool, shift: bool) -> bool {
    vk == windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_ESCAPE && ctrl && shift && !alt
}

/// Modificateurs enfoncés (codes physiques) : envoyés avant une touche retenue, pour que le bureau
/// distant les voie d'abord même si leurs messages attendent encore dans la file de l'interface.
fn held_modifiers() -> impl Iterator<Item = u16> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LMENU, VK_LSHIFT, VK_RCONTROL, VK_RSHIFT};
    [(VK_LCONTROL, 0x1D), (VK_RCONTROL, 0xE01D), (VK_LSHIFT, 0x2A), (VK_RSHIFT, 0x36), (VK_LMENU, 0x38), (VK_RMENU, 0xE038)]
        .into_iter()
        .filter(|(vk, _)| unsafe { GetAsyncKeyState(*vk as i32) } < 0)
        .map(|(_, sc)| sc)
}

unsafe extern "system" fn keyboard_ll(
    code: i32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
    use windows_sys::Win32::UI::WindowsAndMessaging::{CallNextHookEx, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_ALTDOWN, LLKHF_EXTENDED, LLKHF_INJECTED};
    // rapide et sans attente : quelques lectures atomiques ; le seul verrou (SCANCODES) n'est tenu
    // que le temps d'un ajout ou d'un échange de vecteur par l'interface
    if code == HC_ACTION as i32 && lparam != 0 {
        let k = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
        let vk = k.vkCode as u16;
        let mut held = HELD.load(Ordering::Relaxed);
        if k.flags & LLKHF_INJECTED == 0 && chord_bit(vk) != 0 {
            let down = matches!(wparam as u32, WM_KEYDOWN | WM_SYSKEYDOWN);
            // relâchement jamais reçu (Win+L, bureau sécurisé, Ctrl+Alt+Suppr) : la touche n'est plus
            // retenue une fois Escale quittée, sinon son prochain appui ici serait avalé
            if down && held & chord_bit(vk) != 0 && !foreground_is_ours() {
                held &= !chord_bit(vk);
                HELD.store(held, Ordering::Relaxed);
            }
            let alt = k.flags & LLKHF_ALTDOWN != 0;
            let ctrl = unsafe { GetAsyncKeyState(VK_CONTROL as i32) } < 0;
            let shift = unsafe { GetAsyncKeyState(VK_SHIFT as i32) } < 0;
            let rdp = HOOK_ARMED.load(Ordering::Relaxed);
            // terminal / VNC : seulement Ctrl+Maj+Échap, rendu à egui
            let task = !rdp && HOOK_TASK_ARMED.load(Ordering::Relaxed) && is_task_manager_chord(vk, alt, ctrl, shift);
            // premier plan vérifié seulement pour un nouvel appui (relâchement : décidé par l'appui)
            let armed = down && (rdp || task) && foreground_is_ours();
            let (swallow, now) = intercept(held, vk, down, alt, ctrl, armed);
            HELD.store(now, Ordering::Relaxed);
            let bit = chord_bit(vk);
            let fresh = held & bit == 0;
            // destination décidée à l'appui, suivie par le relâchement
            if swallow && down && fresh {
                let e = HELD_EGUI.load(Ordering::Relaxed);
                HELD_EGUI.store(if task { e | bit } else { e & !bit }, Ordering::Relaxed);
            }
            let to_egui = HELD_EGUI.load(Ordering::Relaxed) & bit != 0;
            if swallow && to_egui {
                if let Ok(mut q) = TASK_ESC.lock()
                    && q.len() < 64
                {
                    q.push(down);
                }
            } else if swallow {
                let mut sc = (k.scanCode & 0xFF) as u16;
                if k.flags & LLKHF_EXTENDED != 0 {
                    sc |= 0xE000;
                }
                if sc & 0xFF != 0
                    && let Ok(mut s) = SCANCODES.lock()
                    && s.len() < 512
                {
                    // Ctrl+Maj+Échap, Alt+Tab… : les modificateurs partent avant la touche
                    if down && fresh {
                        s.extend(held_modifiers().map(|m| (m, true)));
                    }
                    s.push((sc, down));
                }
                // aucun message n'atteint la fenêtre : l'interface est réveillée pour l'envoyer
                WAKE.store(true, Ordering::Relaxed);
                if let Some(t) = WAKER.get() {
                    t.unpark();
                }
                // retenue : ni le menu Démarrer ni le sélecteur de fenêtres de cet ordinateur
                return 1;
            }
        }
    }
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

// ---------------------------------------------------------------- fenêtre sur tous les écrans

/// Fenêtre étendue à plusieurs écrans : rectangle englobant voulu (pixels physiques), écrans
/// couverts (la fenêtre est découpée à leur forme) et premier plan appliqué.
struct Spanned {
    hwnd: isize,
    rect: [i32; 4],
    screens: Vec<[i32; 4]>,
    topmost: bool,
}

static SPANNED: Mutex<Vec<Spanned>> = Mutex::new(Vec::new());

/// Fenêtre d'Escale portant exactement ce titre.
fn find_window(title: &str) -> Option<isize> {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, GetWindowThreadProcessId};
    struct Search {
        title: Vec<u16>,
        found: Option<isize>,
    }
    unsafe extern "system" fn each(hwnd: HWND, data: LPARAM) -> windows_sys::core::BOOL {
        let s = unsafe { &mut *(data as *mut Search) };
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if pid != std::process::id() {
            return 1;
        }
        let mut buf = [0u16; 512];
        let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
        if n > 0 && buf[..n as usize] == s.title[..] {
            s.found = Some(hwnd as isize);
            return 0;
        }
        1
    }
    let mut s = Search { title: title.encode_utf16().collect(), found: None };
    unsafe { EnumWindows(Some(each), &mut s as *mut Search as LPARAM) };
    s.found
}

/// Place la fenêtre d'Escale de ce titre sur les écrans `screens` (gauche, haut, droite, bas ; pixels
/// physiques du bureau virtuel), comme `mstsc /multimon` : elle occupe leur rectangle englobant,
/// découpée à leur forme (un écran non choisi entre deux autres reste libre). Au premier plan, elle
/// passe au-dessus de la barre des tâches de cet ordinateur. À rappeler à chaque image : la fenêtre
/// est recalée si Windows ou winit l'ont déplacée (changement d'échelle). Faux tant que la fenêtre
/// n'existe pas encore.
pub fn span_window(title: &str, screens: &[[i32; 4]]) -> bool {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::Graphics::Gdi::{CombineRgn, CreateRectRgn, DeleteObject, RGN_OR, SetWindowRgn};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowRect, HWND_NOTOPMOST, HWND_TOPMOST, IsIconic, IsWindow, SWP_NOACTIVATE, SWP_NOMOVE,
        SWP_NOOWNERZORDER, SWP_NOSIZE, SetWindowPos,
    };
    let Some(first) = screens.first() else { return false };
    let r = screens.iter().fold(*first, |a, s| [a[0].min(s[0]), a[1].min(s[1]), a[2].max(s[2]), a[3].max(s[3])]);
    let Ok(mut spanned) = SPANNED.lock() else { return false };
    spanned.retain(|s| unsafe { IsWindow(s.hwnd as _) } != 0);
    let i = match spanned.iter().position(|s| find_window_title(s.hwnd).as_deref() == Some(title)) {
        Some(i) => i,
        None => {
            let Some(h) = find_window(title) else { return false };
            spanned.push(Spanned { hwnd: h, rect: r, screens: Vec::new(), topmost: false });
            spanned.len() - 1
        }
    };
    let s = &mut spanned[i];
    let hwnd = s.hwnd;
    s.rect = r;
    let mut cur: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetWindowRect(hwnd as _, &mut cur) };
    if [cur.left, cur.top, cur.right, cur.bottom] != r && unsafe { IsIconic(hwnd as _) } == 0 {
        unsafe { SetWindowPos(hwnd as _, std::ptr::null_mut(), r[0], r[1], r[2] - r[0], r[3] - r[1], SWP_NOACTIVATE | SWP_NOOWNERZORDER) };
    }
    // forme de la fenêtre : réunion des écrans, relative à son coin haut-gauche
    if s.screens != screens {
        s.screens = screens.to_vec();
        unsafe {
            let rgn = CreateRectRgn(0, 0, 0, 0);
            for e in screens {
                let part = CreateRectRgn(e[0] - r[0], e[1] - r[1], e[2] - r[0], e[3] - r[1]);
                CombineRgn(rgn, rgn, part, RGN_OR);
                DeleteObject(part);
            }
            // la région appartient désormais à la fenêtre
            SetWindowRgn(hwnd as _, rgn, 1);
        }
    }
    // au premier plan : au-dessus de la barre des tâches locale ; sinon les autres fenêtres
    // (Alt+Tab vers cet ordinateur, réduction) repassent devant
    let top = unsafe { GetForegroundWindow() } as isize == hwnd;
    if top != s.topmost {
        s.topmost = top;
        let after = if top { HWND_TOPMOST } else { HWND_NOTOPMOST };
        unsafe { SetWindowPos(hwnd as _, after, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) };
    }
    true
}

fn find_window_title(hwnd: isize) -> Option<String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextW;
    let mut buf = [0u16; 512];
    let n = unsafe { GetWindowTextW(hwnd as _, buf.as_mut_ptr(), buf.len() as i32) };
    (n > 0).then(|| String::from_utf16_lossy(&buf[..n as usize]))
}

/// Rectangle voulu d'une fenêtre étendue à tous les écrans.
fn spanned_rect(hwnd: isize) -> Option<[i32; 4]> {
    SPANNED.lock().ok()?.iter().find(|s| s.hwnd == hwnd).map(|s| s.rect)
}

// ---------------------------------------------------------------- curseur distant matériel

/// Le pointeur survole un bureau distant (positionné à chaque image par la vue, effacé au début de l'image).
pub static CURSOR_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Curseur du bureau distant : -1 = flèche normale (géré par la fenêtre), 0 = masqué, sinon HCURSOR.
static REMOTE_CURSOR: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(-1);
/// Fenêtres d'Escale dont la procédure est interceptée : (HWND, procédure d'origine).
static SUBCLASSED: Mutex<Vec<(isize, isize)>> = Mutex::new(Vec::new());

/// Image de curseur : pixels RGBA, largeur, hauteur, point actif (x, y).
pub type CursorPixels<'a> = (&'a [[u8; 4]], usize, usize, u16, u16);

/// Curseur du bureau distant sous forme de vrai curseur Windows : déplacé par le système, sans
/// attendre l'affichage d'une image (comme mstsc). `None` = flèche normale ; image vide = masqué.
pub fn set_remote_cursor(image: Option<CursorPixels<'_>>) {
    use windows_sys::Win32::Graphics::Gdi::{BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS, DeleteObject};
    use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, DestroyCursor, ICONINFO};
    let new: isize = match image {
        None => -1,
        Some((_, w, h, ..)) if w == 0 || h == 0 => 0,
        Some((rgba, w, h, hx, hy)) => unsafe {
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader = BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w as i32,
                biHeight: -(h as i32), // de haut en bas
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..std::mem::zeroed()
            };
            let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
            let color = CreateDIBSection(std::ptr::null_mut(), &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
            if color.is_null() || bits.is_null() {
                return;
            }
            // BGRA, alpha non prémultiplié
            let dst = std::slice::from_raw_parts_mut(bits as *mut u8, w * h * 4);
            for (d, s) in dst.as_chunks_mut::<4>().0.iter_mut().zip(rgba) {
                *d = [s[2], s[1], s[0], s[3]];
            }
            let mask_bits = vec![0u8; w.div_ceil(16) * 2 * h];
            let mask = CreateBitmap(w as i32, h as i32, 1, 1, mask_bits.as_ptr() as *const _);
            let info = ICONINFO { fIcon: 0, xHotspot: hx as u32, yHotspot: hy as u32, hbmMask: mask, hbmColor: color };
            let cursor = CreateIconIndirect(&info);
            DeleteObject(color);
            DeleteObject(mask);
            if cursor.is_null() {
                return;
            }
            cursor as isize
        },
    };
    let old = REMOTE_CURSOR.swap(new, Ordering::Relaxed);
    if CURSOR_ACTIVE.load(Ordering::Relaxed) {
        apply_cursor(new);
    }
    if old > 0 {
        unsafe { DestroyCursor(old as _) };
    }
}

fn apply_cursor(c: isize) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::SetCursor;
    if c < 0 {
        return false;
    }
    unsafe { SetCursor(if c == 0 { std::ptr::null_mut() } else { c as _ }) };
    true
}

/// Procédure de fenêtre interposée : applique le curseur distant au-dessus du bureau.
unsafe extern "system" fn subclass_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    use windows_sys::Win32::UI::WindowsAndMessaging::{CallWindowProcW, DefWindowProcW, HTCLIENT, WM_SETCURSOR};
    if msg == WM_SETCURSOR
        && (lparam as u32 & 0xFFFF) == HTCLIENT
        && CURSOR_ACTIVE.load(Ordering::Relaxed)
        && apply_cursor(REMOTE_CURSOR.load(Ordering::Relaxed))
    {
        return 1;
    }
    // procédure d'origine (verrou relâché avant l'appel : elle peut nous rappeler)
    let orig = SUBCLASSED.lock().ok().and_then(|v| v.iter().find(|(h, _)| *h == hwnd as isize).map(|(_, p)| *p));
    let r = match orig {
        Some(p) => unsafe { CallWindowProcW(Some(std::mem::transmute::<isize, unsafe extern "system" fn(_, _, _, _) -> _>(p)), hwnd, msg, wparam, lparam) },
        None => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    };
    // changement d'écran (autre échelle) : winit recale lui-même la fenêtre et la repousse
    // vers l'écran d'origine pendant le glisser ; le rectangle proposé par Windows, lui,
    // garde la taille logique et la souris en place, sans aller-retour entre les écrans
    if msg == windows_sys::Win32::UI::WindowsAndMessaging::WM_DPICHANGED && lparam != 0 {
        use windows_sys::Win32::UI::WindowsAndMessaging::{IsZoomed, SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPos};
        let mut s = unsafe { *(lparam as *const windows_sys::Win32::Foundation::RECT) };
        // fenêtre sur tous les écrans : elle ne bouge pas, quelle que soit l'échelle
        if let Some([l, t, r, b]) = spanned_rect(hwnd as isize) {
            s = windows_sys::Win32::Foundation::RECT { left: l, top: t, right: r, bottom: b };
        }
        if unsafe { IsZoomed(hwnd) } == 0 {
            unsafe { SetWindowPos(hwnd, std::ptr::null_mut(), s.left, s.top, s.right - s.left, s.bottom - s.top, SWP_NOZORDER | SWP_NOACTIVATE) };
        }
    }
    // fenêtre détruite (fenêtre séparée fermée) : son identifiant pourra être réutilisé
    if msg == windows_sys::Win32::UI::WindowsAndMessaging::WM_NCDESTROY
        && let Ok(mut v) = SUBCLASSED.lock()
    {
        v.retain(|(h, _)| *h != hwnd as isize);
    }
    r
}

/// Intercepte la procédure d'une fenêtre d'Escale la première fois qu'elle reçoit la souris.
fn subclass(hwnd: windows_sys::Win32::Foundation::HWND) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GWLP_WNDPROC, SetWindowLongPtrW};
    let Ok(mut v) = SUBCLASSED.lock() else { return };
    if hwnd.is_null() || v.iter().any(|(h, _)| *h == hwnd as isize) {
        return;
    }
    let prev = unsafe { SetWindowLongPtrW(hwnd, GWLP_WNDPROC, subclass_proc as *const () as usize as isize) };
    if prev != 0 {
        v.push((hwnd as isize, prev));
    }
}

/// Codes physiques relevés depuis le dernier appel.
pub fn take_scancodes() -> Vec<(u16, bool)> {
    SCANCODES.lock().map(|mut s| std::mem::take(&mut *s)).unwrap_or_default()
}

/// Code physique à transmettre en RDP : Windows signale Verr. Num comme étendue (0xE045) et Pause
/// comme 0x45, l'inverse de ce qu'attend le serveur (comme FreeRDP, on les rétablit). Pause devient
/// `desktop::PAUSE`, envoyée par la session en Ctrl (préfixe E1) + Verr. Num.
fn rdp_code(vk: u16, code: u16) -> u16 {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_NUMLOCK, VK_PAUSE};
    match vk {
        VK_NUMLOCK => 0x45,
        // Maj droite parfois signalée étendue (comme FreeRDP, on retire le préfixe)
        VK_SHIFT | VK_RSHIFT if code == 0xE036 => 0x36,
        VK_PAUSE if code & 0xFF == 0x45 => crate::desktop::PAUSE,
        _ => code,
    }
}

/// Verr. Num, Verr. Maj et Arrêt défil. de cet ordinateur (fil de l'interface).
pub fn lock_keys() -> crate::desktop::LockKeys {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_NUMLOCK, VK_SCROLL};
    let on = |vk: u16| unsafe { GetKeyState(vk as i32) } & 1 != 0;
    crate::desktop::LockKeys { num: on(VK_NUMLOCK), caps: on(VK_CAPITAL), scroll: on(VK_SCROLL) }
}

/// Ctrl gauche fantôme que Windows envoie avant Alt droit (AltGr) sur les dispositions qui en ont
/// un : le message suivant est Alt droit, au même instant (même test que winit / Chromium).
fn is_fake_altgr_ctrl(msg: &MSG) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PM_NOREMOVE, PM_NOYIELD, PeekMessageW, WM_KEYFIRST, WM_KEYLAST};
    let lp = msg.lParam as u32;
    if msg.wParam as u16 != VK_CONTROL || (lp >> 16) & 0xFF != 0x1D || lp & (1 << 24) != 0 {
        return false;
    }
    let mut next: MSG = unsafe { std::mem::zeroed() };
    if unsafe { PeekMessageW(&mut next, msg.hwnd, WM_KEYFIRST, WM_KEYLAST, PM_NOREMOVE | PM_NOYIELD) } == 0 {
        return false;
    }
    let nlp = next.lParam as u32;
    matches!(next.message, WM_KEYDOWN | WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP)
        && next.wParam as u16 == VK_MENU
        && nlp & (1 << 24) != 0
        && next.time == msg.time
}

fn record_scancode(msg: &MSG) {
    let down = matches!(msg.message, WM_KEYDOWN | WM_SYSKEYDOWN);
    let lp = msg.lParam as u32;
    // AltGr : seul Alt droit part, le serveur recrée lui-même Ctrl selon sa disposition (comme
    // mstsc). Seul l'appui est écarté : un relâchement de Ctrl jamais enfoncé est sans effet,
    // alors qu'un relâchement écarté laisserait Ctrl collé sur le bureau distant.
    if down && is_fake_altgr_ctrl(msg) {
        return;
    }
    let mut code = ((lp >> 16) & 0xFF) as u16;
    if lp & (1 << 24) != 0 {
        code |= 0xE000;
    }
    code = rdp_code(msg.wParam as u16, code);
    if code & 0xFF == 0 {
        // touche sans code (injectée) : on le déduit de la touche virtuelle
        code = unsafe { MapVirtualKeyW(msg.wParam as u32, MAPVK_VK_TO_VSC_EX) } as u16;
        if code & 0xFF00 == 0xE100 || code == 0 {
            return;
        }
    }
    if let Ok(mut s) = SCANCODES.lock()
        && s.len() < 512
    {
        s.push((code, down));
    }
}

/// Une touche enfoncée, avec l'état des modificateurs à cet instant et le texte qu'elle a produit.
struct Press {
    vk: u16,
    ctrl: bool,
    shift: bool,
    alt: bool,
    /// Alt droit (AltGr) : winit masque alors Ctrl et Alt, egui ne voit qu'un caractère.
    altgr: bool,
    text: Vec<u16>,
}

static PRESSES: Mutex<Vec<Press>> = Mutex::new(Vec::new());

/// Appelé pour chaque message Windows, avant qu'il soit traité par winit.
pub fn on_message(msg: &MSG) {
    if msg.message == windows_sys::Win32::UI::WindowsAndMessaging::WM_MOUSEMOVE {
        subclass(msg.hwnd);
    }
    if matches!(msg.message, WM_KEYDOWN | WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP) && CAPTURE.load(Ordering::Relaxed) {
        record_scancode(msg);
    }
    let Ok(mut presses) = PRESSES.lock() else { return };
    match msg.message {
        WM_KEYDOWN | WM_SYSKEYDOWN => {
            let vk = msg.wParam as u16;
            if is_modifier(vk) {
                return;
            }
            let down = |k: u16| unsafe { GetKeyState(k as i32) } < 0;
            if presses.len() > 256 {
                presses.clear();
            }
            presses.push(Press { vk, ctrl: down(VK_CONTROL), shift: down(VK_SHIFT), alt: down(VK_MENU), altgr: down(VK_RMENU), text: Vec::new() });
        }
        WM_CHAR | WM_SYSCHAR => {
            if let Some(p) = presses.last_mut() {
                p.text.push(msg.wParam as u16);
            }
        }
        _ => {}
    }
}

fn is_modifier(vk: u16) -> bool {
    matches!(vk, VK_SHIFT | VK_CONTROL | VK_MENU | VK_CAPITAL | VK_LWIN | VK_RWIN) || (VK_LCONTROL - 2..=VK_RMENU).contains(&vk)
}

#[derive(Clone, Copy, PartialEq)]
enum Clip {
    Copy,
    Cut,
    Paste,
}

/// Raccourci presse-papiers tel qu'egui-winit le reconnaît (mêmes règles, même ordre).
fn clip_chord(p: &Press) -> Option<(Clip, Key)> {
    if p.altgr {
        return None;
    }
    const C: u16 = b'C' as u16;
    const X: u16 = b'X' as u16;
    const V: u16 = b'V' as u16;
    match p.vk {
        X if p.ctrl => Some((Clip::Cut, Key::X)),
        VK_DELETE if p.shift => Some((Clip::Cut, Key::Delete)),
        C if p.ctrl => Some((Clip::Copy, Key::C)),
        VK_INSERT if p.ctrl => Some((Clip::Copy, Key::Insert)),
        V if p.ctrl => Some((Clip::Paste, Key::V)),
        VK_INSERT if p.shift => Some((Clip::Paste, Key::Insert)),
        _ => None,
    }
}

fn mods(p: &Press) -> Modifiers {
    Modifiers { alt: p.alt, ctrl: p.ctrl, shift: p.shift, mac_cmd: false, command: p.ctrl }
}

fn key_event(key: Key, modifiers: Modifiers) -> Event {
    Event::Key { key, physical_key: Some(key), pressed: true, repeat: false, modifiers }
}

/// Réécrit les événements de l'image quand le terminal a le focus : chaque raccourci redevient la
/// touche réellement frappée, pour être transmise telle quelle au serveur.
pub fn fix_events(events: &mut Vec<Event>, terminal_focused: bool) {
    // Ctrl+Maj+Échap retenu par le crochet (terminal, VNC) : la touche que Windows aurait gardée
    let esc = TASK_ESC.lock().map(|mut q| std::mem::take(&mut *q)).unwrap_or_default();
    if terminal_focused {
        let m = Modifiers { ctrl: true, shift: true, command: true, ..Default::default() };
        events.extend(esc.into_iter().map(|pressed| Event::Key { key: Key::Escape, physical_key: Some(Key::Escape), pressed, repeat: false, modifiers: m }));
    }
    let presses = match PRESSES.lock() {
        Ok(mut p) => std::mem::take(&mut *p),
        Err(_) => return,
    };
    if !terminal_focused || presses.is_empty() {
        return;
    }

    // --- Copier / Couper / Coller -> touches
    let mut chords: VecDeque<(Clip, Key, Modifiers)> = presses.iter().filter_map(|p| clip_chord(p).map(|(c, k)| (c, k, mods(p)))).collect();
    let mut lost_pastes = Vec::new();
    let mut out = Vec::with_capacity(events.len());
    for ev in events.drain(..) {
        let kind = match ev {
            Event::Copy => Clip::Copy,
            Event::Cut => Clip::Cut,
            Event::Paste(_) => Clip::Paste,
            _ => {
                out.push(ev);
                continue;
            }
        };
        // un Ctrl+V sur presse-papiers vide ne produit aucun événement : on le retrouve ici
        let mut found = None;
        while let Some(c) = chords.pop_front() {
            if c.0 == kind {
                found = Some(c);
                break;
            }
            if c.0 == Clip::Paste {
                lost_pastes.push(key_event(c.1, c.2));
            }
        }
        match found {
            // Ctrl+Maj+V, Maj+Inser : vrai collage, géré par le terminal
            Some((Clip::Paste, _, m)) if m.shift => out.push(ev),
            Some((_, key, m)) => out.push(key_event(key, m)),
            None => out.push(ev),
        }
    }
    lost_pastes.extend(chords.into_iter().filter(|c| c.0 == Clip::Paste).map(|c| key_event(c.1, c.2)));
    out.extend(lost_pastes);

    // --- Ctrl+Alt+touche ayant produit un caractère (Ctrl+Alt+E = « € » en AZERTY) : egui jette ce texte
    let ctrl_alt: Vec<Option<String>> = presses
        .iter()
        .filter(|p| p.ctrl && p.alt && !p.altgr)
        .map(|p| {
            let t = String::from_utf16_lossy(&p.text);
            (!t.is_empty() && t.chars().all(|c| !c.is_control())).then_some(t)
        })
        .collect();
    if ctrl_alt.iter().any(Option::is_some) {
        let slots: Vec<usize> = out
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e, Event::Key { pressed: true, modifiers, .. } if modifiers.ctrl && modifiers.alt))
            .map(|(i, _)| i)
            .collect();
        if slots.len() == ctrl_alt.len() {
            for (i, text) in slots.into_iter().zip(ctrl_alt) {
                if let Some(t) = text {
                    out[i] = Event::Text(t);
                }
            }
        } else {
            out.extend(ctrl_alt.into_iter().flatten().map(Event::Text));
        }
    }
    *events = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(vk: u16, ctrl: bool, shift: bool, alt: bool, text: &str) -> Press {
        Press { vk, ctrl, shift, alt, altgr: false, text: text.encode_utf16().collect() }
    }

    fn run(presses: Vec<Press>, mut events: Vec<Event>, focused: bool) -> Vec<Event> {
        *PRESSES.lock().unwrap() = presses;
        fix_events(&mut events, focused);
        events
    }

    fn is_key(e: &Event, k: Key, ctrl: bool, shift: bool) -> bool {
        matches!(e, Event::Key { key, pressed: true, modifiers, .. } if *key == k && modifiers.ctrl == ctrl && modifiers.shift == shift)
    }

    #[test]
    fn remote_cursor_becomes_a_system_cursor() {
        let px = vec![[255u8, 0, 0, 255]; 32 * 32];
        set_remote_cursor(Some((&px, 32, 32, 3, 4)));
        assert!(REMOTE_CURSOR.load(Ordering::Relaxed) > 0, "HCURSOR créé");
        set_remote_cursor(Some((&[], 0, 0, 0, 0)));
        assert_eq!(REMOTE_CURSOR.load(Ordering::Relaxed), 0, "masqué");
        set_remote_cursor(None);
        assert_eq!(REMOTE_CURSOR.load(Ordering::Relaxed), -1, "flèche normale");
    }

    #[test]
    fn system_chords_kept_for_the_remote_desktop() {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_ESCAPE, VK_TAB};
        assert!(is_system_chord(VK_LWIN, false, false) && is_system_chord(VK_RWIN, false, false));
        assert!(is_system_chord(VK_TAB, true, false), "Alt+Tab");
        assert!(!is_system_chord(VK_TAB, false, false), "Tab seul : message normal");
        assert!(is_system_chord(VK_ESCAPE, false, true) && is_system_chord(VK_ESCAPE, true, false));
        assert!(!is_system_chord(VK_ESCAPE, false, false));
        assert!(!is_system_chord(b'A' as u16, true, true));
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_F4, VK_SNAPSHOT, VK_SPACE};
        assert!(is_system_chord(VK_F4, true, false), "Alt+F4 : fenêtre distante, pas Escale");
        assert!(is_system_chord(VK_SPACE, true, false), "Alt+Espace : menu système distant");
        assert!(!is_system_chord(VK_F4, false, false) && !is_system_chord(VK_SPACE, false, true));
        assert!(is_system_chord(VK_SNAPSHOT, false, false), "Impr écran");
    }

    #[test]
    fn numlock_and_pause_codes_fixed_for_rdp() {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_NUMLOCK, VK_NUMPAD1, VK_PAUSE, VK_RETURN};
        // Windows : Verr. Num étendue, Pause non étendue ; le serveur attend l'inverse
        assert_eq!(rdp_code(VK_NUMLOCK, 0xE045), 0x45);
        assert_eq!(rdp_code(VK_PAUSE, 0x45), crate::desktop::PAUSE);
        // pavé numérique : codes inchangés (Entrée et / du pavé restent étendues)
        assert_eq!(rdp_code(VK_NUMPAD1, 0x4F), 0x4F);
        assert_eq!(rdp_code(VK_RETURN, 0xE01C), 0xE01C);
        // Maj droite signalée étendue
        assert_eq!(rdp_code(VK_SHIFT, 0xE036), 0x36);
        assert_eq!(rdp_code(VK_SHIFT, 0x2A), 0x2A);
        // Ctrl+Pause (Attn) : touche à part, code d'origine
        assert_eq!(rdp_code(windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_CANCEL, 0xE046), 0xE046);
    }

    #[test]
    fn task_manager_chord_only() {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_ESCAPE, VK_TAB};
        assert!(is_task_manager_chord(VK_ESCAPE, false, true, true), "Ctrl+Maj+Échap");
        assert!(!is_task_manager_chord(VK_ESCAPE, false, true, false), "Ctrl+Échap : menu Démarrer d'ici");
        assert!(!is_task_manager_chord(VK_ESCAPE, false, false, true));
        assert!(!is_task_manager_chord(VK_ESCAPE, true, true, true));
        assert!(!is_task_manager_chord(VK_TAB, false, true, true));
        // retenu comme les autres combinaisons : appui et relâchement
        let (s, h) = intercept(0, VK_ESCAPE, true, false, true, true);
        assert!(s && h != 0);
        assert_eq!(intercept(h, VK_ESCAPE, false, false, false, false), (true, 0));
    }

    #[test]
    fn hook_never_leaves_a_key_stuck() {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_ESCAPE, VK_TAB};
        // bureau RDP au focus : Win retenu à l'appui comme au relâchement
        let (s, h) = intercept(0, VK_LWIN, true, false, false, true);
        assert!(s && h != 0);
        let (s, h2) = intercept(h, VK_LWIN, true, false, false, true);
        assert!(s && h2 == h, "répétition automatique");
        // le focus a changé entre-temps : le relâchement suit quand même l'appui (bureau distant)
        let (s, h) = intercept(h2, VK_LWIN, false, false, false, false);
        assert!(s && h == 0);

        // Win+Tab / Win+1 vers Escale : Win enfoncé ici avant le focus, relâché pendant la capture ;
        // le retenir laisserait Win enfoncé sur cet ordinateur (chaque touche deviendrait Win+touche)
        let (s, h) = intercept(0, VK_RWIN, false, false, false, true);
        assert!(!s && h == 0);

        // Alt+Tab : Tab relâché après Alt (plus de drapeau Alt) : relâchement retenu aussi
        let (s, h) = intercept(0, VK_TAB, true, true, false, true);
        assert!(s);
        let (s, h) = intercept(h, VK_TAB, false, false, false, true);
        assert!(s && h == 0);
        // Alt+Tab vers Escale : Tab relâché pendant la capture, appui vu par Windows
        assert_eq!(intercept(0, VK_TAB, false, true, false, true), (false, 0));

        // non armé (autre fenêtre, SSH, hôte sans raccourcis Windows) : rien n'est retenu
        assert_eq!(intercept(0, VK_LWIN, true, false, false, false), (false, 0));
        assert_eq!(intercept(0, VK_ESCAPE, true, false, true, false), (false, 0));
        // touches ordinaires : jamais
        assert_eq!(intercept(0xFF, b'A' as u16, true, true, true, true), (false, 0xFF));
        // Échap seul : message normal
        assert_eq!(intercept(0, VK_ESCAPE, true, false, false, true), (false, 0));
    }

    #[test]
    fn hook_runs_on_its_own_message_loop_and_is_removed() {
        // désarmé : le crochet laisse tout passer (aucun effet sur le clavier pendant le test)
        HOOK_ARMED.store(false, Ordering::Relaxed);
        let ctx = eframe::egui::Context::default();
        install_keyboard_hook(&ctx);
        let start = std::time::Instant::now();
        while HOOK_TID.load(Ordering::Acquire) == 0 && start.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::yield_now();
        }
        let tid = HOOK_TID.load(Ordering::Acquire);
        assert!(tid != 0, "fil du crochet démarré");
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentThreadId() -> u32;
        }
        assert_ne!(tid, unsafe { GetCurrentThreadId() }, "jamais sur le fil appelant");
        // fin d'image : armé seulement si un bureau RDP qui accepte les raccourcis a le focus
        CAPTURE.store(true, Ordering::Relaxed);
        WIN_KEYS.store(false, Ordering::Relaxed);
        end_frame();
        assert!(!HOOK_ARMED.load(Ordering::Relaxed));
        begin_frame();
        end_frame();
        assert!(!HOOK_ARMED.load(Ordering::Relaxed));
        uninstall_keyboard_hook();
        assert!(HOOK_THREAD.lock().unwrap().is_none() && !HOOK_INSTALLED.load(Ordering::Relaxed));
    }

    // un seul test : PRESSES est global
    #[test]
    fn clipboard_chords_become_keys() {
        let ev = run(vec![press(b'X' as u16, true, false, false, "\x18")], vec![Event::Cut], true);
        assert!(is_key(&ev[0], Key::X, true, false));

        let ev = run(vec![press(b'C' as u16, true, false, false, "")], vec![Event::Copy], true);
        assert!(is_key(&ev[0], Key::C, true, false));

        let ev = run(vec![press(VK_INSERT, true, false, false, "")], vec![Event::Copy], true);
        assert!(is_key(&ev[0], Key::Insert, true, false));

        let ev = run(vec![press(VK_DELETE, false, true, false, "")], vec![Event::Cut], true);
        assert!(is_key(&ev[0], Key::Delete, false, true));

        // Ctrl+V -> ^V ; Ctrl+Maj+V reste un collage
        let ev = run(vec![press(b'V' as u16, true, false, false, "")], vec![Event::Paste("x".into())], true);
        assert!(is_key(&ev[0], Key::V, true, false));
        let ev = run(vec![press(b'V' as u16, true, true, false, "")], vec![Event::Paste("x".into())], true);
        assert!(matches!(&ev[0], Event::Paste(t) if t == "x"));

        // Ctrl+V presse-papiers vide : aucun événement egui, on le recrée
        let ev = run(vec![press(b'V' as u16, true, false, false, ""), press(b'X' as u16, true, false, false, "")], vec![Event::Cut], true);
        assert!(is_key(&ev[0], Key::X, true, false));
        assert!(is_key(&ev[1], Key::V, true, false));

        // terminal sans focus : rien ne change
        let ev = run(vec![press(b'C' as u16, true, false, false, "")], vec![Event::Copy], false);
        assert!(matches!(ev[0], Event::Copy));
        assert!(PRESSES.lock().unwrap().is_empty());

        // Ctrl+Alt+E = « € » (AZERTY) : le texte remplace la touche ; Ctrl+Alt+A reste une touche
        let ca = Modifiers { ctrl: true, alt: true, command: true, ..Default::default() };
        let ev = run(
            vec![press(b'E' as u16, true, false, true, "€"), press(b'A' as u16, true, false, true, "")],
            vec![key_event(Key::E, ca), key_event(Key::A, ca)],
            true,
        );
        assert!(matches!(&ev[0], Event::Text(t) if t == "€"));
        assert!(matches!(ev[1], Event::Key { key: Key::A, .. }));

        // Ctrl+Maj+Échap retenu par le crochet (terminal, VNC) : rendu à egui, même sans autre frappe
        TASK_ESC.lock().unwrap().extend([true, false]);
        let ev = run(Vec::new(), Vec::new(), true);
        assert!(matches!(ev[0], Event::Key { key: Key::Escape, pressed: true, modifiers, .. } if modifiers.ctrl && modifiers.shift && !modifiers.alt));
        assert!(matches!(ev[1], Event::Key { key: Key::Escape, pressed: false, .. }));
        TASK_ESC.lock().unwrap().push(true);
        assert!(run(Vec::new(), Vec::new(), false).is_empty(), "plus de focus : écarté");
        assert!(TASK_ESC.lock().unwrap().is_empty());
    }
}
