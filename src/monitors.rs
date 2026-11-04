//! Écrans de cet ordinateur, pour un bureau distant étendu à plusieurs écrans (comme `mstsc /multimon`
//! et « choisir les moniteurs »).

use crate::desktop::{MAX_SIZE, MIN_SIZE};

/// Un écran, en pixels physiques, dans les coordonnées du bureau virtuel de Windows (l'écran
/// principal de cet ordinateur commence en (0, 0)) ; bords droit et bas exclus.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Screen {
    /// Nom Windows de l'écran (`\\.\DISPLAY2`), qui l'identifie dans les options de l'hôte.
    pub name: String,
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    /// Écran principal (de cet ordinateur dans `list`, du bureau distant dans un `Layout`).
    pub primary: bool,
}

impl Screen {
    pub fn rect(&self) -> [i32; 4] {
        [self.left, self.top, self.right, self.bottom]
    }

    pub fn size(&self) -> (i32, i32) {
        (self.right - self.left, self.bottom - self.top)
    }

    /// Numéro affiché (celui de `\\.\DISPLAYn`), sinon `fallback`.
    pub fn number(&self, fallback: usize) -> usize {
        self.name.trim_start_matches(|c: char| !c.is_ascii_digit()).parse().unwrap_or(fallback)
    }
}

/// Écrans couverts par le bureau distant, l'écran principal distant en tête ; l'image distante est
/// leur rectangle englobant.
#[derive(Clone, PartialEq, Debug)]
pub struct Layout {
    pub screens: Vec<Screen>,
}

/// Nombre d'écrans maximal accepté par un serveur RDP.
const MAX_SCREENS: usize = 16;

impl Layout {
    /// Rectangle englobant : (gauche, haut, droite, bas), bords droit et bas exclus.
    pub fn bounds(&self) -> (i32, i32, i32, i32) {
        bounds(&self.screens)
    }

    /// Taille du bureau distant (pixels).
    pub fn size(&self) -> (u16, u16) {
        let (l, t, r, b) = self.bounds();
        (((r - l).clamp(MIN_SIZE, MAX_SIZE)) as u16, ((b - t).clamp(MIN_SIZE, MAX_SIZE)) as u16)
    }

    pub fn primary(&self) -> &Screen {
        &self.screens[0]
    }
}

pub fn bounds(screens: &[Screen]) -> (i32, i32, i32, i32) {
    screens.iter().fold((i32::MAX, i32::MAX, i32::MIN, i32::MIN), |(l, t, r, b), s| {
        (l.min(s.left), t.min(s.top), r.max(s.right), b.max(s.bottom))
    })
}

/// Disposition à partir des écrans relevés et des noms choisis dans l'hôte (vide = tous ; aucun
/// écran choisi n'est branché = tous). L'écran principal distant est celui de cet ordinateur s'il
/// est retenu, sinon le plus à gauche. Si l'ensemble dépasse les limites d'une image distante
/// (8192 pixels de côté, 16 écrans), l'écran principal distant seul.
pub fn choose(mut screens: Vec<Screen>, selected: &[String]) -> Option<Layout> {
    screens.retain(|s| s.right - s.left >= MIN_SIZE && s.bottom - s.top >= MIN_SIZE);
    if screens.iter().any(|s| selected.contains(&s.name)) {
        screens.retain(|s| selected.contains(&s.name));
    }
    if screens.is_empty() {
        return None;
    }
    let p = screens
        .iter()
        .position(|s| s.primary)
        .unwrap_or_else(|| (0..screens.len()).min_by_key(|&i| (screens[i].left, screens[i].top)).unwrap_or(0));
    let primary = screens.remove(p);
    screens.insert(0, Screen { primary: true, ..primary });
    for s in &mut screens[1..] {
        s.primary = false;
    }
    let (l, t, r, b) = bounds(&screens);
    if screens.len() > MAX_SCREENS || r - l > MAX_SIZE || b - t > MAX_SIZE {
        screens.truncate(1);
    }
    Some(Layout { screens })
}

/// Disposition des écrans actuels pour les noms choisis (aucune hors Windows).
pub fn layout(selected: &[String]) -> Option<Layout> {
    choose(list(), selected)
}

/// Écrans branchés, de gauche à droite.
pub fn list() -> Vec<Screen> {
    let mut v = enumerate();
    v.sort_by_key(|s| (s.left, s.top));
    v
}

#[cfg(windows)]
fn enumerate() -> Vec<Screen> {
    use windows_sys::Win32::Foundation::{LPARAM, RECT};
    use windows_sys::Win32::Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFOEXW};
    // MONITORINFOF_PRIMARY
    const PRIMARY: u32 = 1;
    unsafe extern "system" fn each(m: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> windows_sys::core::BOOL {
        let screens = unsafe { &mut *(data as *mut Vec<Screen>) };
        let mut mi: MONITORINFOEXW = unsafe { std::mem::zeroed() };
        mi.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
        if unsafe { GetMonitorInfoW(m, &mut mi as *mut MONITORINFOEXW as *mut _) } != 0 {
            let r = mi.monitorInfo.rcMonitor;
            let n = mi.szDevice.iter().position(|&c| c == 0).unwrap_or(mi.szDevice.len());
            screens.push(Screen {
                name: String::from_utf16_lossy(&mi.szDevice[..n]),
                left: r.left,
                top: r.top,
                right: r.right,
                bottom: r.bottom,
                primary: mi.monitorInfo.dwFlags & PRIMARY != 0,
            });
        }
        1
    }
    // Escale est déclaré sensible au DPI de chaque écran (winit) : rectangles en pixels physiques
    let mut screens: Vec<Screen> = Vec::new();
    unsafe { EnumDisplayMonitors(std::ptr::null_mut(), std::ptr::null(), Some(each), &mut screens as *mut Vec<Screen> as LPARAM) };
    screens
}

#[cfg(not(windows))]
fn enumerate() -> Vec<Screen> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u8, left: i32, top: i32, right: i32, bottom: i32, primary: bool) -> Screen {
        Screen { name: format!("\\\\.\\DISPLAY{n}"), left, top, right, bottom, primary }
    }

    #[test]
    fn layout_spans_all_screens_with_the_primary_first() {
        // écran secondaire à gauche, plus haut, principal 4K
        let l = choose(vec![s(2, -1920, -200, 0, 880, false), s(1, 0, 0, 3840, 2160, true)], &[]).unwrap();
        assert!(l.screens[0].primary && !l.screens[1].primary);
        assert_eq!(l.bounds(), (-1920, -200, 3840, 2160));
        assert_eq!(l.size(), (5760, 2360));
        assert_eq!(l.primary(), &s(1, 0, 0, 3840, 2160, true));
        assert_eq!(l.primary().number(9), 1);
    }

    #[test]
    fn only_the_chosen_screens() {
        let all = vec![s(1, 0, 0, 1920, 1080, true), s(2, 1920, 0, 3840, 1080, false), s(3, 3840, 0, 5760, 1080, false)];
        // principal de cet ordinateur non retenu : le plus à gauche des écrans choisis le devient
        let l = choose(all.clone(), &[s(3, 0, 0, 0, 0, false).name, s(2, 0, 0, 0, 0, false).name]).unwrap();
        assert_eq!(l.screens.len(), 2);
        assert_eq!(l.primary().number(0), 2);
        assert_eq!(l.bounds(), (1920, 0, 5760, 1080));
        // écrans choisis absents (autre ordinateur) : tous
        assert_eq!(choose(all, &["\\\\.\\DISPLAY9".into()]).unwrap().screens.len(), 3);
    }

    #[test]
    fn too_large_falls_back_to_the_primary_screen() {
        let l = choose(vec![s(1, 0, 0, 3840, 2160, true), s(2, 3840, 0, 7680, 2160, false), s(3, 7680, 0, 11520, 2160, false)], &[]).unwrap();
        assert_eq!(l.screens, vec![s(1, 0, 0, 3840, 2160, true)]);
        // aucun écran principal signalé : un seul le devient
        let l = choose(vec![s(1, 0, 0, 1920, 1080, false), s(2, 1920, 0, 3840, 1080, false)], &[]).unwrap();
        assert_eq!(l.screens.iter().filter(|s| s.primary).count(), 1);
        assert!(choose(Vec::new(), &[]).is_none());
    }
}
