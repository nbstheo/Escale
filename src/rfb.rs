//! Sessions VNC (RFB, crate vnc-rs) : authentification VNC, encodages ZRLE / CopyRect / Raw,
//! curseur distant. Le flux peut passer par les rebonds SSH de l'hôte.

use crate::desktop::{CursorImage, CursorShape, DesktopCmd, DesktopHandle, Frame, Input, MouseBtn, SharedFrame};
use crate::model::Host;
use crate::ssh::{self, Event, Events};
use eframe::egui::Color32;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use vnc::{PixelFormat, VncConnector, VncEncoding, VncEvent, X11Event};

pub fn spawn(rt: &tokio::runtime::Runtime, chain: Vec<Host>, ctx: eframe::egui::Context) -> DesktopHandle {
    let (tx, cmd_rx) = mpsc::unbounded_channel();
    let (events, rx) = Events::new(ctx);
    let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
    let f = frame.clone();
    let ev = events.clone();
    rt.spawn(async move {
        let res = ssh::isolated(run(chain, cmd_rx, ev, f)).await;
        events.send(Event::Closed(res.err()));
    });
    DesktopHandle { tx, rx, frame, drive: None }
}

fn vnc_err(e: vnc::VncError) -> String {
    match e {
        vnc::VncError::NoPassword => "Le serveur VNC exige un mot de passe".into(),
        vnc::VncError::WrongPassword => "Mot de passe VNC refusé".into(),
        e => {
            let s = e.to_string();
            if s.to_lowercase().contains("auth") { format!("Authentification VNC refusée ({s})") } else { format!("VNC : {s}") }
        }
    }
}

async fn run(chain: Vec<Host>, mut cmd_rx: mpsc::UnboundedReceiver<DesktopCmd>, events: Events, frame: SharedFrame) -> Result<(), String> {
    let target = chain.last().ok_or("Aucun hôte")?.clone();
    let (stream, jumps) = ssh::open_stream(&chain, &events).await?;
    let res = session(&target, stream, &mut cmd_rx, &events, &frame).await;
    ssh::disconnect(&jumps).await;
    res
}

/// Masque des boutons RFB : 1 gauche, 2 milieu, 4 droit, 8/16 molette haut/bas, 32/64 gauche/droite.
fn button_bit(b: MouseBtn) -> u8 {
    match b {
        MouseBtn::Left => 1,
        MouseBtn::Middle => 2,
        MouseBtn::Right => 4,
        MouseBtn::X1 => 128,
        MouseBtn::X2 => 0,
    }
}

/// Événements RFB pour une liste d'entrées neutres ; `buttons` / `pos` / `keys` suivent l'état envoyé.
fn to_x11(input: Vec<Input>, buttons: &mut u8, pos: &mut (u16, u16), keys: &mut HashSet<u32>) -> Vec<X11Event> {
    let mut out = Vec::new();
    let pointer = |b: u8, p: (u16, u16)| X11Event::PointerEvent((p.0, p.1, b).into());
    let key = |sym: u32, down: bool| X11Event::KeyEvent((sym, down).into());
    for i in input {
        match i {
            Input::Mouse { x, y } => {
                *pos = (x, y);
                out.push(pointer(*buttons, *pos));
            }
            Input::Button { button, down } => {
                let bit = button_bit(button);
                if down { *buttons |= bit } else { *buttons &= !bit }
                out.push(pointer(*buttons, *pos));
            }
            Input::Wheel { vertical, units } => {
                let bit = match (vertical, units > 0) {
                    (true, true) => 8,
                    (true, false) => 16,
                    (false, false) => 32,
                    (false, true) => 64,
                };
                for _ in 0..(units.unsigned_abs() / 120).max(1) {
                    out.push(pointer(*buttons | bit, *pos));
                    out.push(pointer(*buttons, *pos));
                }
            }
            Input::Keysym { sym, down } => {
                if down { keys.insert(sym) } else { keys.remove(&sym) };
                out.push(key(sym, down));
            }
            Input::Text(t) => {
                // modificateurs relâchés d'abord (Maj, Ctrl, Alt, Super…) : le texte n'est pas un raccourci
                let held: Vec<u32> = keys.iter().copied().filter(|s| (0xFFE1..=0xFFEE).contains(s)).collect();
                for sym in held {
                    keys.remove(&sym);
                    out.push(key(sym, false));
                }
                for c in t.replace("\r\n", "\n").chars() {
                    let sym = crate::desktop::char_keysym(c);
                    out.push(key(sym, true));
                    out.push(key(sym, false));
                }
            }
            Input::ReleaseAll => {
                for sym in keys.drain() {
                    out.push(key(sym, false));
                }
                if *buttons != 0 {
                    *buttons = 0;
                    out.push(pointer(0, *pos));
                }
            }
            Input::Scancode { .. } | Input::Locks(_) => {}
        }
    }
    out
}

fn draw(frame: &SharedFrame, ev: VncEvent) -> Result<bool, String> {
    let Ok(mut f) = frame.lock() else { return Ok(false) };
    match ev {
        VncEvent::SetResolution(s) => f.resize(s.width as usize, s.height as usize),
        VncEvent::DesktopUpdate(u) => {
            if let Some(l) = u.layout {
                f.resize(l.width as usize, l.height as usize);
            }
        }
        VncEvent::RawImage(r, data) => {
            let w = f.width;
            let (x0, y0, rw, rh) = (r.x as usize, r.y as usize, r.width as usize, r.height as usize);
            for (row, line) in data.chunks_exact(rw.max(1) * 4).take(rh).enumerate() {
                let y = y0 + row;
                if y >= f.height {
                    break;
                }
                for (col, px) in line.chunks_exact(4).enumerate() {
                    let x = x0 + col;
                    if x < w {
                        f.pixels[y * w + x] = Color32::from_rgb(px[0], px[1], px[2]);
                    }
                }
            }
            f.mark(x0, y0, x0 + rw, y0 + rh);
        }
        VncEvent::Copy(dst, src) => {
            let w = f.width;
            let (rw, rh) = (dst.width as usize, dst.height as usize);
            if src.x as usize + rw > w || src.y as usize + rh > f.height || dst.x as usize + rw > w || dst.y as usize + rh > f.height {
                return Ok(false);
            }
            // tampon intermédiaire : source et destination peuvent se chevaucher
            let mut tmp = Vec::with_capacity(rw * rh);
            for y in 0..rh {
                let s = (src.y as usize + y) * w + src.x as usize;
                tmp.extend_from_slice(&f.pixels[s..s + rw]);
            }
            for y in 0..rh {
                let d = (dst.y as usize + y) * w + dst.x as usize;
                f.pixels[d..d + rw].copy_from_slice(&tmp[y * rw..(y + 1) * rw]);
            }
            f.mark(dst.x as usize, dst.y as usize, dst.x as usize + rw, dst.y as usize + rh);
        }
        VncEvent::SetCursor(r, data) => {
            let (w, h) = (r.width as usize, r.height as usize);
            if w == 0 || h == 0 || data.len() < w * h * 4 {
                f.set_cursor(CursorShape::Hidden);
            } else {
                let pixels = data.chunks_exact(4).take(w * h).map(|p| Color32::from_rgba_unmultiplied(p[0], p[1], p[2], p[3])).collect();
                // en pseudo-encodage curseur, x / y portent le point chaud
                f.set_cursor(CursorShape::Bitmap(Arc::new(CursorImage { size: [w, h], hotspot: [r.x, r.y], pixels })));
            }
        }
        VncEvent::Error(e) => return Err(format!("VNC : {e}")),
        _ => return Ok(false),
    }
    Ok(true)
}

async fn session(
    host: &Host,
    stream: Box<dyn ssh::Stream>,
    cmd_rx: &mut mpsc::UnboundedReceiver<DesktopCmd>,
    events: &Events,
    frame: &SharedFrame,
) -> Result<(), String> {
    events.send(Event::Status(format!("Négociation VNC avec {}…", host.address())));
    let password = host.password.clone();
    let has_password = !password.is_empty();
    let vnc = VncConnector::new(stream)
        .set_auth_method(async move { if has_password { Ok(password) } else { Err(vnc::VncError::NoPassword) } })
        .add_encoding(VncEncoding::Zrle)
        .add_encoding(VncEncoding::CopyRect)
        .add_encoding(VncEncoding::Raw)
        .add_encoding(VncEncoding::CursorPseudo)
        .add_encoding(VncEncoding::DesktopSizePseudo)
        .allow_shared(true)
        .set_pixel_format(PixelFormat::rgba())
        .build()
        .map_err(vnc_err)?;
    let vnc = tokio::time::timeout(Duration::from_secs(20), vnc.try_start())
        .await
        .map_err(|_| "Délai dépassé pendant la négociation VNC".to_string())?
        .map_err(vnc_err)?
        .finish()
        .map_err(vnc_err)?;
    events.send(Event::Connected);

    let mut tick = tokio::time::interval(Duration::from_millis(16));
    let (mut buttons, mut pos, mut keys) = (0u8, (0u16, 0u16), HashSet::new());
    let result = loop {
        tokio::select! {
            ev = vnc.recv_event() => match ev {
                Ok(ev) => match draw(frame, ev) {
                    Ok(true) => events.repaint(),
                    Ok(false) => {}
                    Err(e) => break Err(e),
                },
                Err(e) => break Err(vnc_err(e)),
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(DesktopCmd::Input(list)) => {
                    for ev in to_x11(list, &mut buttons, &mut pos, &mut keys) {
                        if let Err(e) = vnc.input(ev).await {
                            return Err(vnc_err(e));
                        }
                    }
                }
                // le bureau VNC garde sa taille : l'image est mise à l'échelle
                Some(DesktopCmd::Resize(..)) => {}
                Some(DesktopCmd::Close) | None => break Ok(()),
            },
            // mises à jour incrémentales régulières
            _ = tick.tick() => {
                if let Err(e) = vnc.input(X11Event::Refresh).await {
                    break Err(vnc_err(e));
                }
            }
        }
    };
    let _ = vnc.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serveur RFB 3.8 minimal : sans authentification, bureau 4×2, une mise à jour Raw.
    async fn fake_server(mut s: tokio::io::DuplexStream) -> std::io::Result<()> {
        s.write_all(b"RFB 003.008\n").await?;
        let mut version = [0u8; 12];
        s.read_exact(&mut version).await?;
        s.write_all(&[1, 1]).await?; // un type de sécurité : None
        let mut chosen = [0u8; 1];
        s.read_exact(&mut chosen).await?;
        s.write_u32(0).await?; // authentification réussie
        let mut shared = [0u8; 1];
        s.read_exact(&mut shared).await?;
        s.write_u16(4).await?;
        s.write_u16(2).await?;
        s.write_all(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]).await?;
        s.write_u32(4).await?;
        s.write_all(b"test").await?;
        // FramebufferUpdate : 1 rectangle Raw de 2×1 en (1, 0), au format demandé par le client (RGBA)
        s.write_all(&[0, 0, 0, 1]).await?;
        for v in [1u16, 0, 2, 1] {
            s.write_u16(v).await?;
        }
        s.write_i32(0).await?;
        s.write_all(&[255, 0, 0, 0, 0, 255, 0, 0]).await?;
        let mut sink = [0u8; 4096];
        while s.read(&mut sink).await? > 0 {}
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_draws_server_updates() {
        let (client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(fake_server(server));
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (tx, mut cmd_rx) = mpsc::unbounded_channel();
        let f = frame.clone();
        let task = tokio::spawn(async move {
            let host = Host::default();
            session(&host, Box::new(client), &mut cmd_rx, &events, &f).await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let px = frame.lock().unwrap().pixels.clone();
            if px.len() == 8 && px[1] == Color32::from_rgb(255, 0, 0) {
                assert_eq!(px[2], Color32::from_rgb(0, 255, 0));
                assert_eq!(px[0], Color32::BLACK);
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "image non reçue : {px:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let size = frame.lock().map(|f| (f.width, f.height)).unwrap();
        assert_eq!(size, (4, 2));
        tx.send(DesktopCmd::Close).unwrap();
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[test]
    fn pointer_wheel_and_release() {
        let (mut b, mut p, mut k) = (0u8, (0, 0), HashSet::new());
        let ev = to_x11(
            vec![
                Input::Mouse { x: 10, y: 20 },
                Input::Button { button: MouseBtn::Left, down: true },
                Input::Wheel { vertical: true, units: -240 },
                Input::Keysym { sym: 0xFFE3, down: true },
            ],
            &mut b,
            &mut p,
            &mut k,
        );
        // déplacement, bouton, 2 crans (appui + relâche chacun), touche
        assert_eq!(ev.len(), 1 + 1 + 4 + 1);
        assert!(matches!(&ev[2], X11Event::PointerEvent(m) if m.bottons == 1 | 16 && m.position_x == 10));
        assert_eq!(b, 1);
        let ev = to_x11(vec![Input::ReleaseAll], &mut b, &mut p, &mut k);
        assert_eq!(ev.len(), 2);
        assert_eq!(b, 0);
        assert!(k.is_empty());
    }
}
