//! Pipeline graphique RDP (RDPGFX, MS-RDPEGFX) : le mode d'affichage moderne de Windows, celui de
//! mstsc. Le serveur compose l'écran dans des surfaces qu'il met à jour en H.264 (AVC444 ou
//! AVC420), RemoteFX Progressive, ClearCodec, Planar ou en clair, et les déplace / met en cache sans
//! renvoyer les pixels. Escale reproduit ces surfaces et recopie celles affichées dans l'image
//! partagée avec l'interface.
//!
//! Si le serveur ne propose pas ce pipeline, l'ancien mode (mises à jour bitmap) prend le relais
//! automatiquement : le canal reste simplement fermé.

use crate::desktop::SharedFrame;
use crate::ssh::Events;
use eframe::egui::Color32;
use ironrdp_egfx::client::{BitmapUpdate, GraphicsPipelineClient, GraphicsPipelineHandler, Surface as GfxSurface};
use ironrdp_egfx::pdu::{
    Avc420BitmapStream, Avc444BitmapStream, CacheToSurfacePdu, CapabilitiesV103Flags, CapabilitiesV104Flags,
    CapabilitiesV107Flags, CapabilitiesV10Flags, CapabilitiesV81Flags, CapabilitiesV8Flags, CapabilitySet, Codec1Type,
    DeleteEncodingContextPdu, Encoding, EvictCacheEntryPdu, GfxPdu, MapSurfaceToScaledOutputPdu, SolidFillPdu,
    SurfaceToCachePdu, SurfaceToSurfacePdu, WireToSurface2Pdu,
};
use crate::clearcodec::ClearDecoder;
use ironrdp_graphics::progressive::ProgressiveDecoder;
use ironrdp_graphics::rdp6::BitmapStreamDecoder;
use ironrdp_pdu::geometry::ExclusiveRectangle;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Plafonds contre un serveur hostile ou défaillant : une allocation démesurée arrêterait tout
/// Escale (ce n'est pas une panique, isolée à la session). Largement au-delà des besoins réels
/// (8K = 33 M pixels).
const MAX_SIDE: usize = 32766; // MS-RDPEGFX 2.2.2.14
/// Pixels de l'écran (ResetGraphics).
const MAX_SCREEN_PIXELS: usize = 8192 * 8192;
/// Pixels de l'ensemble des surfaces.
const MAX_SURFACE_PIXELS: usize = 2 * 8192 * 8192;
/// Pixels du cache de bitmaps (le serveur en tient le compte ; 100 Mo au plus selon la spécification).
const MAX_CACHE_PIXELS: usize = 100 * 1024 * 1024 / 4;

/// Indique à la session que le pipeline est actif (l'ancien mode n'envoie alors plus d'image).
#[derive(Default)]
pub struct GfxState {
    active: AtomicBool,
}

impl GfxState {
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

/// Codecs annoncés au serveur.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Codecs {
    /// H.264 AVC444 (versions 10.x), AVC420 en repli (8.1).
    Avc444,
    /// H.264 AVC420 seulement (8.1).
    Avc420,
    /// Sans H.264 : RemoteFX Progressive, ClearCodec, Planar (versions 10.x « AVC désactivé » et 8).
    NoAvc,
}

/// Client du canal RDPGFX. Le H.264 est décodé par le compositeur (un flux par surface) ; sans
/// décodeur utilisable, aucun mode AVC n'est annoncé.
pub fn client(frame: SharedFrame, events: Events, state: Arc<GfxState>, codecs: Codecs) -> GraphicsPipelineClient {
    GraphicsPipelineClient::new(Box::new(Compositor::with_codecs(frame, events, state, codecs)), None)
}

/// Canal RDPGFX branché sur la session. Diagnostic : avec `ESCALE_GFX_CAPTURE=<fichier>`, les
/// messages bruts reçus sont enregistrés (longueur u32 LE + octets) pour être rejoués hors ligne.
/// Attention : l'enregistrement contient l'image du bureau distant.
pub fn channel(frame: SharedFrame, events: Events, state: Arc<GfxState>, codecs: Codecs) -> Recorder {
    let out = std::env::var_os("ESCALE_GFX_CAPTURE")
        .and_then(|p| std::fs::File::create(p).ok())
        .map(std::io::BufWriter::new);
    Recorder { inner: client(frame, events, state, codecs), out }
}

pub struct Recorder {
    inner: GraphicsPipelineClient,
    out: Option<std::io::BufWriter<std::fs::File>>,
}

ironrdp_core::impl_as_any!(Recorder);

impl ironrdp_dvc::DvcProcessor for Recorder {
    fn channel_name(&self) -> &str {
        self.inner.channel_name()
    }

    fn start(&mut self, channel_id: u32) -> ironrdp_pdu::PduResult<Vec<ironrdp_dvc::DvcMessage>> {
        self.inner.start(channel_id)
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> ironrdp_pdu::PduResult<Vec<ironrdp_dvc::DvcMessage>> {
        if let Some(out) = &mut self.out {
            use std::io::Write;
            let _ = out.write_all(&(payload.len() as u32).to_le_bytes()).and_then(|_| out.write_all(payload)).and_then(|_| out.flush());
        }
        self.inner.process(channel_id, payload)
    }

    fn close(&mut self, channel_id: u32) {
        self.inner.close(channel_id)
    }
}

impl ironrdp_dvc::DvcClientProcessor for Recorder {}

struct Surface {
    width: usize,
    height: usize,
    pixels: Vec<Color32>,
    /// Position dans l'écran si la surface est affichée.
    origin: Option<(usize, usize)>,
}

struct CacheEntry {
    width: usize,
    height: usize,
    pixels: Vec<Color32>,
}

/// Diagnostic : erreurs de décodage affichées si `ESCALE_GFX_DEBUG` est défini.
fn debug(msg: std::fmt::Arguments<'_>) {
    if std::env::var_os("ESCALE_GFX_DEBUG").is_some() {
        eprintln!("gfx : {msg}");
    }
}

/// Rectangle borné à une surface : (x, y, largeur, hauteur), vide si hors surface.
fn clip(r: &ExclusiveRectangle, w: usize, h: usize) -> Option<(usize, usize, usize, usize)> {
    let (x0, y0) = (r.left as usize, r.top as usize);
    let (x1, y1) = ((r.right as usize).min(w), (r.bottom as usize).min(h));
    (x0 < x1 && y0 < y1).then(|| (x0, y0, x1 - x0, y1 - y0))
}

/// Recopie de pixels (4 octets chacun, `order` = indices R, G, B) en couleurs opaques.
fn convert(dst: &mut [Color32], src: &[u8], bpp: usize, order: [usize; 3]) {
    for (px, p) in dst.iter_mut().zip(src.chunks_exact(bpp)) {
        *px = Color32::from_rgb(p[order[0]], p[order[1]], p[order[2]]);
    }
}

pub(crate) struct Compositor {
    frame: SharedFrame,
    events: Events,
    state: Arc<GfxState>,
    surfaces: HashMap<u16, Surface>,
    cache: HashMap<u16, CacheEntry>,
    /// Pixels en cache (plafonnés).
    cached: usize,
    progressive: ProgressiveDecoder,
    clear: ClearDecoder,
    planar: BitmapStreamDecoder,
    scratch: Vec<u8>,
    codecs: Codecs,
    /// Décodage H.264 (AVC420 et AVC444), absent sans OpenH264 ou en mode RemoteFX.
    avc: Option<Avc>,
}

impl Compositor {
    pub(crate) fn new(frame: SharedFrame, events: Events, state: Arc<GfxState>) -> Self {
        Self {
            frame,
            events,
            state,
            surfaces: HashMap::new(),
            cache: HashMap::new(),
            cached: 0,
            progressive: ProgressiveDecoder::new(),
            clear: ClearDecoder::new(),
            planar: BitmapStreamDecoder::default(),
            scratch: Vec::new(),
            codecs: Codecs::NoAvc,
            avc: None,
        }
    }

    /// Compositeur pour les codecs demandés : le mode AVC retenu dépend de la disponibilité
    /// d'OpenH264 (repli sur RemoteFX / ClearCodec / Planar sinon).
    pub(crate) fn with_codecs(frame: SharedFrame, events: Events, state: Arc<GfxState>, codecs: Codecs) -> Self {
        let mut c = Self::new(frame, events, state);
        c.avc = (codecs != Codecs::NoAvc && Avc::available()).then(Avc::default);
        c.codecs = if c.avc.is_some() { codecs } else { Codecs::NoAvc };
        c
    }

    /// Écrit un bloc de pixels (4 octets chacun, `order` = indices R, G, B) dans une surface puis
    /// recopie la zone à l'écran.
    #[allow(clippy::too_many_arguments)]
    fn write(&mut self, surface_id: u16, x: usize, y: usize, w: usize, h: usize, data: &[u8], bpp: usize, order: [usize; 3]) {
        let Some(s) = self.surfaces.get_mut(&surface_id) else { return };
        let (cw, ch) = (w.min(s.width.saturating_sub(x)), h.min(s.height.saturating_sub(y)));
        if cw == 0 || ch == 0 || data.len() < w * h * bpp {
            return;
        }
        for row in 0..ch {
            let dst = &mut s.pixels[(y + row) * s.width + x..][..cw];
            convert(dst, &data[row * w * bpp..][..cw * bpp], bpp, order);
        }
        self.present(surface_id, x, y, cw, ch);
    }

    /// Écrit dans la surface la partie `sub` (coordonnées de surface) d'un bloc de pixels posé en
    /// (`x`, `y`) et large de `w` pixels.
    #[allow(clippy::too_many_arguments)]
    fn write_part(&mut self, surface_id: u16, x: usize, y: usize, w: usize, h: usize, data: &[u8], bpp: usize, order: [usize; 3], sub: (usize, usize, usize, usize)) {
        // intersection du bloc et de la zone
        let (sx0, sy0) = (sub.0.max(x), sub.1.max(y));
        let (sx1, sy1) = ((sub.0 + sub.2).min(x + w), (sub.1 + sub.3).min(y + h));
        if sx0 >= sx1 || sy0 >= sy1 || data.len() < w * h * bpp {
            return;
        }
        let Some(s) = self.surfaces.get_mut(&surface_id) else { return };
        let (sx1, sy1) = (sx1.min(s.width), sy1.min(s.height));
        if sx0 >= sx1 || sy0 >= sy1 {
            return;
        }
        for sy in sy0..sy1 {
            let src = &data[((sy - y) * w + (sx0 - x)) * bpp..][..(sx1 - sx0) * bpp];
            convert(&mut s.pixels[sy * s.width + sx0..sy * s.width + sx1], src, bpp, order);
        }
        self.present(surface_id, sx0, sy0, sx1 - sx0, sy1 - sy0);
    }

    /// Contenu actuel d'une zone de surface, en BGRA (noir hors de la surface).
    fn read_bgra(&self, surface_id: u16, x: usize, y: usize, w: usize, h: usize, out: &mut Vec<u8>) {
        out.clear();
        out.resize(w * h * 4, 0);
        let Some(s) = self.surfaces.get(&surface_id) else { return };
        let cw = w.min(s.width.saturating_sub(x));
        for row in 0..h.min(s.height.saturating_sub(y)) {
            let src = &s.pixels[(y + row) * s.width + x..][..cw];
            for (o, c) in out[row * w * 4..][..cw * 4].as_chunks_mut::<4>().0.iter_mut().zip(src) {
                o.copy_from_slice(&[c.b(), c.g(), c.r(), 0xFF]);
            }
        }
    }

    /// Recopie une zone d'une surface affichée vers l'image de l'écran.
    fn present(&self, surface_id: u16, x: usize, y: usize, w: usize, h: usize) {
        let Some(s) = self.surfaces.get(&surface_id) else { return };
        let Some((ox, oy)) = s.origin else { return };
        let Ok(mut f) = self.frame.lock() else { return };
        let (fw, fh) = (f.width, f.height);
        let (dx, dy) = (ox + x, oy + y);
        if dx >= fw || dy >= fh {
            return;
        }
        let (cw, ch) = (w.min(fw - dx), h.min(fh - dy));
        for row in 0..ch {
            let src = &s.pixels[(y + row) * s.width + x..][..cw];
            f.pixels[(dy + row) * fw + dx..][..cw].copy_from_slice(src);
        }
        f.mark(dx, dy, dx + cw, dy + ch);
    }

    fn present_all(&self, surface_id: u16) {
        if let Some(s) = self.surfaces.get(&surface_id) {
            self.present(surface_id, 0, 0, s.width, s.height);
        }
    }

    fn wire_to_surface1(&mut self, surface_id: u16, codec: Codec1Type, rect: &ExclusiveRectangle, data: &[u8]) {
        let (x, y) = (rect.left as usize, rect.top as usize);
        let (w, h) = (rect.right.saturating_sub(rect.left) as usize, rect.bottom.saturating_sub(rect.top) as usize);
        let Some(s) = self.surfaces.get(&surface_id) else { return };
        let (sw, sh) = (s.width, s.height);
        if w == 0 || h == 0 {
            return;
        }
        if matches!(codec, Codec1Type::Avc420 | Codec1Type::Avc444 | Codec1Type::Avc444v2) {
            let Some(mut avc) = self.avc.take() else { return };
            // seule la partie de l'image décodée qui tombe dans la surface est utile
            let dest = (x, y, w.min(sw.saturating_sub(x)), h.min(sh.saturating_sub(y)));
            avc.process(surface_id, codec, data, dest, &mut |rx, ry, rw, rh, rgba| {
                self.write(surface_id, x + rx, y + ry, rw, rh, rgba, 4, [0, 1, 2]);
            });
            self.avc = Some(avc);
            return;
        }
        // les autres codecs décodent toute la zone : elle doit tenir dans la surface (comme
        // FreeRDP), sinon un rectangle de 65535×65535 ferait allouer 17 Go
        if x + w > sw || y + h > sh {
            debug(format_args!("{codec:?} hors de la surface {surface_id} ({x},{y} {w}×{h})"));
            return;
        }
        match codec {
            Codec1Type::ClearCodec => {
                // ClearCodec peint par-dessus le contenu existant de la zone
                let mut buf = std::mem::take(&mut self.scratch);
                self.read_bgra(surface_id, x, y, w, h, &mut buf);
                match self.clear.decode(data, w, h, &mut buf) {
                    Ok(()) => self.write(surface_id, x, y, w, h, &buf, 4, [2, 1, 0]),
                    Err(e) => debug(format_args!("{e} ({x},{y} {w}×{h})")),
                }
                self.scratch = buf;
            }
            Codec1Type::Planar => {
                let mut buf = std::mem::take(&mut self.scratch);
                match decode_planar(&mut self.planar, data, w, h, &mut buf) {
                    Ok(order) => self.write(surface_id, x, y, w, h, &buf, 3, order),
                    Err(e) => debug(format_args!("Planar : {e} ({x},{y} {w}×{h})")),
                }
                self.scratch = buf;
            }
            // canal alpha : surfaces ARGB, la transparence n'est pas affichée (FreeRDP ne
            // l'applique qu'à l'octet alpha, sans effet sur les couleurs)
            Codec1Type::Alpha => {}
            // codecs non annoncés (RemoteFX CAVIDEO n'est permis qu'en version 8) : signalés,
            // car la zone resterait sinon figée sans explication
            _ => debug(format_args!("codec {codec:?} non pris en charge ({x},{y} {w}×{h})")),
        }
    }
}

/// Décode un flux Planar (RDP6_BITMAP_STREAM, MS-RDPEGDI 2.2.2.5.1) en RGB 24 bits ; renvoie
/// l'ordre des composantes R, G, B du résultat. Deux écarts du décodeur d'IronRDP avec FreeRDP :
/// - en YCoCg avec plan alpha, FreeRDP (YCoCgToRGB_8u_AC4R) inverse R et B comme sans alpha,
///   IronRDP non (rouge et bleu échangés) ;
/// - sans RLE, l'octet de bourrage final est facultatif pour FreeRDP, obligatoire pour IronRDP
///   (qui retire sinon le dernier octet utile et refuse l'image).
fn decode_planar(dec: &mut BitmapStreamDecoder, data: &[u8], w: usize, h: usize, out: &mut Vec<u8>) -> Result<[usize; 3], String> {
    let &header = data.first().ok_or("flux vide")?;
    let (cll, cs, rle, alpha) = (header & 0x07, header & 0x08 != 0, header & 0x10 != 0, header & 0x20 == 0);
    out.clear();
    let mut padded = Vec::new();
    let mut data = data;
    if !rle {
        let chroma = if cs { w.div_ceil(2) * h.div_ceil(2) } else { w * h };
        let planes = w * h + 2 * chroma + if alpha { w * h } else { 0 };
        if data.len() == 1 + planes {
            padded.reserve(data.len() + 1);
            padded.extend_from_slice(data);
            padded.push(0);
            data = &padded;
        }
    }
    dec.decode_bitmap_stream_to_rgb24(data, out, w, h).map_err(|e| e.to_string())?;
    if out.len() < w * h * 3 {
        return Err("image incomplète".into());
    }
    Ok(if cll != 0 && alpha { [2, 1, 0] } else { [0, 1, 2] })
}

/// Plans YUV 4:2:0 d'une image H.264 décodée (chrominance à demi-résolution).
struct Yuv420 {
    w: usize,
    h: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

impl Yuv420 {
    fn cw(&self) -> usize {
        self.w.div_ceil(2)
    }

    /// Chrominance 4:2:0 étendue au pixel (x, y).
    fn uv(&self, x: usize, y: usize) -> (u8, u8) {
        let i = (y / 2) * self.cw() + x / 2;
        (self.u.get(i).copied().unwrap_or(128), self.v.get(i).copied().unwrap_or(128))
    }

    /// Chrominance 4:4:4 d'un pixel hors position paire / paire, lue dans une vue auxiliaire
    /// (MS-RDPEGFX 3.3.8.3.2 pour AVC444, 3.3.8.3.3 pour AVC444v2).
    fn aux_uv(&self, v2: bool, x: usize, y: usize) -> Option<(u8, u8)> {
        let (w, cw) = (self.w, self.cw());
        if !v2 {
            if y % 2 == 1 {
                // lignes impaires : par blocs de 16 lignes, 8 de U puis 8 de V
                let k = y / 2;
                let row = k / 8 * 16 + k % 8;
                Some((*self.y.get(row * w + x)?, *self.y.get((row + 8) * w + x)?))
            } else {
                let i = (y / 2) * cw + x / 2;
                Some((*self.u.get(i)?, *self.v.get(i)?))
            }
        } else if x % 2 == 1 {
            // colonnes impaires : U à gauche, V à droite du plan de luminance auxiliaire
            Some((*self.y.get(y * w + x / 2)?, *self.y.get(y * w + w / 2 + x / 2)?))
        } else {
            // colonnes paires des lignes impaires : 4k dans le plan U, 4k + 2 dans le plan V
            let i = (y / 2) * cw + x / 4;
            let plane = if x.is_multiple_of(4) { &self.u } else { &self.v };
            Some((*plane.get(i)?, *plane.get(i + w / 4)?))
        }
    }
}

/// Flux H.264 d'une surface. Chaque surface a le sien (comme dans FreeRDP) : un décodeur commun
/// mélangerait les images de références de plusieurs écrans.
struct AvcStream {
    main: openh264::decoder::Decoder,
    /// Décodeur propre à la vue auxiliaire AVC444, si le serveur en fait un flux séparé (il
    /// commence alors par une image IDR) ; sinon les deux vues se suivent dans le même flux.
    aux: Option<openh264::decoder::Decoder>,
    /// Modèle de flux, déterminé à la première vue auxiliaire.
    separate: Option<bool>,
    /// Dernière vue principale (mises à jour « chrominance seule »).
    last_main: Option<Yuv420>,
}

/// Réception d'une zone décodée : x, y, largeur, hauteur, pixels RGBA.
type Deliver<'a> = dyn FnMut(usize, usize, usize, usize, &[u8]) + 'a;

/// Décodage H.264 (AVC420, AVC444 et AVC444v2) de toutes les surfaces.
#[derive(Default)]
struct Avc {
    streams: HashMap<u16, AvcStream>,
    annexb: Vec<u8>,
    rgba: Vec<u8>,
}

/// Données H.264 en Annex B pour OpenH264 ; indique si une IDR / SPS est présente. Windows envoie de
/// l'Annex B (codes de début, comme le lit FreeRDP) ; IronRDP serveur des unités NAL préfixées par
/// leur longueur sur 4 octets : les deux formes sont acceptées.
fn annex_b(data: &[u8], out: &mut Vec<u8>) -> bool {
    out.clear();
    // préfixes de longueur : valides seulement s'ils couvrent exactement les données
    let mut i = 0;
    let mut chained = !data.is_empty();
    while i < data.len() {
        let Some(n) = data.get(i..i + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) else {
            chained = false;
            break;
        };
        if n == 0 || n > data.len() - i - 4 {
            chained = false;
            break;
        }
        i += 4 + n;
    }
    let mut idr = false;
    if chained {
        let mut i = 0;
        while i < data.len() {
            let n = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
            let nal = &data[i + 4..i + 4 + n];
            idr |= matches!(nal[0] & 0x1F, 5 | 7);
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(nal);
            i += 4 + n;
        }
    } else {
        out.extend_from_slice(data);
        // type de chaque unité NAL : l'octet qui suit un code de début 00 00 01
        idr = data.windows(4).any(|w| w[..3] == [0, 0, 1] && matches!(w[3] & 0x1F, 5 | 7));
    }
    idr
}

/// Décode une image ; renvoie ses plans YUV si le décodeur en produit une.
fn decode_yuv(dec: &mut openh264::decoder::Decoder, annexb: &[u8]) -> Option<Yuv420> {
    use openh264::formats::YUVSource as _;
    let yuv = match dec.decode(annexb) {
        Ok(Some(y)) => y,
        Ok(None) => return None,
        Err(e) => {
            debug(format_args!("H.264 : {e}"));
            return None;
        }
    };
    let (w, h) = yuv.dimensions();
    let (sy, su, sv) = yuv.strides();
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    let copy = |src: &[u8], stride: usize, pw: usize, ph: usize| -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(pw * ph);
        for r in 0..ph {
            out.extend_from_slice(src.get(r * stride..r * stride + pw)?);
        }
        Some(out)
    };
    Some(Yuv420 { w, h, y: copy(yuv.y(), sy, w, h)?, u: copy(yuv.u(), su, cw, ch)?, v: copy(yuv.v(), sv, cw, ch)? })
}

impl Avc {
    /// OpenH264 utilisable (le repli se fait sinon sans H.264).
    fn available() -> bool {
        openh264::decoder::Decoder::new().is_ok()
    }

    fn reset(&mut self) {
        self.streams.clear();
    }

    fn remove(&mut self, surface_id: u16) {
        self.streams.remove(&surface_id);
    }

    /// Décode un RFX_AVC420_BITMAP_STREAM ou RFX_AVC444_BITMAP_STREAM posé en `dest` (x, y,
    /// largeur, hauteur utiles, coordonnées de surface) et livre les zones mises à jour en RGBA,
    /// en coordonnées relatives à `dest`. Les rectangles des méta-blocs sont en coordonnées de
    /// surface (comme FreeRDP) ; seuls les pixels réellement décodés sont livrés.
    fn process(&mut self, surface_id: u16, codec: Codec1Type, data: &[u8], dest: (usize, usize, usize, usize), out: &mut Deliver<'_>) {
        use ironrdp_core::Decode as _;
        let mut cur = ironrdp_core::ReadCursor::new(data);
        // LC : deux vues, vue principale seule, ou vue auxiliaire seule (dans le premier flux)
        let (v2, luma, chroma) = if codec == Codec1Type::Avc420 {
            match Avc420BitmapStream::decode(&mut cur) {
                Ok(s) => (false, Some(s), None),
                Err(e) => return debug(format_args!("AVC420 : {e}")),
            }
        } else {
            match Avc444BitmapStream::decode(&mut cur) {
                Ok(s) if s.encoding == Encoding::LUMA => (codec == Codec1Type::Avc444v2, Some(s.stream1), None),
                Ok(s) if s.encoding == Encoding::CHROMA => (codec == Codec1Type::Avc444v2, None, Some(s.stream1)),
                Ok(s) => (codec == Codec1Type::Avc444v2, Some(s.stream1), s.stream2),
                Err(e) => return debug(format_args!("AVC444 : {e}")),
            }
        };
        let Self { streams, annexb, rgba } = self;
        let stream = match streams.entry(surface_id) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => match openh264::decoder::Decoder::new() {
                Ok(main) => e.insert(AvcStream { main, aux: None, separate: None, last_main: None }),
                Err(err) => return debug(format_args!("H.264 : {err}")),
            },
        };
        if let Some(l) = &luma {
            annex_b(l.data, annexb);
            match decode_yuv(&mut stream.main, annexb) {
                Some(m) => stream.last_main = Some(m),
                None => return,
            }
        }
        let aux = chroma.as_ref().and_then(|c| {
            let idr = annex_b(c.data, annexb);
            let dec = if *stream.separate.get_or_insert(idr) {
                if stream.aux.is_none() {
                    stream.aux = openh264::decoder::Decoder::new().ok();
                }
                stream.aux.as_mut()?
            } else {
                &mut stream.main
            };
            decode_yuv(dec, annexb)
        });
        let Some(main) = &stream.last_main else { return };
        let (dx, dy, dw, dh) = dest;
        let (fw, fh) = (dw.min(main.w), dh.min(main.h));
        let rects = |s: &Avc420BitmapStream<'_>| -> Vec<(usize, usize, usize, usize)> {
            // RDPGFX_RECT16 : droite / bas exclus ; ramenés à l'image décodée
            s.rectangles
                .iter()
                .map(|r| {
                    let x0 = (r.left as usize).max(dx) - dx;
                    let y0 = (r.top as usize).max(dy) - dy;
                    (x0, y0, (r.right as usize).saturating_sub(dx).min(fw), (r.bottom as usize).saturating_sub(dy).min(fh))
                })
                .filter(|r| r.0 < r.2 && r.1 < r.3)
                .collect()
        };
        let mut draw = |r: (usize, usize, usize, usize), aux: Option<&Yuv420>| {
            to_rgba(main, aux, v2, r, rgba);
            out(r.0, r.1, r.2 - r.0, r.3 - r.1, rgba);
        };
        let luma_rects = luma.as_ref().map(rects).unwrap_or_default();
        let chroma_rects = chroma.as_ref().map(rects).unwrap_or_default();
        match &aux {
            // cas courant : mêmes zones pour les deux vues, une seule conversion
            Some(a) if luma.is_some() && luma_rects == chroma_rects => luma_rects.into_iter().for_each(|r| draw(r, Some(a))),
            Some(a) => {
                luma_rects.into_iter().for_each(|r| draw(r, None));
                chroma_rects.into_iter().for_each(|r| draw(r, Some(a)));
            }
            None => luma_rects.into_iter().for_each(|r| draw(r, None)),
        }
    }
}

/// Convertit la zone `r` (x0, y0, x1, y1 exclus) d'une image décodée en RGBA.
fn to_rgba(main: &Yuv420, aux: Option<&Yuv420>, v2: bool, r: (usize, usize, usize, usize), buf: &mut Vec<u8>) {
    buf.clear();
    buf.reserve((r.2 - r.0) * (r.3 - r.1) * 4);
    let cw = main.cw();
    for y in r.1..r.3 {
        let luma = &main.y[y * main.w..][r.0..r.2];
        match aux {
            // 4:2:0 : boucle directe, sans recherche de voisins
            None => {
                let (u, v) = (&main.u[(y / 2) * cw..], &main.v[(y / 2) * cw..]);
                for (x, &l) in (r.0..r.2).zip(luma) {
                    let [rr, g, b] = yuv_to_rgb(l, u[x / 2], v[x / 2]);
                    buf.extend_from_slice(&[rr, g, b, 255]);
                }
            }
            Some(a) => {
                for (x, &l) in (r.0..r.2).zip(luma) {
                    let (u, v) = chroma444(main, Some(a), v2, x, y);
                    let [rr, g, b] = yuv_to_rgb(l, u, v);
                    buf.extend_from_slice(&[rr, g, b, 255]);
                }
            }
        }
    }
}

/// Chrominance 4:4:4 d'un pixel. En position paire / paire, la vue principale porte la moyenne des
/// quatre pixels voisins : la valeur d'origine en est déduite (filtre de MS-RDPEGFX, appliqué
/// seulement quand l'écart est net, comme Windows et FreeRDP).
fn chroma444(main: &Yuv420, aux: Option<&Yuv420>, v2: bool, x: usize, y: usize) -> (u8, u8) {
    let avg = main.uv(x, y);
    let Some(a) = aux else { return avg };
    if x % 2 == 1 || y % 2 == 1 {
        return a.aux_uv(v2, x, y).unwrap_or(avg);
    }
    if x + 1 >= main.w || y + 1 >= main.h {
        return avg;
    }
    let (Some(p1), Some(p2), Some(p3)) = (a.aux_uv(v2, x + 1, y), a.aux_uv(v2, x, y + 1), a.aux_uv(v2, x + 1, y + 1)) else {
        return avg;
    };
    let rebuild = |m: u8, n1: u8, n2: u8, n3: u8| {
        let v = (4 * m as i32 - n1 as i32 - n2 as i32 - n3 as i32).clamp(0, 255) as u8;
        if v.abs_diff(m) < 30 { m } else { v }
    };
    (rebuild(avg.0, p1.0, p2.0, p3.0), rebuild(avg.1, p1.1, p2.1, p3.1))
}

/// YUV -> RGB pour le H.264 de RDPGFX : BT.709 pleine plage (MS-RDPEGFX 3.3.8.3.1), mêmes
/// coefficients (virgule fixe 8 bits) que FreeRDP. La conversion d'OpenH264 (BT.601, plage
/// limitée) écrasait les gris sombres et saturait les couleurs.
fn yuv_to_rgb(y: u8, u: u8, v: u8) -> [u8; 3] {
    let c = (y as i32) << 8;
    let (d, e) = (u as i32 - 128, v as i32 - 128);
    let clip = |x: i32| (x >> 8).clamp(0, 255) as u8;
    [clip(c + 403 * e), clip(c - 48 * d - 120 * e), clip(c + 475 * d)]
}

impl GraphicsPipelineHandler for Compositor {
    fn capabilities(&self) -> Vec<CapabilitySet> {
        // le serveur retient la version la plus récente qu'il connaît. Les 10.x sans AVC_DISABLED
        // impliquent AVC444 ; la mise à l'échelle côté serveur (10.7) est refusée.
        let off = self.codecs == Codecs::NoAvc;
        let mut caps = Vec::new();
        if self.codecs != Codecs::Avc420 {
            let (f10, f103, f104, f107) = if off {
                (
                    CapabilitiesV10Flags::AVC_DISABLED,
                    CapabilitiesV103Flags::AVC_DISABLED,
                    CapabilitiesV104Flags::AVC_DISABLED,
                    CapabilitiesV107Flags::AVC_DISABLED,
                )
            } else {
                (
                    CapabilitiesV10Flags::empty(),
                    CapabilitiesV103Flags::empty(),
                    CapabilitiesV104Flags::empty(),
                    CapabilitiesV107Flags::empty(),
                )
            };
            let f10 = f10 | CapabilitiesV10Flags::SMALL_CACHE;
            let f104 = f104 | CapabilitiesV104Flags::SMALL_CACHE;
            caps.extend([
                CapabilitySet::V10_7 { flags: f107 | CapabilitiesV107Flags::SMALL_CACHE | CapabilitiesV107Flags::SCALEDMAP_DISABLE },
                CapabilitySet::V10_6 { flags: f104 },
                CapabilitySet::V10_5 { flags: f104 },
                CapabilitySet::V10_4 { flags: f104 },
                CapabilitySet::V10_3 { flags: f103 },
                CapabilitySet::V10_2 { flags: f10 },
            ]);
            if !off {
                // 10.1 n'a pas d'indicateur AVC_DISABLED
                caps.push(CapabilitySet::V10_1);
            }
            caps.push(CapabilitySet::V10 { flags: f10 });
        }
        let v81 = if off { CapabilitiesV81Flags::empty() } else { CapabilitiesV81Flags::AVC420_ENABLED };
        caps.push(CapabilitySet::V8_1 { flags: v81 | CapabilitiesV81Flags::SMALL_CACHE });
        caps.push(CapabilitySet::V8 { flags: CapabilitiesV8Flags::SMALL_CACHE });
        caps
    }

    fn decodes_h264(&self) -> bool {
        self.avc.is_some()
    }

    fn on_capabilities_confirmed(&mut self, _caps: &CapabilitySet) {
        self.state.active.store(true, Ordering::Relaxed);
    }

    fn on_reset_graphics(&mut self, width: u32, height: u32) {
        self.surfaces.clear();
        self.progressive.reset();
        if let Some(a) = &mut self.avc {
            a.reset();
        }
        let (w, h) = (width as usize, height as usize);
        if w > MAX_SIDE || h > MAX_SIDE || w * h > MAX_SCREEN_PIXELS {
            debug(format_args!("écran {w}×{h} refusé"));
        } else if let Ok(mut f) = self.frame.lock() {
            f.resize(w, h);
        }
        self.events.repaint();
    }

    fn on_surface_created(&mut self, s: &GfxSurface) {
        let (w, h) = (s.width as usize, s.height as usize);
        // une surface recréée sous le même identifiant repart de zéro (pixels et flux H.264)
        self.surfaces.remove(&s.id);
        self.progressive.delete_context(s.id.into());
        if let Some(a) = &mut self.avc {
            a.remove(s.id);
        }
        let used: usize = self.surfaces.values().map(|s| s.width * s.height).sum();
        if w > MAX_SIDE || h > MAX_SIDE || used + w * h > MAX_SURFACE_PIXELS {
            debug(format_args!("surface {} de {w}×{h} refusée", s.id));
            return;
        }
        self.surfaces.insert(s.id, Surface { width: w, height: h, pixels: vec![Color32::BLACK; w * h], origin: None });
    }

    fn on_surface_deleted(&mut self, surface_id: u16) {
        self.surfaces.remove(&surface_id);
        self.progressive.delete_context(surface_id.into());
        if let Some(a) = &mut self.avc {
            a.remove(surface_id);
        }
    }

    fn on_surface_mapped(&mut self, surface_id: u16, x: u32, y: u32) {
        if let Some(s) = self.surfaces.get_mut(&surface_id) {
            s.origin = Some((x as usize, y as usize));
        }
        self.present_all(surface_id);
    }

    fn on_map_surface_to_scaled_output(&mut self, pdu: &MapSurfaceToScaledOutputPdu) {
        // mise à l'échelle côté serveur non reproduite : affichée à sa position, taille réelle
        self.on_surface_mapped(pdu.surface_id, pdu.output_origin_x, pdu.output_origin_y);
    }

    fn on_bitmap_updated(&mut self, u: &BitmapUpdate) {
        // non compressé (et H.264 décodé par IronRDP s'il en avait la charge), déjà en RGBA ;
        // seules les zones annoncées sont valides
        let r = &u.destination_rectangle;
        let (x, y, w, h) = (r.left as usize, r.top as usize, u.width as usize, u.height as usize);
        for z in &u.regions {
            let sub = (z.left as usize, z.top as usize, z.right.saturating_sub(z.left) as usize, z.bottom.saturating_sub(z.top) as usize);
            self.write_part(u.surface_id, x, y, w, h, &u.data, 4, [0, 1, 2], sub);
        }
    }

    fn on_wire_to_surface2(&mut self, pdu: &WireToSurface2Pdu) {
        // RemoteFX Progressive : tuiles de 64×64
        let Some(s) = self.surfaces.get(&pdu.surface_id) else { return };
        let (sw, sh) = (s.width as u16, s.height as u16);
        // zones mises à jour : les tuiles ne sont recopiées qu'à l'intérieur
        let regions: Vec<(usize, usize, usize, usize)> = match ironrdp_pdu::codecs::rfx::progressive::decode_progressive_stream(&pdu.bitmap_data) {
            Ok(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ironrdp_pdu::codecs::rfx::progressive::ProgressiveBlock::Region(r) => Some(r),
                    _ => None,
                })
                .flat_map(|r| r.rects.iter().map(|q| (q.x as usize, q.y as usize, q.width as usize, q.height as usize)))
                .collect(),
            Err(e) => {
                debug(format_args!("RemoteFX Progressive illisible (surface {}) : {e}", pdu.surface_id));
                return;
            }
        };
        // état des tuiles (coefficients, signes, positions de bit) gardé par surface, comme FreeRDP
        // (progressive_create_surface_context / progressive_decompress(…, surfaceId, …)) : les
        // passes d'amélioration s'appliquent aux tuiles de la surface quel que soit l'identifiant
        // de contexte de codec ; rangé par contexte, une amélioration envoyée sous un autre
        // identifiant que la première passe était ignorée et la tuile restait floue
        let tiles = match self.progressive.decode_bitmap(pdu.surface_id.into(), sw, sh, &pdu.bitmap_data) {
            Ok(t) => t,
            Err(e) => {
                debug(format_args!("RemoteFX Progressive : {e}"));
                return;
            }
        };
        for t in tiles {
            let (tx, ty) = (t.x_idx as usize * 64, t.y_idx as usize * 64);
            for z in &regions {
                self.write_part(pdu.surface_id, tx, ty, 64, 64, &t.pixels, 4, [0, 1, 2], *z);
            }
        }
    }

    fn on_delete_encoding_context(&mut self, pdu: &DeleteEncodingContextPdu) {
        // ignoré, comme FreeRDP (gdi_DeleteEncodingContext) : l'état progressif appartient à la
        // surface et disparaît avec elle
        debug(format_args!("fin du contexte de codec {} (surface {})", pdu.codec_context_id, pdu.surface_id));
    }

    fn on_solid_fill(&mut self, pdu: &SolidFillPdu) {
        let Some(s) = self.surfaces.get_mut(&pdu.surface_id) else { return };
        let c = Color32::from_rgb(pdu.fill_pixel.r, pdu.fill_pixel.g, pdu.fill_pixel.b);
        let (sw, sh) = (s.width, s.height);
        let mut done = Vec::new();
        for r in &pdu.rectangles {
            if let Some((x, y, w, h)) = clip(r, sw, sh) {
                for row in y..y + h {
                    s.pixels[row * sw + x..][..w].fill(c);
                }
                done.push((x, y, w, h));
            }
        }
        for (x, y, w, h) in done {
            self.present(pdu.surface_id, x, y, w, h);
        }
    }

    fn on_surface_to_surface(&mut self, pdu: &SurfaceToSurfacePdu) {
        let Some(src) = self.surfaces.get(&pdu.source_surface_id) else { return };
        let Some((x, y, w, h)) = clip(&pdu.source_rectangle, src.width, src.height) else { return };
        // copie intermédiaire : source et destination peuvent être la même surface et se chevaucher
        let block: Vec<Color32> = (y..y + h).flat_map(|row| src.pixels[row * src.width + x..][..w].iter().copied()).collect();
        for p in &pdu.destination_points {
            let (dx, dy) = (p.x as usize, p.y as usize);
            if let Some(dst) = self.surfaces.get_mut(&pdu.destination_surface_id) {
                let (cw, ch) = (w.min(dst.width.saturating_sub(dx)), h.min(dst.height.saturating_sub(dy)));
                if cw == 0 || ch == 0 {
                    continue;
                }
                for row in 0..ch {
                    dst.pixels[(dy + row) * dst.width + dx..][..cw].copy_from_slice(&block[row * w..row * w + cw]);
                }
                self.present(pdu.destination_surface_id, dx, dy, cw, ch);
            }
        }
    }

    fn on_surface_to_cache(&mut self, pdu: &SurfaceToCachePdu) {
        let Some(s) = self.surfaces.get(&pdu.surface_id) else { return };
        let Some((x, y, w, h)) = clip(&pdu.source_rectangle, s.width, s.height) else { return };
        let freed = self.cache.get(&pdu.cache_slot).map_or(0, |c| c.pixels.len());
        if self.cached - freed + w * h > MAX_CACHE_PIXELS {
            // l'ancien contenu de l'emplacement est périmé : le garder ferait recopier une
            // ancienne image (cases fausses) au prochain CacheToSurface
            debug(format_args!("cache plein : emplacement {} refusé", pdu.cache_slot));
            if self.cache.remove(&pdu.cache_slot).is_some() {
                self.cached -= freed;
            }
            return;
        }
        let pixels: Vec<Color32> = (y..y + h).flat_map(|row| s.pixels[row * s.width + x..][..w].iter().copied()).collect();
        self.cached = self.cached - freed + pixels.len();
        self.cache.insert(pdu.cache_slot, CacheEntry { width: w, height: h, pixels });
    }

    fn on_cache_to_surface(&mut self, pdu: &CacheToSurfacePdu) {
        let Some(c) = self.cache.get(&pdu.cache_slot) else { return };
        let Some(dst) = self.surfaces.get_mut(&pdu.surface_id) else { return };
        let mut done = Vec::new();
        for p in &pdu.destination_points {
            let (dx, dy) = (p.x as usize, p.y as usize);
            let (cw, ch) = (c.width.min(dst.width.saturating_sub(dx)), c.height.min(dst.height.saturating_sub(dy)));
            // point hors de la surface : rien à copier (et pas de tranche hors limites)
            if cw == 0 || ch == 0 {
                continue;
            }
            for row in 0..ch {
                dst.pixels[(dy + row) * dst.width + dx..][..cw].copy_from_slice(&c.pixels[row * c.width..row * c.width + cw]);
            }
            done.push((dx, dy, cw, ch));
        }
        for (x, y, w, h) in done {
            self.present(pdu.surface_id, x, y, w, h);
        }
    }

    fn on_evict_cache_entry(&mut self, pdu: &EvictCacheEntryPdu) {
        if let Some(c) = self.cache.remove(&pdu.cache_slot) {
            self.cached -= c.pixels.len();
        }
    }

    fn on_unhandled_pdu(&mut self, pdu: &GfxPdu) {
        if let GfxPdu::WireToSurface1(w) = pdu {
            let rect = w.destination_rectangle.clone();
            self.wire_to_surface1(w.surface_id, w.codec_id, &rect, &w.bitmap_data);
        }
    }

    fn on_frame_complete(&mut self, _frame_id: u32) {
        // une image complète : un seul rafraîchissement de l'interface
        self.events.repaint();
    }

    fn on_close(&mut self) {
        self.state.active.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::Frame;
    use ironrdp_egfx::pdu::{Color, Point, annex_b_to_avc};
    use std::sync::Mutex;

    fn compositor() -> (Compositor, SharedFrame) {
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        (Compositor::new(frame.clone(), events, Default::default()), frame)
    }

    fn rect(l: u16, t: u16, r: u16, b: u16) -> ExclusiveRectangle {
        ExclusiveRectangle { left: l, top: t, right: r, bottom: b }
    }

    fn surface(c: &mut Compositor, id: u16, w: usize, h: usize) {
        c.surfaces.insert(id, Surface { width: w, height: h, pixels: vec![Color32::BLACK; w * h], origin: None });
    }

    #[test]
    fn surfaces_fills_copies_and_cache_reach_the_screen() {
        let (mut c, frame) = compositor();
        c.on_reset_graphics(20, 10);
        surface(&mut c, 1, 20, 10);
        c.on_surface_mapped(1, 0, 0);
        let red = || Color { b: 0, g: 0, r: 255, xa: 0 };
        c.on_solid_fill(&SolidFillPdu { surface_id: 1, fill_pixel: red(), rectangles: vec![rect(0, 0, 4, 4)] });
        // copie dans la même surface, puis via le cache
        c.on_surface_to_surface(&SurfaceToSurfacePdu {
            source_surface_id: 1,
            destination_surface_id: 1,
            source_rectangle: rect(0, 0, 4, 4),
            destination_points: vec![Point { x: 8, y: 2 }],
        });
        c.on_surface_to_cache(&SurfaceToCachePdu { surface_id: 1, cache_key: 0, cache_slot: 3, source_rectangle: rect(0, 0, 2, 2) });
        c.on_cache_to_surface(&CacheToSurfacePdu { cache_slot: 3, surface_id: 1, destination_points: vec![Point { x: 18, y: 8 }] });
        let f = frame.lock().unwrap();
        let at = |x: usize, y: usize| f.pixels[y * 20 + x];
        assert_eq!((f.width, f.height), (20, 10));
        assert_eq!(at(1, 1), Color32::from_rgb(255, 0, 0));
        assert_eq!(at(9, 3), Color32::from_rgb(255, 0, 0));
        assert_eq!(at(19, 9), Color32::from_rgb(255, 0, 0));
        assert_eq!(at(5, 5), Color32::BLACK);
    }

    /// Planar YCoCg avec plan alpha (Y = 100, Co = 40, Cg = 0, sans perte de couleur) : FreeRDP
    /// donne R = Y − Co − Cg = 60, B = Y + Co − Cg = 140, comme sans alpha.
    #[test]
    fn planar_ycocg_with_alpha_keeps_red_and_blue() {
        let (mut c, frame) = compositor();
        c.on_reset_graphics(2, 2);
        surface(&mut c, 1, 2, 2);
        c.on_surface_mapped(1, 0, 0);
        let alpha = [0x01u8, 255, 255, 100, 100, 40, 40, 0, 0, 0];
        c.wire_to_surface1(1, Codec1Type::Planar, &rect(0, 0, 2, 1), &alpha);
        // même couleur sans alpha (NA) : IronRDP inversait déjà R et B dans ce cas
        let no_alpha = [0x21u8, 100, 100, 40, 40, 0, 0, 0];
        c.wire_to_surface1(1, Codec1Type::Planar, &rect(0, 1, 2, 2), &no_alpha);
        let f = frame.lock().unwrap();
        assert_eq!(f.pixels[0], Color32::from_rgb(60, 100, 140));
        assert_eq!(f.pixels[2], Color32::from_rgb(60, 100, 140));
    }

    /// Planar non compressé sans l'octet de bourrage final (facultatif pour FreeRDP).
    #[test]
    fn planar_raw_without_padding_is_decoded() {
        let (mut c, frame) = compositor();
        c.on_reset_graphics(2, 1);
        surface(&mut c, 1, 2, 1);
        c.on_surface_mapped(1, 0, 0);
        c.wire_to_surface1(1, Codec1Type::Planar, &rect(0, 0, 2, 1), &[0x20, 10, 10, 20, 20, 30, 30]);
        assert_eq!(frame.lock().unwrap().pixels[1], Color32::from_rgb(10, 20, 30));
    }

    /// Un SurfaceToCache refusé (cache plein) vide l'emplacement : son ancien contenu ne doit
    /// plus être recopié.
    #[test]
    fn refused_surface_to_cache_does_not_replay_the_old_entry() {
        let (mut c, frame) = compositor();
        c.on_reset_graphics(4, 4);
        surface(&mut c, 1, 4, 4);
        c.on_surface_mapped(1, 0, 0);
        let red = Color { b: 0, g: 0, r: 255, xa: 0 };
        c.on_solid_fill(&SolidFillPdu { surface_id: 1, fill_pixel: red, rectangles: vec![rect(0, 0, 1, 1)] });
        c.on_surface_to_cache(&SurfaceToCachePdu { surface_id: 1, cache_key: 0, cache_slot: 2, source_rectangle: rect(0, 0, 1, 1) });
        c.cached = MAX_CACHE_PIXELS;
        c.on_surface_to_cache(&SurfaceToCachePdu { surface_id: 1, cache_key: 0, cache_slot: 2, source_rectangle: rect(1, 1, 4, 4) });
        c.on_cache_to_surface(&CacheToSurfacePdu { cache_slot: 2, surface_id: 1, destination_points: vec![Point { x: 3, y: 3 }] });
        assert_eq!(frame.lock().unwrap().pixels[15], Color32::BLACK);
        assert_eq!(c.cached, MAX_CACHE_PIXELS - 1);
    }

    /// SurfaceToSurface dans la même surface, zones qui se chevauchent (défilement, sélection) et
    /// destinations multiples : la source est lue avant toute écriture.
    #[test]
    fn overlapping_surface_to_surface_reads_the_source_first() {
        let (mut c, frame) = compositor();
        c.on_reset_graphics(8, 1);
        surface(&mut c, 1, 8, 1);
        c.on_surface_mapped(1, 0, 0);
        for x in 0..4u8 {
            let col = Color { b: 0, g: 0, r: 10 * (x + 1), xa: 0 };
            c.on_solid_fill(&SolidFillPdu { surface_id: 1, fill_pixel: col, rectangles: vec![rect(x as u16, 0, x as u16 + 1, 1)] });
        }
        c.on_surface_to_surface(&SurfaceToSurfacePdu {
            source_surface_id: 1,
            destination_surface_id: 1,
            source_rectangle: rect(0, 0, 4, 1),
            destination_points: vec![Point { x: 1, y: 0 }, Point { x: 4, y: 0 }],
        });
        let reds: Vec<u8> = frame.lock().unwrap().pixels.iter().map(|p| p.r()).collect();
        assert_eq!(reds, [10, 10, 20, 30, 10, 20, 30, 40]);
    }

    #[test]
    fn decoded_bitmaps_are_composited_at_the_surface_origin() {
        let (mut c, frame) = compositor();
        c.on_reset_graphics(16, 16);
        surface(&mut c, 7, 8, 8);
        c.on_surface_mapped(7, 4, 4);
        // RGBA 2×2 vert (comme une image H.264 décodée)
        let data = [0u8, 255, 0, 255].repeat(4);
        c.write(7, 1, 1, 2, 2, &data, 4, [0, 1, 2]);
        // BGRA bleu (ClearCodec)
        c.write(7, 0, 0, 1, 1, &[255, 0, 0, 255], 4, [2, 1, 0]);
        let f = frame.lock().unwrap();
        assert_eq!(f.pixels[5 * 16 + 5], Color32::from_rgb(0, 255, 0));
        assert_eq!(f.pixels[4 * 16 + 4], Color32::from_rgb(0, 0, 255));
        assert_eq!(f.pixels[0], Color32::BLACK);
        // écriture hors surface : bornée, sans panique
        drop(f);
        c.write(7, 7, 7, 4, 4, &[0u8; 64], 4, [0, 1, 2]);
        c.write(99, 0, 0, 1, 1, &[0u8; 4], 4, [0, 1, 2]);
    }

    /// Commandes GFX encodées puis enveloppées en ZGFX, comme sur le canal.
    fn wire(pdus: Vec<GfxPdu>) -> Vec<u8> {
        let mut raw = Vec::new();
        for p in &pdus {
            raw.extend(ironrdp_core::encode_vec(p).unwrap());
        }
        ironrdp_graphics::zgfx::wrap_uncompressed(&raw)
    }

    #[test]
    fn pipeline_client_decodes_h264_and_keeps_acknowledging() {
        use ironrdp_dvc::DvcProcessor as _;
        use ironrdp_egfx::pdu::*;
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        let state: Arc<GfxState> = Default::default();
        let mut client = client(frame.clone(), events, state.clone(), Codecs::Avc420);
        assert!(!client.start(1).unwrap().is_empty(), "capacités annoncées");

        client
            .process(
                1,
                &wire(vec![
                    GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V8_1 {
                        flags: CapabilitiesV81Flags::AVC420_ENABLED,
                    })),
                    GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 128, height: 64, monitors: vec![] }),
                    GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 1, width: 128, height: 64, pixel_format: PixelFormat::XRgb }),
                    GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 1, output_origin_x: 0, output_origin_y: 0 }),
                ]),
            )
            .unwrap();
        assert!(state.active());

        // image verte 64×64 réellement encodée en H.264
        let yuv = openh264::formats::YUVBuffer::from_vec(solid_i420(64, 64, [0, 220, 0]), 64, 64);
        let mut enc = openh264::encoder::Encoder::new().unwrap();
        let annex_b = enc.encode(&yuv).unwrap().to_vec();
        // une seule zone valide (moitié gauche, bords exclusifs comme Windows) : le reste de l'image
        // décodée ne doit pas être recopié
        let avc = encode_avc420_bitmap_stream(&[Avc420Region::new(0, 0, 32, 64, 22, 100)], &annex_b_to_avc(&annex_b));

        let ts = Timestamp { milliseconds: 0, seconds: 0, minutes: 0, hours: 0 };
        let r = |l, t, rr, b| ExclusiveRectangle { left: l, top: t, right: rr, bottom: b };
        let out = client
            .process(
                1,
                &wire(vec![
                    GfxPdu::StartFrame(StartFramePdu { timestamp: ts, frame_id: 1 }),
                    GfxPdu::SolidFill(SolidFillPdu { surface_id: 1, fill_pixel: Color { b: 0, g: 0, r: 255, xa: 0 }, rectangles: vec![r(0, 0, 128, 64)] }),
                    // surface inexistante : la commande échoue, la suite doit passer quand même
                    GfxPdu::WireToSurface1(WireToSurface1Pdu {
                        surface_id: 9,
                        codec_id: Codec1Type::Uncompressed,
                        pixel_format: PixelFormat::XRgb,
                        destination_rectangle: r(0, 0, 1, 1),
                        bitmap_data: vec![0; 4],
                    }),
                    GfxPdu::WireToSurface1(WireToSurface1Pdu {
                        surface_id: 1,
                        codec_id: Codec1Type::Avc420,
                        pixel_format: PixelFormat::XRgb,
                        destination_rectangle: r(0, 0, 64, 64),
                        bitmap_data: avc,
                    }),
                    GfxPdu::EndFrame(EndFramePdu { frame_id: 1 }),
                ]),
            )
            .unwrap();
        assert_eq!(out.len(), 1, "accusé de réception de l'image envoyé");

        let f = frame.lock().unwrap();
        assert_eq!((f.width, f.height), (128, 64));
        let h264 = f.pixels[32 * 128 + 16];
        assert!(h264.g() > 180 && h264.r() < 60 && h264.b() < 60, "pixel H.264 vert : {h264:?}");
        assert_eq!(f.pixels[32 * 128 + 48], Color32::from_rgb(255, 0, 0), "hors zone annoncée : contenu précédent conservé");
        assert_eq!(f.pixels[32 * 128 + 100], Color32::from_rgb(255, 0, 0), "remplissage hors de l'image H.264");
    }

    /// Capacités annoncées (message CapabilitiesAdvertise) selon les codecs demandés.
    fn advertised(codecs: Codecs) -> Vec<CapabilitySet> {
        use ironrdp_dvc::DvcProcessor as _;
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        let mut c = client(frame, events, Default::default(), codecs);
        let msg = c.start(1).unwrap().pop().unwrap();
        let mut buf = vec![0; msg.size()];
        msg.encode(&mut ironrdp_core::WriteCursor::new(&mut buf)).unwrap();
        match ironrdp_core::decode::<GfxPdu>(&buf).unwrap() {
            GfxPdu::CapabilitiesAdvertise(p) => p.0.iter().map(|r| r.parsed().unwrap().unwrap()).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn capabilities_follow_the_graphics_mode() {
        let avc = |c: &CapabilitySet| {
            let s = format!("{c:?}");
            !s.contains("AVC_DISABLED") && (matches!(c, CapabilitySet::V10_1) || s.contains("V10") || s.contains("AVC420_ENABLED"))
        };
        // Auto : 10.7 (AVC444) en tête, AVC420 en repli
        let auto = advertised(Codecs::Avc444);
        assert!(matches!(auto[0], CapabilitySet::V10_7 { flags } if !flags.contains(CapabilitiesV107Flags::AVC_DISABLED)), "{auto:?}");
        assert!(auto.iter().any(|c| matches!(c, CapabilitySet::V8_1 { flags } if flags.contains(CapabilitiesV81Flags::AVC420_ENABLED))));
        // RemoteFX : aucun H.264, versions 10.x conservées
        let rfx = advertised(Codecs::NoAvc);
        assert!(rfx.iter().all(|c| !avc(c)), "{rfx:?}");
        assert!(matches!(rfx[0], CapabilitySet::V10_7 { flags } if flags.contains(CapabilitiesV107Flags::AVC_DISABLED)));
        assert!(!rfx.iter().any(|c| matches!(c, CapabilitySet::V10_1)));
        // AVC420 seul : pas de 10.x
        let a420 = advertised(Codecs::Avc420);
        assert!(matches!(a420[0], CapabilitySet::V8_1 { .. }), "{a420:?}");
    }

    /// Image 4:4:4 de test : luminance en dégradé, chrominance qui alterne d'une colonne (U) et
    /// d'une ligne (V) à l'autre — détail que le 4:2:0 seul ne peut pas restituer.
    fn yuv444(w: usize, h: usize, flip: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (a, b) = if flip { (190u8, 70u8) } else { (70u8, 190u8) };
        let y = (0..w * h).map(|i| 90 + ((i % w) * 60 / w) as u8).collect();
        let u = (0..w * h).map(|i| if (i % w) % 2 == 0 { a } else { b }).collect();
        let v = (0..w * h).map(|i| if (i / w) % 2 == 0 { 80 } else { 180 }).collect();
        (y, u, v)
    }

    /// Vues principale et auxiliaire (I420) d'une image 4:4:4, comme les construit le serveur.
    fn split444(w: usize, h: usize, (y, u, v): &(Vec<u8>, Vec<u8>, Vec<u8>), v2: bool) -> (Vec<u8>, Vec<u8>) {
        let (cw, ch) = (w / 2, h / 2);
        let at = |p: &Vec<u8>, x: usize, yy: usize| p[yy * w + x];
        let avg = |p: &Vec<u8>, x: usize, yy: usize| ((at(p, 2 * x, 2 * yy) as u32 + at(p, 2 * x + 1, 2 * yy) as u32 + at(p, 2 * x, 2 * yy + 1) as u32 + at(p, 2 * x + 1, 2 * yy + 1) as u32 + 2) / 4) as u8;
        let mut main = y.clone();
        main.extend((0..cw * ch).map(|i| avg(u, i % cw, i / cw)));
        main.extend((0..cw * ch).map(|i| avg(v, i % cw, i / cw)));
        let mut aux = Vec::with_capacity(w * h * 3 / 2);
        if !v2 {
            for r in 0..h {
                let (b, i) = (r / 16, r % 16);
                let (plane, src) = if i < 8 { (u, 2 * (b * 8 + i) + 1) } else { (v, 2 * (b * 8 + i - 8) + 1) };
                aux.extend((0..w).map(|x| at(plane, x, src)));
            }
            aux.extend((0..cw * ch).map(|i| at(u, 2 * (i % cw) + 1, 2 * (i / cw))));
            aux.extend((0..cw * ch).map(|i| at(v, 2 * (i % cw) + 1, 2 * (i / cw))));
        } else {
            for r in 0..h {
                aux.extend((0..w).map(|x| if x < w / 2 { at(u, 2 * x + 1, r) } else { at(v, 2 * (x - w / 2) + 1, r) }));
            }
            let quarter = |off: usize| {
                (0..cw * ch)
                    .map(|i| {
                        let (x, r) = (i % cw, i / cw);
                        if x < w / 4 { at(u, 4 * x + off, 2 * r + 1) } else { at(v, 4 * (x - w / 4) + off, 2 * r + 1) }
                    })
                    .collect::<Vec<u8>>()
            };
            aux.extend(quarter(0));
            aux.extend(quarter(2));
        }
        (main, aux)
    }

    fn encoder() -> openh264::encoder::Encoder {
        use openh264::encoder::{EncoderConfig, QpRange};
        let config = EncoderConfig::new().qp(QpRange::new(0, 4)).scene_change_detect(false);
        openh264::encoder::Encoder::with_api_config(openh264::OpenH264API::from_source(), config).unwrap()
    }

    fn avc_stream(data: &[u8], w: u16, h: u16) -> Avc420BitmapStream<'_> {
        use ironrdp_egfx::pdu::QuantQuality;
        Avc420BitmapStream {
            rectangles: vec![ironrdp_pdu::geometry::InclusiveRectangle { left: 0, top: 0, right: w, bottom: h }],
            quant_qual_vals: vec![QuantQuality { quantization_parameter: 0, progressive: false, quality: 100 }],
            data,
        }
    }

    /// Deux images AVC444 (v1 ou v2) codées avec un même flux H.264 ou deux flux séparés :
    /// la chrominance pleine résolution est restituée.
    fn avc444_round_trip(v2: bool, separate: bool) {
        use ironrdp_dvc::DvcProcessor as _;
        use ironrdp_egfx::pdu::*;
        const W: usize = 64;
        const H: usize = 48;
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        let mut c = client(frame.clone(), events, Default::default(), Codecs::Avc444);
        c.start(1).unwrap();
        c.process(
            1,
            &wire(vec![
                GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&CapabilitySet::V10_7 { flags: CapabilitiesV107Flags::SMALL_CACHE })),
                GfxPdu::ResetGraphics(ResetGraphicsPdu { width: W as u32, height: H as u32, monitors: vec![] }),
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 1, width: W as u16, height: H as u16, pixel_format: PixelFormat::XRgb }),
                GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 1, output_origin_x: 0, output_origin_y: 0 }),
            ]),
        )
        .unwrap();

        let (mut enc_main, mut enc_aux) = (encoder(), encoder());
        for (n, flip) in [(1u32, false), (2, true)] {
            let img = yuv444(W, H, flip);
            let (main, aux) = split444(W, H, &img, v2);
            let main = annex_b_to_avc(&enc_main.encode(&openh264::formats::YUVBuffer::from_vec(main, W, H)).unwrap().to_vec());
            let enc = if separate { &mut enc_aux } else { &mut enc_main };
            let aux = annex_b_to_avc(&enc.encode(&openh264::formats::YUVBuffer::from_vec(aux, W, H)).unwrap().to_vec());
            let stream = Avc444BitmapStream { encoding: Encoding::LUMA_AND_CHROMA, stream1: avc_stream(&main, W as u16, H as u16), stream2: Some(avc_stream(&aux, W as u16, H as u16)) };
            let ts = Timestamp { milliseconds: 0, seconds: 0, minutes: 0, hours: 0 };
            c.process(
                1,
                &wire(vec![
                    GfxPdu::StartFrame(StartFramePdu { timestamp: ts, frame_id: n }),
                    GfxPdu::WireToSurface1(WireToSurface1Pdu {
                        surface_id: 1,
                        codec_id: if v2 { Codec1Type::Avc444v2 } else { Codec1Type::Avc444 },
                        pixel_format: PixelFormat::XRgb,
                        destination_rectangle: ExclusiveRectangle { left: 0, top: 0, right: W as u16, bottom: H as u16 },
                        bitmap_data: ironrdp_core::encode_vec(&stream).unwrap(),
                    }),
                    GfxPdu::EndFrame(EndFramePdu { frame_id: n }),
                ]),
            )
            .unwrap();

            let f = frame.lock().unwrap();
            let (mut worst, mut worst420) = (0u8, 0u8);
            for y in 0..H {
                for x in 0..W {
                    let i = y * W + x;
                    let want = yuv_to_rgb(img.0[i], img.1[i], img.2[i]);
                    let got = f.pixels[i];
                    let d = want[0].abs_diff(got.r()).max(want[1].abs_diff(got.g())).max(want[2].abs_diff(got.b()));
                    worst = worst.max(d);
                    // ce qu'aurait donné la seule vue principale (4:2:0 : moyennes à 130)
                    let flat = yuv_to_rgb(img.0[i], 130, 130);
                    worst420 = worst420.max(want[0].abs_diff(flat[0]).max(want[1].abs_diff(flat[1])).max(want[2].abs_diff(flat[2])));
                }
            }
            assert!(worst420 > 60, "le motif de test doit dépasser ce que restitue le 4:2:0 ({worst420})");
            assert!(worst <= 16, "AVC444{} {} flux, image {n} : écart maximal {worst}", if v2 { "v2" } else { "" }, if separate { "deux" } else { "un" });
        }
    }

    #[test]
    fn avc444_restores_full_chroma() {
        avc444_round_trip(false, false);
        avc444_round_trip(false, true);
    }

    #[test]
    fn avc444v2_restores_full_chroma() {
        avc444_round_trip(true, false);
        avc444_round_trip(true, true);
    }

    // ---- robustesse et exactitude de l'affichage ----

    /// Client prêt : capacités confirmées, écran `w`×`h`, surface 1 de même taille affichée en (0, 0).
    fn ready(codecs: Codecs, w: u16, h: u16) -> (GraphicsPipelineClient, SharedFrame) {
        use ironrdp_dvc::DvcProcessor as _;
        use ironrdp_egfx::pdu::*;
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        let mut c = client(frame.clone(), events, Default::default(), codecs);
        c.start(1).unwrap();
        let cap = match codecs {
            Codecs::Avc420 => CapabilitySet::V8_1 { flags: CapabilitiesV81Flags::AVC420_ENABLED },
            Codecs::Avc444 => CapabilitySet::V10_7 { flags: CapabilitiesV107Flags::SMALL_CACHE },
            Codecs::NoAvc => CapabilitySet::V10_7 { flags: CapabilitiesV107Flags::AVC_DISABLED },
        };
        send(
            &mut c,
            vec![
                GfxPdu::CapabilitiesConfirm(CapabilitiesConfirmPdu::from_typed(&cap)),
                GfxPdu::ResetGraphics(ResetGraphicsPdu { width: w.into(), height: h.into(), monitors: vec![] }),
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 1, width: w, height: h, pixel_format: PixelFormat::XRgb }),
                GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 1, output_origin_x: 0, output_origin_y: 0 }),
            ],
        );
        (c, frame)
    }

    /// Envoie des commandes sur le canal ; renvoie le nombre de réponses.
    fn send(c: &mut GraphicsPipelineClient, pdus: Vec<GfxPdu>) -> usize {
        use ironrdp_dvc::DvcProcessor as _;
        c.process(1, &wire(pdus)).unwrap().len()
    }

    fn w1(surface_id: u16, codec_id: Codec1Type, (l, t, r, b): (u16, u16, u16, u16), bitmap_data: Vec<u8>) -> GfxPdu {
        GfxPdu::WireToSurface1(ironrdp_egfx::pdu::WireToSurface1Pdu {
            surface_id,
            codec_id,
            pixel_format: ironrdp_egfx::pdu::PixelFormat::XRgb,
            destination_rectangle: rect(l, t, r, b),
            bitmap_data,
        })
    }

    fn px(frame: &SharedFrame, x: usize, y: usize) -> Color32 {
        let f = frame.lock().unwrap();
        f.pixels[y * f.width + x]
    }

    fn near(c: Color32, rgb: [u8; 3], tol: u8) -> bool {
        c.r().abs_diff(rgb[0]) <= tol && c.g().abs_diff(rgb[1]) <= tol && c.b().abs_diff(rgb[2]) <= tol
    }

    const RED: [u8; 3] = [255, 0, 0];
    const BLUE: [u8; 3] = [0, 0, 255];

    /// Moitié gauche rouge, moitié droite bleue : une inversion R / B se voit tout de suite.
    fn red_blue(x: usize, w: usize) -> [u8; 3] {
        if x < w / 2 { RED } else { BLUE }
    }

    /// Plans Y, U, V 4:4:4 (BT.709 pleine plage, l'inverse de `yuv_to_rgb`, comme le codeur de
    /// Windows) d'une image RGB.
    fn planes(w: usize, h: usize, f: impl Fn(usize, usize) -> [u8; 3]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (mut y, mut u, mut v) = (Vec::new(), Vec::new(), Vec::new());
        for j in 0..h {
            for i in 0..w {
                let [r, g, b] = f(i, j).map(|c| c as f32);
                let l = 0.2126 * r + 0.7152 * g + 0.0722 * b;
                y.push(l.round() as u8);
                u.push((128.0 + (b - l) / 1.8556).round().clamp(0.0, 255.0) as u8);
                v.push((128.0 + (r - l) / 1.5748).round().clamp(0.0, 255.0) as u8);
            }
        }
        (y, u, v)
    }

    /// Couleurs du H.264 de RDPGFX : BT.709 pleine plage (MS-RDPEGFX 3.3.8.3.1). Le noir, le blanc et
    /// les gris sombres (thème sombre de Windows) doivent ressortir tels quels.
    #[test]
    fn h264_colors_are_full_range_bt709() {
        for rgb in [[0, 0, 0], [255, 255, 255], [32, 32, 32], [200, 30, 60], [20, 120, 220]] {
            let (y, u, v) = planes(1, 1, |_, _| rgb);
            let back = yuv_to_rgb(y[0], u[0], v[0]);
            for k in 0..3 {
                assert!(back[k].abs_diff(rgb[k]) <= 2, "{rgb:?} -> {back:?}");
            }
        }
        // gris sombre de Windows (#202020) : Y = 32 pleine plage, pas 18 comme en plage limitée
        assert_eq!(yuv_to_rgb(32, 128, 128), [32, 32, 32]);
    }

    /// Codeur RLGR1 (RemoteFX) : un flux qu'il produit se relit à l'identique (UP_GR au lieu de
    /// UQ_GR le désynchronisait dès la première valeur nulle en mode Golomb-Rice).
    #[test]
    fn rlgr1_encoder_round_trips() {
        use ironrdp_pdu::codecs::rfx::EntropyAlgorithm;
        let mut rng = Rng(42);
        for _ in 0..50 {
            let src: Vec<i16> = (0..4096).map(|_| if rng.below(3) == 0 { rng.next() as i16 >> rng.below(15) } else { 0 }).collect();
            for mode in [EntropyAlgorithm::Rlgr1, EntropyAlgorithm::Rlgr3] {
                let mut out = vec![0u8; 32768];
                let n = ironrdp_graphics::rlgr::encode(mode, &src, &mut out).unwrap();
                let mut back = vec![0i16; 4096];
                ironrdp_graphics::rlgr::decode(mode, &out[..n], &mut back).unwrap();
                assert_eq!(back, src, "{mode:?}");
            }
        }
    }

    /// Image I420 codée en H.264 (unités NAL au format AVC, comme sur le canal).
    fn h264(enc: &mut openh264::encoder::Encoder, i420: Vec<u8>, w: usize, h: usize) -> Vec<u8> {
        annex_b_to_avc(&enc.encode(&openh264::formats::YUVBuffer::from_vec(i420, w, h)).unwrap().to_vec())
    }

    fn meta<'a>(data: &'a [u8], regions: &[(u16, u16, u16, u16)]) -> Avc420BitmapStream<'a> {
        use ironrdp_egfx::pdu::QuantQuality;
        Avc420BitmapStream {
            rectangles: regions.iter().map(|&(left, top, right, bottom)| ironrdp_pdu::geometry::InclusiveRectangle { left, top, right, bottom }).collect(),
            quant_qual_vals: regions.iter().map(|_| QuantQuality { quantization_parameter: 0, progressive: false, quality: 100 }).collect(),
            data,
        }
    }

    fn avc420(data: &[u8], regions: &[(u16, u16, u16, u16)]) -> Vec<u8> {
        ironrdp_core::encode_vec(&meta(data, regions)).unwrap()
    }

    fn avc444(encoding: Encoding, s1: (&[u8], &[(u16, u16, u16, u16)]), s2: Option<(&[u8], &[(u16, u16, u16, u16)])>) -> Vec<u8> {
        let stream = Avc444BitmapStream { encoding, stream1: meta(s1.0, s1.1), stream2: s2.map(|s| meta(s.0, s.1)) };
        ironrdp_core::encode_vec(&stream).unwrap()
    }

    /// Image RemoteFX Progressive d'une tuile 64×64 (TILE_SIMPLE), avec les indicateurs de bloc
    /// CONTEXT et REGION donnés.
    fn progressive_tile(rgba: &[u8], context_flags: u8, region_flags: u8, rects: Vec<(u16, u16, u16, u16)>) -> Vec<u8> {
        use ironrdp_pdu::codecs::rfx::RfxRectangle;
        use ironrdp_pdu::codecs::rfx::progressive::*;
        let extrapolate = region_flags & 1 != 0;
        let (mut y, mut cb, mut cr) = ([0i16; 4096], [0i16; 4096], [0i16; 4096]);
        ironrdp_graphics::color_conversion::to_64x64_ycbcr_tile(rgba, 64, 64, 64 * 4, ironrdp_graphics::image_processing::PixelFormat::RgbA32, &mut y, &mut cb, &mut cr).unwrap();
        let quant = ComponentCodecQuant { ll3: 6, hl3: 6, lh3: 6, hh3: 6, hl2: 6, lh2: 6, hh2: 6, hl1: 6, lh1: 6, hh1: 6 };
        let enc = |c: &mut [i16; 4096]| {
            let mut out = vec![0u8; 16384];
            let n = ironrdp_graphics::progressive::encode_first_pass(c, &mut out, &quant, &ComponentCodecQuant::LOSSLESS, extrapolate).unwrap();
            out.truncate(n);
            out
        };
        let (yd, cbd, crd) = (enc(&mut y), enc(&mut cb), enc(&mut cr));
        let tile = ProgressiveTile::Simple(TileSimple {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            flags: 0,
            y_data: &yd,
            cb_data: &cbd,
            cr_data: &crd,
            tail_data: &[],
        });
        let region = ProgressiveRegion {
            tile_size: 0x40,
            rects: rects.into_iter().map(|(x, y, width, height)| RfxRectangle { x, y, width, height }).collect(),
            quant_vals: vec![quant],
            quant_prog_vals: vec![],
            flags: region_flags,
            tiles: vec![tile],
        };
        encode_progressive_stream(&[
            ProgressiveBlock::Sync(ProgressiveSyncPdu),
            ProgressiveBlock::Context(ProgressiveContextPdu { context_id: 0, tile_size: 0x40, flags: context_flags }),
            ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu { frame_index: 0, region_count: 1 }),
            ProgressiveBlock::Region(region),
            ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
        ])
        .unwrap()
    }

    fn w2(surface_id: u16, codec_context_id: u32, bitmap_data: Vec<u8>) -> GfxPdu {
        GfxPdu::WireToSurface2(ironrdp_egfx::pdu::WireToSurface2Pdu {
            surface_id,
            codec_id: ironrdp_egfx::pdu::Codec2Type::RemoteFxProgressive,
            codec_context_id,
            pixel_format: ironrdp_egfx::pdu::PixelFormat::XRgb,
            bitmap_data,
        })
    }

    /// Chaque chemin de décodage respecte l'ordre des composantes : bande par bande, moitié gauche
    /// rouge et moitié droite bleue.
    #[test]
    fn every_codec_keeps_red_and_blue_apart() {
        use ironrdp_egfx::pdu::Color;
        const W: usize = 64;
        let (mut c, frame) = ready(Codecs::Avc444, W as u16, 64);
        let band = |y0: usize, name: &str, tol: u8| {
            for (x, want) in [(8, RED), (48, BLUE)] {
                let got = px(&frame, x, y0 + 4);
                assert!(near(got, want, tol), "{name} : pixel ({x}, {}) = {got:?}, attendu {want:?}", y0 + 4);
            }
        };
        let rgb: Vec<[u8; 3]> = (0..W * 8).map(|i| red_blue(i % W, W)).collect();

        // 0..8 : remplissage
        let fill = |l, r, [cr, cg, cb]: [u8; 3]| GfxPdu::SolidFill(SolidFillPdu { surface_id: 1, fill_pixel: Color { b: cb, g: cg, r: cr, xa: 0 }, rectangles: vec![rect(l, 0, r, 8)] });
        send(&mut c, vec![fill(0, 32, RED), fill(32, 64, BLUE)]);
        band(0, "SolidFill", 0);
        // le canal alpha ne touche pas aux couleurs
        send(&mut c, vec![w1(1, Codec1Type::Alpha, (0, 0, 64, 8), vec![0x4C, 0x41, 0, 0, 0, 0])]);
        band(0, "Alpha", 0);

        // 8..16 : non compressé (BGRA sur le fil)
        let bgra = rgb.iter().flat_map(|p| [p[2], p[1], p[0], 0xFF]).collect();
        send(&mut c, vec![w1(1, Codec1Type::Uncompressed, (0, 8, 64, 16), bgra)]);
        band(8, "Uncompressed", 0);

        // 16..24 : Planar
        let raw: Vec<u8> = rgb.iter().flatten().copied().collect();
        let mut planar = vec![0u8; raw.len() * 2 + 64];
        let n = ironrdp_graphics::rdp6::BitmapStreamEncoder::new(W, 8).encode_bitmap::<ironrdp_graphics::rdp6::RgbChannels>(&raw, &mut planar, true).unwrap();
        planar.truncate(n);
        send(&mut c, vec![w1(1, Codec1Type::Planar, (0, 16, 64, 24), planar)]);
        band(16, "Planar", 0);

        // 24..32 : RemoteFX Progressive (une tuile 64×64, seule la bande annoncée est recopiée)
        let tile: Vec<u8> = (0..64 * 64).flat_map(|i| { let [r, g, b] = red_blue(i % 64, 64); [r, g, b, 255] }).collect();
        send(&mut c, vec![w2(1, 1, progressive_tile(&tile, 1, 1, vec![(0, 24, 64, 8)]))]);
        band(24, "Progressive", 12);
        band(16, "Planar (hors zone Progressive)", 0);

        // 32..40 : ClearCodec, résidu BGR : 32 rouges puis 32 bleus par ligne
        let mut residual = Vec::new();
        for _ in 0..8 {
            residual.extend_from_slice(&[0, 0, 255, 32, 255, 0, 0, 32]);
        }
        let mut clear = vec![0u8, 0];
        for len in [residual.len() as u32, 0, 0] {
            clear.extend_from_slice(&len.to_le_bytes());
        }
        clear.extend_from_slice(&residual);
        send(&mut c, vec![w1(1, Codec1Type::ClearCodec, (0, 32, 64, 40), clear)]);
        band(32, "ClearCodec", 0);

        // 40..48 : AVC420 ; 48..64 : AVC444 (image entière décodée, seule la zone annoncée compte)
        let (y, u, v) = planes(W, 64, |x, _| red_blue(x, W));
        let (main, aux) = split444(W, 64, &(y, u, v), false);
        let mut enc = encoder();
        let frame420 = h264(&mut enc, main.clone(), W, 64);
        send(&mut c, vec![w1(1, Codec1Type::Avc420, (0, 0, 64, 64), avc420(&frame420, &[(0, 40, 64, 48)]))]);
        band(40, "AVC420", 40);
        band(32, "ClearCodec (hors zone AVC420)", 0);
        let mut enc = encoder();
        let (m, a) = (h264(&mut enc, main, W, 64), h264(&mut enc, aux, W, 64));
        let r: &[(u16, u16, u16, u16)] = &[(0, 48, 64, 64)];
        send(&mut c, vec![w1(1, Codec1Type::Avc444, (0, 0, 64, 64), avc444(Encoding::LUMA_AND_CHROMA, (&m, r), Some((&a, r))))]);
        band(48, "AVC444", 40);
        band(56, "AVC444", 40);
        band(40, "AVC420 (hors zone AVC444)", 40);
    }

    /// AVC444 sur une surface non multiple de 16 (images H.264 alignées à 48×48, comme celles de
    /// Windows), mise à jour partielle, puis vue principale seule suivie de la vue auxiliaire seule.
    fn avc444_partial_and_split(v2: bool) {
        const S: usize = 40; // surface
        const F: usize = 48; // image H.264
        let (mut c, frame) = ready(Codecs::Avc444, S as u16, S as u16);
        let codec = if v2 { Codec1Type::Avc444v2 } else { Codec1Type::Avc444 };
        let mut enc = encoder();
        let (a, b) = (yuv444(F, F, false), yuv444(F, F, true));
        let worst = |img: &(Vec<u8>, Vec<u8>, Vec<u8>), zone: (usize, usize, usize, usize)| {
            let f = frame.lock().unwrap();
            let mut worst = 0u8;
            for y in zone.1..zone.3 {
                for x in zone.0..zone.2 {
                    let i = y * F + x;
                    let want = yuv_to_rgb(img.0[i], img.1[i], img.2[i]);
                    let got = f.pixels[y * S + x];
                    worst = worst.max(want[0].abs_diff(got.r()).max(want[1].abs_diff(got.g())).max(want[2].abs_diff(got.b())));
                }
            }
            worst
        };
        let full: &[(u16, u16, u16, u16)] = &[(0, 0, F as u16, F as u16)];
        let send444 = |c: &mut GraphicsPipelineClient, img, enc: &mut openh264::encoder::Encoder, lc: Encoding, r: &[(u16, u16, u16, u16)]| {
            let (main, aux) = split444(F, F, img, v2);
            let (m, x) = (h264(enc, main, F, F), h264(enc, aux, F, F));
            let data = if lc == Encoding::LUMA {
                avc444(lc, (&m, r), None)
            } else if lc == Encoding::CHROMA {
                avc444(lc, (&x, r), None)
            } else {
                avc444(lc, (&m, r), Some((&x, r)))
            };
            send(c, vec![w1(1, codec, (0, 0, S as u16, S as u16), data)]);
        };
        let tag = if v2 { "AVC444v2" } else { "AVC444" };

        send444(&mut c, &a, &mut enc, Encoding::LUMA_AND_CHROMA, full);
        assert!(worst(&a, (0, 0, S, S)) <= 16, "{tag} image entière : {}", worst(&a, (0, 0, S, S)));

        // zone partielle (8, 16)-(40, 32) : le reste de l'écran garde l'image précédente
        send444(&mut c, &b, &mut enc, Encoding::LUMA_AND_CHROMA, &[(8, 16, 40, 32)]);
        assert!(worst(&b, (8, 16, 40, 32)) <= 16, "{tag} zone partielle : {}", worst(&b, (8, 16, 40, 32)));
        assert!(worst(&a, (0, 0, S, 16)) <= 16, "{tag} hors zone : {}", worst(&a, (0, 0, S, 16)));
        assert!(worst(&a, (0, 32, S, S)) <= 16, "{tag} hors zone : {}", worst(&a, (0, 32, S, S)));

        // vue principale seule (4:2:0), puis vue auxiliaire seule : la chrominance complète revient.
        // Seules les données utiles sont codées : la vue principale de `a` puis sa vue auxiliaire.
        let (main, aux) = split444(F, F, &a, v2);
        let m = h264(&mut enc, main, F, F);
        send(&mut c, vec![w1(1, codec, (0, 0, S as u16, S as u16), avc444(Encoding::LUMA, (&m, full), None))]);
        assert!(worst(&a, (0, 0, S, S)) > 40, "{tag} vue principale seule : chrominance 4:2:0 attendue");
        let x = h264(&mut enc, aux, F, F);
        send(&mut c, vec![w1(1, codec, (0, 0, S as u16, S as u16), avc444(Encoding::CHROMA, (&x, full), None))]);
        assert!(worst(&a, (0, 0, S, S)) <= 16, "{tag} vue auxiliaire seule : {}", worst(&a, (0, 0, S, S)));
    }

    #[test]
    fn avc444_partial_regions_odd_surface_and_chroma_only() {
        avc444_partial_and_split(false);
        avc444_partial_and_split(true);
    }

    /// Une image verte puis une rouge de `w`×`h` en H.264, avec le codeur donné.
    fn solid_i420(w: usize, h: usize, rgb: [u8; 3]) -> Vec<u8> {
        split444(w, h, &planes(w, h, |_, _| rgb), false).0
    }

    /// Deux surfaces, chacune avec son propre flux H.264 (tailles différentes), entrelacés image
    /// par image comme le fait Windows avec plusieurs écrans ; puis une surface supprimée et recréée
    /// avec le même identifiant et une autre taille.
    fn two_surfaces(codec: Codec1Type) {
        use ironrdp_egfx::pdu::*;
        let (mut c, frame) = ready(Codecs::Avc444, 96, 48);
        send(
            &mut c,
            vec![
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 2, width: 32, height: 32, pixel_format: PixelFormat::XRgb }),
                GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 2, output_origin_x: 64, output_origin_y: 0 }),
            ],
        );
        let wrap = |data: &[u8], w: u16, h: u16| {
            let r: &[(u16, u16, u16, u16)] = &[(0, 0, w, h)];
            if codec == Codec1Type::Avc420 { avc420(data, r) } else { avc444(Encoding::LUMA, (data, r), None) }
        };
        let (mut e1, mut e2) = (encoder(), encoder());
        let green = [0, 200, 0];
        let yellow = [220, 220, 0];
        for (n, (c1, c2)) in [(green, BLUE), (RED, yellow), (BLUE, green)].into_iter().enumerate() {
            let f1 = h264(&mut e1, solid_i420(64, 48, c1), 64, 48);
            let f2 = h264(&mut e2, solid_i420(32, 32, c2), 32, 32);
            send(&mut c, vec![w1(1, codec, (0, 0, 64, 48), wrap(&f1, 64, 48)), w1(2, codec, (0, 0, 32, 32), wrap(&f2, 32, 32))]);
            let (p1, p2) = (px(&frame, 20, 20), px(&frame, 80, 20));
            assert!(near(p1, c1, 40), "{codec:?} image {n}, surface 1 : {p1:?}, attendu {c1:?}");
            assert!(near(p2, c2, 40), "{codec:?} image {n}, surface 2 : {p2:?}, attendu {c2:?}");
        }
        // surface 2 supprimée puis recréée (même identifiant, autre taille) : nouveau flux
        send(
            &mut c,
            vec![
                GfxPdu::DeleteSurface(DeleteSurfacePdu { surface_id: 2 }),
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 2, width: 16, height: 16, pixel_format: PixelFormat::XRgb }),
                GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 2, output_origin_x: 64, output_origin_y: 0 }),
            ],
        );
        let mut e3 = encoder();
        let f3 = h264(&mut e3, solid_i420(16, 16, RED), 16, 16);
        let f1 = h264(&mut e1, solid_i420(64, 48, yellow), 64, 48);
        send(&mut c, vec![w1(2, codec, (0, 0, 16, 16), wrap(&f3, 16, 16)), w1(1, codec, (0, 0, 64, 48), wrap(&f1, 64, 48))]);
        assert!(near(px(&frame, 70, 8), RED, 40), "{codec:?} surface recréée : {:?}", px(&frame, 70, 8));
        assert!(near(px(&frame, 20, 20), yellow, 40), "{codec:?} surface 1 après recréation : {:?}", px(&frame, 20, 20));
    }

    #[test]
    fn h264_streams_of_several_surfaces_stay_independent() {
        two_surfaces(Codec1Type::Avc420);
        two_surfaces(Codec1Type::Avc444);
    }

    /// Nouvelle SPS (résolution du flux qui change), image plus petite que la surface et zones qui
    /// dépassent l'image : seuls les pixels réellement décodés sont recopiés.
    #[test]
    fn h264_resolution_change_and_frames_smaller_than_the_surface() {
        let (mut c, frame) = ready(Codecs::Avc444, 64, 64);
        let mut e = encoder();
        let f = h264(&mut e, solid_i420(64, 64, [0, 200, 0]), 64, 64);
        send(&mut c, vec![w1(1, Codec1Type::Avc420, (0, 0, 64, 64), avc420(&f, &[(0, 0, 64, 64)]))]);
        assert!(near(px(&frame, 40, 40), [0, 200, 0], 40));
        // nouveau flux 32×16 : zone annoncée plus grande que l'image décodée
        let mut e = encoder();
        let f = h264(&mut e, solid_i420(32, 16, RED), 32, 16);
        send(&mut c, vec![w1(1, Codec1Type::Avc420, (0, 0, 32, 16), avc420(&f, &[(0, 0, 64, 64)]))]);
        assert!(near(px(&frame, 8, 8), RED, 40), "{:?}", px(&frame, 8, 8));
        assert!(near(px(&frame, 40, 40), [0, 200, 0], 40), "hors de l'image décodée : {:?}", px(&frame, 40, 40));
        let f = h264(&mut e, solid_i420(32, 16, BLUE), 32, 16);
        send(&mut c, vec![w1(1, Codec1Type::Avc444v2, (0, 0, 32, 16), avc444(Encoding::LUMA, (&f, &[(0, 0, 64, 64)]), None))]);
        assert!(near(px(&frame, 8, 8), BLUE, 40), "{:?}", px(&frame, 8, 8));
    }

    /// RemoteFX Progressive : le mode de DWT (« reduce-extrapolate ») est donné par le bloc REGION
    /// (MS-RDPEGFX 2.2.4.2.1.5) ; l'indicateur du bloc CONTEXT est RFX_SUBBAND_DIFFING. FreeRDP et
    /// xrdp envoient un CONTEXT à 0.
    #[test]
    fn progressive_dwt_mode_comes_from_the_region_block() {
        let (mut c, frame) = ready(Codecs::NoAvc, 64, 64);
        let tile: Vec<u8> = (0..64 * 64).flat_map(|i| { let [r, g, b] = red_blue(i % 64, 64); [r, g, b, 255] }).collect();
        send(&mut c, vec![w2(1, 1, progressive_tile(&tile, 0, 1, vec![(0, 0, 64, 64)]))]);
        for (x, want) in [(8, RED), (48, BLUE)] {
            assert!(near(px(&frame, x, 30), want, 12), "pixel ({x}, 30) = {:?}", px(&frame, x, 30));
        }
        // nouveau contexte sans bloc CONTEXT, DWT classique
        let mut data = progressive_tile(&tile, 0, 0, vec![(0, 0, 64, 64)]);
        // retrait du bloc CONTEXT (type 0xCCC3, 10 octets) qui suit SYNC (12 octets)
        assert_eq!(&data[12..14], &[0xC3, 0xCC]);
        data.drain(12..22);
        send(&mut c, vec![GfxPdu::SolidFill(SolidFillPdu { surface_id: 1, fill_pixel: ironrdp_egfx::pdu::Color { b: 0, g: 0, r: 0, xa: 0 }, rectangles: vec![rect(0, 0, 64, 64)] })]);
        send(&mut c, vec![w2(1, 2, data)]);
        assert!(near(px(&frame, 8, 30), RED, 12), "sans CONTEXT : {:?}", px(&frame, 8, 30));
    }

    // ---- RemoteFX Progressive : premières passes et passes d'amélioration ----
    // Codeur de référence écrit d'après le décodeur de FreeRDP (libfreerdp/codec/progressive.c :
    // progressive_decompress_tile_first / _upgrade, progressive_rfx_upgrade_block,
    // progressive_rfx_srl_read), indépendant du code de la caisse ironrdp-graphics.

    /// Écriture de bits, poids fort d'abord (flux RAW et SRL).
    #[derive(Default)]
    struct BitOut {
        out: Vec<u8>,
        cur: u8,
        n: u8,
    }

    impl BitOut {
        fn bit(&mut self, b: bool) {
            self.cur = self.cur << 1 | b as u8;
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.cur);
                (self.cur, self.n) = (0, 0);
            }
        }
        fn bits(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.bit(v >> i & 1 != 0);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.cur << (8 - self.n));
            }
            self.out
        }
    }

    /// Codeur SRL : chaque valeur est lue par un appel de `progressive_rfx_srl_read` (kp = 8 au
    /// départ, état commun à toutes les bandes d'une composante).
    struct SrlOut {
        bits: BitOut,
        kp: u32,
        zeros: u32,
    }

    impl SrlOut {
        fn new() -> Self {
            SrlOut { bits: BitOut::default(), kp: 8, zeros: 0 }
        }
        /// Suites complètes de 2^k zéros (bit '0').
        fn runs(&mut self) {
            while self.zeros >= 1 << (self.kp / 8) {
                self.zeros -= 1 << (self.kp / 8);
                self.bits.bit(false);
                self.kp = (self.kp + 4).min(80);
            }
        }
        fn push(&mut self, v: i32, num_bits: u32) {
            if v == 0 {
                self.zeros += 1;
                return;
            }
            self.runs();
            // '1' + zéros restants sur k bits, puis signe et magnitude unaire (bornée à 2^n - 1)
            let k = self.kp / 8;
            self.bits.bit(true);
            self.bits.bits(self.zeros, k);
            self.zeros = 0;
            self.bits.bit(v < 0);
            self.kp = self.kp.saturating_sub(6);
            if num_bits > 1 {
                let (max, mag) = ((1u32 << num_bits) - 1, v.unsigned_abs());
                assert!(mag <= max);
                for _ in 1..mag {
                    self.bits.bit(false);
                }
                if mag < max {
                    self.bits.bit(true);
                }
            }
        }
        fn finish(mut self) -> Vec<u8> {
            self.runs();
            if self.zeros > 0 {
                let k = self.kp / 8;
                self.bits.bit(true);
                self.bits.bits(self.zeros, k);
            }
            self.bits.finish()
        }
    }

    use ironrdp_pdu::codecs::rfx::progressive::{ComponentCodecQuant as Cq, ProgressiveCodecQuant as Pq};

    /// Quantification par niveau de décomposition (comme les tables de Windows) : LL3, niveau 3,
    /// niveau 2, niveau 1.
    fn cq(ll3: u8, l3: u8, l2: u8, l1: u8) -> Cq {
        Cq { ll3, hl3: l3, lh3: l3, hh3: l3, hl2: l2, lh2: l2, hh2: l2, hl1: l1, lh1: l1, hh1: l1 }
    }

    /// Quantification de base (6 : un pas de 32 en virgule fixe 11.5, soit un niveau de couleur).
    const PQ_BASE: Cq = Cq { ll3: 6, hl3: 6, lh3: 6, hh3: 6, hl2: 6, lh2: 6, hh2: 6, hl1: 6, lh1: 6, hh1: 6 };

    /// Niveaux de qualité progressifs : positions de bit décroissantes (0xFF : toutes nulles).
    fn pq_levels() -> Vec<Pq> {
        [cq(3, 4, 5, 6), cq(1, 2, 3, 3), cq(0, 1, 1, 2)]
            .into_iter()
            .enumerate()
            .map(|(i, q)| Pq { quality: [20, 60, 90][i], y_quant: q, cb_quant: cq(q.ll3, q.hl3, q.hl2 + 1, q.hl1 + 1), cr_quant: cq(q.ll3, q.hl3, q.hl2 + 1, q.hl1 + 1) })
            .collect()
    }

    /// Positions de bit progressives d'une composante pour un niveau de qualité.
    fn pq_of(quality: u8, comp: usize) -> Cq {
        if quality == 0xFF {
            return Cq::LOSSLESS;
        }
        let l = &pq_levels()[quality as usize];
        [l.y_quant, l.cb_quant, l.cr_quant][comp]
    }

    /// État du codeur pour une tuile : coefficients pleine qualité et signes vus par le décodeur.
    struct TileEnc {
        x: u16,
        y: u16,
        q: [[i16; 4096]; 3],
        sign: [[i8; 4096]; 3],
        quality: u8,
    }

    /// Tuile codée, prête à être mise dans un bloc REGION.
    enum TileOut {
        Simple(u16, u16, [Vec<u8>; 3]),
        First(u16, u16, u8, [Vec<u8>; 3]),
        Upgrade(u16, u16, u8, [(Vec<u8>, Vec<u8>); 3]),
    }

    impl TileEnc {
        /// Tuile (`x`, `y`) d'une image RGBA de 64×64 : YCbCr 11.5, DWT reduce-extrapolate,
        /// quantification de base (troncature vers zéro).
        fn new(x: u16, y: u16, rgba: &[u8]) -> Self {
            Self::with_base(x, y, rgba, &PQ_BASE)
        }

        fn with_base(x: u16, y: u16, rgba: &[u8], base: &Cq) -> Self {
            let (mut cy, mut cb, mut cr) = ([0i16; 4096], [0i16; 4096], [0i16; 4096]);
            ironrdp_graphics::color_conversion::to_64x64_ycbcr_tile(rgba, 64, 64, 64 * 4, ironrdp_graphics::image_processing::PixelFormat::RgbA32, &mut cy, &mut cb, &mut cr).unwrap();
            let mut q = [cy, cb, cr];
            for c in &mut q {
                ironrdp_graphics::dwt_extrapolate::encode(c, &mut [0i16; 4096]);
                for (b, band) in ironrdp_graphics::dwt_extrapolate::band_layout().iter().enumerate() {
                    let s = base.for_band(b) - 1;
                    for v in &mut c[band.offset..band.offset + band.count()] {
                        *v = if *v < 0 { -(-*v >> s) } else { *v >> s };
                    }
                }
            }
            TileEnc { x, y, q, sign: [[0; 4096]; 3], quality: 0 }
        }

        /// Valeurs transmises par une première passe : |v| >> b (signe conservé), LL3 : v >> b.
        fn first_values(&mut self, quality: u8) -> [[i16; 4096]; 3] {
            self.quality = quality;
            let mut out = self.q;
            for (comp, w) in out.iter_mut().enumerate() {
                let pq = pq_of(quality, comp);
                for (b, band) in ironrdp_graphics::dwt_extrapolate::band_layout().iter().enumerate() {
                    let s = pq.for_band(b);
                    for v in &mut w[band.offset..band.offset + band.count()] {
                        *v = if b == 9 || *v >= 0 { *v >> s } else { -(-*v >> s) };
                    }
                }
                self.sign[comp] = w.map(|v| v.signum() as i8);
                ironrdp_graphics::subband_reconstruction::encode(&mut w[4015..]);
            }
            out
        }

        fn rlgr(w: &[i16; 4096]) -> Vec<u8> {
            let mut out = vec![0u8; 32768];
            let n = ironrdp_graphics::rlgr::encode(ironrdp_pdu::codecs::rfx::EntropyAlgorithm::Rlgr1, w, &mut out).unwrap();
            out.truncate(n);
            out
        }

        fn simple(&mut self) -> TileOut {
            let w = self.first_values(0xFF);
            TileOut::Simple(self.x, self.y, w.map(|c| Self::rlgr(&c)))
        }

        fn first(&mut self, quality: u8) -> TileOut {
            let w = self.first_values(quality);
            TileOut::First(self.x, self.y, quality, w.map(|c| Self::rlgr(&c)))
        }

        /// Passe d'amélioration : `numBits` = ancienne position - nouvelle ; coefficient de signe non
        /// nul : nouveaux bits de |v| en RAW ; signe nul : valeur en SRL ; LL3 : bits de v en RAW.
        fn upgrade(&mut self, quality: u8) -> TileOut {
            let prev = self.quality;
            self.quality = quality;
            let data = std::array::from_fn(|comp| {
                let (pp, cp) = (pq_of(prev, comp), pq_of(quality, comp));
                let (mut srl, mut raw) = (SrlOut::new(), BitOut::default());
                for (b, band) in ironrdp_graphics::dwt_extrapolate::band_layout().iter().enumerate() {
                    let (from, to) = (pp.for_band(b) as u32, cp.for_band(b) as u32);
                    let nb = from - to;
                    if nb == 0 {
                        continue;
                    }
                    let mask = (1u32 << nb) - 1;
                    for j in band.offset..band.offset + band.count() {
                        let v = self.q[comp][j] as i32;
                        if b == 9 {
                            raw.bits((v >> to) as u32 & mask, nb);
                        } else if self.sign[comp][j] != 0 {
                            raw.bits(v.unsigned_abs() >> to & mask, nb);
                        } else {
                            let m = (v.unsigned_abs() >> to) as i32;
                            let val = if v < 0 { -m } else { m };
                            srl.push(val, nb);
                            self.sign[comp][j] = val.signum() as i8;
                        }
                    }
                }
                (srl.finish(), raw.finish())
            });
            TileOut::Upgrade(self.x, self.y, quality, data)
        }
    }

    /// Flux RemoteFX Progressive : [SYNC + CONTEXT], FRAME_BEGIN, une REGION par lot de tuiles
    /// (avec ses rectangles), FRAME_END.
    fn prog_frame(regions: &[(&[TileOut], &[(u16, u16, u16, u16)])], with_context: bool) -> Vec<u8> {
        prog_frame_base(regions, with_context, PQ_BASE)
    }

    fn prog_frame_base(regions: &[(&[TileOut], &[(u16, u16, u16, u16)])], with_context: bool, base: Cq) -> Vec<u8> {
        use ironrdp_pdu::codecs::rfx::RfxRectangle;
        use ironrdp_pdu::codecs::rfx::progressive::*;
        fn tile(t: &TileOut) -> ProgressiveTile<'_> {
            match t {
                TileOut::Simple(x, y, d) => ProgressiveTile::Simple(TileSimple { quant_idx_y: 0, quant_idx_cb: 0, quant_idx_cr: 0, x_idx: *x, y_idx: *y, flags: 0, y_data: &d[0], cb_data: &d[1], cr_data: &d[2], tail_data: &[] }),
                TileOut::First(x, y, q, d) => ProgressiveTile::First(TileFirst { quant_idx_y: 0, quant_idx_cb: 0, quant_idx_cr: 0, x_idx: *x, y_idx: *y, flags: 0, quality: *q, y_data: &d[0], cb_data: &d[1], cr_data: &d[2], tail_data: &[] }),
                TileOut::Upgrade(x, y, q, d) => ProgressiveTile::Upgrade(TileUpgrade {
                    quant_idx_y: 0,
                    quant_idx_cb: 0,
                    quant_idx_cr: 0,
                    x_idx: *x,
                    y_idx: *y,
                    quality: *q,
                    y_srl_data: &d[0].0,
                    y_raw_data: &d[0].1,
                    cb_srl_data: &d[1].0,
                    cb_raw_data: &d[1].1,
                    cr_srl_data: &d[2].0,
                    cr_raw_data: &d[2].1,
                }),
            }
        }
        let mut blocks = Vec::new();
        if with_context {
            blocks.push(ProgressiveBlock::Sync(ProgressiveSyncPdu));
            blocks.push(ProgressiveBlock::Context(ProgressiveContextPdu { context_id: 0, tile_size: 0x40, flags: 1 }));
        }
        blocks.push(ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu { frame_index: 0, region_count: regions.len() as u16 }));
        for (tiles, rects) in regions {
            blocks.push(ProgressiveBlock::Region(ProgressiveRegion {
                tile_size: 0x40,
                rects: rects.iter().map(|&(x, y, width, height)| RfxRectangle { x, y, width, height }).collect(),
                quant_vals: vec![base],
                quant_prog_vals: pq_levels(),
                flags: 1,
                tiles: tiles.iter().map(tile).collect(),
            }));
        }
        blocks.push(ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu));
        encode_progressive_stream(&blocks).unwrap()
    }

    /// Image de test « bureau » : dégradé, texte (traits fins sombres), bords nets ; `selected` :
    /// sélection bleue (rectangle de sélection / texte surligné) sur (20, 10)-(100, 50).
    fn desk(x: usize, y: usize, selected: bool) -> [u8; 3] {
        let text = (y % 12 < 9) && (x % 7 == 1 || (y % 12 == 4 && x % 7 < 5)) && (x / 40 + y / 30) % 2 == 0;
        let mut c = [(200 + x / 3).min(255) as u8, (230 - y / 2) as u8, (180 + (x * y) % 70) as u8];
        if x > 110 && y > 60 {
            c = [30, 120, 40];
        }
        if selected && (20..100).contains(&x) && (10..50).contains(&y) {
            c = [0, 120, 215];
            if x == 20 || x == 99 || y == 10 || y == 49 {
                c = [0, 84, 153];
            }
        }
        if text {
            c = [c[0] / 6, c[1] / 6, c[2] / 5];
        }
        c
    }

    /// Tuile 64×64 RGBA de l'image (`tx`, `ty` : indices de tuile).
    fn desk_tile(tx: usize, ty: usize, selected: bool) -> Vec<u8> {
        (0..64 * 64).flat_map(|i| { let [r, g, b] = desk(tx * 64 + i % 64, ty * 64 + i / 64, selected); [r, g, b, 255] }).collect()
    }

    fn frame_pixels(frame: &SharedFrame, w: usize, h: usize) -> Vec<Color32> {
        let f = frame.lock().unwrap();
        (0..h).flat_map(|y| (0..w).map(move |x| (x, y))).map(|(x, y)| f.pixels[y * f.width + x]).collect()
    }

    /// Écart maximal (par composante) entre l'écran et une image attendue.
    fn max_diff(got: &[Color32], want: &[[u8; 3]]) -> u8 {
        got.iter().zip(want).map(|(g, w)| g.r().abs_diff(w[0]).max(g.g().abs_diff(w[1])).max(g.b().abs_diff(w[2]))).max().unwrap_or(0)
    }

    /// Scénario « sélection » sur une surface de 150×100 (non multiple de 64 : tuiles du bord
    /// partiellement hors surface) : premières passes en qualité basse, améliorations successives
    /// dans plusieurs régions et plusieurs commandes, nouvelle première passe sur les tuiles
    /// touchées par la sélection, puis pleine qualité. L'image finale doit être exactement celle
    /// d'un envoi direct en pleine qualité (TILE_SIMPLE) et proche de l'image d'origine.
    #[test]
    fn progressive_upgrades_converge_to_full_quality() {
        let (w, h) = (150usize, 100usize);
        let (mut c, frame) = ready(Codecs::NoAvc, w as u16, h as u16);
        let full: &[(u16, u16, u16, u16)] = &[(0, 0, w as u16, h as u16)];
        let mut enc: Vec<TileEnc> = (0..6).map(|i| TileEnc::new((i % 3) as u16, (i / 3) as u16, &desk_tile(i % 3, i / 3, false))).collect();
        let want = |sel: bool| -> Vec<[u8; 3]> { (0..h).flat_map(|y| (0..w).map(move |x| desk(x, y, sel))).collect() };

        // 1. premières passes, qualité 0 (floue)
        let first: Vec<TileOut> = enc.iter_mut().map(|t| t.first(0)).collect();
        send(&mut c, vec![w2(1, 1, prog_frame(&[(&first, full)], true))]);
        let coarse = max_diff(&frame_pixels(&frame, w, h), &want(false));
        // 2. qualité 1 en deux commandes, chacune une région (moitiés gauche et droite)
        let left: Vec<TileOut> = enc[..].iter_mut().filter(|t| t.x == 0).map(|t| t.upgrade(1)).collect();
        let right: Vec<TileOut> = enc[..].iter_mut().filter(|t| t.x > 0).map(|t| t.upgrade(1)).collect();
        send(&mut c, vec![w2(1, 1, prog_frame(&[(&left, &[(0, 0, 64, 100)])], false)), w2(1, 1, prog_frame(&[(&right, &[(64, 0, 86, 100)])], false))]);
        let medium = max_diff(&frame_pixels(&frame, w, h), &want(false));
        // 3. sélection : nouvelles premières passes des tuiles (0, 0) et (1, 0), limitées au
        //    rectangle de sélection, sous un autre identifiant de contexte de codec
        for t in enc.iter_mut().filter(|t| t.y == 0 && t.x < 2) {
            *t = TileEnc::new(t.x, t.y, &desk_tile(t.x as usize, 0, true));
        }
        let sel: Vec<TileOut> = enc.iter_mut().filter(|t| t.y == 0 && t.x < 2).map(|t| t.first(0)).collect();
        send(&mut c, vec![w2(1, 2, prog_frame(&[(&sel, &[(20, 10, 80, 40)])], false))]);
        // 4. améliorations : qualité 1 pour la sélection, puis 2 partout, dans deux régions d'une
        //    même commande (la sélection et le reste)
        let sel: Vec<TileOut> = enc.iter_mut().filter(|t| t.y == 0 && t.x < 2).map(|t| t.upgrade(1)).collect();
        send(&mut c, vec![w2(1, 2, prog_frame(&[(&sel, &[(20, 10, 80, 40)])], false))]);
        let all2: Vec<TileOut> = enc.iter_mut().map(|t| t.upgrade(2)).collect();
        let (a, b) = all2.split_at(3);
        send(&mut c, vec![w2(1, 1, prog_frame(&[(a, &[(0, 0, 150, 64)]), (b, &[(0, 64, 150, 36)])], false))]);
        // 5. pleine qualité
        let fin: Vec<TileOut> = enc.iter_mut().map(|t| t.upgrade(0xFF)).collect();
        send(&mut c, vec![w2(1, 1, prog_frame(&[(&fin, full)], false))]);
        let got = frame_pixels(&frame, w, h);

        // référence : les mêmes tuiles envoyées directement en pleine qualité
        let (mut r, rframe) = ready(Codecs::NoAvc, w as u16, h as u16);
        let simple: Vec<TileOut> = (0..6).map(|i| TileEnc::new((i % 3) as u16, (i / 3) as u16, &desk_tile(i % 3, i / 3, i < 2)).simple()).collect();
        send(&mut r, vec![w2(1, 7, prog_frame(&[(&simple, full)], true))]);
        let reference = frame_pixels(&rframe, w, h);
        let diff = max_diff(&reference, &want(true));
        let mismatch = got.iter().zip(&reference).position(|(a, b)| a != b);
        let fine = max_diff(&got, &want(true));
        println!("écart à l'original : qualité 0 = {coarse}, qualité 1 = {medium}, pleine qualité = {fine} (TILE_SIMPLE : {diff})");
        assert_eq!(mismatch, None, "pixel ({:?}) différent de la pleine qualité directe", mismatch.map(|i| (i % w, i / w)));
        assert!(diff <= 24, "pleine qualité directe trop loin de l'original : {diff}");
        assert!(fine < medium.max(1) || medium == 0, "{fine} / {medium}");
    }

    /// Quantification de base minimale (1 : aucun décalage) : après les passes d'amélioration, la
    /// tuile ne s'écarte de l'image d'origine que des arrondis de la DWT et des couleurs.
    #[test]
    fn progressive_upgrades_reach_the_original_image() {
        let (mut c, frame) = ready(Codecs::NoAvc, 64, 64);
        let base = cq(1, 1, 1, 1);
        let mut t = TileEnc::with_base(0, 0, &desk_tile(0, 0, true), &base);
        let full: &[(u16, u16, u16, u16)] = &[(0, 0, 64, 64)];
        let want: Vec<[u8; 3]> = (0..64 * 64).map(|i| desk(i % 64, i / 64, true)).collect();
        let mut errors = Vec::new();
        let first = [t.first(0)];
        send(&mut c, vec![w2(1, 3, prog_frame_base(&[(&first, full)], true, base))]);
        errors.push(max_diff(&frame_pixels(&frame, 64, 64), &want));
        for q in [1, 2, 0xFF] {
            let up = [t.upgrade(q)];
            send(&mut c, vec![w2(1, 3, prog_frame_base(&[(&up, full)], false, base))]);
            errors.push(max_diff(&frame_pixels(&frame, 64, 64), &want));
        }
        println!("écarts successifs : {errors:?}");
        assert!(errors.windows(2).all(|e| e[1] <= e[0]), "{errors:?}");
        assert!(errors[3] <= 3, "{errors:?}");
    }

    /// Couleurs : conversion YCbCr 11.5 -> RVB identique à FreeRDP (general_yCbCrToRGB_16s8u_P3AC4R,
    /// constantes ycbcr_constants[16]) ; une tuile uniforme (seul LL3 non nul) garde ses valeurs
    /// à travers la DWT.
    #[test]
    fn progressive_colors_match_freerdp() {
        let freerdp = |y: i32, cb: i32, cr: i32| -> [u8; 3] {
            let yy = (y + 4096) << 16;
            let clip = |v: i32| v.clamp(0, 255) as u8;
            [clip(((cr * 91916 + yy) >> 16) >> 5), clip(((yy - cb * 22527 - cr * 46819) >> 16) >> 5), clip(((cb * 115992 + yy) >> 16) >> 5)]
        };
        for (y, cb, cr) in [(1000i16, -1500i16, 2000i16), (-3000, 1200, -900), (4000, 0, 0), (-4096, 30, -30), (2500, 2500, -2500)] {
            let (mut c, frame) = ready(Codecs::NoAvc, 64, 64);
            let dc = |v: i16| -> Vec<u8> {
                let mut w = [0i16; 4096];
                w[4015] = v; // LL3 différentiel : première valeur, les suivantes identiques
                TileEnc::rlgr(&w)
            };
            let quant = Cq { ll3: 1, ..PQ_BASE };
            let data = {
                use ironrdp_pdu::codecs::rfx::RfxRectangle;
                use ironrdp_pdu::codecs::rfx::progressive::*;
                let (yd, cbd, crd) = (dc(y), dc(cb), dc(cr));
                let region = ProgressiveRegion {
                    tile_size: 0x40,
                    rects: vec![RfxRectangle { x: 0, y: 0, width: 64, height: 64 }],
                    quant_vals: vec![quant],
                    quant_prog_vals: vec![],
                    flags: 1,
                    tiles: vec![ProgressiveTile::Simple(TileSimple { quant_idx_y: 0, quant_idx_cb: 0, quant_idx_cr: 0, x_idx: 0, y_idx: 0, flags: 0, y_data: &yd, cb_data: &cbd, cr_data: &crd, tail_data: &[] })],
                };
                encode_progressive_stream(&[ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu { frame_index: 0, region_count: 1 }), ProgressiveBlock::Region(region), ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu)]).unwrap()
            };
            send(&mut c, vec![w2(1, 1, data)]);
            let want = freerdp(y.into(), cb.into(), cr.into());
            for (x, yy) in [(0, 0), (31, 17), (63, 63)] {
                let p = px(&frame, x, yy);
                assert_eq!([p.r(), p.g(), p.b()], want, "Y {y} Cb {cb} Cr {cr} en ({x}, {yy})");
            }
        }
    }

    /// Coefficients extrêmes : la DWT inverse sature comme FreeRDP (clampi16) au lieu de
    /// déborder ; un débordement donnait des pixels noirs au milieu d'une zone blanche.
    #[test]
    fn progressive_dwt_saturates_instead_of_wrapping() {
        let (mut c, frame) = ready(Codecs::NoAvc, 64, 64);
        let mut w = [0i16; 4096];
        w[4015] = 30000; // LL3 (Y) uniforme
        for v in &mut w[3807..3879] {
            *v = 16000; // HL3
        }
        let yd = TileEnc::rlgr(&w);
        let zero = TileEnc::rlgr(&[0i16; 4096]);
        let data = {
            use ironrdp_pdu::codecs::rfx::RfxRectangle;
            use ironrdp_pdu::codecs::rfx::progressive::*;
            let region = ProgressiveRegion {
                tile_size: 0x40,
                rects: vec![RfxRectangle { x: 0, y: 0, width: 64, height: 64 }],
                quant_vals: vec![Cq { ll3: 1, hl3: 1, ..PQ_BASE }],
                quant_prog_vals: vec![],
                flags: 1,
                tiles: vec![ProgressiveTile::Simple(TileSimple { quant_idx_y: 0, quant_idx_cb: 0, quant_idx_cr: 0, x_idx: 0, y_idx: 0, flags: 0, y_data: &yd, cb_data: &zero, cr_data: &zero, tail_data: &[] })],
            };
            encode_progressive_stream(&[ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu { frame_index: 0, region_count: 1 }), ProgressiveBlock::Region(region), ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu)]).unwrap()
        };
        send(&mut c, vec![w2(1, 1, data)]);
        let dark = frame_pixels(&frame, 64, 64).iter().filter(|p| p.r() < 200).count();
        assert_eq!(dark, 0, "pixels sombres dans une tuile saturée en blanc");
    }

    /// Générateur pseudo-aléatoire (xorshift) à graine fixe : tests reproductibles.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        /// Coordonnée : le plus souvent petite, parfois extrême.
        fn coord(&mut self) -> u16 {
            match self.below(10) {
                0 => u16::MAX,
                1 => self.next() as u16,
                _ => self.below(140) as u16,
            }
        }

        fn rect(&mut self) -> ExclusiveRectangle {
            rect(self.coord(), self.coord(), self.coord(), self.coord())
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }

        /// Copie abîmée d'un message valide : octets modifiés, tronquée ou rallongée.
        fn mutate(&mut self, data: &[u8]) -> Vec<u8> {
            let mut d = data.to_vec();
            for _ in 0..1 + self.below(6) {
                if d.is_empty() {
                    break;
                }
                let i = self.below(d.len() as u64) as usize;
                match self.below(4) {
                    0 => d[i] = self.next() as u8,
                    1 => d[i] ^= 1 << self.below(8),
                    2 => d.truncate(i),
                    _ => d[i] = [0, 0xFF, 0x7F, 0x80][self.below(4) as usize],
                }
            }
            d
        }
    }

    /// Mini-fuzz : des milliers de commandes RDPGFX aléatoires, abîmées ou tronquées (graine fixe).
    /// Aucune panique, aucun blocage, et le canal répond toujours.
    #[test]
    fn fuzz_gfx_commands() {
        use ironrdp_dvc::DvcProcessor as _;
        use ironrdp_egfx::pdu::*;
        let (mut c, _frame) = ready(Codecs::Avc444, 128, 96);
        // graines valides de chaque codec
        let mut e = encoder();
        let idr = h264(&mut e, solid_i420(32, 32, RED), 32, 32);
        let p = h264(&mut e, solid_i420(32, 32, BLUE), 32, 32);
        let r: &[(u16, u16, u16, u16)] = &[(0, 0, 32, 32)];
        let seeds: Vec<(Codec1Type, Vec<u8>)> = vec![
            (Codec1Type::Avc420, avc420(&idr, r)),
            (Codec1Type::Avc420, avc420(&p, r)),
            (Codec1Type::Avc444, avc444(Encoding::LUMA_AND_CHROMA, (&idr, r), Some((&p, r)))),
            (Codec1Type::Avc444v2, avc444(Encoding::CHROMA, (&p, r), None)),
            (Codec1Type::ClearCodec, vec![0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 10, 4, 5, 6, 0xFF]),
            (Codec1Type::Planar, vec![0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0]),
            (Codec1Type::Uncompressed, vec![0x40; 64]),
        ];
        let tile: Vec<u8> = (0..64 * 64 * 4).map(|i| (i * 7) as u8).collect();
        let prog = progressive_tile(&tile, 1, 1, vec![(0, 0, 64, 64)]);
        // ESCALE_FUZZ=<itérations> : campagne plus longue, graine tirée de l'horloge et affichée
        let (iterations, seed) = match std::env::var("ESCALE_FUZZ").ok().and_then(|n| n.parse().ok()) {
            Some(n) => (n, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 | 1),
            None => (4000, 0x5EED_CAFE_F00D_1234),
        };
        println!("graine {seed:#x}");
        let mut rng = Rng(seed);
        let ts = Timestamp { milliseconds: 0, seconds: 0, minutes: 0, hours: 0 };
        for _ in 0..iterations {
            let mut pdus = Vec::new();
            for _ in 0..1 + rng.below(4) {
                let sid = rng.below(4) as u16;
                let pdu = match rng.below(17) {
                    0 => GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: sid, width: rng.coord().min(300), height: rng.coord().min(300), pixel_format: PixelFormat::XRgb }),
                    1 => GfxPdu::DeleteSurface(DeleteSurfacePdu { surface_id: sid }),
                    2 => GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: sid, output_origin_x: rng.coord().into(), output_origin_y: rng.coord().into() }),
                    3 => GfxPdu::SolidFill(SolidFillPdu { surface_id: sid, fill_pixel: Color { b: 1, g: 2, r: 3, xa: 0 }, rectangles: vec![rng.rect(), rng.rect()] }),
                    4 => GfxPdu::SurfaceToSurface(SurfaceToSurfacePdu {
                        source_surface_id: sid,
                        destination_surface_id: rng.below(4) as u16,
                        source_rectangle: rng.rect(),
                        destination_points: vec![Point { x: rng.coord(), y: rng.coord() }],
                    }),
                    5 => GfxPdu::SurfaceToCache(SurfaceToCachePdu { surface_id: sid, cache_key: rng.next(), cache_slot: rng.coord(), source_rectangle: rng.rect() }),
                    6 => GfxPdu::CacheToSurface(CacheToSurfacePdu { cache_slot: rng.coord(), surface_id: sid, destination_points: vec![Point { x: rng.coord(), y: rng.coord() }] }),
                    7 => GfxPdu::EvictCacheEntry(EvictCacheEntryPdu { cache_slot: rng.coord() }),
                    8 | 9 | 10 => {
                        let (codec, seed) = &seeds[rng.below(seeds.len() as u64) as usize];
                        let data = if rng.below(4) == 0 { seed.clone() } else { rng.mutate(seed) };
                        w1(sid, *codec, (rng.coord(), rng.coord(), rng.coord(), rng.coord()), data)
                    }
                    11 => {
                        let n = rng.below(64) as usize;
                        let codec = [Codec1Type::ClearCodec, Codec1Type::Planar, Codec1Type::Alpha, Codec1Type::Avc420, Codec1Type::Avc444][rng.below(5) as usize];
                        w1(sid, codec, (rng.coord(), rng.coord(), rng.coord(), rng.coord()), rng.bytes(n))
                    }
                    12 | 13 => {
                        let data = if rng.below(4) == 0 { prog.clone() } else { rng.mutate(&prog) };
                        w2(sid, rng.below(3) as u32, data)
                    }
                    14 => GfxPdu::ResetGraphics(ResetGraphicsPdu { width: rng.below(200) as u32 + 1, height: rng.below(200) as u32 + 1, monitors: vec![] }),
                    15 => GfxPdu::DeleteEncodingContext(DeleteEncodingContextPdu { surface_id: sid, codec_context_id: rng.below(3) as u32 }),
                    _ => GfxPdu::StartFrame(StartFramePdu { timestamp: ts, frame_id: rng.next() as u32 }),
                };
                pdus.push(pdu);
            }
            pdus.push(GfxPdu::EndFrame(EndFramePdu { frame_id: 1 }));
            let mut raw = Vec::new();
            for p in &pdus {
                raw.extend(ironrdp_core::encode_vec(p).unwrap());
            }
            let n = pdus.len();
            match rng.below(8) {
                // message abîmé au niveau des en-têtes RDPGFX
                0 => {
                    let raw = rng.mutate(&raw);
                    let _ = c.process(1, &ironrdp_graphics::zgfx::wrap_uncompressed(&raw));
                }
                // octets quelconques (ZGFX invalide)
                1 => {
                    let n = rng.below(80) as usize;
                    let _ = c.process(1, &rng.bytes(n));
                }
                _ => {
                    let out = c.process(1, &ironrdp_graphics::zgfx::wrap_uncompressed(&raw)).unwrap();
                    assert_eq!(out.len(), 1, "accusé de réception après {n} commandes : {pdus:?}");
                }
            }
        }
    }

    /// Décompresseur ZGFX (en amont de toutes les commandes) : flux compressés abîmés, segments
    /// tronqués, longueurs et distances hostiles. Aucune panique, et rien de démesuré en sortie.
    #[test]
    fn fuzz_zgfx() {
        use ironrdp_graphics::zgfx::{Compressor, Decompressor, wrap_compressed};
        let text: Vec<u8> = b"RDPGFX ZGFX ".iter().cycle().take(3000).copied().chain((0..2000u32).map(|i| (i * 31 % 251) as u8)).collect();
        let mut comp = Compressor::new();
        let seeds: Vec<Vec<u8>> = vec![
            wrap_compressed(&comp.compress(&text).unwrap()),
            wrap_compressed(&comp.compress(&text[100..900]).unwrap()),
            ironrdp_graphics::zgfx::wrap_uncompressed(&text),
        ];
        let mut rng = Rng(0xA11CE);
        let mut d = Decompressor::new();
        let mut out = Vec::new();
        for _ in 0..5000 {
            let seed = &seeds[rng.below(seeds.len() as u64) as usize];
            let n = rng.below(40) as usize;
            let data = if rng.below(10) == 0 { rng.bytes(n) } else { rng.mutate(seed) };
            out.clear();
            let _ = d.decompress(&data, &mut out);
            assert!(out.len() <= 256 * 1024 * 1024, "sortie démesurée : {} octets", out.len());
        }
        let mut d = Decompressor::new();
        out.clear();
        d.decompress(&seeds[0], &mut out).unwrap();
        assert_eq!(out, text);
    }

    /// Commandes hostiles : dimensions démesurées, rectangles inversés ou hors limites, surfaces
    /// inconnues, supprimées puis recréées. Rien ne doit paniquer ni allouer des gigaoctets.
    #[test]
    fn hostile_commands_are_contained() {
        use ironrdp_egfx::pdu::*;
        let (mut c, frame) = ready(Codecs::Avc444, 64, 64);
        let red = || Color { b: 0, g: 0, r: 255, xa: 0 };
        // surfaces et écran géants : refusés (17 Go et 4 Go de pixels sinon)
        send(
            &mut c,
            vec![
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 9, width: u16::MAX, height: u16::MAX, pixel_format: PixelFormat::XRgb }),
                GfxPdu::SolidFill(SolidFillPdu { surface_id: 9, fill_pixel: red(), rectangles: vec![rect(0, 0, u16::MAX, u16::MAX)] }),
                GfxPdu::DeleteSurface(DeleteSurfacePdu { surface_id: 9 }),
            ],
        );
        send(&mut c, vec![GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 32766, height: 32766, monitors: vec![] })]);
        send(
            &mut c,
            vec![
                GfxPdu::ResetGraphics(ResetGraphicsPdu { width: 64, height: 64, monitors: vec![] }),
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 1, width: 64, height: 64, pixel_format: PixelFormat::XRgb }),
                GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 1, output_origin_x: 0, output_origin_y: 0 }),
                GfxPdu::CreateSurface(CreateSurfacePdu { surface_id: 2, width: 8, height: 8, pixel_format: PixelFormat::XRgb }),
                GfxPdu::MapSurfaceToOutput(MapSurfaceToOutputPdu { surface_id: 2, output_origin_x: u32::MAX, output_origin_y: 60 }),
                GfxPdu::SolidFill(SolidFillPdu { surface_id: 1, fill_pixel: red(), rectangles: vec![rect(10, 10, 5, 5), rect(60, 60, u16::MAX, u16::MAX), rect(u16::MAX, 0, 0, u16::MAX)] }),
                GfxPdu::SurfaceToSurface(SurfaceToSurfacePdu {
                    source_surface_id: 1,
                    destination_surface_id: 2,
                    source_rectangle: rect(0, 0, u16::MAX, u16::MAX),
                    destination_points: vec![Point { x: 4, y: 4 }, Point { x: u16::MAX, y: u16::MAX }],
                }),
                GfxPdu::SurfaceToSurface(SurfaceToSurfacePdu { source_surface_id: 1, destination_surface_id: 1, source_rectangle: rect(50, 50, 10, 10), destination_points: vec![Point { x: 0, y: 0 }] }),
                GfxPdu::SurfaceToCache(SurfaceToCachePdu { surface_id: 1, cache_key: 1, cache_slot: u16::MAX, source_rectangle: rect(32, 32, u16::MAX, u16::MAX) }),
                GfxPdu::CacheToSurface(CacheToSurfacePdu { cache_slot: u16::MAX, surface_id: 1, destination_points: vec![Point { x: 63, y: 63 }, Point { x: u16::MAX, y: 0 }] }),
                GfxPdu::CacheToSurface(CacheToSurfacePdu { cache_slot: 7, surface_id: 1, destination_points: vec![Point { x: 0, y: 0 }] }),
                GfxPdu::EvictCacheEntry(EvictCacheEntryPdu { cache_slot: 12 }),
            ],
        );
        assert_eq!(px(&frame, 62, 62), Color32::from_rgb(255, 0, 0));
        assert_eq!(px(&frame, 5, 5), Color32::BLACK);
        // rectangles de destination démesurés : ClearCodec et Planar alloueraient 17 Go
        let mut clear = vec![0u8, 0];
        clear.extend_from_slice(&[0; 12]);
        send(
            &mut c,
            vec![
                w1(1, Codec1Type::ClearCodec, (0, 0, u16::MAX, u16::MAX), clear),
                w1(1, Codec1Type::Planar, (0, 0, u16::MAX, u16::MAX), vec![0x20, 0, 0, 0]),
                w1(1, Codec1Type::Uncompressed, (0, 0, u16::MAX, u16::MAX), vec![0; 16]),
                w1(1, Codec1Type::Avc420, (0, 0, u16::MAX, u16::MAX), avc420(&[0, 0, 0, 1, 0x65], &[(0, 0, u16::MAX, u16::MAX)])),
                w1(1, Codec1Type::Avc444, (40, 40, 10, 10), avc444(Encoding::CHROMA, (&[], &[(0, 0, 1, 1)]), None)),
                w2(1, 5, vec![0xC0, 0xCC, 6, 0, 0, 0]),
            ],
        );
        // ClearCodec : sous-codec NSCodec annoncé bien plus grand que la zone
        let mut sub = Vec::new();
        for v in [0u16, 0, u16::MAX, u16::MAX] {
            sub.extend_from_slice(&v.to_le_bytes());
        }
        let ns = [0u8; 16].iter().copied().chain([1, 0, 0, 0]).collect::<Vec<u8>>();
        sub.extend_from_slice(&(ns.len() as u32).to_le_bytes());
        sub.push(1);
        sub.extend_from_slice(&ns);
        let mut clear = vec![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        clear.extend_from_slice(&(sub.len() as u32).to_le_bytes());
        clear.extend_from_slice(&sub);
        send(&mut c, vec![w1(1, Codec1Type::ClearCodec, (0, 0, 8, 8), clear)]);
        // l'affichage continue
        send(&mut c, vec![GfxPdu::SolidFill(SolidFillPdu { surface_id: 1, fill_pixel: red(), rectangles: vec![rect(0, 0, 2, 2)] })]);
        assert_eq!(px(&frame, 1, 1), Color32::from_rgb(255, 0, 0));
    }

    /// Rejoue un enregistrement (`ESCALE_GFX_CAPTURE`) et écrit l'image finale en PPM :
    /// `ESCALE_GFX_REPLAY=capture.bin cargo test replay_capture -- --ignored`
    #[test]
    #[ignore]
    fn replay_capture() {
        use ironrdp_dvc::DvcProcessor as _;
        let path = std::env::var("ESCALE_GFX_REPLAY").expect("ESCALE_GFX_REPLAY");
        let data = std::fs::read(&path).unwrap();
        let frame: SharedFrame = Arc::new(Mutex::new(Frame::new()));
        let (events, _rx) = Events::new(eframe::egui::Context::default());
        let mut c = client(frame.clone(), events, Default::default(), Codecs::Avc444);
        let _ = c.start(1);
        let (mut i, mut n) = (0, 0);
        while i + 4 <= data.len() {
            let len = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            let msg = &data[i + 4..(i + 4 + len).min(data.len())];
            let _ = c.process(1, msg);
            i += 4 + len;
            n += 1;
        }
        let f = frame.lock().unwrap();
        let mut ppm = format!("P6\n{} {}\n255\n", f.width, f.height).into_bytes();
        for p in &f.pixels {
            ppm.extend_from_slice(&[p.r(), p.g(), p.b()]);
        }
        std::fs::write(format!("{path}.ppm"), ppm).unwrap();
        println!("{n} messages rejoués, image {}x{}", f.width, f.height);
    }
}
