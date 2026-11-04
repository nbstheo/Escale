//! Décodeur ClearCodec (MS-RDPEGFX 2.2.4.1), le codec sans perte de Windows pour le texte, les
//! icônes et les fenêtres. Écrit pour Escale d'après la spécification (et le comportement de
//! FreeRDP) : celui d'IronRDP lit mal les V-bars, ignore NSCodec et rejetait presque tous les
//! messages de Windows.
//!
//! Les couches se peignent sur le contenu existant de la zone : résidu (aplats BGR), bandes de
//! colonnes (V-bars, avec leurs caches), puis sous-codecs (brut, NSCodec, RLEX).

const FLAG_GLYPH_INDEX: u8 = 0x01;
const FLAG_GLYPH_HIT: u8 = 0x02;
const FLAG_CACHE_RESET: u8 = 0x04;

const VBAR_CACHE_SIZE: usize = 32768;
const SHORT_VBAR_CACHE_SIZE: usize = 16384;
const GLYPH_CACHE_SIZE: usize = 4000;
/// Taille maximale d'un glyphe (celle de FreeRDP).
const MAX_GLYPH_PIXELS: usize = 1024 * 1024;
/// Plafond de l'ensemble du cache de glyphes (64 Mo) contre un serveur hostile.
const MAX_GLYPH_CACHE_PIXELS: usize = 16 * 1024 * 1024;
/// Hauteur maximale d'une bande (et donc d'une V-bar).
const MAX_BAND_HEIGHT: usize = 52;

#[derive(Debug)]
pub struct ClearError(&'static str);

impl std::fmt::Display for ClearError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClearCodec : {}", self.0)
    }
}

type Result<T> = std::result::Result<T, ClearError>;

/// Lecture séquentielle petit-boutiste.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(ClearError("données tronquées"));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Longueur de répétition : un octet, prolongé en u16 puis u32 si saturé.
    fn run_length(&mut self) -> Result<usize> {
        let mut n = u32::from(self.u8()?);
        if n == 0xFF {
            n = u32::from(self.u16()?);
            if n == 0xFFFF {
                n = self.u32()?;
            }
        }
        Ok(n as usize)
    }
}

/// Zone de destination : pixels BGRA (4 octets), déjà remplis avec le contenu actuel.
struct Canvas<'a> {
    px: &'a mut [u8],
    w: usize,
    h: usize,
}

impl Canvas<'_> {
    fn set(&mut self, x: usize, y: usize, bgr: [u8; 3]) {
        if x < self.w && y < self.h {
            let o = (y * self.w + x) * 4;
            self.px[o..o + 4].copy_from_slice(&[bgr[0], bgr[1], bgr[2], 0xFF]);
        }
    }
}

pub struct ClearDecoder {
    vbars: Vec<Vec<[u8; 3]>>,
    vbar_cursor: usize,
    short_vbars: Vec<Vec<[u8; 3]>>,
    short_cursor: usize,
    glyphs: Vec<Option<(usize, usize, Vec<u8>)>>,
    /// Pixels en cache de glyphes (plafonnés).
    glyph_pixels: usize,
}

impl Default for ClearDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClearDecoder {
    pub fn new() -> Self {
        Self {
            vbars: vec![Vec::new(); VBAR_CACHE_SIZE],
            vbar_cursor: 0,
            short_vbars: vec![Vec::new(); SHORT_VBAR_CACHE_SIZE],
            short_cursor: 0,
            glyphs: vec![None; GLYPH_CACHE_SIZE],
            glyph_pixels: 0,
        }
    }

    /// Décode un message dans `dst` (BGRA, `w`×`h`, contenu actuel de la zone).
    pub fn decode(&mut self, data: &[u8], w: usize, h: usize, dst: &mut [u8]) -> Result<()> {
        if dst.len() < w * h * 4 {
            return Err(ClearError("zone de destination trop petite"));
        }
        let mut r = Reader::new(data);
        let flags = r.u8()?;
        let _seq = r.u8()?;
        if flags & FLAG_CACHE_RESET != 0 {
            self.vbar_cursor = 0;
            self.short_cursor = 0;
        }
        let glyph = if flags & FLAG_GLYPH_INDEX != 0 {
            let i = usize::from(r.u16()?);
            if i >= GLYPH_CACHE_SIZE {
                return Err(ClearError("indice de glyphe invalide"));
            }
            Some(i)
        } else {
            None
        };
        if flags & FLAG_GLYPH_HIT != 0 {
            let i = glyph.ok_or(ClearError("glyphe sans indice"))?;
            let (gw, gh, px) = self.glyphs[i].as_ref().ok_or(ClearError("glyphe absent du cache"))?;
            for y in 0..h.min(*gh) {
                let n = w.min(*gw) * 4;
                dst[y * w * 4..][..n].copy_from_slice(&px[y * gw * 4..][..n]);
            }
            // comme FreeRDP : un contenu peut suivre le glyphe rappelé (rien en pratique)
            if r.remaining() < 12 {
                return Ok(());
            }
        }

        let residual_len = r.u32()? as usize;
        let bands_len = r.u32()? as usize;
        let subcodec_len = r.u32()? as usize;
        let residual = r.bytes(residual_len)?;
        let bands = r.bytes(bands_len)?;
        let subcodecs = r.bytes(subcodec_len)?;

        let mut canvas = Canvas { px: &mut dst[..w * h * 4], w, h };
        if !residual.is_empty() {
            decode_residual(residual, &mut canvas)?;
        }
        if !bands.is_empty() {
            self.decode_bands(bands, &mut canvas)?;
        }
        if !subcodecs.is_empty() {
            decode_subcodecs(subcodecs, &mut canvas)?;
        }

        // la spécification limite les glyphes à 1024 pixels, mais FreeRDP (et donc ce que Windows
        // peut envoyer sans casser ce client de référence) accepte jusqu'à 1024×1024. L'entrée est
        // toujours remplacée : un ancien glyphe de même indice serait sinon rejoué à tort.
        if let Some(i) = glyph.filter(|_| flags & FLAG_GLYPH_HIT == 0) {
            let freed = self.glyphs[i].take().map_or(0, |g| g.0 * g.1);
            self.glyph_pixels -= freed;
            if w * h <= MAX_GLYPH_PIXELS && self.glyph_pixels + w * h <= MAX_GLYPH_CACHE_PIXELS {
                self.glyphs[i] = Some((w, h, dst[..w * h * 4].to_vec()));
                self.glyph_pixels += w * h;
            }
        }
        Ok(())
    }

    fn decode_bands(&mut self, data: &[u8], c: &mut Canvas<'_>) -> Result<()> {
        let mut r = Reader::new(data);
        while r.remaining() > 0 {
            let x_start = usize::from(r.u16()?);
            let x_end = usize::from(r.u16()?);
            let y_start = usize::from(r.u16()?);
            let y_end = usize::from(r.u16()?);
            let bkg = {
                let b = r.bytes(3)?;
                [b[0], b[1], b[2]]
            };
            if x_end < x_start || y_end < y_start {
                return Err(ClearError("bande invalide"));
            }
            let height = y_end - y_start + 1;
            if height > MAX_BAND_HEIGHT {
                return Err(ClearError("bande trop haute"));
            }
            for x in x_start..=x_end {
                let header = r.u16()?;
                let index = match header & 0xC000 {
                    // VBAR_CACHE_HIT
                    0x8000 | 0xC000 => usize::from(header & 0x7FFF),
                    // SHORT_VBAR_CACHE_HIT
                    0x4000 => {
                        let short = usize::from(header & 0x3FFF);
                        let y_on = usize::from(r.u8()?);
                        self.store_vbar(short, y_on, height, bkg)
                    }
                    // SHORT_VBAR_CACHE_MISS
                    _ => {
                        let y_on = usize::from(header & 0xFF);
                        let y_off = usize::from((header >> 8) & 0x3F);
                        if y_off < y_on {
                            return Err(ClearError("V-bar courte invalide"));
                        }
                        let px = r.bytes((y_off - y_on) * 3)?;
                        let slot = self.short_cursor;
                        self.short_vbars[slot] = px.as_chunks::<3>().0.to_vec();
                        self.short_cursor = (self.short_cursor + 1) % SHORT_VBAR_CACHE_SIZE;
                        self.store_vbar(slot, y_on, height, bkg)
                    }
                };
                let vbar = self.vbars.get(index).ok_or(ClearError("indice de V-bar invalide"))?;
                for (dy, p) in vbar.iter().take(height).enumerate() {
                    c.set(x, y_start + dy, *p);
                }
            }
        }
        Ok(())
    }

    /// Reconstitue une V-bar complète (fond, pixels de la V-bar courte à partir de `y_on`, fond)
    /// et la range dans le cache ; renvoie son indice.
    fn store_vbar(&mut self, short: usize, y_on: usize, height: usize, bkg: [u8; 3]) -> usize {
        let mut full = vec![bkg; height];
        if let Some(s) = self.short_vbars.get(short) {
            for (i, p) in s.iter().enumerate() {
                if let Some(slot) = full.get_mut(y_on + i) {
                    *slot = *p;
                }
            }
        }
        let slot = self.vbar_cursor;
        self.vbars[slot] = full;
        self.vbar_cursor = (self.vbar_cursor + 1) % VBAR_CACHE_SIZE;
        slot
    }
}

fn decode_residual(data: &[u8], c: &mut Canvas<'_>) -> Result<()> {
    let mut r = Reader::new(data);
    let total = c.w * c.h;
    let mut i = 0;
    while r.remaining() > 0 && i < total {
        let b = r.bytes(3)?;
        let color = [b[0], b[1], b[2]];
        let n = r.run_length()?.min(total - i);
        for p in i..i + n {
            c.set(p % c.w, p / c.w, color);
        }
        i += n;
    }
    Ok(())
}

fn decode_subcodecs(data: &[u8], c: &mut Canvas<'_>) -> Result<()> {
    let mut r = Reader::new(data);
    while r.remaining() > 0 {
        let x0 = usize::from(r.u16()?);
        let y0 = usize::from(r.u16()?);
        let w = usize::from(r.u16()?);
        let h = usize::from(r.u16()?);
        let len = r.u32()? as usize;
        let id = r.u8()?;
        let bitmap = r.bytes(len)?;
        // le sous-codec doit tenir dans la zone (comme FreeRDP) : NSCodec alloue ses plans
        // d'après ces dimensions
        if x0 + w > c.w || y0 + h > c.h {
            return Err(ClearError("sous-codec hors de la zone"));
        }
        let mut put = |i: usize, bgr: [u8; 3]| c.set(x0 + i % w.max(1), y0 + i / w.max(1), bgr);
        match id {
            // brut : BGR 24 bits
            0 => {
                if bitmap.len() < w * h * 3 {
                    return Err(ClearError("sous-codec brut tronqué"));
                }
                for (i, p) in bitmap.as_chunks::<3>().0.iter().take(w * h).enumerate() {
                    put(i, *p);
                }
            }
            1 => {
                for (i, p) in nscodec(bitmap, w, h)?.as_chunks::<4>().0.iter().enumerate() {
                    put(i, [p[0], p[1], p[2]]);
                }
            }
            2 => rlex(bitmap, w * h, &mut put)?,
            _ => return Err(ClearError("sous-codec inconnu")),
        }
    }
    Ok(())
}

/// RLEX : palette puis segments (répétition d'une couleur suivie d'une « suite » de couleurs
/// consécutives de la palette).
fn rlex(data: &[u8], total: usize, put: &mut impl FnMut(usize, [u8; 3])) -> Result<()> {
    let mut r = Reader::new(data);
    let count = usize::from(r.u8()?);
    if count == 0 || count > 127 {
        return Err(ClearError("palette RLEX invalide"));
    }
    let palette: Vec<[u8; 3]> = r.bytes(count * 3)?.as_chunks::<3>().0.to_vec();
    // bits nécessaires pour un indice de palette
    let bits = (usize::BITS - (count - 1).leading_zeros()).max(1);
    let mut i = 0;
    while r.remaining() > 0 && i < total {
        let packed = u32::from(r.u8()?);
        let stop = (packed & ((1 << bits) - 1)) as usize;
        let depth = ((packed >> bits) & ((1 << (8 - bits)) - 1)) as usize;
        let start = stop.checked_sub(depth).ok_or(ClearError("segment RLEX invalide"))?;
        if stop >= count {
            return Err(ClearError("indice RLEX hors palette"));
        }
        let run = r.run_length()?;
        for _ in 0..run.min(total - i) {
            put(i, palette[start]);
            i += 1;
        }
        for color in &palette[start..=stop] {
            if i >= total {
                break;
            }
            put(i, *color);
            i += 1;
        }
    }
    Ok(())
}

/// NSCodec (MS-RDPNSC) : plans luminance / chrominance (YCoCg) compressés en RLE, chrominance
/// éventuellement sous-échantillonnée et à précision réduite. Renvoie du BGRA.
fn nscodec(data: &[u8], w: usize, h: usize) -> Result<Vec<u8>> {
    let mut r = Reader::new(data);
    let lens = [r.u32()? as usize, r.u32()? as usize, r.u32()? as usize, r.u32()? as usize];
    let loss = r.u8()?;
    let subsampling = r.u8()? != 0;
    let _reserved = r.u16()?;
    if !(1..=7).contains(&loss) {
        return Err(ClearError("niveau de perte NSCodec invalide"));
    }
    // largeur de ligne des plans : arrondie à 8 (luminance) en sous-échantillonnage
    let rw = if subsampling { w.div_ceil(8) * 8 } else { w };
    let ch = if subsampling { h.div_ceil(2) } else { h };
    let cw = if subsampling { rw / 2 } else { w };
    let sizes = [rw * h, cw * ch, cw * ch, w * h];
    let mut planes: Vec<Vec<u8>> = Vec::with_capacity(4);
    for (i, &len) in lens.iter().enumerate() {
        let raw = r.bytes(len)?;
        let size = sizes[i];
        planes.push(if len == 0 {
            vec![0xFF; size]
        } else if len < size {
            nsc_rle(raw, size)?
        } else {
            raw[..size].to_vec()
        });
    }
    let shift = u32::from(loss - 1);
    let mut out = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let yv = i32::from(planes[0][y * rw + x]);
            let (cx, cy) = if subsampling { (x / 2, y / 2) } else { (x, y) };
            let co = i32::from(((u32::from(planes[1][cy * cw + cx]) << shift) as u8) as i8);
            let cg = i32::from(((u32::from(planes[2][cy * cw + cx]) << shift) as u8) as i8);
            let a = planes[3][y * w + x];
            let o = (y * w + x) * 4;
            out[o] = (yv - co - cg).clamp(0, 255) as u8;
            out[o + 1] = (yv + cg).clamp(0, 255) as u8;
            out[o + 2] = (yv + co - cg).clamp(0, 255) as u8;
            out[o + 3] = a;
        }
    }
    Ok(out)
}

/// RLE de NSCodec : un octet répété deux fois annonce une répétition ; les 4 derniers octets du
/// plan sont toujours transmis tels quels.
fn nsc_rle(data: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    let mut r = Reader::new(data);
    let mut left = size;
    while left > 4 {
        let value = r.u8()?;
        if left == 5 {
            out.push(value);
            left -= 1;
        } else if r.remaining() > 0 && r.data[r.pos] == value {
            r.pos += 1;
            let mut len = usize::from(r.u8()?);
            if len < 0xFF {
                len += 2;
            } else {
                len = r.u32()? as usize;
            }
            let len = len.min(left);
            out.extend(std::iter::repeat_n(value, len));
            left -= len;
        } else {
            out.push(value);
            left -= 1;
        }
    }
    out.extend_from_slice(r.bytes(left)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u8, residual: &[u8], bands: &[u8], sub: &[u8]) -> Vec<u8> {
        let mut d = vec![flags, 0];
        for part in [residual, bands, sub] {
            d.extend_from_slice(&(part.len() as u32).to_le_bytes());
        }
        for part in [residual, bands, sub] {
            d.extend_from_slice(part);
        }
        d
    }

    #[test]
    fn residual_fills_the_area() {
        // 3 pixels rouges puis 3 bleus (BGR)
        let residual = [0, 0, 255, 3, 255, 0, 0, 3];
        let mut px = vec![0u8; 3 * 2 * 4];
        ClearDecoder::new().decode(&header(0, &residual, &[], &[]), 3, 2, &mut px).unwrap();
        assert_eq!(&px[..4], &[0, 0, 255, 255]);
        assert_eq!(&px[20..], &[255, 0, 0, 255]);
    }

    #[test]
    fn short_vbar_miss_then_cache_hits_draw_columns() {
        // bande x 0..=1, y 0..=3, fond vert ; colonne 0 : V-bar courte (y 1..3, 2 pixels rouges) ;
        // colonne 1 : la même V-bar complète, depuis le cache
        let mut bands = Vec::new();
        for v in [0u16, 1, 0, 3] {
            bands.extend_from_slice(&v.to_le_bytes());
        }
        bands.extend_from_slice(&[0, 255, 0]);
        let miss: u16 = (3 << 8) | 1; // y_on = 1, y_off = 3
        bands.extend_from_slice(&miss.to_le_bytes());
        bands.extend_from_slice(&[0, 0, 255, 0, 0, 255]);
        bands.extend_from_slice(&0x8000u16.to_le_bytes()); // V-bar n° 0
        let mut px = vec![9u8; 2 * 4 * 4];
        ClearDecoder::new().decode(&header(0, &[], &bands, &[]), 2, 4, &mut px).unwrap();
        let at = |x: usize, y: usize| &px[(y * 2 + x) * 4..][..3];
        for x in 0..2 {
            assert_eq!(at(x, 0), &[0, 255, 0]);
            assert_eq!(at(x, 1), &[0, 0, 255]);
            assert_eq!(at(x, 2), &[0, 0, 255]);
            assert_eq!(at(x, 3), &[0, 255, 0]);
        }
    }

    #[test]
    fn untouched_pixels_keep_the_existing_content() {
        let sub = {
            let mut s = Vec::new();
            for v in [1u16, 0, 1, 1] {
                s.extend_from_slice(&v.to_le_bytes());
            }
            s.extend_from_slice(&3u32.to_le_bytes());
            s.push(0);
            s.extend_from_slice(&[1, 2, 3]);
            s
        };
        let mut px = vec![7u8; 2 * 4];
        ClearDecoder::new().decode(&header(0, &[], &[], &sub), 2, 1, &mut px).unwrap();
        assert_eq!(px, [7, 7, 7, 7, 1, 2, 3, 255]);
    }

    #[test]
    fn rlex_runs_and_suites() {
        // palette de 3 couleurs (2 bits) : 2 × couleur 0 puis la suite 0..=2
        let mut sub = Vec::new();
        for v in [0u16, 0, 5, 1] {
            sub.extend_from_slice(&v.to_le_bytes());
        }
        let bitmap = [3, 10, 0, 0, 20, 0, 0, 30, 0, 0, (2 << 2) | 2, 2];
        sub.extend_from_slice(&(bitmap.len() as u32).to_le_bytes());
        sub.push(2);
        sub.extend_from_slice(&bitmap);
        let mut px = vec![0u8; 5 * 4];
        ClearDecoder::new().decode(&header(0, &[], &[], &sub), 5, 1, &mut px).unwrap();
        let blues: Vec<u8> = px.chunks(4).map(|p| p[0]).collect();
        assert_eq!(blues, [10, 10, 10, 20, 30]);
    }

    #[test]
    fn glyph_is_cached_then_replayed() {
        let mut d = ClearDecoder::new();
        let mut data = header(FLAG_GLYPH_INDEX, &[4, 5, 6, 1], &[], &[]);
        data.splice(2..2, 7u16.to_le_bytes());
        let mut px = vec![0u8; 4];
        d.decode(&data, 1, 1, &mut px).unwrap();
        let mut again = vec![0u8; 4];
        let mut hit = vec![FLAG_GLYPH_INDEX | FLAG_GLYPH_HIT, 0];
        hit.extend_from_slice(&7u16.to_le_bytes());
        d.decode(&hit, 1, 1, &mut again).unwrap();
        assert_eq!(again, [4, 5, 6, 255]);
    }

    /// Mini-fuzz (graine fixe) : messages valides abîmés et octets quelconques, zones de toutes
    /// tailles. Aucune panique, et l'état des caches reste utilisable.
    #[test]
    fn fuzz_messages() {
        let mut s = 0x0123_4567_89AB_CDEFu64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        // graines : résidu, bandes + V-bars, sous-codecs brut / RLEX / NSCodec, glyphe
        let mut bands = Vec::new();
        for v in [0u16, 3, 0, 5] {
            bands.extend_from_slice(&v.to_le_bytes());
        }
        bands.extend_from_slice(&[1, 2, 3]);
        bands.extend_from_slice(&((4u16 << 8) | 1).to_le_bytes());
        bands.extend_from_slice(&[9; 9]);
        bands.extend_from_slice(&0x8000u16.to_le_bytes());
        bands.extend_from_slice(&0x4000u16.to_le_bytes());
        bands.push(2);
        bands.extend_from_slice(&0xC001u16.to_le_bytes());
        let mut sub = Vec::new();
        for (id, bitmap) in [(0u8, vec![7u8; 12]), (2, vec![3, 10, 0, 0, 20, 0, 0, 30, 0, 0, 0x0A, 2, 0x05, 0xFF, 4, 0]), (1, {
            let mut b = Vec::new();
            for len in [3u32, 2, 2, 0] {
                b.extend_from_slice(&len.to_le_bytes());
            }
            b.extend_from_slice(&[2, 1, 0, 0, 50, 50, 60, 1, 2, 3, 4]);
            b
        })] {
            for v in [1u16, 1, 2, 2] {
                sub.extend_from_slice(&v.to_le_bytes());
            }
            sub.extend_from_slice(&(bitmap.len() as u32).to_le_bytes());
            sub.push(id);
            sub.extend_from_slice(&bitmap);
        }
        let seeds = [
            header(0, &[1, 2, 3, 0xFF, 0x10, 0, 4, 5, 6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], &bands, &sub),
            header(FLAG_CACHE_RESET, &[], &bands, &[]),
            {
                let mut d = header(FLAG_GLYPH_INDEX, &[4, 5, 6, 9], &[], &sub);
                d.splice(2..2, 3u16.to_le_bytes());
                d
            },
            vec![FLAG_GLYPH_INDEX | FLAG_GLYPH_HIT, 0, 3, 0],
        ];
        let mut d = ClearDecoder::new();
        let mut px = Vec::new();
        for _ in 0..20000 {
            let (w, h) = (1 + (next() % 20) as usize, 1 + (next() % 20) as usize);
            px.clear();
            px.resize(w * h * 4, 0);
            let mut data = if next() % 5 == 0 {
                (0..next() % 64).map(|_| next() as u8).collect()
            } else {
                seeds[(next() % seeds.len() as u64) as usize].clone()
            };
            for _ in 0..next() % 5 {
                if data.is_empty() {
                    break;
                }
                let i = (next() % data.len() as u64) as usize;
                match next() % 4 {
                    0 => data[i] = next() as u8,
                    1 => data.truncate(i),
                    2 => data[i] = 0xFF,
                    _ => data[i] ^= 0x80,
                }
            }
            let _ = d.decode(&data, w, h, &mut px);
        }
        // le décodeur fonctionne toujours
        let mut px = vec![0u8; 3 * 2 * 4];
        d.decode(&header(0, &[0, 0, 255, 6], &[], &[]), 3, 2, &mut px).unwrap();
        assert_eq!(&px[20..], &[0, 0, 255, 255]);
    }

    /// Un sous-codec ne peut pas déborder de la zone décodée (sinon NSCodec allouerait des
    /// gigaoctets pour un rectangle annoncé de 65535×65535).
    #[test]
    fn subcodec_outside_the_area_is_rejected() {
        let mut sub = Vec::new();
        for v in [0u16, 0, u16::MAX, u16::MAX] {
            sub.extend_from_slice(&v.to_le_bytes());
        }
        let ns: Vec<u8> = [0u8; 16].into_iter().chain([1, 0, 0, 0]).collect();
        sub.extend_from_slice(&(ns.len() as u32).to_le_bytes());
        sub.push(1);
        sub.extend_from_slice(&ns);
        let mut px = vec![0u8; 4 * 4 * 4];
        assert!(ClearDecoder::new().decode(&header(0, &[], &[], &sub), 4, 4, &mut px).is_err());
        // brut 2×2 posé en (3, 3) d'une zone 4×4 : dépasse aussi
        let mut sub = Vec::new();
        for v in [3u16, 3, 2, 2] {
            sub.extend_from_slice(&v.to_le_bytes());
        }
        sub.extend_from_slice(&12u32.to_le_bytes());
        sub.push(0);
        sub.extend_from_slice(&[1; 12]);
        assert!(ClearDecoder::new().decode(&header(0, &[], &[], &sub), 4, 4, &mut px).is_err());
    }

    // Exemples de MS-RDPEGFX 4.1.1.1 (flux capturés de Windows, repris par FreeRDP dans
    // TestFreeRDPCodecClear.c, octet nul final compris comme dans ce test).
    const EXAMPLE_1: &[u8] = b"\x03\xc3\x11\x00\x00";
    const EXAMPLE_2: &[u8] = b"\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x82\x00\x00\x00\x00\x00\
        \x00\x00\x4e\x00\x11\x00\x75\x00\x00\x00\x02\x0e\xff\xff\xff\x00\
        \x00\x00\xdb\xff\xff\x00\x3a\x90\xff\xb6\x66\x66\xb6\xff\xb6\x66\
        \x00\x90\xdb\xff\x00\x00\x3a\xdb\x90\x3a\x3a\x90\xdb\x66\x00\x00\
        \xff\xff\xb6\x64\x64\x64\x11\x04\x11\x4c\x11\x4c\x11\x4c\x11\x4c\
        \x11\x4c\x00\x47\x13\x00\x01\x01\x04\x00\x01\x00\x00\x47\x16\x00\
        \x11\x02\x00\x47\x29\x00\x11\x01\x00\x49\x0a\x00\x01\x00\x04\x00\
        \x01\x00\x00\x4a\x0a\x00\x09\x00\x01\x00\x00\x47\x05\x00\x01\x01\
        \x1c\x00\x01\x00\x11\x4c\x11\x4c\x11\x4c\x00\x47\x0d\x4d\x00\x4d\x00";
    const EXAMPLE_3: &[u8] = b"\x00\xdf\x0e\x00\x00\x00\x8b\x00\x00\x00\x00\x00\x00\x00\xfe\xfe\
        \xfe\xff\x80\x05\xff\xff\xff\x40\xfe\xfe\xfe\x40\x00\x00\x3f\x00\
        \x03\x00\x0b\x00\xfe\xfe\xfe\xc5\xd0\xc6\xd0\xc7\xd0\x68\xd4\x69\
        \xd4\x6a\xd4\x6b\xd4\x6c\xd4\x6d\xd4\x1a\xd4\x1a\xd4\xa6\xd0\x6e\
        \xd4\x6f\xd4\x70\xd4\x71\xd4\x72\xd4\x73\xd4\x74\xd4\x21\xd4\x22\
        \xd4\x23\xd4\x24\xd4\x25\xd4\xd9\xd0\xda\xd0\xdb\xd0\xc5\xd0\xc5\
        \xd0\xdc\xd0\xc2\xd0\x21\xd4\x22\xd4\x23\xd4\x24\xd4\x25\xd4\xc9\
        \xd0\xca\xd0\x5a\xd4\x2b\xd1\x28\xd1\x2c\xd1\x75\xd4\x27\xd4\x28\
        \xd4\x29\xd4\x2a\xd4\x1a\xd4\x1a\xd4\x1a\xd4\xb7\xd0\xb8\xd0\xb9\
        \xd0\xba\xd0\xbb\xd0\xbc\xd0\xbd\xd0\xbe\xd0\xbf\xd0\xc0\xd0\xc1\
        \xd0\xc2\xd0\xc3\xd0\xc4\xd0\x00";
    const EXAMPLE_4: &[u8] = b"\x01\x0b\x78\x00\x00\x00\x00\x00\x46\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x06\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x0f\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xb6\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xb6\x66\xff\xff\xff\xff\xff\xff\xff\xb6\x66\xdb\x90\x3a\xff\xff\
        \xb6\xff\xff\xff\xff\xff\xff\xff\xff\xff\x46\x91\x47\x91\x48\x91\
        \x49\x91\x4a\x91\x1b\x91\x00";

    /// Exemple 2 : RLEX 78×17 couvrant toute la zone, couleurs prises dans la palette.
    #[test]
    fn windows_example_2_rlex_covers_the_area() {
        let (w, h) = (78, 17);
        let mut px = vec![0x11u8; w * h * 4];
        ClearDecoder::new().decode(EXAMPLE_2, w, h, &mut px).unwrap();
        // palette BGR de 14 couleurs, lue dans le flux
        let palette: Vec<[u8; 3]> = EXAMPLE_2[28..28 + 14 * 3].as_chunks::<3>().0.to_vec();
        for p in px.as_chunks::<4>().0 {
            assert_eq!(p[3], 255, "pixel non écrit");
            assert!(palette.contains(&[p[0], p[1], p[2]]), "couleur hors palette {p:?}");
        }
        // le texte (noir) est sur fond blanc : premier pixel blanc, du noir quelque part
        assert_eq!(&px[..3], &[0xff, 0xff, 0xff]);
        assert!(px.as_chunks::<4>().0.iter().any(|p| p[..3] == [0, 0, 0]));
    }

    /// Exemple 3 : résidu (aplats) puis bande de 64 V-bars prises dans un cache vide (comme le
    /// test de FreeRDP, le décodage doit réussir ; les colonnes inconnues gardent le résidu).
    #[test]
    fn windows_example_3_residual_and_bands() {
        let (w, h) = (64, 24);
        let mut px = vec![0x11u8; w * h * 4];
        ClearDecoder::new().decode(EXAMPLE_3, w, h, &mut px).unwrap();
        let at = |x: usize, y: usize| &px[(y * w + x) * 4..][..4];
        assert_eq!(at(0, 0), &[0xfe, 0xfe, 0xfe, 255]);
        // résidu : 1408 pixels gris clair, 64 blancs (ligne 22), 64 gris clair (ligne 23)
        assert_eq!(at(5, 22), &[0xff, 0xff, 0xff, 255]);
        assert_eq!(at(5, 23), &[0xfe, 0xfe, 0xfe, 255]);
        assert!(px.as_chunks::<4>().0.iter().all(|p| p[3] == 255));
    }

    /// Exemples 4 puis 1 : un glyphe 7×15 dessiné par des V-bars courtes et rangé à l'indice 0x78,
    /// puis un glyphe (indice 0x11) rejoué depuis le cache.
    #[test]
    fn windows_examples_4_and_1_glyphs() {
        let mut d = ClearDecoder::new();
        let (w, h) = (7, 15);
        let mut px = vec![0x11u8; w * h * 4];
        d.decode(EXAMPLE_4, w, h, &mut px).unwrap();
        // bande x 0..=6, y 0..=14 : colonne 0 en V-bar courte de 15 pixels ; les 6 autres
        // désignent des V-bars d'un cache rempli auparavant (vide ici : contenu existant gardé)
        let at = |x: usize, y: usize| px[(y * w + x) * 4..][..4].to_vec();
        assert_eq!(at(0, 0), [0xff, 0xff, 0xff, 255]);
        assert_eq!(at(0, 3), [0xb6, 0xff, 0xff, 255]);
        assert_eq!(at(0, 6), [0xff, 0xb6, 0x66, 255]);
        assert_eq!(at(6, 0), [0x11, 0x11, 0x11, 0x11]);
        // rejoué tel quel depuis l'indice 0x78
        let mut again = vec![0u8; w * h * 4];
        d.decode(b"\x03\x0c\x78\x00", w, h, &mut again).unwrap();
        assert_eq!(again, px);
        // exemple 1 : indice 0x11, à remplir d'abord (8×9)
        let mut glyph = header(FLAG_GLYPH_INDEX, &[1, 2, 3, 72], &[], &[]);
        glyph.splice(2..2, 0x11u16.to_le_bytes());
        let mut px = vec![0u8; 8 * 9 * 4];
        d.decode(&glyph, 8, 9, &mut px).unwrap();
        let mut hit = vec![0u8; 8 * 9 * 4];
        d.decode(EXAMPLE_1, 8, 9, &mut hit).unwrap();
        assert_eq!(hit, [1, 2, 3, 255].repeat(72));
    }

    /// Un glyphe de plus de 1024 pixels est mis en cache comme les autres (FreeRDP accepte
    /// jusqu'à 1024×1024) : sinon le rappel suivant échoue ou rejoue un ancien glyphe de même
    /// indice (cases figées ou de la mauvaise couleur dans le texte).
    #[test]
    fn large_glyphs_are_cached_and_replace_the_old_entry() {
        let mut d = ClearDecoder::new();
        let small = {
            let mut g = header(FLAG_GLYPH_INDEX, &[9, 9, 9, 1], &[], &[]);
            g.splice(2..2, 5u16.to_le_bytes());
            g
        };
        d.decode(&small, 1, 1, &mut [0u8; 4]).unwrap();
        // 40×30 = 1200 pixels rouges sous le même indice
        let (w, h) = (40, 30);
        let mut big = header(FLAG_GLYPH_INDEX, &[0, 0, 255, 0xFF, 0xB0, 0x04], &[], &[]);
        big.splice(2..2, 5u16.to_le_bytes());
        let mut px = vec![0u8; w * h * 4];
        d.decode(&big, w, h, &mut px).unwrap();
        let mut hit = vec![0u8; w * h * 4];
        d.decode(&[FLAG_GLYPH_INDEX | FLAG_GLYPH_HIT, 0, 5, 0], w, h, &mut hit).unwrap();
        assert_eq!(hit, [0, 0, 255, 255].repeat(w * h));
    }

    #[test]
    fn nscodec_plane_rle_and_colors() {
        // 2×1 gris (Y = 100, Co = Cg = 0), plans non compressés, alpha absent (opaque)
        let mut bitmap = Vec::new();
        for len in [2u32, 2, 2, 0] {
            bitmap.extend_from_slice(&len.to_le_bytes());
        }
        bitmap.extend_from_slice(&[1, 0, 0, 0]);
        bitmap.extend_from_slice(&[100, 100, 0, 0, 0, 0]);
        let out = nscodec(&bitmap, 2, 1).unwrap();
        assert_eq!(out, [100, 100, 100, 255, 100, 100, 100, 255]);
        // RLE : 7 × 5 puis 4 octets bruts
        assert_eq!(nsc_rle(&[5, 5, 5, 1, 2, 3, 4], 11).unwrap(), [5, 5, 5, 5, 5, 5, 5, 1, 2, 3, 4]);
    }
}
