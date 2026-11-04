//! Son du bureau distant (MS-RDPEA, canal statique « rdpsnd ») : PCM 8 / 16 bits, ADPCM IMA et
//! Microsoft, A-law / µ-law. Lecture via cpal (WASAPI sous Windows), convertie au format de la
//! carte son, avec un tampon borné (latence) et amorcé (pas de craquements).
//!
//! Le fil RDP ne bloque jamais : les échantillons décodés sont déposés dans une file que le fil
//! audio de cpal vide. Sans périphérique de sortie, la session continue sans son.

use crate::model::{Host, RdpAudio};
use ironrdp_pdu::PduResult;
use ironrdp_pdu::gcc::ChannelName;
use ironrdp_svc::{CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// messages du canal (MS-RDPEA 2.2.1)
const SNDC_CLOSE: u8 = 0x01;
const SNDC_WAVE: u8 = 0x02;
const SNDC_SETVOLUME: u8 = 0x03;
const SNDC_WAVECONFIRM: u8 = 0x05;
const SNDC_TRAINING: u8 = 0x06;
const SNDC_FORMATS: u8 = 0x07;
const SNDC_QUALITYMODE: u8 = 0x0C;
const SNDC_WAVE2: u8 = 0x0D;

const TSSNDCAPS_ALIVE: u32 = 0x1;
const HIGH_QUALITY: u16 = 0x2;
/// Version annoncée : 8 = Wave2 (horodatage audio), les serveurs plus anciens envoient WaveInfo + Wave.
const CLIENT_VERSION: u16 = 0x08;

// étiquettes de format (RFC 2361)
const WAVE_FORMAT_PCM: u16 = 0x0001;
const WAVE_FORMAT_ADPCM: u16 = 0x0002;
const WAVE_FORMAT_ALAW: u16 = 0x0006;
const WAVE_FORMAT_MULAW: u16 = 0x0007;
const WAVE_FORMAT_DVI_ADPCM: u16 = 0x0011;

/// Latence : lecture lancée quand ce tampon est atteint (absorbe la gigue du réseau)…
const PRIME_MS: u32 = 80;
/// … au-delà de celui-ci, les plus anciens échantillons sont abandonnés jusqu'à `TRIM_MS`.
const MAX_MS: u32 = 400;
const TRIM_MS: u32 = 200;
/// Retard propre à la carte son, ajouté à l'accusé de lecture.
const DEVICE_MS: u32 = 30;
/// Sortie audio libérée après ce silence (ne garde pas le périphérique ouvert sans raison).
const IDLE: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------------------------
// Lecture des PDU

/// Lecteur petit-boutiste sur une tranche.
pub(crate) struct Rd<'a>(pub &'a [u8]);

impl<'a> Rd<'a> {
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Description d'un format audio (structure AUDIO_FORMAT / WAVEFORMATEX).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AudioFormat {
    pub tag: u16,
    pub channels: u16,
    pub rate: u32,
    pub avg_bytes: u32,
    pub block_align: u16,
    pub bits: u16,
    pub extra: Vec<u8>,
}

impl AudioFormat {
    pub fn read(r: &mut Rd) -> Option<Self> {
        let tag = r.u16()?;
        let channels = r.u16()?;
        let rate = r.u32()?;
        let avg_bytes = r.u32()?;
        let block_align = r.u16()?;
        let bits = r.u16()?;
        let n = r.u16()? as usize;
        let extra = r.take(n)?.to_vec();
        Some(Self { tag, channels, rate, avg_bytes, block_align, bits, extra })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tag.to_le_bytes());
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.rate.to_le_bytes());
        out.extend_from_slice(&self.avg_bytes.to_le_bytes());
        out.extend_from_slice(&self.block_align.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&(self.extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.extra);
    }

    /// PCM 16 bits.
    #[cfg(test)]
    pub fn pcm16(rate: u32, channels: u16) -> Self {
        Self { tag: WAVE_FORMAT_PCM, channels, rate, avg_bytes: rate * channels as u32 * 2, block_align: channels * 2, bits: 16, extra: Vec::new() }
    }

    /// Préférence d'annonce (plus petit = mieux) : qualité du codec, fréquence proche de 44,1 / 48 kHz,
    /// stéréo d'abord.
    pub fn rank(&self) -> (u8, u32, u16) {
        let codec = match (self.tag, self.bits) {
            (WAVE_FORMAT_PCM, 16) => 0,
            (WAVE_FORMAT_ADPCM | WAVE_FORMAT_DVI_ADPCM, _) => 1,
            (WAVE_FORMAT_ALAW | WAVE_FORMAT_MULAW, _) => 2,
            _ => 3,
        };
        let rate = if self.rate <= 48_000 { 48_000 - self.rate } else { self.rate };
        (codec, rate, 2u16.abs_diff(self.channels))
    }
}

// ---------------------------------------------------------------------------------------------
// Décodage

/// Décodeur d'un format pris en charge.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Codec {
    Pcm8,
    Pcm16,
    Alaw,
    Mulaw,
    /// ADPCM IMA / DVI (blocs de `block` octets).
    Ima { block: usize },
    /// ADPCM Microsoft, avec ses coefficients de prédiction.
    MsAdpcm { block: usize, coefs: Vec<(i32, i32)> },
}

const MS_COEFS: [(i32, i32); 7] = [(256, 0), (512, -256), (0, 0), (192, 64), (240, 0), (460, -208), (392, -232)];

impl Codec {
    pub fn for_format(f: &AudioFormat) -> Option<Self> {
        if !(1..=2).contains(&f.channels) || !(4_000..=192_000).contains(&f.rate) {
            return None;
        }
        let block = f.block_align as usize;
        Some(match (f.tag, f.bits) {
            (WAVE_FORMAT_PCM, 8) => Codec::Pcm8,
            (WAVE_FORMAT_PCM, 16) => Codec::Pcm16,
            (WAVE_FORMAT_ALAW, 8) => Codec::Alaw,
            (WAVE_FORMAT_MULAW, 8) => Codec::Mulaw,
            (WAVE_FORMAT_DVI_ADPCM, 4) if block > 4 * f.channels as usize => Codec::Ima { block },
            (WAVE_FORMAT_ADPCM, 4) if block > 7 * f.channels as usize => {
                // extra : wSamplesPerBlock, wNumCoef, puis les paires de coefficients
                let mut r = Rd(&f.extra);
                let coefs = match (r.u16(), r.u16()) {
                    (Some(_), Some(n)) => (0..n).map_while(|_| Some((r.u16()? as i16 as i32, r.u16()? as i16 as i32))).collect(),
                    _ => Vec::new(),
                };
                Codec::MsAdpcm { block, coefs: if coefs.is_empty() { MS_COEFS.to_vec() } else { coefs } }
            }
            _ => return None,
        })
    }

    /// Décode `data` en échantillons 16 bits entrelacés, ajoutés à `out`.
    pub fn decode(&self, data: &[u8], channels: usize, out: &mut Vec<i16>) {
        match self {
            Codec::Pcm8 => out.extend(data.iter().map(|&b| ((b as i16) - 128) << 8)),
            Codec::Pcm16 => out.extend(data.as_chunks::<2>().0.iter().map(|c| i16::from_le_bytes(*c))),
            Codec::Alaw => out.extend(data.iter().map(|&b| alaw(b))),
            Codec::Mulaw => out.extend(data.iter().map(|&b| mulaw(b))),
            Codec::Ima { block } => data.chunks(*block).for_each(|b| ima_block(b, channels, out)),
            Codec::MsAdpcm { block, coefs } => data.chunks(*block).for_each(|b| ms_block(b, channels, coefs, out)),
        }
    }
}

fn alaw(b: u8) -> i16 {
    let a = b ^ 0x55;
    let seg = (a >> 4) & 7;
    let mut t = ((a & 0x0F) as i32) << 4;
    t = match seg {
        0 => t + 8,
        1 => t + 0x108,
        _ => (t + 0x108) << (seg - 1),
    };
    (if a & 0x80 != 0 { t } else { -t }) as i16
}

fn mulaw(b: u8) -> i16 {
    let u = !b;
    let t = ((((u & 0x0F) as i32) << 3) + 0x84) << ((u >> 4) & 7);
    (if u & 0x80 != 0 { 0x84 - t } else { t - 0x84 }) as i16
}

const IMA_STEPS: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
    157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411,
    1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442,
    11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];
const IMA_INDEX: [i32; 16] = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

/// État d'un canal ADPCM IMA.
#[derive(Clone, Copy, Default)]
pub(crate) struct Ima {
    pub pred: i32,
    pub index: i32,
}

impl Ima {
    pub fn step(&mut self, nibble: u8) -> i16 {
        let step = IMA_STEPS[self.index as usize];
        let mut diff = step >> 3;
        if nibble & 4 != 0 {
            diff += step;
        }
        if nibble & 2 != 0 {
            diff += step >> 1;
        }
        if nibble & 1 != 0 {
            diff += step >> 2;
        }
        self.pred = if nibble & 8 != 0 { self.pred - diff } else { self.pred + diff }.clamp(-32768, 32767);
        self.index = (self.index + IMA_INDEX[nibble as usize & 15]).clamp(0, 88);
        self.pred as i16
    }
}

/// Bloc IMA : en-tête de 4 octets par canal, puis des mots de 4 octets (8 échantillons) par canal
/// à tour de rôle, quartet de poids faible d'abord.
fn ima_block(b: &[u8], ch: usize, out: &mut Vec<i16>) {
    if b.len() < 4 * ch {
        return;
    }
    let mut st = [Ima::default(); 2];
    for (c, s) in st.iter_mut().enumerate().take(ch) {
        s.pred = i16::from_le_bytes([b[4 * c], b[4 * c + 1]]) as i32;
        s.index = (b[4 * c + 2] as i32).clamp(0, 88);
        out.push(s.pred as i16);
    }
    let data = &b[4 * ch..];
    let base = out.len();
    let frames = data.len() / (4 * ch) * 8;
    out.resize(base + frames * ch, 0);
    for (w, word) in data.as_chunks::<4>().0.iter().enumerate() {
        let c = w % ch;
        let first = w / ch * 8;
        for (k, &byte) in word.iter().enumerate() {
            for (h, nib) in [byte & 0x0F, byte >> 4].into_iter().enumerate() {
                out[base + (first + 2 * k + h) * ch + c] = st[c].step(nib);
            }
        }
    }
}

const MS_ADAPT: [i32; 16] = [230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230];

/// Bloc ADPCM Microsoft : prédicteurs, deltas, deux échantillons initiaux (le plus ancien d'abord),
/// puis des quartets (poids fort d'abord) alternant les canaux.
fn ms_block(b: &[u8], ch: usize, coefs: &[(i32, i32)], out: &mut Vec<i16>) {
    if b.len() < 7 * ch {
        return;
    }
    let rd16 = |i: usize| i16::from_le_bytes([b[i], b[i + 1]]) as i32;
    let mut coef = [(0, 0); 2];
    let mut delta = [0i32; 2];
    let mut s1 = [0i32; 2];
    let mut s2 = [0i32; 2];
    for c in 0..ch {
        coef[c] = coefs.get(b[c] as usize).copied().unwrap_or(MS_COEFS[0]);
        delta[c] = rd16(ch + 2 * c);
        s1[c] = rd16(3 * ch + 2 * c);
        s2[c] = rd16(5 * ch + 2 * c);
    }
    out.extend((0..ch).map(|c| s2[c] as i16));
    out.extend((0..ch).map(|c| s1[c] as i16));
    let mut c = 0;
    for &byte in &b[7 * ch..] {
        for nib in [byte >> 4, byte & 0x0F] {
            let signed = if nib & 8 != 0 { nib as i64 - 16 } else { nib as i64 };
            // calcul sur 64 bits, pas borné : coefficients et pas extrêmes d'un serveur hostile
            let pred = (s1[c] as i64 * coef[c].0 as i64 + s2[c] as i64 * coef[c].1 as i64) >> 8;
            let v = (pred + signed * delta[c] as i64).clamp(-32768, 32767) as i32;
            s2[c] = s1[c];
            s1[c] = v;
            delta[c] = ((MS_ADAPT[nib as usize] as i64 * delta[c] as i64) >> 8).clamp(16, i32::MAX as i64 / 768) as i32;
            out.push(v as i16);
            c = (c + 1) % ch;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Conversion (canaux, fréquence)

/// Convertit un flux entrelacé (fréquence, canaux) vers un autre, par morceaux successifs :
/// interpolation cubique (Hermite) qui garde son historique d'un morceau à l'autre.
pub(crate) struct Converter {
    in_ch: usize,
    out_ch: usize,
    step: f64,
    pos: f64,
    /// Dernières trames reçues (déjà au nombre de canaux de sortie).
    hist: Vec<f32>,
    mapped: Vec<f32>,
}

impl Converter {
    pub fn new(in_rate: u32, in_ch: u16, out_rate: u32, out_ch: u16) -> Self {
        Self {
            in_ch: in_ch.max(1) as usize,
            out_ch: out_ch.max(1) as usize,
            step: in_rate.max(1) as f64 / out_rate.max(1) as f64,
            pos: 0.0,
            hist: Vec::new(),
            mapped: Vec::new(),
        }
    }

    /// Répartition des canaux : mono dupliqué sur gauche / droite, stéréo moyenné en mono,
    /// canaux de sortie supplémentaires (5.1…) silencieux.
    fn map_frame(&self, f: &[f32], out: &mut Vec<f32>) {
        let (i, o) = (self.in_ch, self.out_ch);
        for c in 0..o {
            out.push(if o == 1 {
                f.iter().sum::<f32>() / i as f32
            } else if i == 1 {
                if c < 2 { f[0] } else { 0.0 }
            } else if c < i {
                f[c]
            } else {
                0.0
            });
        }
    }

    pub fn process(&mut self, input: &[f32], out: &mut Vec<f32>) {
        let ch = self.out_ch;
        let mut mapped = std::mem::take(&mut self.mapped);
        mapped.clear();
        for f in input.chunks_exact(self.in_ch) {
            self.map_frame(f, &mut mapped);
        }
        if self.step == 1.0 {
            out.extend_from_slice(&mapped);
            self.mapped = mapped;
            return;
        }
        if self.hist.is_empty() {
            if mapped.is_empty() {
                self.mapped = mapped;
                return;
            }
            // première trame dupliquée : point d'appui avant le début du flux
            self.hist.extend_from_slice(&mapped[..ch]);
            self.pos = 1.0;
        }
        self.hist.extend_from_slice(&mapped);
        let buf = &self.hist;
        let n = buf.len() / ch;
        while (self.pos as usize) + 2 < n {
            let i = self.pos as usize;
            let t = (self.pos - i as f64) as f32;
            for c in 0..ch {
                let y0 = buf[(i - 1) * ch + c];
                let y1 = buf[i * ch + c];
                let y2 = buf[(i + 1) * ch + c];
                let y3 = buf[(i + 2) * ch + c];
                let a = -0.5 * y0 + 1.5 * y1 - 1.5 * y2 + 0.5 * y3;
                let b = y0 - 2.5 * y1 + 2.0 * y2 - 0.5 * y3;
                let cc = -0.5 * y0 + 0.5 * y2;
                out.push(((a * t + b) * t + cc) * t + y1);
            }
            self.pos += self.step;
        }
        // on ne garde que les 3 dernières trames
        let keep = n.min(3);
        self.hist.drain(..(n - keep) * ch);
        self.pos -= (n - keep) as f64;
        self.mapped = mapped;
    }
}

// ---------------------------------------------------------------------------------------------
// Sortie audio

/// Destination des échantillons décodés (carte son, ou factice pour les tests).
pub trait Sink: Send {
    /// Joue des échantillons 16 bits entrelacés ; renvoie le retard (ms) avant la fin de leur lecture.
    fn play(&mut self, pcm: &[i16], rate: u32, channels: u16) -> u32;
    /// Volume demandé par le serveur (0.0 – 1.0, gauche / droite).
    fn volume(&mut self, left: f32, right: f32);
    /// Fin d'un flux sonore côté serveur (le tampon finit d'être joué).
    fn stop(&mut self);
}

/// File partagée avec le fil audio de cpal.
struct Ring {
    q: VecDeque<f32>,
    primed: bool,
    prime: usize,
    last_push: Instant,
}

impl Ring {
    fn fill<T: cpal::Sample + cpal::FromSample<f32>>(&mut self, out: &mut [T]) {
        if !self.primed {
            if self.q.len() < self.prime {
                out.fill(T::EQUILIBRIUM);
                return;
            }
            self.primed = true;
        }
        for s in out.iter_mut() {
            *s = match self.q.pop_front() {
                Some(v) => T::from_sample(v),
                None => {
                    // sous-alimentation : silence et nouvel amorçage
                    self.primed = false;
                    T::EQUILIBRIUM
                }
            };
        }
    }
}

/// Flux de sortie ouvert ; cpal::Stream n'est pas `Send` : il vit sur son propre fil.
struct Output {
    ring: Arc<Mutex<Ring>>,
    rate: u32,
    channels: u16,
    /// Périphérique perdu ou fermé pour inactivité : à rouvrir.
    dead: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn lock(ring: &Mutex<Ring>) -> std::sync::MutexGuard<'_, Ring> {
    ring.lock().unwrap_or_else(|e| e.into_inner())
}

impl Output {
    fn open() -> Result<Output, String> {
        let ring = Arc::new(Mutex::new(Ring { q: VecDeque::new(), primed: false, prime: 0, last_push: Instant::now() }));
        let dead = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let (r, d, s) = (ring.clone(), dead.clone(), stop.clone());
        let thread = std::thread::Builder::new()
            .name("escale-son".into())
            .spawn(move || {
                let stream = match build_output(r.clone(), d.clone()) {
                    Ok((stream, rate, ch)) => {
                        let _ = tx.send(Ok((rate, ch)));
                        stream
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                };
                while !s.load(Ordering::Relaxed) {
                    std::thread::park_timeout(Duration::from_secs(1));
                    let idle = {
                        let g = lock(&r);
                        g.q.is_empty() && g.last_push.elapsed() > IDLE
                    };
                    if idle {
                        d.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                drop(stream);
            })
            .map_err(|e| e.to_string())?;
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok((rate, channels))) => {
                lock(&ring).prime = (rate * channels as u32 * PRIME_MS / 1000) as usize;
                Ok(Output { ring, rate, channels, dead, stop, thread: Some(thread) })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                Err("la carte son ne répond pas".into())
            }
        }
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            t.thread().unpark();
            let _ = t.join();
        }
    }
}

fn build_output(ring: Arc<Mutex<Ring>>, dead: Arc<AtomicBool>) -> Result<(cpal::Stream, u32, u16), String> {
    use cpal::SampleFormat as F;
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    let host = cpal::default_host();
    let dev = host.default_output_device().ok_or("aucune sortie audio")?;
    let cfg = dev.default_output_config().map_err(|e| e.to_string())?;
    let format = cfg.sample_format();
    let config: cpal::StreamConfig = cfg.into();
    let (rate, ch) = (config.sample_rate, config.channels);
    fn build<T: cpal::SizedSample + cpal::FromSample<f32>>(
        dev: &cpal::Device,
        config: cpal::StreamConfig,
        ring: Arc<Mutex<Ring>>,
        dead: Arc<AtomicBool>,
    ) -> Result<cpal::Stream, cpal::Error> {
        dev.build_output_stream(
            config,
            move |out: &mut [T], _: &cpal::OutputCallbackInfo| lock(&ring).fill(out),
            move |e: cpal::Error| {
                use cpal::ErrorKind as K;
                match e.kind() {
                    K::Xrun | K::DeviceChanged | K::RealtimeDenied => {}
                    // périphérique par défaut changé : rouvert (sur le nouveau) au prochain son, sans bruit
                    K::StreamInvalidated => dead.store(true, Ordering::Relaxed),
                    _ => {
                        if !dead.swap(true, Ordering::Relaxed) {
                            eprintln!("escale: son : {e}");
                        }
                    }
                }
            },
            None,
        )
    }
    let stream = match format {
        F::F32 => build::<f32>(&dev, config, ring, dead),
        F::F64 => build::<f64>(&dev, config, ring, dead),
        F::I16 => build::<i16>(&dev, config, ring, dead),
        F::I32 => build::<i32>(&dev, config, ring, dead),
        F::I8 => build::<i8>(&dev, config, ring, dead),
        F::U8 => build::<u8>(&dev, config, ring, dead),
        F::U16 => build::<u16>(&dev, config, ring, dead),
        F::U32 => build::<u32>(&dev, config, ring, dead),
        other => return Err(format!("format d'échantillons {other} non pris en charge")),
    }
    .map_err(|e| e.to_string())?;
    stream.play().map_err(|e| e.to_string())?;
    Ok((stream, rate, ch))
}

/// Sortie sur la carte son par défaut, ouverte au premier son (et rouverte après une perte).
pub struct CpalSink {
    out: Option<Output>,
    open: fn() -> Result<Output, String>,
    retry: Option<Instant>,
    /// Délai avant la prochaine tentative d'ouverture (doublé à chaque échec).
    backoff: Duration,
    warned: bool,
    conv: Option<((u32, u16, u32, u16), Converter)>,
    gain: [f32; 2],
    input: Vec<f32>,
    buf: Vec<f32>,
}

impl CpalSink {
    pub fn new() -> Self {
        Self::with_opener(Output::open)
    }

    fn with_opener(open: fn() -> Result<Output, String>) -> Self {
        Self {
            out: None,
            open,
            retry: None,
            backoff: Duration::from_secs(5),
            warned: false,
            conv: None,
            gain: [1.0; 2],
            input: Vec::new(),
            buf: Vec::new(),
        }
    }

    fn output(&mut self) -> Option<&Output> {
        if self.out.as_ref().is_some_and(|o| o.dead.load(Ordering::Relaxed)) {
            self.out = None;
        }
        if self.out.is_none() {
            if self.retry.is_some_and(|t| Instant::now() < t) {
                return None;
            }
            match (self.open)() {
                Ok(o) => {
                    self.out = Some(o);
                    self.backoff = Duration::from_secs(5);
                }
                Err(e) => {
                    if !self.warned {
                        eprintln!("escale: son indisponible ({e}) : la session continue sans son");
                        self.warned = true;
                    }
                    // l'ouverture peut bloquer le fil RDP (jusqu'à 5 s) : tentatives de plus en plus rares
                    self.retry = Some(Instant::now() + self.backoff);
                    self.backoff = (self.backoff * 2).min(Duration::from_secs(60));
                    return None;
                }
            }
        }
        self.out.as_ref()
    }
}

impl Sink for CpalSink {
    fn play(&mut self, pcm: &[i16], rate: u32, channels: u16) -> u32 {
        let Some((out_rate, out_ch)) = self.output().map(|o| (o.rate, o.channels)) else { return 0 };
        let key = (rate, channels, out_rate, out_ch);
        if self.conv.as_ref().is_none_or(|(k, _)| *k != key) {
            self.conv = Some((key, Converter::new(rate, channels, out_rate, out_ch)));
        }
        // volume appliqué avant la conversion (canal 0 = gauche, 1 = droite)
        let ch = channels.max(1) as usize;
        let mono = (self.gain[0] + self.gain[1]) / 2.0;
        self.input.clear();
        self.input.extend(pcm.iter().enumerate().map(|(i, &s)| {
            let g = if ch == 1 { mono } else { self.gain[(i % ch).min(1)] };
            s as f32 / 32768.0 * g
        }));
        self.buf.clear();
        if let Some((_, conv)) = self.conv.as_mut() {
            conv.process(&self.input, &mut self.buf);
        }
        let Some(o) = self.out.as_ref() else { return 0 };
        let per_ms = (out_rate * out_ch as u32 / 1000).max(1) as usize;
        let mut ring = lock(&o.ring);
        ring.q.extend(self.buf.iter().copied());
        ring.last_push = Instant::now();
        // latence bornée : l'excédent (rafale après une coupure, dérive d'horloge) est abandonné
        if ring.q.len() > MAX_MS as usize * per_ms {
            let excess = ring.q.len() - TRIM_MS as usize * per_ms;
            let excess = excess - excess % out_ch.max(1) as usize;
            ring.q.drain(..excess);
        }
        (ring.q.len() / per_ms) as u32 + DEVICE_MS
    }

    fn volume(&mut self, left: f32, right: f32) {
        self.gain = [left.clamp(0.0, 1.0), right.clamp(0.0, 1.0)];
    }

    fn stop(&mut self) {}
}

// ---------------------------------------------------------------------------------------------
// Canal statique

/// Client du canal « rdpsnd ».
pub struct RdpsndClient {
    sink: Box<dyn Sink>,
    /// Formats annoncés au serveur ; `wFormatNo` est un indice dans cette liste.
    formats: Vec<(AudioFormat, Codec)>,
    /// WaveInfo reçu, en attente du message Wave qui porte la suite des données.
    pending: Option<WaveInfo>,
    pcm: Vec<i16>,
}

struct WaveInfo {
    ts: u16,
    format: u16,
    block: u8,
    head: [u8; 4],
    size: usize,
}

impl std::fmt::Debug for RdpsndClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RdpsndClient({} formats)", self.formats.len())
    }
}

ironrdp_core::impl_as_any!(RdpsndClient);

/// Sorties factices des tests, par port de l'hôte.
#[cfg(test)]
pub static TEST_SINKS: Mutex<Vec<(u16, Box<dyn Sink>)>> = Mutex::new(Vec::new());

/// Canal son de l'hôte : seulement si le son est joué ici.
pub fn channel(host: &Host) -> Option<RdpsndClient> {
    if host.rdp.audio != RdpAudio::Local {
        return None;
    }
    #[cfg(test)]
    {
        let mut sinks = TEST_SINKS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = sinks.iter().position(|(p, _)| *p == host.port) {
            return Some(RdpsndClient::new(sinks.remove(i).1));
        }
    }
    Some(RdpsndClient::new(Box::new(CpalSink::new())))
}

fn pdu(msg: u8, body: &[u8]) -> SvcMessage {
    let mut v = Vec::with_capacity(4 + body.len());
    v.extend_from_slice(&[msg, 0]);
    v.extend_from_slice(&(body.len() as u16).to_le_bytes());
    v.extend_from_slice(body);
    SvcMessage::from(v)
}

impl RdpsndClient {
    pub const NAME: ChannelName = ChannelName::from_static(b"rdpsnd\0\0");

    pub fn new(sink: Box<dyn Sink>) -> Self {
        Self { sink, formats: Vec::new(), pending: None, pcm: Vec::new() }
    }

    /// Formats du serveur → ceux que l'on sait décoder, du meilleur au moins bon.
    fn on_formats(&mut self, body: &[u8]) -> Vec<SvcMessage> {
        let mut r = Rd(body);
        let (Some(_flags), Some(_vol), Some(_pitch), Some(_port), Some(n), Some(_last), Some(version), Some(_pad)) =
            (r.u32(), r.u32(), r.u32(), r.u16(), r.u16(), r.u8(), r.u16(), r.u8())
        else {
            return Vec::new();
        };
        let mut formats: Vec<(AudioFormat, Codec)> =
            (0..n).map_while(|_| AudioFormat::read(&mut r)).filter_map(|f| Codec::for_format(&f).map(|c| (f, c))).collect();
        formats.sort_by_key(|(f, _)| f.rank());
        if formats.is_empty() {
            eprintln!("escale: son : aucun format audio commun avec le serveur");
        }
        self.sink.stop();
        self.pending = None;
        let mut out = Vec::new();
        out.extend_from_slice(&TSSNDCAPS_ALIVE.to_le_bytes());
        out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // volume (géré par le serveur)
        out.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // hauteur 1.0
        out.extend_from_slice(&0u16.to_le_bytes()); // pas d'UDP
        out.extend_from_slice(&(formats.len() as u16).to_le_bytes());
        out.push(0);
        out.extend_from_slice(&CLIENT_VERSION.to_le_bytes());
        out.push(0);
        for (f, _) in &formats {
            f.write(&mut out);
        }
        self.formats = formats;
        let mut msgs = vec![pdu(SNDC_FORMATS, &out)];
        if version >= 6 {
            msgs.push(pdu(SNDC_QUALITYMODE, &[HIGH_QUALITY as u8, 0, 0, 0]));
        }
        msgs
    }

    /// Données d'un bloc → sortie audio, puis accusé horodaté à la fin prévue de sa lecture.
    fn wave(&mut self, ts: u16, format: u16, block: u8, data: &[u8]) -> Vec<SvcMessage> {
        let mut delay = 0;
        if let Some((f, codec)) = self.formats.get(format as usize) {
            self.pcm.clear();
            codec.decode(data, f.channels as usize, &mut self.pcm);
            delay = self.sink.play(&self.pcm, f.rate, f.channels);
        }
        let ts = ts.wrapping_add(delay.min(u16::MAX as u32) as u16).to_le_bytes();
        vec![pdu(SNDC_WAVECONFIRM, &[ts[0], ts[1], block, 0])]
    }
}

impl SvcProcessor for RdpsndClient {
    fn channel_name(&self) -> ChannelName {
        Self::NAME
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::Never
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        // message Wave (sans en-tête) qui suit un WaveInfo : ses 4 premiers octets sont remplacés
        if let Some(info) = self.pending.take() {
            let mut data = info.head.to_vec();
            data.extend_from_slice(payload.get(4..).unwrap_or_default());
            data.truncate(info.size);
            return Ok(self.wave(info.ts, info.format, info.block, &data));
        }
        let mut r = Rd(payload);
        let (Some(msg), Some(_), Some(size)) = (r.u8(), r.u8(), r.u16()) else { return Ok(Vec::new()) };
        let body = r.0;
        let mut b = Rd(body);
        Ok(match msg {
            SNDC_FORMATS => self.on_formats(body),
            SNDC_TRAINING => match (b.u16(), b.u16()) {
                (Some(ts), Some(pack)) => {
                    let (t, p) = (ts.to_le_bytes(), pack.to_le_bytes());
                    vec![pdu(SNDC_TRAINING, &[t[0], t[1], p[0], p[1]])]
                }
                _ => Vec::new(),
            },
            SNDC_WAVE => {
                let (Some(ts), Some(format), Some(block), Some(_), Some(head)) = (b.u16(), b.u16(), b.u8(), b.take(3), b.take(4)) else {
                    return Ok(Vec::new());
                };
                let info = WaveInfo { ts, format, block, head: [head[0], head[1], head[2], head[3]], size: (size as usize).saturating_sub(8) };
                if b.0.len() > 4 {
                    // WaveInfo et Wave dans le même message (serveurs non Windows)
                    let mut data = info.head.to_vec();
                    data.extend_from_slice(&b.0[4..]);
                    data.truncate(info.size);
                    self.wave(info.ts, info.format, info.block, &data)
                } else {
                    self.pending = Some(info);
                    Vec::new()
                }
            }
            SNDC_WAVE2 => {
                let (Some(ts), Some(format), Some(block), Some(_), Some(_audio_ts)) = (b.u16(), b.u16(), b.u8(), b.take(3), b.u32()) else {
                    return Ok(Vec::new());
                };
                self.wave(ts, format, block, b.0)
            }
            SNDC_SETVOLUME => {
                if let (Some(l), Some(rt)) = (b.u16(), b.u16()) {
                    self.sink.volume(l as f32 / 65535.0, rt as f32 / 65535.0);
                }
                Vec::new()
            }
            SNDC_CLOSE => {
                self.sink.stop();
                Vec::new()
            }
            // hauteur, clé de chiffrement UDP… : sans objet
            _ => Vec::new(),
        })
    }
}

impl SvcClientProcessor for RdpsndClient {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Échantillons joués, fréquence, canaux, volume.
    type Played = (Vec<i16>, u32, u16, [f32; 2]);

    /// Sortie factice : garde tout ce qui est joué.
    #[derive(Clone, Default)]
    pub(crate) struct Recorder(pub Arc<Mutex<Played>>);

    impl Sink for Recorder {
        fn play(&mut self, pcm: &[i16], rate: u32, channels: u16) -> u32 {
            let mut g = self.0.lock().unwrap();
            g.0.extend_from_slice(pcm);
            g.1 = rate;
            g.2 = channels;
            25
        }
        fn volume(&mut self, l: f32, r: f32) {
            self.0.lock().unwrap().3 = [l, r];
        }
        fn stop(&mut self) {}
    }

    fn encode(m: &SvcMessage) -> Vec<u8> {
        m.encode_unframed_pdu().unwrap()
    }

    fn server_formats(version: u16, formats: &[AudioFormat]) -> Vec<u8> {
        let mut body = vec![0u8; 14];
        body.extend_from_slice(&(formats.len() as u16).to_le_bytes());
        body.push(0);
        body.extend_from_slice(&version.to_le_bytes());
        body.push(0);
        for f in formats {
            f.write(&mut body);
        }
        encode(&pdu(SNDC_FORMATS, &body))
    }

    fn ima_format(ch: u16) -> AudioFormat {
        AudioFormat { tag: WAVE_FORMAT_DVI_ADPCM, channels: ch, rate: 22050, avg_bytes: 11100, block_align: 512 * ch, bits: 4, extra: vec![2, 0, 0xF9, 0x01] }
    }

    #[test]
    fn rdpsnd_negotiates_decodable_formats_in_preference_order() {
        let rec = Recorder::default();
        let mut c = RdpsndClient::new(Box::new(rec));
        let aac = AudioFormat { tag: 0xA106, channels: 2, rate: 44100, avg_bytes: 24000, block_align: 4, bits: 16, extra: vec![0; 12] };
        let srv = [AudioFormat::pcm16(22050, 1), aac, ima_format(2), AudioFormat::pcm16(44100, 2), AudioFormat::pcm16(48000, 2)];
        let out = c.process(&server_formats(8, &srv)).unwrap();
        assert_eq!(out.len(), 2, "formats + mode qualité");
        let reply = encode(&out[0]);
        assert_eq!(reply[0], SNDC_FORMATS);
        let mut r = Rd(&reply[4..]);
        assert_eq!(r.u32(), Some(TSSNDCAPS_ALIVE));
        r.take(10);
        assert_eq!(r.u16(), Some(4), "AAC écarté");
        r.u8();
        assert_eq!(r.u16(), Some(8));
        r.u8();
        let got: Vec<AudioFormat> = (0..4).map(|_| AudioFormat::read(&mut r).unwrap()).collect();
        assert_eq!(got[0], AudioFormat::pcm16(48000, 2));
        assert_eq!(got[1], AudioFormat::pcm16(44100, 2));
        assert_eq!(got[2], AudioFormat::pcm16(22050, 1));
        assert_eq!(got[3], ima_format(2));
        assert_eq!(encode(&out[1]), vec![SNDC_QUALITYMODE, 0, 4, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn rdpsnd_wave_info_then_wave_and_wave2_reach_sink_and_are_confirmed() {
        let rec = Recorder::default();
        let mut c = RdpsndClient::new(Box::new(rec.clone()));
        c.process(&server_formats(6, &[AudioFormat::pcm16(44100, 2)])).unwrap();
        // entraînement
        let t = c.process(&encode(&pdu(SNDC_TRAINING, &[0x34, 0x12, 0x00, 0x04]))).unwrap();
        assert_eq!(encode(&t[0]), vec![SNDC_TRAINING, 0, 4, 0, 0x34, 0x12, 0x00, 0x04]);
        // WaveInfo (4 premiers octets) puis Wave séparé
        let samples: Vec<i16> = vec![1, -1, 300, -300, 32767, -32768];
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let mut info = vec![0x10, 0x00, 0, 0, 7, 0, 0, 0];
        info.extend_from_slice(&bytes[..4]);
        let mut info_pdu = vec![SNDC_WAVE, 0];
        info_pdu.extend_from_slice(&((8 + bytes.len()) as u16).to_le_bytes());
        info_pdu.extend_from_slice(&info);
        assert!(c.process(&info_pdu).unwrap().is_empty());
        let mut wave = vec![0u8; 4];
        wave.extend_from_slice(&bytes[4..]);
        let confirm = c.process(&wave).unwrap();
        // horodatage + retard de lecture (25 ms)
        assert_eq!(encode(&confirm[0]), vec![SNDC_WAVECONFIRM, 0, 4, 0, 0x10 + 25, 0, 7, 0]);
        assert_eq!(rec.0.lock().unwrap().0, samples);
        // Wave2
        let mut w2 = vec![0xFF, 0xFF, 0, 0, 8, 0, 0, 0, 1, 2, 3, 4];
        w2.extend_from_slice(&bytes);
        let confirm = c.process(&encode(&pdu(SNDC_WAVE2, &w2))).unwrap();
        assert_eq!(encode(&confirm[0]), vec![SNDC_WAVECONFIRM, 0, 4, 0, 24, 0, 8, 0], "horodatage modulo 65536");
        let g = rec.0.lock().unwrap();
        assert_eq!(g.0.len(), 12);
        assert_eq!((g.1, g.2), (44100, 2));
        drop(g);
        // volume
        c.process(&encode(&pdu(SNDC_SETVOLUME, &[0xFF, 0xFF, 0, 0]))).unwrap();
        assert_eq!(rec.0.lock().unwrap().3, [1.0, 0.0]);
        // format inconnu : accusé quand même, rien de joué
        let mut w2 = vec![1, 0, 9, 0, 9, 0, 0, 0, 0, 0, 0, 0];
        w2.extend_from_slice(&bytes);
        assert_eq!(c.process(&encode(&pdu(SNDC_WAVE2, &w2))).unwrap().len(), 1);
        assert_eq!(rec.0.lock().unwrap().0.len(), 12);
    }

    /// Encodeur IMA de référence (pour vérifier le décodeur par aller-retour).
    fn ima_encode(st: &mut Ima, s: i16) -> u8 {
        let step = IMA_STEPS[st.index as usize];
        let mut diff = s as i32 - st.pred;
        let mut nib = 0u8;
        if diff < 0 {
            nib = 8;
            diff = -diff;
        }
        let mut step2 = step;
        for bit in [4u8, 2, 1] {
            if diff >= step2 {
                nib |= bit;
                diff -= step2;
            }
            step2 >>= 1;
        }
        st.step(nib);
        nib
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn rdpsnd_ima_adpcm_round_trip_mono_and_stereo() {
        for ch in [1usize, 2] {
            // sinusoïde : 1 échantillon d'en-tête + 2 mots de 8 échantillons par canal
            let n = 1 + 16;
            let src: Vec<i16> = (0..n * ch).map(|i| (((i / ch) as f32 * 0.3 + (i % ch) as f32).sin() * 3000.0) as i16).collect();
            // reconstruction attendue = état de l'encodeur (même prédicteur que le décodeur)
            let mut expect = vec![0i16; n * ch];
            let mut block = Vec::new();
            let mut st = [Ima::default(); 2];
            for c in 0..ch {
                st[c].pred = src[c] as i32;
                expect[c] = src[c];
                block.extend_from_slice(&src[c].to_le_bytes());
                block.extend_from_slice(&[0, 0]);
            }
            for w in 0..2 {
                for c in 0..ch {
                    for k in 0..4 {
                        let i = (1 + w * 8 + 2 * k) * ch + c;
                        let a = ima_encode(&mut st[c], src[i]);
                        expect[i] = st[c].pred as i16;
                        let b = ima_encode(&mut st[c], src[i + ch]);
                        expect[i + ch] = st[c].pred as i16;
                        block.push(a | (b << 4));
                    }
                }
            }
            let f = AudioFormat { tag: WAVE_FORMAT_DVI_ADPCM, channels: ch as u16, rate: 22050, avg_bytes: 0, block_align: block.len() as u16, bits: 4, extra: vec![] };
            let codec = Codec::for_format(&f).unwrap();
            let mut out = Vec::new();
            // deux blocs à la suite
            let two = [block.clone(), block].concat();
            codec.decode(&two, ch, &mut out);
            assert_eq!(out.len(), 2 * src.len());
            assert_eq!(out[..src.len()], expect[..], "canaux : {ch}");
            assert_eq!(out[src.len()..], expect[..]);
            // l'ADPCM suit le signal (le pas part du minimum : écart sur les derniers échantillons)
            let err = out.iter().zip(&src).skip(12 * ch).take(5 * ch).map(|(a, b)| (*a as i32 - *b as i32).abs()).max().unwrap();
            assert!(err < 1200, "écart {err} (canaux : {ch})");
        }
    }

    #[test]
    fn rdpsnd_ms_adpcm_decodes_reference_block() {
        // en-tête mono : prédicteur 0 (256, 0), delta 16, s1 = 100, s2 = 50, puis quartets 1 et -1
        let mut block = vec![0u8];
        block.extend_from_slice(&16i16.to_le_bytes());
        block.extend_from_slice(&100i16.to_le_bytes());
        block.extend_from_slice(&50i16.to_le_bytes());
        block.push(0x1F);
        let mut extra = vec![];
        extra.extend_from_slice(&4u16.to_le_bytes());
        extra.extend_from_slice(&7u16.to_le_bytes());
        for (a, b) in MS_COEFS {
            extra.extend_from_slice(&(a as i16).to_le_bytes());
            extra.extend_from_slice(&(b as i16).to_le_bytes());
        }
        let f = AudioFormat { tag: WAVE_FORMAT_ADPCM, channels: 1, rate: 22050, avg_bytes: 0, block_align: 8, bits: 4, extra };
        let codec = Codec::for_format(&f).unwrap();
        let mut out = Vec::new();
        codec.decode(&block, 1, &mut out);
        // 50, 100, puis 100 + 1×16 = 116 ; delta = max(230×16/256, 16) = 16 ; 116 − 16 = 100
        assert_eq!(out, vec![50, 100, 116, 100]);
    }

    #[test]
    fn rdpsnd_hostile_ms_adpcm_does_not_overflow() {
        // coefficients extrêmes et quartets qui font croître le pas sans fin (serveur hostile)
        let mut extra = vec![];
        extra.extend_from_slice(&4u16.to_le_bytes());
        extra.extend_from_slice(&1u16.to_le_bytes());
        extra.extend_from_slice(&i16::MIN.to_le_bytes());
        extra.extend_from_slice(&i16::MIN.to_le_bytes());
        let f = AudioFormat { tag: WAVE_FORMAT_ADPCM, channels: 1, rate: 22050, avg_bytes: 0, block_align: 2048, bits: 4, extra };
        let codec = Codec::for_format(&f).unwrap();
        let mut block = vec![0u8];
        block.extend_from_slice(&i16::MAX.to_le_bytes());
        block.extend_from_slice(&i16::MIN.to_le_bytes());
        block.extend_from_slice(&i16::MIN.to_le_bytes());
        block.extend(std::iter::repeat_n(0x77, 2041));
        let mut out = Vec::new();
        codec.decode(&block, 1, &mut out);
        assert_eq!(out.len(), 2 + 2 * 2041);
    }

    #[test]
    fn rdpsnd_wave_without_info_and_bad_format_are_harmless() {
        let rec = Recorder::default();
        let mut c = RdpsndClient::new(Box::new(rec.clone()));
        // Wave (4 octets de bourrage + données) sans WaveInfo préalable : ignoré
        assert!(c.process(&[0, 0, 0, 0, 1, 2, 3, 4]).unwrap().is_empty());
        // son avant toute négociation : accusé, rien de joué
        let mut w2 = vec![5, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0];
        w2.extend_from_slice(&[1, 0, 2, 0]);
        let confirm = c.process(&encode(&pdu(SNDC_WAVE2, &w2))).unwrap();
        assert_eq!(encode(&confirm[0]), vec![SNDC_WAVECONFIRM, 0, 4, 0, 5, 0, 3, 0]);
        c.process(&server_formats(8, &[AudioFormat::pcm16(44100, 2)])).unwrap();
        // numéro de format hors limites
        let mut w2 = vec![5, 0, 0xFF, 0xFF, 4, 0, 0, 0, 0, 0, 0, 0];
        w2.extend_from_slice(&[1, 0, 2, 0]);
        assert_eq!(c.process(&encode(&pdu(SNDC_WAVE2, &w2))).unwrap().len(), 1);
        // PDU tronquées
        for p in [&[SNDC_WAVE2, 0, 2, 0, 1][..], &[SNDC_WAVE, 0], &[SNDC_FORMATS, 0, 0, 0], &[SNDC_SETVOLUME, 0, 4, 0, 1]] {
            assert!(c.process(p).unwrap().is_empty(), "{p:?}");
        }
        assert!(rec.0.lock().unwrap().0.is_empty());
        // volume nul : transmis tel quel
        c.process(&encode(&pdu(SNDC_SETVOLUME, &[0, 0, 0, 0]))).unwrap();
        assert_eq!(rec.0.lock().unwrap().3, [0.0, 0.0]);
    }

    #[test]
    fn rdpsnd_failing_output_is_reported_once_and_retried_rarely() {
        use std::sync::atomic::AtomicUsize;
        static OPENS: AtomicUsize = AtomicUsize::new(0);
        fn failing() -> Result<Output, String> {
            OPENS.fetch_add(1, Ordering::Relaxed);
            Err("aucune sortie audio".into())
        }
        let mut s = CpalSink::with_opener(failing);
        for _ in 0..200 {
            assert_eq!(s.play(&[0; 64], 44100, 2), 0, "sans sortie : accusé immédiat");
        }
        assert_eq!(OPENS.load(Ordering::Relaxed), 1, "pas de nouvelle tentative à chaque bloc");
        assert!(s.warned);
        // nouvelle tentative après le délai, délai allongé ensuite
        s.retry = Some(Instant::now());
        s.play(&[0; 64], 44100, 2);
        assert_eq!(OPENS.load(Ordering::Relaxed), 2);
        assert!(s.retry.unwrap() > Instant::now() + Duration::from_secs(8), "délai croissant");
    }

    #[test]
    fn rdpsnd_g711_reference_values() {
        assert_eq!(mulaw(0xFF), 0);
        assert_eq!(mulaw(0x00), -32124);
        assert_eq!(mulaw(0x80), 32124);
        assert_eq!(alaw(0xD5), 8);
        assert_eq!(alaw(0x55), -8);
        assert_eq!(alaw(0xAA), 32256);
    }

    #[test]
    fn rdpsnd_converter_channels_and_rate() {
        // mêmes fréquences : simple répartition des canaux
        let mut c = Converter::new(48000, 1, 48000, 2);
        let mut out = Vec::new();
        c.process(&[0.5, -0.25], &mut out);
        assert_eq!(out, vec![0.5, 0.5, -0.25, -0.25]);
        let mut c = Converter::new(48000, 2, 48000, 1);
        out.clear();
        c.process(&[0.5, -0.5, 1.0, 0.0], &mut out);
        assert_eq!(out, vec![0.0, 0.5]);
        let mut c = Converter::new(48000, 2, 48000, 6);
        out.clear();
        c.process(&[0.1, 0.2], &mut out);
        assert_eq!(out, vec![0.1, 0.2, 0.0, 0.0, 0.0, 0.0]);

        // 44,1 → 48 kHz par petits morceaux : bon nombre d'échantillons, sinusoïde préservée
        let f = 440.0;
        let src: Vec<f32> = (0..44100).map(|i| (2.0 * std::f32::consts::PI * f * i as f32 / 44100.0).sin()).collect();
        let mut c = Converter::new(44100, 1, 48000, 1);
        let mut out = Vec::new();
        for chunk in src.chunks(441) {
            c.process(chunk, &mut out);
        }
        assert!((out.len() as i32 - 48000).abs() <= 3, "{}", out.len());
        let err = out
            .iter()
            .enumerate()
            .skip(4)
            .map(|(i, v)| (v - (2.0 * std::f32::consts::PI * f * i as f32 / 48000.0).sin()).abs())
            .fold(0.0f32, f32::max);
        assert!(err < 0.01, "écart {err}");

        // 48 → 16 kHz stéréo
        let mut c = Converter::new(48000, 2, 16000, 2);
        let mut out = Vec::new();
        c.process(&vec![0.25; 4800 * 2], &mut out);
        assert!((out.len() as i32 - 1600 * 2).abs() <= 4, "{}", out.len());
        assert!(out.iter().all(|v| (v - 0.25).abs() < 1e-6));
    }

    #[test]
    fn rdpsnd_ring_primes_and_recovers_from_underrun() {
        let mut r = Ring { q: VecDeque::new(), primed: false, prime: 4, last_push: Instant::now() };
        let mut out = [1.0f32; 2];
        r.q.extend([0.5, 0.5, 0.5]);
        r.fill(&mut out);
        assert_eq!(out, [0.0, 0.0], "pas assez pour démarrer");
        r.q.push_back(0.5);
        r.fill(&mut out);
        assert_eq!(out, [0.5, 0.5]);
        let mut out = [1.0f32; 4];
        r.fill(&mut out);
        assert_eq!(out, [0.5, 0.5, 0.0, 0.0]);
        assert!(!r.primed, "sous-alimentation : nouvel amorçage");
    }

    /// Carte son réelle (silence) : `cargo test rdpsnd_real -- --ignored`.
    #[test]
    #[ignore]
    fn rdpsnd_real_output_plays_silence() {
        let mut s = CpalSink::new();
        let delay = s.play(&[0; 44100 * 2 / 10], 44100, 2);
        assert!(delay >= DEVICE_MS + 90, "{delay}");
        std::thread::sleep(Duration::from_millis(300));
        assert!(s.out.as_ref().is_some_and(|o| !o.dead.load(Ordering::Relaxed)));
    }

    #[test]
    fn rdpsnd_channel_follows_host_option() {
        let mut h = Host::default();
        h.rdp.audio = RdpAudio::Remote;
        assert!(channel(&h).is_none());
        h.rdp.audio = RdpAudio::Off;
        assert!(channel(&h).is_none());
        h.rdp.audio = RdpAudio::Local;
        assert!(channel(&h).is_some(), "aucun périphérique n'est ouvert avant le premier son");
    }

    // --- bout en bout : serveur IronRDP avec son → session Escale → sortie factice

    mod e2e {
        use super::*;
        use ironrdp_rdpsnd::pdu::{AudioFormat as SrvFormat, WaveFormat};
        use ironrdp_rdpsnd::server::{NegotiatedFormat, RdpsndError, RdpsndServerHandler, RdpsndServerMessage};
        use ironrdp_server::{
            DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler,
            ServerEvent, ServerEventSender, SoundServerFactory,
        };
        use tokio::sync::mpsc::UnboundedSender;

        const WAVES: i16 = 12;
        const FRAMES: usize = 441;

        struct Display;
        struct NoUpdates;

        #[async_trait::async_trait]
        impl RdpServerDisplayUpdates for NoUpdates {
            async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
                std::future::pending().await
            }
        }

        #[async_trait::async_trait]
        impl RdpServerDisplay for Display {
            async fn size(&mut self) -> DesktopSize {
                DesktopSize { width: 64, height: 48 }
            }
            async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
                Ok(Box::new(NoUpdates))
            }
        }

        struct NoInput;
        impl RdpServerInputHandler for NoInput {
            fn keyboard(&mut self, _: KeyboardEvent) {}
            fn mouse(&mut self, _: MouseEvent) {}
        }

        #[derive(Default)]
        struct Factory(Option<UnboundedSender<ServerEvent>>);

        impl ServerEventSender for Factory {
            fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
                self.0 = Some(sender);
            }
        }

        impl SoundServerFactory for Factory {
            fn build_backend(&self) -> Box<dyn RdpsndServerHandler> {
                let pcm = SrvFormat {
                    format: WaveFormat::PCM,
                    n_channels: 2,
                    n_samples_per_sec: 44100,
                    n_avg_bytes_per_sec: 176400,
                    n_block_align: 4,
                    bits_per_sample: 16,
                    data: None,
                };
                Box::new(Sound { formats: vec![pcm], tx: self.0.clone() })
            }
        }

        #[derive(Debug)]
        struct Sound {
            formats: Vec<SrvFormat>,
            tx: Option<UnboundedSender<ServerEvent>>,
        }

        impl RdpsndServerHandler for Sound {
            fn get_formats(&self) -> &[SrvFormat] {
                &self.formats
            }
            fn choose_format<'a>(&mut self, common: &'a [NegotiatedFormat]) -> Option<&'a NegotiatedFormat> {
                common.first()
            }
            fn start(&mut self, _format: &NegotiatedFormat) -> Result<(), Box<dyn RdpsndError>> {
                // blocs de 10 ms, valeur constante propre à chaque bloc
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    for k in 1..=WAVES {
                        let data: Vec<u8> = std::iter::repeat_n((k * 100).to_le_bytes(), FRAMES * 2).flatten().collect();
                        if let Some(tx) = &tx {
                            let _ = tx.send(ServerEvent::Rdpsnd(RdpsndServerMessage::Wave(data, k as u32 * 10)));
                        }
                        std::thread::sleep(Duration::from_millis(30));
                    }
                });
                Ok(())
            }
            fn stop(&mut self) {}
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn rdpsnd_end_to_end_server_samples_reach_sink() {
            // le serveur IronRDP n'est pas `Send` : il tourne sur ce fil
            tokio::task::LocalSet::new().run_until(body()).await;
        }

        async fn body() {
            use tokio_rustls::rustls;
            let _ = rustls::crypto::ring::default_provider().install_default();
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let pub_key = cert.signing_key.public_key_raw().to_vec();
            let der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
            let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], der).unwrap();
            let mut srv = RdpServer::builder()
                .with_addr(([127, 0, 0, 1], 0))
                .with_hybrid(tokio_rustls::TlsAcceptor::from(Arc::new(config)), pub_key)
                .with_input_handler(NoInput)
                .with_display_handler(Display)
                .with_sound_factory(Some(Box::new(Factory::default())))
                .build();
            srv.set_credentials(Some(ironrdp_pdu::rdp::client_info::Credentials { username: "alice".into(), password: "s3cret".into(), domain: None }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::task::spawn_local(async move {
                if let Ok((s, _)) = listener.accept().await {
                    let _ = srv.run_connection(s).await;
                }
            });

            // la session Escale (fil « escale-rdp ») jouera dans cette sortie factice
            let rec = Recorder::default();
            TEST_SINKS.lock().unwrap().push((port, Box::new(rec.clone())));
            let mut host = Host::default();
            host.protocol = crate::model::Protocol::Rdp;
            host.hostname = "127.0.0.1".into();
            host.port = port;
            host.username = "alice".into();
            host.password = "s3cret".into();
            let share = std::env::temp_dir().join(format!("escale-rdpsnd-{}", uuid::Uuid::new_v4()));
            let handle = crate::rdp::spawn(vec![host], (64, 48), share.clone(), eframe::egui::Context::default());

            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                while let Ok(ev) = handle.rx.try_recv() {
                    match ev {
                        crate::ssh::Event::VerifyHostKey { reply, .. } => {
                            let _ = reply.send(true);
                        }
                        crate::ssh::Event::Closed(e) => panic!("session fermée : {e:?}"),
                        _ => {}
                    }
                }
                if rec.0.lock().unwrap().0.len() >= 3 * FRAMES * 2 {
                    break;
                }
                assert!(Instant::now() < deadline, "son non reçu : {} échantillons", rec.0.lock().unwrap().0.len());
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            {
                let g = rec.0.lock().unwrap();
                assert_eq!((g.1, g.2), (44100, 2));
                // blocs intacts : valeurs constantes par bloc, dans l'ordre d'émission
                let mut last = 0;
                for b in g.0.chunks(FRAMES * 2) {
                    assert_eq!(b.len(), FRAMES * 2);
                    assert!(b.iter().all(|&v| v == b[0]), "bloc altéré");
                    assert!(b[0] % 100 == 0 && b[0] > last && b[0] <= WAVES * 100, "ordre : {} après {last}", b[0]);
                    last = b[0];
                }
            }
            let _ = handle.tx.send(crate::desktop::DesktopCmd::Close);
            let _ = std::fs::remove_dir_all(&share);
        }
    }
}
