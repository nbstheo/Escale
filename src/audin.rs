//! Micro de cet ordinateur vers le bureau distant (MS-RDPEAI, canal dynamique « AUDIO_INPUT »).
//!
//! Le serveur ouvre le canal, annonce ses formats et demande l'ouverture du micro ; la capture
//! (cpal, entrée par défaut) tourne sur son propre fil et envoie des paquets PCM 16 bits à la
//! boucle de session, qui les transmet (`send`).
//!
//! Vie privée : le micro n'est ouvert qu'à la demande du serveur (Open) et fermé dès qu'il ferme le
//! canal, change de format ou que la session se termine ; les paquets d'une capture terminée encore
//! en file ne sont jamais transmis.

use crate::rdpsnd::{AudioFormat, Converter, Rd};
use ironrdp_core::{Encode, EncodeResult, WriteCursor};
use ironrdp_dvc::{DvcChannelListener, DvcEncode, DvcMessage, DvcProcessor};
use ironrdp_pdu::PduResult;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

pub const CHANNEL: &str = "AUDIO_INPUT";

// messages (MS-RDPEAI 2.2.2)
const MSG_SNDIN_VERSION: u8 = 0x01;
const MSG_SNDIN_FORMATS: u8 = 0x02;
const MSG_SNDIN_OPEN: u8 = 0x03;
const MSG_SNDIN_OPEN_REPLY: u8 = 0x04;
const MSG_SNDIN_DATA_INCOMING: u8 = 0x05;
const MSG_SNDIN_DATA: u8 = 0x06;
const MSG_SNDIN_FORMATCHANGE: u8 = 0x07;

const WAVE_FORMAT_PCM: u16 = 0x0001;
/// E_FAIL : micro indisponible.
const E_FAIL: u32 = 0x8000_4005;

/// Paquet PCM capturé, marqué de la capture qui l'a produit.
pub struct Packet {
    channel: u32,
    capture: u64,
    live: Arc<AtomicU64>,
    data: Vec<u8>,
}

impl Packet {
    /// Produit par la capture en cours (ni canal fermé, ni format changé depuis).
    fn current(&self) -> bool {
        self.live.load(Ordering::Acquire) == self.capture
    }
}

/// Numéro de capture unique (0 : aucune).
fn next_capture() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Destination des paquets d'une capture, vers la boucle de session (file bornée : les paquets en
/// trop sont perdus, la capture ne bloque jamais).
#[derive(Clone)]
pub struct Packets {
    tx: mpsc::Sender<Packet>,
    channel: u32,
    capture: u64,
    live: Arc<AtomicU64>,
}

impl Packets {
    /// `false` si le paquet est perdu (file pleine, session terminée).
    pub fn push(&self, data: Vec<u8>) -> bool {
        let p = Packet { channel: self.channel, capture: self.capture, live: self.live.clone(), data };
        self.tx.try_send(p).is_ok()
    }
}

/// Message DVC déjà encodé.
struct Raw(Vec<u8>);

impl Encode for Raw {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ironrdp_core::ensure_size!(in: dst, size: self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "SNDIN"
    }
    fn size(&self) -> usize {
        self.0.len()
    }
}

impl DvcEncode for Raw {}

fn msg(v: Vec<u8>) -> DvcMessage {
    Box::new(Raw(v))
}

/// Origine du son capturé (micro, ou factice pour les tests).
pub trait Source: Send {
    /// Démarre la capture au format demandé ; paquets de `frames` trames (octets PCM bruts).
    fn start(&mut self, format: &AudioFormat, frames: usize, tx: Packets) -> Result<(), String>;
    fn stop(&mut self);
}

/// Client du canal « AUDIO_INPUT ».
pub struct AudinClient {
    source: Box<dyn Source>,
    tx: mpsc::Sender<Packet>,
    channel: u32,
    /// Capture en cours (0 : micro fermé), partagée avec ses paquets.
    live: Arc<AtomicU64>,
    /// Formats annoncés au serveur (indices des messages Open / Format Change).
    formats: Vec<AudioFormat>,
    frames: usize,
}

ironrdp_core::impl_as_any!(AudinClient);

impl AudinClient {
    pub fn new(source: Box<dyn Source>, tx: mpsc::Sender<Packet>) -> Self {
        Self { source, tx, channel: 0, live: Arc::new(AtomicU64::new(0)), formats: Vec::new(), frames: 0 }
    }

    /// Ferme le micro ; les paquets encore en file sont abandonnés.
    fn stop(&mut self) {
        self.live.store(0, Ordering::Release);
        self.source.stop();
    }

    /// (Re)démarre la capture ; `true` si le micro est ouvert.
    fn open(&mut self, index: u32) -> bool {
        self.stop();
        let Some(f) = self.formats.get(index as usize) else { return false };
        let capture = next_capture();
        let out = Packets { tx: self.tx.clone(), channel: self.channel, capture, live: self.live.clone() };
        self.live.store(capture, Ordering::Release);
        match self.source.start(f, self.frames, out) {
            Ok(()) => true,
            Err(e) => {
                self.live.store(0, Ordering::Release);
                eprintln!("escale: micro indisponible ({e}) : la session continue sans micro");
                false
            }
        }
    }
}

/// Crée un client à chaque ouverture du canal par le serveur (un client enregistré une seule fois
/// disparaît à la première fermeture du canal).
pub struct Listener {
    source: Box<dyn FnMut() -> Box<dyn Source> + Send>,
    tx: mpsc::Sender<Packet>,
}

/// Canal micro de l'hôte (à enregistrer avec `DrdynvcClient::with_listener`), si l'option est activée.
#[allow(dead_code)]
pub fn listener(host: &crate::model::Host, tx: mpsc::Sender<Packet>) -> Option<Listener> {
    host.rdp.microphone.then(|| Listener { source: Box::new(|| Box::new(CpalSource::default())), tx })
}

impl DvcChannelListener for Listener {
    fn channel_name(&self) -> &str {
        CHANNEL
    }

    fn create(&mut self, _channel_id: u32) -> Option<Box<dyn DvcProcessor>> {
        Some(Box::new(AudinClient::new((self.source)(), self.tx.clone())))
    }
}

/// Formats de capture pris en charge : PCM 16 bits, mono ou stéréo, 8 à 48 kHz.
fn supported(f: &AudioFormat) -> bool {
    f.tag == WAVE_FORMAT_PCM && f.bits == 16 && (1..=2).contains(&f.channels) && (8_000..=48_000).contains(&f.rate)
}

impl DvcProcessor for AudinClient {
    fn channel_name(&self) -> &str {
        CHANNEL
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        self.channel = channel_id;
        // le serveur parle le premier (Version)
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let mut r = Rd(payload);
        let Some(id) = r.u8() else { return Ok(Vec::new()) };
        Ok(match id {
            MSG_SNDIN_VERSION => {
                let v = r.u32().unwrap_or(1).clamp(1, 2);
                let mut out = vec![MSG_SNDIN_VERSION];
                out.extend_from_slice(&v.to_le_bytes());
                vec![msg(out)]
            }
            MSG_SNDIN_FORMATS => {
                let (Some(n), Some(_size)) = (r.u32(), r.u32()) else { return Ok(Vec::new()) };
                let mut formats: Vec<AudioFormat> = (0..n).map_while(|_| AudioFormat::read(&mut r)).filter(supported).collect();
                // meilleure qualité d'abord ; un micro est le plus souvent mono
                formats.sort_by_key(|f| {
                    let (_, rate, _) = f.rank();
                    (rate, f.channels)
                });
                if formats.is_empty() {
                    eprintln!("escale: micro : aucun format commun avec le serveur");
                }
                let mut out = vec![MSG_SNDIN_FORMATS];
                out.extend_from_slice(&(formats.len() as u32).to_le_bytes());
                out.extend_from_slice(&[0; 4]);
                for f in &formats {
                    f.write(&mut out);
                }
                let total = (out.len() as u32).to_le_bytes();
                out[5..9].copy_from_slice(&total);
                // nouvelle négociation : les indices changent, le micro attend un nouvel Open
                self.stop();
                self.formats = formats;
                vec![msg(out)]
            }
            MSG_SNDIN_OPEN => {
                let (Some(frames), Some(initial)) = (r.u32(), r.u32()) else { return Ok(Vec::new()) };
                self.frames = frames as usize;
                let ok = self.open(initial);
                let mut reply = vec![MSG_SNDIN_OPEN_REPLY];
                reply.extend_from_slice(&(if ok { 0 } else { E_FAIL }).to_le_bytes());
                if !ok {
                    return Ok(vec![msg(reply)]);
                }
                let mut change = vec![MSG_SNDIN_FORMATCHANGE];
                change.extend_from_slice(&initial.to_le_bytes());
                vec![msg(change), msg(reply)]
            }
            MSG_SNDIN_FORMATCHANGE => {
                let Some(new) = r.u32() else { return Ok(Vec::new()) };
                // format inconnu : micro fermé, pas d'accusé
                if !self.open(new) && new as usize >= self.formats.len() {
                    return Ok(Vec::new());
                }
                let mut out = vec![MSG_SNDIN_FORMATCHANGE];
                out.extend_from_slice(&new.to_le_bytes());
                vec![msg(out)]
            }
            _ => Vec::new(),
        })
    }

    fn close(&mut self, _channel_id: u32) {
        self.stop();
    }
}

impl Drop for AudinClient {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Messages DVC d'un paquet capturé : Incoming Data puis Data.
fn data_messages(pcm: &[u8]) -> Vec<DvcMessage> {
    let mut data = Vec::with_capacity(pcm.len() + 1);
    data.push(MSG_SNDIN_DATA);
    data.extend_from_slice(pcm);
    vec![msg(vec![MSG_SNDIN_DATA_INCOMING]), msg(data)]
}

/// Paquet capturé → trame à écrire (rien si le canal est fermé ou le format changé entre-temps).
pub fn send(stage: &mut ActiveStage, p: Packet) -> Vec<ActiveStageOutput> {
    if !p.current() || !stage.get_dvc_by_channel_id(p.channel).is_some_and(|c| c.is_open()) {
        return Vec::new();
    }
    let frame = ironrdp_dvc::encode_dvc_messages(p.channel, data_messages(&p.data), ironrdp_svc::ChannelFlags::empty())
        .map_err(|e| e.to_string())
        .and_then(|m| stage.encode_dvc_messages(m).map_err(|e| e.to_string()));
    match frame {
        Ok(f) => vec![ActiveStageOutput::ResponseFrame(f)],
        Err(e) => {
            eprintln!("escale: micro : {e}");
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Capture

/// Découpe le son converti en paquets de `frames` trames PCM 16 bits.
pub(crate) struct Packetizer {
    conv: Converter,
    channels: usize,
    frames: usize,
    buf: Vec<f32>,
    pending: Vec<u8>,
}

impl Packetizer {
    pub fn new(in_rate: u32, in_ch: u16, f: &AudioFormat, frames: usize) -> Self {
        // paquets de 10 à 100 ms (20 ms si le serveur n'en demande pas)
        let ms = |n: u32| (f.rate * n / 1000) as usize;
        let frames = if frames == 0 { ms(20) } else { frames.clamp(ms(10), ms(100)) };
        Self { conv: Converter::new(in_rate, in_ch, f.rate, f.channels), channels: f.channels.max(1) as usize, frames, buf: Vec::new(), pending: Vec::new() }
    }

    /// Échantillons capturés (flottants entrelacés) → paquets complets.
    pub fn push(&mut self, input: &[f32], mut emit: impl FnMut(Vec<u8>)) {
        self.buf.clear();
        self.conv.process(input, &mut self.buf);
        self.pending.extend(self.buf.iter().flat_map(|v| ((v.clamp(-1.0, 1.0) * 32767.0).round() as i16).to_le_bytes()));
        let size = self.frames * self.channels * 2;
        while self.pending.len() >= size {
            let rest = self.pending.split_off(size);
            emit(std::mem::replace(&mut self.pending, rest));
        }
    }
}

/// Capture sur l'entrée audio par défaut ; cpal::Stream n'est pas `Send` : il vit sur son fil.
#[derive(Default)]
pub struct CpalSource {
    running: Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)>,
}

impl Source for CpalSource {
    fn start(&mut self, format: &AudioFormat, frames: usize, out: Packets) -> Result<(), String> {
        self.stop();
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (s, f) = (stop.clone(), format.clone());
        let thread = std::thread::Builder::new()
            .name("escale-micro".into())
            .spawn(move || {
                let lost = Arc::new(AtomicBool::new(false));
                let mut stream = match build_input(&f, frames, out.clone(), lost.clone()) {
                    Ok(stream) => {
                        let _ = ready_tx.send(Ok(()));
                        Some(stream)
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                while !s.load(Ordering::Acquire) {
                    std::thread::park_timeout(Duration::from_secs(1));
                    // entrée par défaut changée ou retirée : capture relancée sur la nouvelle
                    if lost.load(Ordering::Acquire) && !s.load(Ordering::Acquire) {
                        drop(stream.take());
                        lost.store(false, Ordering::Release);
                        stream = build_input(&f, frames, out.clone(), lost.clone()).ok();
                        if stream.is_none() {
                            lost.store(true, Ordering::Release);
                        }
                    }
                }
                drop(stream);
            })
            .map_err(|e| e.to_string())?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.running = Some((stop, thread));
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // le fil fermera le micro s'il finit par s'ouvrir
                stop.store(true, Ordering::Release);
                thread.thread().unpark();
                Err("le micro ne répond pas".into())
            }
        }
    }

    fn stop(&mut self) {
        if let Some((stop, thread)) = self.running.take() {
            stop.store(true, Ordering::Release);
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

impl Drop for CpalSource {
    fn drop(&mut self) {
        self.stop();
    }
}

fn build_input(f: &AudioFormat, frames: usize, out: Packets, lost: Arc<AtomicBool>) -> Result<cpal::Stream, String> {
    use cpal::SampleFormat as F;
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    let host = cpal::default_host();
    let dev = host.default_input_device().ok_or("aucune entrée audio")?;
    let cfg = dev.default_input_config().map_err(|e| e.to_string())?;
    let sample = cfg.sample_format();
    let config: cpal::StreamConfig = cfg.into();
    let pk = Packetizer::new(config.sample_rate, config.channels, f, frames);
    fn build<T: cpal::SizedSample>(
        dev: &cpal::Device,
        config: cpal::StreamConfig,
        mut pk: Packetizer,
        out: Packets,
        lost: Arc<AtomicBool>,
    ) -> Result<cpal::Stream, cpal::Error>
    where
        f32: cpal::FromSample<T>,
    {
        let mut input = Vec::new();
        dev.build_input_stream(
            config,
            move |data: &[T], _: &cpal::InputCallbackInfo| {
                input.clear();
                input.extend(data.iter().map(|s| s.to_sample::<f32>()));
                pk.push(&input, |p| {
                    out.push(p);
                });
            },
            move |e: cpal::Error| {
                use cpal::ErrorKind as K;
                match e.kind() {
                    K::Xrun | K::DeviceChanged | K::RealtimeDenied => {}
                    // périphérique changé ou retiré : relancé par le fil de capture, sans bruit
                    K::StreamInvalidated | K::DeviceNotAvailable => lost.store(true, Ordering::Release),
                    _ => eprintln!("escale: micro : {e}"),
                }
            },
            None,
        )
    }
    let stream = match sample {
        F::F32 => build::<f32>(&dev, config, pk, out, lost),
        F::F64 => build::<f64>(&dev, config, pk, out, lost),
        F::I16 => build::<i16>(&dev, config, pk, out, lost),
        F::I32 => build::<i32>(&dev, config, pk, out, lost),
        F::I8 => build::<i8>(&dev, config, pk, out, lost),
        F::U8 => build::<u8>(&dev, config, pk, out, lost),
        F::U16 => build::<u16>(&dev, config, pk, out, lost),
        F::U32 => build::<u32>(&dev, config, pk, out, lost),
        other => return Err(format!("format d'échantillons {other} non pris en charge")),
    }
    .map_err(|e| e.to_string())?;
    stream.play().map_err(|e| e.to_string())?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Capture factice : note les formats demandés (et si le micro est ouvert), peut refuser ;
    /// garde la destination de la dernière capture pour y produire des paquets.
    /// Captures demandées, micro ouvert, micro absent, destination de la dernière capture.
    type FakeState = (Vec<(AudioFormat, usize)>, bool, bool, Option<Packets>);

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<FakeState>>);

    impl Fake {
        fn open(&self) -> bool {
            self.0.lock().unwrap().1
        }
        /// Paquet produit par la dernière capture (même arrêtée).
        fn emit(&self, data: Vec<u8>) {
            self.0.lock().unwrap().3.as_ref().unwrap().push(data);
        }
    }

    impl Source for Fake {
        fn start(&mut self, f: &AudioFormat, frames: usize, tx: Packets) -> Result<(), String> {
            let mut g = self.0.lock().unwrap();
            if g.2 {
                return Err("pas de micro".into());
            }
            g.0.push((f.clone(), frames));
            g.1 = true;
            tx.push(vec![1, 2, 3, 4]);
            g.3 = Some(tx);
            Ok(())
        }
        fn stop(&mut self) {
            self.0.lock().unwrap().1 = false;
        }
    }

    fn bytes(m: &DvcMessage) -> Vec<u8> {
        ironrdp_core::encode_vec(m.as_ref()).unwrap()
    }

    fn formats_pdu(formats: &[AudioFormat]) -> Vec<u8> {
        let mut v = vec![MSG_SNDIN_FORMATS];
        v.extend_from_slice(&(formats.len() as u32).to_le_bytes());
        v.extend_from_slice(&[0; 4]);
        for f in formats {
            f.write(&mut v);
        }
        v
    }

    #[test]
    fn audin_handshake_open_and_format_change() {
        let fake = Fake::default();
        let (tx, mut rx) = mpsc::channel(8);
        let mut c = AudinClient::new(Box::new(fake.clone()), tx);
        assert!(c.start(3).unwrap().is_empty());

        // version : le client répond au plus 2
        let out = c.process(3, &[MSG_SNDIN_VERSION, 2, 0, 0, 0]).unwrap();
        assert_eq!(bytes(&out[0]), vec![MSG_SNDIN_VERSION, 2, 0, 0, 0]);

        // formats : PCM 16 bits seulement, meilleure fréquence d'abord
        let adpcm = AudioFormat { tag: 0x11, channels: 1, rate: 22050, avg_bytes: 11100, block_align: 512, bits: 4, extra: vec![2, 0, 0xF9, 1] };
        let srv = [AudioFormat::pcm16(22050, 1), adpcm, AudioFormat::pcm16(44100, 2), AudioFormat::pcm16(44100, 1), AudioFormat::pcm16(96000, 2)];
        let out = c.process(3, &formats_pdu(&srv)).unwrap();
        let reply = bytes(&out[0]);
        let mut r = Rd(&reply);
        assert_eq!(r.u8(), Some(MSG_SNDIN_FORMATS));
        assert_eq!(r.u32(), Some(3));
        assert_eq!(r.u32(), Some(reply.len() as u32), "taille du paquet");
        let got: Vec<AudioFormat> = (0..3).map(|_| AudioFormat::read(&mut r).unwrap()).collect();
        assert_eq!(got, vec![AudioFormat::pcm16(44100, 1), AudioFormat::pcm16(44100, 2), AudioFormat::pcm16(22050, 1)]);

        // ouverture au format 1 : Format Change puis Open Reply (succès), capture lancée
        let mut open = vec![MSG_SNDIN_OPEN];
        open.extend_from_slice(&882u32.to_le_bytes());
        open.extend_from_slice(&1u32.to_le_bytes());
        AudioFormat::pcm16(44100, 2).write(&mut open);
        let out = c.process(3, &open).unwrap();
        assert_eq!(bytes(&out[0]), vec![MSG_SNDIN_FORMATCHANGE, 1, 0, 0, 0]);
        assert_eq!(bytes(&out[1]), vec![MSG_SNDIN_OPEN_REPLY, 0, 0, 0, 0]);
        assert_eq!(fake.0.lock().unwrap().0[0], (AudioFormat::pcm16(44100, 2), 882));
        let p = rx.try_recv().unwrap();
        assert_eq!((p.data.as_slice(), p.channel, p.current()), (&[1u8, 2, 3, 4][..], 3, true));

        // changement de format demandé par le serveur
        let out = c.process(3, &[MSG_SNDIN_FORMATCHANGE, 2, 0, 0, 0]).unwrap();
        assert_eq!(bytes(&out[0]), vec![MSG_SNDIN_FORMATCHANGE, 2, 0, 0, 0]);
        assert_eq!(fake.0.lock().unwrap().0[1].0, AudioFormat::pcm16(22050, 1));

        // fermeture du canal : capture arrêtée
        c.close(3);
        assert!(!fake.0.lock().unwrap().1);

        // micro absent : Open Reply en échec, sans erreur de session
        fake.0.lock().unwrap().2 = true;
        let out = c.process(3, &open).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(bytes(&out[0]), vec![MSG_SNDIN_OPEN_REPLY, 0x05, 0x40, 0x00, 0x80]);
        // message inconnu ou tronqué : ignoré
        assert!(c.process(3, &[MSG_SNDIN_OPEN, 1]).unwrap().is_empty());
        assert!(c.process(3, &[0x42]).unwrap().is_empty());
    }

    fn open_pdu(index: u32) -> Vec<u8> {
        let mut open = vec![MSG_SNDIN_OPEN];
        open.extend_from_slice(&441u32.to_le_bytes());
        open.extend_from_slice(&index.to_le_bytes());
        AudioFormat::pcm16(44100, 1).write(&mut open);
        open
    }

    #[test]
    fn audin_microphone_opens_only_while_server_wants_it() {
        let fake = Fake::default();
        let (tx, mut rx) = mpsc::channel(8);
        let mut c = AudinClient::new(Box::new(fake.clone()), tx);
        c.start(3).unwrap();
        c.process(3, &[MSG_SNDIN_VERSION, 1, 0, 0, 0]).unwrap();
        c.process(3, &formats_pdu(&[AudioFormat::pcm16(44100, 1), AudioFormat::pcm16(22050, 1)])).unwrap();
        assert!(fake.0.lock().unwrap().0.is_empty() && !fake.open(), "aucune capture avant Open");

        c.process(3, &open_pdu(0)).unwrap();
        assert!(fake.open());
        let first = fake.0.lock().unwrap().3.clone().unwrap();
        assert!(rx.try_recv().unwrap().current());

        // format changé : les paquets de l'ancienne capture encore en file ne partent pas
        c.process(3, &[MSG_SNDIN_FORMATCHANGE, 1, 0, 0, 0]).unwrap();
        first.push(vec![9]);
        assert!(rx.try_recv().unwrap().current(), "premier paquet de la nouvelle capture");
        assert!(!rx.try_recv().unwrap().current(), "paquet de l'ancien format abandonné");
        // format inconnu : micro fermé, pas d'accusé
        assert!(c.process(3, &[MSG_SNDIN_FORMATCHANGE, 7, 0, 0, 0]).unwrap().is_empty());
        assert!(!fake.open());

        // nouvelle négociation : micro fermé jusqu'au prochain Open
        c.process(3, &open_pdu(1)).unwrap();
        while rx.try_recv().is_ok() {}
        c.process(3, &formats_pdu(&[AudioFormat::pcm16(44100, 1)])).unwrap();
        assert!(!fake.open());
        fake.emit(vec![1]);
        assert!(!rx.try_recv().unwrap().current());

        // fermeture du canal, puis fin de session : micro fermé, paquets en file abandonnés
        c.process(3, &open_pdu(0)).unwrap();
        while rx.try_recv().is_ok() {}
        c.close(3);
        assert!(!fake.open());
        fake.emit(vec![2]);
        assert!(!rx.try_recv().unwrap().current());
        c.process(3, &open_pdu(0)).unwrap();
        assert!(fake.open());
        drop(c);
        assert!(!fake.open(), "micro fermé avec la session");
    }

    #[test]
    fn audin_full_queue_drops_packets_without_blocking() {
        let (tx, mut rx) = mpsc::channel(1);
        let out = Packets { tx, channel: 1, capture: 5, live: Arc::new(AtomicU64::new(5)) };
        assert!(out.push(vec![1]));
        assert!(!out.push(vec![2]), "file pleine : paquet perdu");
        assert_eq!(rx.try_recv().unwrap().data, vec![1]);
        drop(rx);
        assert!(!out.push(vec![3]), "session terminée");
    }

    #[test]
    fn audin_listener_survives_server_close_and_reopen() {
        use ironrdp_dvc::pdu::{CapabilitiesRequestPdu, CapsVersion, ClosePdu, CreateRequestPdu, DataPdu, DrdynvcDataPdu, DrdynvcServerPdu};
        use ironrdp_dvc::DrdynvcClient;
        use ironrdp_svc::SvcProcessor;
        let enc = |p: DrdynvcServerPdu| ironrdp_core::encode_vec(&p).unwrap();
        let data = |id: u32, d: Vec<u8>| enc(DrdynvcServerPdu::Data(DrdynvcDataPdu::Data(DataPdu::new(id, d))));
        // une ouverture du micro sur le canal `id`, comme Windows à chaque application qui enregistre
        let session = |dvc: &mut DrdynvcClient, id: u32| {
            dvc.process(&enc(DrdynvcServerPdu::Create(CreateRequestPdu::new(id, CHANNEL.into())))).unwrap();
            if dvc.get_dvc_by_channel_id(id).is_none() {
                return false;
            }
            dvc.process(&data(id, vec![MSG_SNDIN_VERSION, 1, 0, 0, 0])).unwrap();
            dvc.process(&data(id, formats_pdu(&[AudioFormat::pcm16(44100, 1)]))).unwrap();
            dvc.process(&data(id, open_pdu(0))).unwrap();
            true
        };
        let caps = enc(DrdynvcServerPdu::Capabilities(CapabilitiesRequestPdu::new(CapsVersion::V1, None)));

        let fake = Fake::default();
        let (tx, _rx) = mpsc::channel(8);
        let f = fake.clone();
        let listener = Listener { source: Box::new(move || Box::new(f.clone())), tx: tx.clone() };
        let mut dvc = DrdynvcClient::new().with_listener(listener);
        dvc.process(&caps).unwrap();
        for id in [5, 6] {
            assert!(session(&mut dvc, id), "canal {id} accepté");
            assert!(fake.open());
            dvc.process(&enc(DrdynvcServerPdu::Close(ClosePdu::new(id)))).unwrap();
            assert!(!fake.open(), "micro fermé avec le canal {id}");
        }

        // client enregistré une seule fois (`with_dynamic_channel`) : refusé à la réouverture
        let mut dvc = DrdynvcClient::new().with_dynamic_channel(AudinClient::new(Box::new(fake.clone()), tx));
        dvc.process(&caps).unwrap();
        assert!(session(&mut dvc, 5));
        dvc.process(&enc(DrdynvcServerPdu::Close(ClosePdu::new(5)))).unwrap();
        assert!(!fake.open());
        assert!(!session(&mut dvc, 6), "limite d'IronRDP : d'où `listener`");
    }

    /// Micro réel : `cargo test audin_real -- --ignored` (échoue proprement sans micro).
    #[test]
    #[ignore]
    fn audin_real_capture_produces_packets() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut s = CpalSource::default();
        let out = Packets { tx, channel: 1, capture: 1, live: Arc::new(AtomicU64::new(1)) };
        match s.start(&AudioFormat::pcm16(44100, 1), 882, out) {
            Ok(()) => {
                std::thread::sleep(Duration::from_millis(500));
                let p = rx.try_recv().expect("aucun paquet capturé");
                assert_eq!(p.data.len(), 882 * 2);
                s.stop();
            }
            Err(e) => eprintln!("pas de micro : {e}"),
        }
    }

    #[test]
    fn audin_data_pdus() {
        let m = data_messages(&[9, 8, 7]);
        assert_eq!(bytes(&m[0]), vec![MSG_SNDIN_DATA_INCOMING]);
        assert_eq!(bytes(&m[1]), vec![MSG_SNDIN_DATA, 9, 8, 7]);
        // gros paquet : découpé en DataFirst + Data par ironrdp-dvc
        let big = vec![0u8; 4000];
        let svc = ironrdp_dvc::encode_dvc_messages(7, data_messages(&big), ironrdp_svc::ChannelFlags::empty()).unwrap();
        assert_eq!(svc.len(), 1 + 3);
    }

    #[test]
    fn audin_packetizer_converts_and_splits() {
        // capture 48 kHz stéréo → PCM 16 kHz mono, paquets de 20 ms (320 trames)
        let f = AudioFormat::pcm16(16000, 1);
        let mut pk = Packetizer::new(48000, 2, &f, 320);
        let mut packets = Vec::new();
        for _ in 0..10 {
            // 10 ms de signal constant 0.5 / 0.5
            pk.push(&vec![0.5f32; 480 * 2], |p| packets.push(p));
        }
        // 100 ms → 1600 trames (à l'historique du rééchantillonneur près), en paquets de 640 octets
        let total = packets.len() * 640 + pk.pending.len();
        assert!((3190..=3200).contains(&total), "{total}");
        assert!(packets.iter().all(|p| p.len() == 640));
        let s = i16::from_le_bytes([packets[1][10], packets[1][11]]);
        assert_eq!(s, (0.5f32 * 32767.0).round() as i16);
        // trames par paquet bornées (10 à 100 ms)
        assert_eq!(Packetizer::new(48000, 1, &f, 1).frames, 160);
        assert_eq!(Packetizer::new(48000, 1, &f, 0).frames, 320);
        assert_eq!(Packetizer::new(48000, 1, &f, 1_000_000).frames, 1600);
    }
}
