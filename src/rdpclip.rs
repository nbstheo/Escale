//! Presse-papiers partagé RDP (MS-RDPECLIP, canal statique CLIPRDR) : texte, images, formats riches
//! (HTML, RTF…) et fichiers, dans les deux sens, en rendu différé : seule la liste des formats est
//! échangée à la copie, les données ne circulent qu'au collage.
//!
//! Trois acteurs : le fil RDP (canal `CliprdrClient` + `Backend`), un fil « presse-papiers » propre à
//! la session qui parle au système (fenêtre cachée Windows) et attend les données du serveur, et
//! l'interface, jamais bloquée.

use ironrdp_cliprdr::CliprdrClient;
use ironrdp_cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp_cliprdr::pdu::{
    ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags as Caps,
    FileContentsFlags, FileContentsRequest, FileContentsResponse, FileDescriptor, FormatDataRequest, FormatDataResponse, LockDataId,
    OwnedFormatDataResponse,
};
use ironrdp_session::{ActiveStage, ActiveStageOutput, SessionResult};
use ironrdp_svc::SvcProcessorMessages;
use std::collections::{HashMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc as smpsc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// formats standard Windows
const CF_TEXT: u32 = 1;
const CF_OEMTEXT: u32 = 7;
const CF_DIB: u32 = 8;
const CF_UNICODETEXT: u32 = 13;
const CF_HDROP: u32 = 15;
const CF_DIBV5: u32 = 17;

/// Formats standard échangés (mémoire globale, sans poignée GDI ni chemin local).
const STANDARD: [u32; 8] = [CF_TEXT, 4 /* SYLK */, 5 /* DIF */, CF_OEMTEXT, CF_DIB, CF_UNICODETEXT, 16 /* LOCALE */, CF_DIBV5];
/// Formats nommés échangés tels quels.
const NAMED: [&str; 22] = [
    "HTML Format",
    "Rich Text Format",
    "Rich Text Format Without Objects",
    "RTF As Text",
    "PNG",
    "image/png",
    "JFIF",
    "GIF",
    "image/jpeg",
    "image/gif",
    "image/bmp",
    "image/svg+xml",
    "text/html",
    "text/plain",
    "text/uri-list",
    "UniformResourceLocatorW",
    "UniformResourceLocator",
    "CSV",
    "XML Spreadsheet",
    "Biff5",
    "Biff8",
    "Biff12",
];
const FILE_LIST: &str = "FileGroupDescriptorW";
/// Formats textuels (collés aussi dans Escale : délai d'attente court).
const TEXT_IDS: [u32; 4] = [CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT, 16 /* LOCALE */];
const TEXT_NAMED: [&str; 10] = [
    "HTML Format",
    "Rich Text Format",
    "Rich Text Format Without Objects",
    "RTF As Text",
    "text/html",
    "text/plain",
    "text/uri-list",
    "UniformResourceLocatorW",
    "UniformResourceLocator",
    "CSV",
];

/// Délai d'attente d'une réponse du serveur (collage d'image, de liste de fichiers…).
const TIMEOUT: Duration = Duration::from_secs(10);
/// Délai pour le texte : le collage peut venir d'Escale même (terminal, champ de saisie), dont
/// l'interface reste figée tant que Windows attend le rendu différé.
const TEXT_TIMEOUT: Duration = Duration::from_secs(2);
/// Au-delà, une réponse abandonnée est tenue pour perdue (elle ne décale plus les suivantes).
const LATE: Duration = Duration::from_secs(60);
/// Taille maximale des données distantes gardées pour les rendre à la fin de la session.
const MAX_CACHE: usize = 64 << 20;
/// Délai d'attente d'un morceau de fichier.
const FILE_TIMEOUT: Duration = Duration::from_secs(30);
/// Taille des morceaux de fichiers demandés au serveur.
const CHUNK: u32 = 1 << 20;
/// Taille maximale d'un format échangé.
const MAX_DATA: usize = 256 << 20;
/// Nombre maximal de fichiers et dossiers d'une copie.
const MAX_FILES: usize = 10_000;
/// Fréquence du nettoyage des verrous du canal et de la surveillance sans fenêtre système.
const TICK: Duration = Duration::from_secs(5);

type Wake = Arc<dyn Fn() + Send + Sync>;

/// Message du fil RDP (rappels du canal) vers le fil presse-papiers.
#[derive(Debug)]
enum ToLocal {
    Caps(Caps),
    /// Le serveur attend la liste des formats locaux (initialisation du canal).
    Announce,
    /// Canal initialisé.
    Ready,
    /// Copie sur le bureau distant : formats disponibles.
    RemoteFormats(Vec<ClipboardFormat>),
    /// Le serveur colle : données locales demandées.
    DataRequest(u32),
    /// Réponse à notre demande (`None` : indisponible).
    DataResponse(Option<Vec<u8>>),
    /// Liste des fichiers copiés sur le bureau distant.
    RemoteFiles(Vec<FileDescriptor>),
    FileRequest(FileContentsRequest),
    FileResponse(u32, Option<Vec<u8>>),
    Lock(u32),
    Unlock(u32),
    Quit,
    /// Collage local simulé (tests).
    #[cfg(test)]
    Paste(u32, smpsc::Sender<Option<Vec<u8>>>),
}

/// Rappels du canal CLIPRDR (fil RDP) : simplement relayés au fil presse-papiers.
struct Backend {
    tx: smpsc::Sender<ToLocal>,
    wake: Wake,
    caps: Caps,
    temp: String,
}

impl Backend {
    fn send(&self, m: ToLocal) {
        if self.tx.send(m).is_ok() {
            (self.wake)();
        }
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Backend presse-papiers")
    }
}

impl ironrdp_core::AsAny for Backend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl CliprdrBackend for Backend {
    fn temporary_directory(&self) -> &str {
        &self.temp
    }
    fn client_capabilities(&self) -> Caps {
        self.caps
    }
    fn on_ready(&mut self) {
        self.send(ToLocal::Ready)
    }
    fn on_request_format_list(&mut self) {
        self.send(ToLocal::Announce)
    }
    fn on_process_negotiated_capabilities(&mut self, caps: Caps) {
        self.send(ToLocal::Caps(caps))
    }
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        self.send(ToLocal::RemoteFormats(formats.to_vec()))
    }
    fn on_format_data_request(&mut self, r: FormatDataRequest) {
        self.send(ToLocal::DataRequest(r.format.value()))
    }
    fn on_format_data_response(&mut self, r: FormatDataResponse<'_>) {
        self.send(ToLocal::DataResponse((!r.is_error()).then(|| r.data().to_vec())))
    }
    fn on_file_contents_request(&mut self, r: FileContentsRequest) {
        self.send(ToLocal::FileRequest(r))
    }
    fn on_file_contents_response(&mut self, r: FileContentsResponse<'_>) {
        self.send(ToLocal::FileResponse(r.stream_id(), (!r.is_error()).then(|| r.data().to_vec())))
    }
    fn on_lock(&mut self, id: LockDataId) {
        self.send(ToLocal::Lock(id.0))
    }
    fn on_unlock(&mut self, id: LockDataId) {
        self.send(ToLocal::Unlock(id.0))
    }
    fn on_remote_file_list(&mut self, files: &[FileDescriptor], _lock: Option<u32>) {
        self.send(ToLocal::RemoteFiles(files.to_vec()))
    }
}

/// Événement à traiter dans la boucle de la session RDP.
pub enum ClipEvent {
    Message(ClipboardMessage),
    /// Nettoyage périodique des verrous du canal.
    Tick,
}

/// Lien entre la boucle RDP et le fil presse-papiers ; le fil s'arrête quand le lien est libéré.
pub struct Link {
    rx: mpsc::UnboundedReceiver<ClipboardMessage>,
    tick: tokio::time::Interval,
    open: bool,
    _stop: Stop,
}

struct Stop(smpsc::Sender<ToLocal>, Wake);

impl Drop for Stop {
    fn drop(&mut self) {
        if self.0.send(ToLocal::Quit).is_ok() {
            (self.1)();
        }
    }
}

impl Link {
    async fn next(&mut self) -> ClipEvent {
        if self.open {
            tokio::select! {
                m = self.rx.recv() => match m {
                    Some(m) => return ClipEvent::Message(m),
                    None => self.open = false,
                },
                _ = self.tick.tick() => return ClipEvent::Tick,
            }
        }
        self.tick.tick().await;
        ClipEvent::Tick
    }
}

/// Prochain événement du presse-papiers (jamais si le partage est désactivé). Annulable sans perte.
pub async fn recv(link: &mut Option<Link>) -> ClipEvent {
    match link {
        Some(l) => l.next().await,
        None => std::future::pending().await,
    }
}

/// Canal CLIPRDR à enregistrer sur la connexion, et son lien avec le presse-papiers local.
pub fn open(host: &crate::model::Host) -> Option<(CliprdrClient, Link)> {
    let (out, rx) = mpsc::unbounded_channel();
    let (tx, local_rx) = smpsc::channel();
    let (wake, files) = start(Worker::new(local_rx, out), &tx, host)?;
    let caps = if files {
        Caps::STREAM_FILECLIP_ENABLED | Caps::FILECLIP_NO_FILE_PATHS | Caps::CAN_LOCK_CLIPDATA | Caps::HUGE_FILE_SUPPORT_ENABLED
    } else {
        Caps::empty()
    };
    let temp = std::env::temp_dir().to_string_lossy().into_owned();
    let temp = if temp.chars().count() < 250 { temp } else { "C:\\Windows\\Temp".into() };
    let backend = Backend { tx: tx.clone(), wake: wake.clone(), caps, temp };
    let tick = tokio::time::interval_at(tokio::time::Instant::now() + TICK, TICK);
    Some((CliprdrClient::new(Box::new(backend)), Link { rx, tick, open: true, _stop: Stop(tx, wake) }))
}

/// Traite un événement du presse-papiers : trames à envoyer au serveur.
pub fn process(stage: &mut ActiveStage, ev: ClipEvent) -> SessionResult<Vec<ActiveStageOutput>> {
    let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else { return Ok(Vec::new()) };
    let Some(msgs) = apply(c, ev) else { return Ok(Vec::new()) };
    let frame = stage.process_svc_processor_messages(msgs)?;
    Ok(if frame.is_empty() { Vec::new() } else { vec![ActiveStageOutput::ResponseFrame(frame)] })
}

/// Message du fil presse-papiers -> PDU du canal. Une erreur n'interrompt jamais la session.
fn apply(c: &mut CliprdrClient, ev: ClipEvent) -> Option<SvcProcessorMessages<CliprdrClient>> {
    let res = match ev {
        ClipEvent::Tick => c.drive_timeouts(),
        ClipEvent::Message(m) => match m {
            ClipboardMessage::SendInitiateCopy(f) => c.initiate_copy(&f),
            ClipboardMessage::SendInitiateFileCopy(files) => c.initiate_file_copy(files),
            ClipboardMessage::SendFormatData(r) => c.submit_format_data(r),
            ClipboardMessage::SendFileContentsResponse(r) => c.submit_file_contents(r),
            ClipboardMessage::SendInitiatePaste(id) => {
                let r = c.initiate_paste(id);
                if r.is_err() {
                    // le fil presse-papiers attend une réponse : refus immédiat
                    feedback(c, ToLocal::DataResponse(None));
                }
                r
            }
            ClipboardMessage::SendFileContentsRequest(req) => {
                let stream = req.stream_id;
                let r = c.request_file_contents(req);
                if r.is_err() {
                    feedback(c, ToLocal::FileResponse(stream, None));
                }
                r
            }
            ClipboardMessage::Error(e) => {
                eprintln!("escale: presse-papiers : {e}");
                return None;
            }
        },
    };
    match res {
        Ok(m) => {
            let list: Vec<_> = m.into();
            (!list.is_empty()).then(|| list.into())
        }
        Err(e) => {
            eprintln!("escale: presse-papiers : {e}");
            None
        }
    }
}

fn feedback(c: &CliprdrClient, m: ToLocal) {
    if let Some(b) = c.downcast_backend::<Backend>() {
        b.send(m);
    }
}

/// Accès au presse-papiers du système.
trait Os {
    /// Formats présents (identifiant, nom pour les formats enregistrés), `None` s'ils viennent de cette session.
    fn formats(&mut self) -> Option<Vec<(u32, Option<String>)>>;
    /// Fichiers copiés (CF_HDROP).
    fn files(&mut self) -> Vec<PathBuf>;
    fn read(&mut self, id: u32) -> Option<Vec<u8>>;
    /// Identifiant local d'un format nommé.
    fn register(&mut self, name: &str) -> Option<u32>;
    /// Prend le presse-papiers et y annonce ces formats en rendu différé.
    fn own(&mut self, ids: &[u32]);
    /// Pas de rendu différé : les données distantes sont écrites dès la copie.
    fn eager(&self) -> bool {
        false
    }
    fn accepts(&self, _id: u32) -> bool {
        true
    }
    fn write(&mut self, _id: u32, _data: Vec<u8>) {}
    /// Contenu modifié depuis le dernier appel (surveillance par scrutation).
    fn changed(&mut self) -> bool {
        false
    }
}

/// Logique du fil presse-papiers, indépendante du système.
struct Worker {
    rx: smpsc::Receiver<ToLocal>,
    out: mpsc::UnboundedSender<ClipboardMessage>,
    queued: VecDeque<ToLocal>,
    caps: Caps,
    ready: bool,
    /// Copie locale survenue avant l'initialisation du canal.
    dirty: bool,
    /// Formats distants annoncés localement : (identifiant local, identifiant distant).
    remote: Vec<(u32, u32)>,
    /// Formats locaux textuels de la copie distante (délai d'attente court).
    texts: Vec<u32>,
    /// Données distantes déjà rendues localement (rendues à nouveau à la fin de la session).
    rendered: Vec<(u32, Vec<u8>)>,
    /// Demandes de données abandonnées (délai dépassé) : leurs réponses tardives sont écartées.
    abandoned: VecDeque<Instant>,
    /// Identifiant distant de la liste de fichiers.
    remote_files: Option<u32>,
    /// Fichiers locaux annoncés au serveur (index = `lindex`).
    local_files: Vec<PathBuf>,
    /// Instantanés verrouillés par le serveur.
    locked: HashMap<u32, Vec<PathBuf>>,
    stream: u32,
    quit: bool,
}

impl Worker {
    fn new(rx: smpsc::Receiver<ToLocal>, out: mpsc::UnboundedSender<ClipboardMessage>) -> Self {
        Worker {
            rx,
            out,
            queued: VecDeque::new(),
            caps: Caps::empty(),
            ready: false,
            dirty: false,
            remote: Vec::new(),
            texts: Vec::new(),
            rendered: Vec::new(),
            abandoned: VecDeque::new(),
            remote_files: None,
            local_files: Vec::new(),
            locked: HashMap::new(),
            stream: 0,
            quit: false,
        }
    }

    fn send(&mut self, m: ClipboardMessage) {
        if self.out.send(m).is_err() {
            self.quit = true;
        }
    }

    fn try_next(&mut self) -> Option<ToLocal> {
        if let Some(e) = self.queued.pop_front() {
            return Some(e);
        }
        match self.rx.try_recv() {
            Ok(e) => Some(e),
            Err(smpsc::TryRecvError::Empty) => None,
            Err(smpsc::TryRecvError::Disconnected) => {
                self.quit = true;
                None
            }
        }
    }

    fn next(&mut self, timeout: Duration) -> Option<ToLocal> {
        if let Some(e) = self.queued.pop_front() {
            return Some(e);
        }
        match self.rx.recv_timeout(timeout) {
            Ok(e) => Some(e),
            Err(smpsc::RecvTimeoutError::Timeout) => None,
            Err(smpsc::RecvTimeoutError::Disconnected) => {
                self.quit = true;
                None
            }
        }
    }

    /// Attend une réponse du serveur : `pick` la reconnaît (`Ok(Some)`), l'écarte (`Ok(None)`) ou
    /// rend le message, traité ensuite (`Err`).
    fn wait<T>(&mut self, timeout: Duration, mut pick: impl FnMut(ToLocal) -> Result<Option<T>, ToLocal>) -> Option<T> {
        let end = Instant::now() + timeout;
        let mut later = Vec::new();
        let res = loop {
            let left = end.saturating_duration_since(Instant::now());
            if self.quit || left.is_zero() {
                break None;
            }
            match self.rx.recv_timeout(left) {
                Ok(ToLocal::Quit) | Err(smpsc::RecvTimeoutError::Disconnected) => {
                    self.quit = true;
                    break None;
                }
                Ok(ev) => match pick(ev) {
                    Ok(Some(v)) => break Some(v),
                    Ok(None) => {}
                    Err(ev) => later.push(ev),
                },
                Err(smpsc::RecvTimeoutError::Timeout) => break None,
            }
        };
        self.queued.extend(later);
        res
    }

    /// Réponse tardive à une demande abandonnée (à écarter) ?
    fn late_response(abandoned: &mut VecDeque<Instant>) -> bool {
        abandoned.retain(|t| t.elapsed() < LATE);
        abandoned.pop_front().is_some()
    }

    /// Demande au serveur les données d'un format ; `None` sans réponse (délai, session fermée).
    /// Les réponses arrivent dans l'ordre des demandes : celles des demandes abandonnées sont écartées.
    fn request<T>(&mut self, remote: u32, timeout: Duration, mut pick: impl FnMut(ToLocal) -> Result<T, ToLocal>) -> Option<T> {
        if self.quit {
            return None;
        }
        self.send(ClipboardMessage::SendInitiatePaste(ClipboardFormatId::new(remote)));
        let mut abandoned = std::mem::take(&mut self.abandoned);
        let res = self.wait(timeout, |e| match e {
            ToLocal::DataResponse(_) | ToLocal::RemoteFiles(_) if Self::late_response(&mut abandoned) => Ok(None),
            e => pick(e).map(Some),
        });
        if res.is_none() && !self.quit {
            abandoned.push_back(Instant::now());
        }
        self.abandoned = abandoned;
        res
    }

    /// Garde une copie des données distantes rendues (pour la fin de la session).
    fn remember(&mut self, local: u32, data: &[u8]) {
        self.rendered.retain(|(id, _)| *id != local);
        let used: usize = self.rendered.iter().map(|(_, d)| d.len()).sum();
        if used + data.len() <= MAX_CACHE {
            self.rendered.push((local, data.to_vec()));
        }
    }

    /// Fin de vie de la fenêtre propriétaire (WM_RENDERALLFORMATS) : données à laisser dans le
    /// presse-papiers. Session fermée : seulement celles déjà reçues (les autres formats seraient
    /// « morts », annoncés mais vides) ; sinon, les formats manquants sont encore demandés.
    fn render_all(&mut self, os: &mut dyn Os) -> Vec<(u32, Vec<u8>)> {
        if !self.quit {
            let missing: Vec<u32> =
                self.remote.iter().map(|(l, _)| *l).filter(|l| *l != CF_HDROP && !self.rendered.iter().any(|(r, _)| r == l)).collect();
            for l in missing {
                self.render(os, l);
            }
        }
        self.rendered.clone()
    }

    fn handle(&mut self, os: &mut dyn Os, ev: ToLocal) {
        match ev {
            ToLocal::Caps(c) => self.caps = c,
            ToLocal::Announce => {
                // réponse obligatoire, même vide : elle achève l'initialisation du canal
                let formats = os.formats().map(|f| announced(&f)).unwrap_or_default();
                self.send(ClipboardMessage::SendInitiateCopy(formats));
            }
            ToLocal::Ready => {
                self.ready = true;
                // les fichiers ne peuvent être annoncés qu'une fois le canal prêt
                if self.dirty || !os.files().is_empty() {
                    self.local_changed(os);
                }
            }
            ToLocal::RemoteFormats(f) => self.remote_copy(os, &f),
            ToLocal::DataRequest(id) => {
                let r = match os.read(id).and_then(|d| normalize(id, d)) {
                    Some(d) => OwnedFormatDataResponse::new_data(d),
                    None => OwnedFormatDataResponse::new_error(),
                };
                self.send(ClipboardMessage::SendFormatData(r));
            }
            ToLocal::FileRequest(r) => {
                let resp = self.serve_file(&r);
                self.send(ClipboardMessage::SendFileContentsResponse(resp));
            }
            ToLocal::Lock(id) => {
                if self.locked.len() >= 100 {
                    self.locked.clear();
                }
                self.locked.insert(id, self.local_files.clone());
            }
            ToLocal::Unlock(id) => {
                self.locked.remove(&id);
            }
            ToLocal::Quit => self.quit = true,
            // réponse arrivée après l'abandon de l'attente
            ToLocal::DataResponse(_) | ToLocal::RemoteFiles(_) => {
                Self::late_response(&mut self.abandoned);
            }
            ToLocal::FileResponse(..) => {}
            #[cfg(test)]
            ToLocal::Paste(id, reply) => {
                let _ = reply.send(self.render(os, id));
            }
        }
    }

    /// Copie locale : annonce au serveur (sauf si le contenu vient de lui).
    fn local_changed(&mut self, os: &mut dyn Os) {
        if !self.ready {
            self.dirty = true;
            return;
        }
        self.dirty = false;
        let Some(formats) = os.formats() else { return };
        if self.caps.contains(Caps::STREAM_FILECLIP_ENABLED) && formats.iter().any(|(id, _)| *id == CF_HDROP) {
            let (desc, paths) = describe_files(&os.files());
            if !desc.is_empty() {
                self.local_files = paths;
                self.send(ClipboardMessage::SendInitiateFileCopy(desc));
                return;
            }
        }
        let list = announced(&formats);
        self.send(ClipboardMessage::SendInitiateCopy(list));
    }

    /// Copie distante : formats annoncés localement en rendu différé.
    fn remote_copy(&mut self, os: &mut dyn Os, formats: &[ClipboardFormat]) {
        self.remote.clear();
        self.texts.clear();
        self.rendered.clear();
        self.remote_files = None;
        let unicode = formats.iter().any(|f| f.id.value() == CF_UNICODETEXT);
        for f in formats {
            let id = f.id.value();
            let name = f.name.as_ref().map(|n| n.value()).filter(|n| !n.is_empty());
            let local = match name {
                Some(FILE_LIST) => {
                    if !self.caps.contains(Caps::STREAM_FILECLIP_ENABLED) {
                        continue;
                    }
                    self.remote_files = Some(id);
                    Some(CF_HDROP)
                }
                Some(n) if NAMED.contains(&n) => os.register(n),
                Some(_) => None,
                // le texte 8 bits converti par Windows abîmerait les accents
                None if unicode && (id == CF_TEXT || id == CF_OEMTEXT) => None,
                None => STANDARD.contains(&id).then_some(id),
            };
            if let Some(l) = local.filter(|l| os.accepts(*l))
                && !self.remote.iter().any(|(a, _)| *a == l)
            {
                self.remote.push((l, id));
                if name.map_or(TEXT_IDS.contains(&id), |n| TEXT_NAMED.contains(&n)) {
                    self.texts.push(l);
                }
            }
        }
        if self.remote.is_empty() {
            return;
        }
        if os.eager() {
            for (l, _) in self.remote.clone() {
                if let Some(d) = self.render(os, l) {
                    os.write(l, d);
                }
            }
        } else {
            let ids: Vec<u32> = self.remote.iter().map(|(l, _)| *l).collect();
            os.own(&ids);
        }
    }

    /// Données distantes d'un format local (collage local), converties pour ce système.
    fn render(&mut self, _os: &mut dyn Os, local: u32) -> Option<Vec<u8>> {
        let data = if local == CF_HDROP && self.remote_files.is_some() {
            dropfiles(&self.download()?)
        } else {
            let remote = self.remote.iter().find(|(l, _)| *l == local)?.1;
            let timeout = if self.texts.contains(&local) { TEXT_TIMEOUT } else { TIMEOUT };
            let data = self.request(remote, timeout, |e| match e {
                ToLocal::DataResponse(d) => Ok(d),
                e => Err(e),
            })??;
            normalize(local, data)?
        };
        self.remember(local, &data);
        Some(data)
    }

    fn next_stream(&mut self) -> u32 {
        self.stream = self.stream.wrapping_add(1);
        self.stream
    }

    fn file_request(&mut self, index: usize, flags: FileContentsFlags, position: u64, size: u32) -> Option<Vec<u8>> {
        let stream = self.next_stream();
        let req = FileContentsRequest { stream_id: stream, index: i32::try_from(index).ok()?, flags, position, requested_size: size, data_id: None };
        self.send(ClipboardMessage::SendFileContentsRequest(req));
        self.wait(FILE_TIMEOUT, |e| match e {
            ToLocal::FileResponse(s, d) if s == stream => Ok(Some(d)),
            e => Err(e),
        })?
    }

    /// Télécharge les fichiers copiés sur le bureau distant ; chemins de premier niveau.
    fn download(&mut self) -> Option<Vec<PathBuf>> {
        let remote = self.remote_files?;
        let files = self.request(remote, TIMEOUT, |e| match e {
            ToLocal::RemoteFiles(f) => Ok(Some(f)),
            ToLocal::DataResponse(_) => Ok(None),
            e => Err(e),
        })??;
        let dir = clip_dir().join(uuid::Uuid::new_v4().to_string());
        let res = self.download_into(&dir, &files);
        if res.is_none() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        res
    }

    fn download_into(&mut self, dir: &Path, files: &[FileDescriptor]) -> Option<Vec<PathBuf>> {
        use std::io::Write;
        std::fs::create_dir_all(dir).ok()?;
        let mut top = Vec::new();
        for (i, f) in files.iter().enumerate().take(MAX_FILES) {
            let Some(rel) = safe_relative(f) else { continue };
            let path = dir.join(&rel);
            if rel.components().count() == 1 {
                top.push(path.clone());
            }
            if f.attributes.is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY)) {
                std::fs::create_dir_all(&path).ok()?;
                continue;
            }
            if let Some(p) = path.parent() {
                std::fs::create_dir_all(p).ok()?;
            }
            let size = match f.file_size {
                Some(s) => s,
                None => {
                    let d = self.file_request(i, FileContentsFlags::SIZE, 0, 8)?;
                    u64::from_le_bytes(d.get(..8)?.try_into().ok()?)
                }
            };
            let mut out = std::fs::File::create(&path).ok()?;
            let mut pos = 0u64;
            while pos < size {
                let n = u32::try_from((size - pos).min(u64::from(CHUNK))).ok()?;
                let mut data = self.file_request(i, FileContentsFlags::RANGE, pos, n)?;
                // fichier raccourci entre la copie et le collage : gardé tel quel
                if data.is_empty() {
                    break;
                }
                // jamais plus que demandé (la taille annoncée borne le fichier écrit)
                data.truncate(n as usize);
                out.write_all(&data).ok()?;
                pos += data.len() as u64;
            }
            if let Some(t) = f.last_write_time.and_then(from_filetime) {
                let _ = out.set_modified(t);
            }
        }
        Some(top)
    }

    /// Le serveur lit un fichier local annoncé.
    fn serve_file(&self, r: &FileContentsRequest) -> FileContentsResponse<'static> {
        use std::io::{Read, Seek, SeekFrom};
        let list = r.data_id.and_then(|id| self.locked.get(&id)).unwrap_or(&self.local_files);
        let Some(path) = usize::try_from(r.index).ok().and_then(|i| list.get(i)) else {
            return FileContentsResponse::new_error(r.stream_id);
        };
        if r.flags.contains(FileContentsFlags::SIZE) {
            return match std::fs::metadata(path) {
                Ok(m) => FileContentsResponse::new_size_response(r.stream_id, if m.is_dir() { 0 } else { m.len() }),
                Err(_) => FileContentsResponse::new_error(r.stream_id),
            };
        }
        let read = || -> std::io::Result<Vec<u8>> {
            let mut f = std::fs::File::open(path)?;
            f.seek(SeekFrom::Start(r.position))?;
            let mut buf = Vec::new();
            f.take(u64::from(r.requested_size.min(16 << 20))).read_to_end(&mut buf)?;
            Ok(buf)
        };
        match read() {
            Ok(buf) => FileContentsResponse::new_data_response(r.stream_id, buf),
            Err(_) => FileContentsResponse::new_error(r.stream_id),
        }
    }
}

/// Formats locaux annoncés au serveur.
fn announced(formats: &[(u32, Option<String>)]) -> Vec<ClipboardFormat> {
    let unicode = formats.iter().any(|(id, _)| *id == CF_UNICODETEXT);
    let mut out: Vec<ClipboardFormat> = Vec::new();
    for (id, name) in formats {
        let ok = match name.as_deref() {
            Some(n) => NAMED.contains(&n),
            None => STANDARD.contains(id) && !(unicode && (*id == CF_TEXT || *id == CF_OEMTEXT)),
        };
        if ok && !out.iter().any(|f| f.id.value() == *id) {
            let f = ClipboardFormat::new(ClipboardFormatId::new(*id));
            out.push(match name {
                Some(n) => f.with_name(ClipboardFormatName::new(n.clone())),
                None => f,
            });
        }
    }
    out
}

/// Vérifie et convertit des données échangées (dans les deux sens).
fn normalize(id: u32, data: Vec<u8>) -> Option<Vec<u8>> {
    if data.len() > MAX_DATA {
        return None;
    }
    match id {
        CF_UNICODETEXT => Some(utf16_bytes(&utf16_text(&data))),
        CF_TEXT | CF_OEMTEXT => {
            let mut d: Vec<u8> = data.into_iter().take_while(|b| *b != 0).collect();
            d.push(0);
            Some(d)
        }
        CF_DIB | CF_DIBV5 => dib_valid(&data).then_some(data),
        _ => Some(data),
    }
}

/// Fins de ligne Windows (CRLF), attendues par les applications des deux côtés.
pub fn crlf(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                out.push_str("\r\n");
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            '\n' => out.push_str("\r\n"),
            c => out.push(c),
        }
    }
    out
}

/// Texte UTF‑16LE jusqu'au premier terminateur.
pub fn utf16_text(data: &[u8]) -> String {
    let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|u| *u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// CF_UNICODETEXT : UTF‑16LE, fins de ligne CRLF, terminateur nul.
pub fn utf16_bytes(text: &str) -> Vec<u8> {
    crlf(text).encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// CF_HDROP : structure DROPFILES (chemins larges) suivie des chemins, double terminateur.
pub fn dropfiles(paths: &[PathBuf]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend(20u32.to_le_bytes()); // pFiles
    v.extend([0u8; 8]); // pt
    v.extend(0u32.to_le_bytes()); // fNC
    v.extend(1u32.to_le_bytes()); // fWide
    for p in paths {
        for u in p.to_string_lossy().encode_utf16().chain([0]) {
            v.extend(u.to_le_bytes());
        }
    }
    v.extend([0u8; 2]);
    v
}

/// Chemins d'une structure DROPFILES.
pub fn parse_dropfiles(data: &[u8]) -> Vec<PathBuf> {
    let u32_at = |o: usize| data.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let (Some(off), Some(wide)) = (u32_at(0), u32_at(16)) else { return Vec::new() };
    let Some(body) = data.get(off as usize..) else { return Vec::new() };
    let names: Vec<String> = if wide != 0 {
        let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        units.split(|u| *u == 0).take_while(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()
    } else {
        body.split(|b| *b == 0).take_while(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
    };
    names.into_iter().map(PathBuf::from).collect()
}

/// Dossier des fichiers reçus du bureau distant.
fn clip_dir() -> PathBuf {
    std::env::temp_dir().join("Escale").join("presse-papiers")
}

/// Supprime les fichiers reçus il y a plus d'un jour.
fn clean_clip_dir() {
    let Ok(entries) = std::fs::read_dir(clip_dir()) else { return };
    let day = Duration::from_secs(24 * 3600);
    for e in entries.flatten() {
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > day);
        if old {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Chemin relatif sûr d'un fichier distant (ni `..`, ni chemin absolu, ni nom de périphérique).
fn safe_relative(f: &FileDescriptor) -> Option<PathBuf> {
    let mut rel = PathBuf::new();
    let parts = f.relative_path.iter().flat_map(|p| p.split('\\')).chain(f.name.split('\\'));
    for part in parts.filter(|p| !p.is_empty()) {
        let mut comps = Path::new(part).components();
        let ok = matches!(comps.next(), Some(Component::Normal(_))) && comps.next().is_none();
        if !ok || part.contains(['/', ':']) || ironrdp_cliprdr::is_windows_device_name(part) {
            return None;
        }
        rel.push(part);
    }
    (!rel.as_os_str().is_empty()).then_some(rel)
}

/// Horodatage Windows (centaines de nanosecondes depuis 1601).
fn to_filetime(t: std::time::SystemTime) -> Option<u64> {
    let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    u64::try_from(d.as_nanos() / 100).ok()?.checked_add(116_444_736_000_000_000)
}

fn from_filetime(ft: u64) -> Option<std::time::SystemTime> {
    let since_unix = ft.checked_sub(116_444_736_000_000_000)?;
    std::time::UNIX_EPOCH.checked_add(Duration::from_nanos(since_unix.checked_mul(100)?))
}

/// Descripteurs des fichiers locaux (dossiers parcourus), et chemin de chacun.
fn describe_files(paths: &[PathBuf]) -> (Vec<FileDescriptor>, Vec<PathBuf>) {
    fn add(p: &Path, rel: Option<&str>, depth: usize, d: &mut Vec<FileDescriptor>, ps: &mut Vec<PathBuf>) {
        let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else { return };
        let Ok(meta) = std::fs::metadata(p) else { return };
        let wire = match rel {
            Some(r) => format!("{r}\\{name}"),
            None => name.clone(),
        };
        // mêmes règles que le canal (sinon les index ne correspondraient plus)
        if d.len() >= MAX_FILES || name.is_empty() || wire.chars().count() > 259 {
            return;
        }
        let mut fd = FileDescriptor::new(name);
        if let Some(t) = meta.modified().ok().and_then(to_filetime) {
            fd = fd.with_last_write_time(t);
        }
        fd = if meta.is_dir() {
            fd.with_attributes(ClipboardFileAttributes::DIRECTORY).with_file_size(0)
        } else {
            fd.with_attributes(ClipboardFileAttributes::NORMAL).with_file_size(meta.len())
        };
        if let Some(r) = rel {
            fd = fd.with_relative_path(r);
        }
        d.push(fd);
        ps.push(p.to_path_buf());
        if meta.is_dir() && depth < 32 {
            let mut children: Vec<PathBuf> = std::fs::read_dir(p).into_iter().flatten().flatten().map(|e| e.path()).collect();
            children.sort();
            for c in children {
                add(&c, Some(&wire), depth + 1, d, ps);
            }
        }
    }
    let (mut d, mut ps) = (Vec::new(), Vec::new());
    for p in paths {
        add(p, None, 0, &mut d, &mut ps);
    }
    (d, ps)
}

// --- images DIB (BITMAPINFOHEADER et suivants)

struct Dib {
    width: usize,
    height: usize,
    top_down: bool,
    bpp: u16,
    compression: u32,
    palette: usize,
    pixels: usize,
    masks: [u32; 4],
}

fn le_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Structure d'un DIB, si l'en-tête est cohérent et les données suffisantes.
fn dib_layout(d: &[u8]) -> Option<Dib> {
    let header = le_u32(d, 0)? as usize;
    if !matches!(header, 40 | 52 | 56 | 108 | 124) || d.len() < header {
        return None;
    }
    let w = le_u32(d, 4)? as i32;
    let h = le_u32(d, 8)? as i32;
    let (planes, bpp, compression) = (le_u16(d, 12)?, le_u16(d, 14)?, le_u32(d, 16)?);
    let (size_image, used) = (le_u32(d, 20)? as usize, le_u32(d, 32)? as usize);
    if w <= 0 || h == 0 || w > 1 << 16 || h.unsigned_abs() > 1 << 16 || planes != 1 || ![1, 4, 8, 16, 24, 32].contains(&bpp) {
        return None;
    }
    let (width, height) = (w as usize, h.unsigned_abs() as usize);
    let extra_masks = match (header, compression) {
        (40, 3) => 12,
        (40, 6) => 16,
        _ => 0,
    };
    let palette = if used > 0 { used.min(1 << 16) } else if bpp <= 8 { 1 << bpp } else { 0 };
    let pixels = header + extra_masks + palette * 4;
    let masks = if compression == 3 || compression == 6 {
        let m = |i: usize| le_u32(d, 40 + 4 * i).unwrap_or(0);
        [m(0), m(1), m(2), if header > 52 || extra_masks == 16 { m(3) } else { 0 }]
    } else if bpp == 16 {
        [0x7C00, 0x03E0, 0x001F, 0]
    } else {
        [0x00FF_0000, 0x0000_FF00, 0x0000_00FF, 0]
    };
    let need = match compression {
        0 | 3 | 6 => (width * bpp as usize).div_ceil(32) * 4 * height,
        // RLE, JPEG, PNG : taille déclarée
        1 | 2 | 4 | 5 if size_image > 0 => size_image,
        _ => return None,
    };
    (d.len() >= pixels.checked_add(need)?).then_some(Dib { width, height, top_down: h < 0, bpp, compression, palette, pixels, masks })
}

/// DIB cohérent (protège les applications locales d'une image distante malformée).
pub fn dib_valid(d: &[u8]) -> bool {
    dib_layout(d).is_some()
}

/// DIB non compressé -> (largeur, hauteur, RGBA).
#[cfg_attr(not(test), allow(dead_code))]
pub fn dib_to_rgba(d: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    let dib = dib_layout(d)?;
    if !matches!(dib.compression, 0 | 3 | 6) {
        return None;
    }
    let stride = (dib.width * dib.bpp as usize).div_ceil(32) * 4;
    let pal_off = dib.pixels - dib.palette * 4;
    let channel = |v: u32, mask: u32| -> u8 {
        if mask == 0 {
            return 255;
        }
        // 64 bits : un masque de 32 bits (0xFFFFFFFF) ferait déborder le calcul
        let max = u64::from(mask >> mask.trailing_zeros());
        (u64::from((v & mask) >> mask.trailing_zeros()) * 255 / max) as u8
    };
    let mut out = Vec::with_capacity(dib.width * dib.height * 4);
    let mut any_alpha = false;
    for y in 0..dib.height {
        let row = if dib.top_down { y } else { dib.height - 1 - y };
        let line = &d[dib.pixels + row * stride..];
        for x in 0..dib.width {
            let px = match dib.bpp {
                1 | 4 | 8 => {
                    let bits = dib.bpp as usize;
                    let byte = line[x * bits / 8];
                    let shift = 8 - bits - (x * bits % 8);
                    let i = ((byte >> shift) as usize) & ((1 << bits) - 1);
                    let p = d.get(pal_off + i * 4..pal_off + i * 4 + 3)?;
                    [p[2], p[1], p[0], 255]
                }
                16 => {
                    let v = u32::from(u16::from_le_bytes([line[x * 2], line[x * 2 + 1]]));
                    [channel(v, dib.masks[0]), channel(v, dib.masks[1]), channel(v, dib.masks[2]), channel(v, dib.masks[3])]
                }
                24 => [line[x * 3 + 2], line[x * 3 + 1], line[x * 3], 255],
                _ => {
                    let v = u32::from_le_bytes([line[x * 4], line[x * 4 + 1], line[x * 4 + 2], line[x * 4 + 3]]);
                    // en BI_RGB, l'octet haut n'est pas une transparence fiable
                    let a = if dib.compression == 0 { 0 } else { dib.masks[3] };
                    let alpha = if a == 0 { 255 } else { channel(v, a) };
                    any_alpha |= alpha != 0;
                    [channel(v, dib.masks[0]), channel(v, dib.masks[1]), channel(v, dib.masks[2]), alpha]
                }
            };
            out.extend(px);
        }
    }
    // masque alpha entièrement nul : image opaque
    if dib.bpp == 32 && !any_alpha {
        out.as_chunks_mut::<4>().0.iter_mut().for_each(|p| p[3] = 255);
    }
    Some((dib.width, dib.height, out))
}

/// RGBA -> DIB 32 bits (BITMAPINFOHEADER, BI_RGB, lignes de bas en haut).
#[cfg_attr(not(test), allow(dead_code))]
pub fn rgba_to_dib(width: usize, height: usize, rgba: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(40 + width * height * 4);
    v.extend(40u32.to_le_bytes());
    v.extend((width as i32).to_le_bytes());
    v.extend((height as i32).to_le_bytes());
    v.extend(1u16.to_le_bytes());
    v.extend(32u16.to_le_bytes());
    v.extend(0u32.to_le_bytes()); // BI_RGB
    v.extend(((width * height * 4) as u32).to_le_bytes());
    v.extend([0u8; 16]); // résolution, palette
    for y in (0..height).rev() {
        for p in rgba[y * width * 4..(y + 1) * width * 4].as_chunks::<4>().0 {
            v.extend([p[2], p[1], p[0], p[3]]);
        }
    }
    v
}

// --- côté système

/// Démarre le fil presse-papiers : réveil, et prise en charge des fichiers.
#[cfg_attr(not(test), allow(unused_variables))]
fn start(w: Worker, tx: &smpsc::Sender<ToLocal>, host: &crate::model::Host) -> Option<(Wake, bool)> {
    clean_clip_dir();
    #[cfg(test)]
    {
        let mem = TEST_CLIPS.lock().ok()?.iter().find(|(id, _)| *id == host.id).map(|(_, m)| m.clone()).unwrap_or_default();
        mem.0.lock().ok()?.link = Some(tx.clone());
        poll_start(w, MemOs(mem), true)
    }
    #[cfg(all(windows, not(test)))]
    {
        win::start(w)
    }
    #[cfg(all(not(windows), not(test)))]
    {
        poll_start(w, text::TextOs::new()?, false)
    }
}

/// Fil presse-papiers sans fenêtre système : scrutation régulière du contenu.
#[cfg_attr(all(windows, not(test)), allow(dead_code))]
fn poll_start(mut w: Worker, mut os: impl Os + Send + 'static, files: bool) -> Option<(Wake, bool)> {
    std::thread::Builder::new()
        .name("escale-presse-papiers".into())
        .spawn(move || {
            while !w.quit {
                match w.next(Duration::from_millis(if cfg!(test) { 20 } else { 500 })) {
                    Some(ev) => w.handle(&mut os, ev),
                    None if !w.quit && os.changed() => w.local_changed(&mut os),
                    None => {}
                }
            }
        })
        .ok()?;
    Some((Arc::new(|| {}), files))
}

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
mod win {
    //! Fenêtre cachée (message seulement) : surveillance du presse-papiers et rendu différé.

    use super::*;
    use std::cell::RefCell;
    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::DataExchange::{
        AddClipboardFormatListener, CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetClipboardData, GetClipboardFormatNameW,
        GetClipboardOwner, OpenClipboard, RegisterClipboardFormatW, RemoveClipboardFormatListener, SetClipboardData,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG, PostMessageW, PostQuitMessage,
        RegisterClassW, WM_APP, WM_CLIPBOARDUPDATE, WM_RENDERALLFORMATS, WM_RENDERFORMAT, WNDCLASSW,
    };

    const WM_WAKE: u32 = WM_APP + 1;

    thread_local! {
        static STATE: RefCell<Option<(Worker, WinOs)>> = const { RefCell::new(None) };
    }

    pub(super) fn start(w: Worker) -> Option<(Wake, bool)> {
        let (htx, hrx) = smpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("escale-presse-papiers".into())
            .spawn(move || {
                let hwnd = unsafe { create() };
                let _ = htx.send((!hwnd.is_null()).then_some(hwnd as usize));
                if hwnd.is_null() {
                    return;
                }
                unsafe { AddClipboardFormatListener(hwnd) };
                STATE.with(|s| *s.borrow_mut() = Some((w, WinOs { hwnd })));
                let mut msg: MSG = unsafe { std::mem::zeroed() };
                while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
                    unsafe { DispatchMessageW(&msg) };
                }
                unsafe {
                    RemoveClipboardFormatListener(hwnd);
                    DestroyWindow(hwnd);
                }
                STATE.with(|s| s.borrow_mut().take());
            })
            .ok()?;
        let hwnd = hrx.recv().ok()??;
        let wake: Wake = Arc::new(move || unsafe {
            PostMessageW(hwnd as HWND, WM_WAKE, 0, 0);
        });
        Some((wake, true))
    }

    unsafe fn create() -> HWND {
        let class: Vec<u16> = "EscalePressePapiers\0".encode_utf16().collect();
        unsafe {
            let inst = GetModuleHandleW(std::ptr::null());
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = inst;
            wc.lpszClassName = class.as_ptr();
            // échoue sans conséquence si la classe existe déjà (autre session)
            RegisterClassW(&wc);
            CreateWindowExW(0, class.as_ptr(), std::ptr::null(), 0, 0, 0, 0, 0, HWND_MESSAGE, std::ptr::null_mut(), inst, std::ptr::null())
        }
    }

    /// Accès à l'état du fil ; ignoré en cas de réentrance (message envoyé pendant un traitement).
    fn with(f: impl FnOnce(&mut Worker, &mut WinOs)) {
        STATE.with(|s| {
            if let Ok(mut g) = s.try_borrow_mut()
                && let Some((w, os)) = g.as_mut()
            {
                f(w, os)
            }
        })
    }

    fn pump() {
        with(|w, os| {
            while let Some(ev) = w.try_next() {
                w.handle(os, ev);
            }
            if w.quit {
                unsafe { PostQuitMessage(0) };
            }
        })
    }

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        match msg {
            WM_CLIPBOARDUPDATE => {
                // contenu posé par cette session : rien à annoncer (pas de boucle)
                with(|w, os| {
                    if unsafe { GetClipboardOwner() } != os.hwnd {
                        w.local_changed(os)
                    }
                });
                pump();
                0
            }
            WM_RENDERFORMAT => {
                let id = wp as u32;
                with(|w, os| {
                    if let Some(d) = w.render(os, id) {
                        unsafe { set_global(id, &d) };
                    }
                });
                0
            }
            WM_RENDERALLFORMATS => {
                // fenêtre détruite (fin de session, reconnexion) alors que des formats distants sont
                // annoncés : ne restent que les données déjà reçues, pas de formats « morts »
                with(|w, os| {
                    let Some(_c) = open(os.hwnd) else { return };
                    if unsafe { GetClipboardOwner() } != os.hwnd {
                        return;
                    }
                    let data = w.render_all(os);
                    unsafe {
                        EmptyClipboard();
                        for (id, d) in data {
                            set_global(id, &d);
                        }
                    }
                });
                0
            }
            WM_WAKE => {
                pump();
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
        }
    }

    pub(super) struct WinOs {
        hwnd: HWND,
    }

    /// Presse-papiers ouvert, refermé à la libération.
    struct Opened;

    impl Drop for Opened {
        fn drop(&mut self) {
            unsafe { CloseClipboard() };
        }
    }

    /// Ouvre le presse-papiers (souvent occupé un court instant par l'application qui copie).
    fn open(hwnd: HWND) -> Option<Opened> {
        for _ in 0..10 {
            if unsafe { OpenClipboard(hwnd) } != 0 {
                return Some(Opened);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    unsafe fn global_bytes(h: HANDLE) -> Option<Vec<u8>> {
        unsafe {
            let size = GlobalSize(h);
            if size == 0 || size > MAX_DATA {
                return None;
            }
            let p = GlobalLock(h) as *const u8;
            if p.is_null() {
                return None;
            }
            let v = std::slice::from_raw_parts(p, size).to_vec();
            GlobalUnlock(h);
            Some(v)
        }
    }

    unsafe fn set_global(id: u32, data: &[u8]) -> bool {
        unsafe {
            let h = GlobalAlloc(GMEM_MOVEABLE, data.len().max(1));
            if h.is_null() {
                return false;
            }
            let p = GlobalLock(h) as *mut u8;
            if p.is_null() {
                GlobalFree(h);
                return false;
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
            GlobalUnlock(h);
            if SetClipboardData(id, h).is_null() {
                GlobalFree(h);
                return false;
            }
            true
        }
    }

    impl Os for WinOs {
        fn formats(&mut self) -> Option<Vec<(u32, Option<String>)>> {
            if unsafe { GetClipboardOwner() } == self.hwnd {
                return None;
            }
            let _c = open(self.hwnd)?;
            let mut out = Vec::new();
            let mut id = 0;
            while out.len() < 512 {
                id = unsafe { EnumClipboardFormats(id) };
                if id == 0 {
                    break;
                }
                let name = (id >= 0xC000).then(|| {
                    let mut buf = [0u16; 256];
                    let n = unsafe { GetClipboardFormatNameW(id, buf.as_mut_ptr(), buf.len() as i32) };
                    String::from_utf16_lossy(&buf[..n.max(0) as usize])
                });
                out.push((id, name.filter(|n| !n.is_empty())));
            }
            Some(out)
        }

        fn files(&mut self) -> Vec<PathBuf> {
            self.read(CF_HDROP).map(|d| parse_dropfiles(&d)).unwrap_or_default()
        }

        fn read(&mut self, id: u32) -> Option<Vec<u8>> {
            let _c = open(self.hwnd)?;
            let h = unsafe { GetClipboardData(id) };
            if h.is_null() {
                return None;
            }
            unsafe { global_bytes(h) }
        }

        fn register(&mut self, name: &str) -> Option<u32> {
            let w: Vec<u16> = name.encode_utf16().chain([0]).collect();
            let id = unsafe { RegisterClipboardFormatW(w.as_ptr()) };
            (id != 0).then_some(id)
        }

        fn own(&mut self, ids: &[u32]) {
            let Some(_c) = open(self.hwnd) else { return };
            unsafe {
                EmptyClipboard();
                for &id in ids {
                    SetClipboardData(id, std::ptr::null_mut());
                }
            }
        }
    }
}

#[cfg(all(not(windows), not(test)))]
mod text {
    //! Autres systèmes : texte seul, par scrutation (arboard), sans rendu différé.

    use super::*;

    pub(super) struct TextOs {
        cb: arboard::Clipboard,
        mine: Option<String>,
        seen: Option<String>,
    }

    impl TextOs {
        pub(super) fn new() -> Option<Self> {
            let mut cb = arboard::Clipboard::new().ok()?;
            let seen = cb.get_text().ok();
            Some(TextOs { cb, mine: None, seen })
        }
    }

    impl Os for TextOs {
        fn formats(&mut self) -> Option<Vec<(u32, Option<String>)>> {
            let t = self.cb.get_text().ok()?;
            (Some(&t) != self.mine.as_ref()).then(|| vec![(CF_UNICODETEXT, None)])
        }
        fn files(&mut self) -> Vec<PathBuf> {
            Vec::new()
        }
        fn read(&mut self, id: u32) -> Option<Vec<u8>> {
            (id == CF_UNICODETEXT).then(|| self.cb.get_text().ok().map(|t| utf16_bytes(&t)))?
        }
        fn register(&mut self, _name: &str) -> Option<u32> {
            None
        }
        fn own(&mut self, _ids: &[u32]) {}
        fn eager(&self) -> bool {
            true
        }
        fn accepts(&self, id: u32) -> bool {
            id == CF_UNICODETEXT
        }
        fn write(&mut self, _id: u32, data: Vec<u8>) {
            let t = utf16_text(&data).replace("\r\n", "\n");
            if self.cb.set_text(t.clone()).is_ok() {
                self.mine = Some(t.clone());
                self.seen = Some(t);
            }
        }
        fn changed(&mut self) -> bool {
            let t = self.cb.get_text().ok();
            let changed = t != self.seen;
            self.seen = t;
            changed
        }
    }
}

// --- presse-papiers en mémoire (tests)

/// Presse-papiers en mémoire des hôtes de test (les autres reçoivent un presse-papiers vide).
#[cfg(test)]
static TEST_CLIPS: std::sync::Mutex<Vec<(uuid::Uuid, Mem)>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
#[derive(Clone, Default)]
pub struct Mem(Arc<std::sync::Mutex<MemState>>);

#[cfg(test)]
#[derive(Default)]
pub struct MemState {
    data: HashMap<u32, Vec<u8>>,
    /// Formats distants en rendu différé.
    delayed: Vec<u32>,
    ours: bool,
    changed: bool,
    files: Vec<PathBuf>,
    names: Vec<String>,
    link: Option<smpsc::Sender<ToLocal>>,
}

#[cfg(test)]
impl Mem {
    /// Les sessions de cet hôte utilisent ce presse-papiers.
    pub fn install(&self, host: uuid::Uuid) {
        TEST_CLIPS.lock().unwrap().push((host, self.clone()));
    }
    pub fn copy(&self, data: Vec<(u32, Vec<u8>)>) {
        let mut st = self.0.lock().unwrap();
        st.data = data.into_iter().collect();
        st.files = st.data.get(&CF_HDROP).map(|d| parse_dropfiles(d)).unwrap_or_default();
        st.delayed.clear();
        st.ours = false;
        st.changed = true;
    }
    pub fn copy_text(&self, s: &str) {
        self.copy(vec![(CF_UNICODETEXT, utf16_bytes(s))]);
    }
    pub fn delayed(&self) -> Vec<u32> {
        self.0.lock().unwrap().delayed.clone()
    }
    /// Collage local : rendu différé demandé au fil presse-papiers.
    pub fn paste(&self, id: u32) -> Option<Vec<u8>> {
        let link = self.0.lock().unwrap().link.clone()?;
        let (tx, rx) = smpsc::channel();
        link.send(ToLocal::Paste(id, tx)).ok()?;
        rx.recv_timeout(Duration::from_secs(60)).ok().flatten()
    }
}

#[cfg(test)]
struct MemOs(Mem);

#[cfg(test)]
impl Os for MemOs {
    fn formats(&mut self) -> Option<Vec<(u32, Option<String>)>> {
        let st = self.0.0.lock().unwrap();
        if st.ours {
            return None;
        }
        let name = |id: u32| (id >= 0xC000).then(|| st.names.get((id - 0xC000) as usize).cloned()).flatten();
        let mut ids: Vec<u32> = st.data.keys().copied().collect();
        ids.sort();
        Some(ids.into_iter().map(|id| (id, name(id))).collect())
    }
    fn files(&mut self) -> Vec<PathBuf> {
        let st = self.0.0.lock().unwrap();
        if st.ours { Vec::new() } else { st.files.clone() }
    }
    fn read(&mut self, id: u32) -> Option<Vec<u8>> {
        self.0.0.lock().unwrap().data.get(&id).cloned()
    }
    fn register(&mut self, name: &str) -> Option<u32> {
        let mut st = self.0.0.lock().unwrap();
        let i = match st.names.iter().position(|n| n == name) {
            Some(i) => i,
            None => {
                st.names.push(name.to_owned());
                st.names.len() - 1
            }
        };
        Some(0xC000 + i as u32)
    }
    fn own(&mut self, ids: &[u32]) {
        let mut st = self.0.0.lock().unwrap();
        st.data.clear();
        st.files.clear();
        st.delayed = ids.to_vec();
        st.ours = true;
        // comme sous Windows : notification de changement, que l'on doit ignorer
        st.changed = true;
    }
    fn changed(&mut self) -> bool {
        std::mem::take(&mut self.0.0.lock().unwrap().changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_cliprdr::CliprdrServer;
    use ironrdp_svc::{SvcMessage, SvcProcessor};

    #[test]
    fn text_is_utf16_crlf_and_terminated() {
        assert_eq!(crlf("a\nb\r\nc\rd"), "a\r\nb\r\nc\r\nd");
        let b = utf16_bytes("é\n😀");
        // é, CR, LF, paire de substitution, terminateur
        assert_eq!(b.len(), (1 + 2 + 2 + 1) * 2);
        assert_eq!(&b[b.len() - 2..], &[0, 0]);
        assert_eq!(utf16_text(&b), "é\r\n😀");
        // s'arrête au premier terminateur, ignore un octet impair final
        let mut d = utf16_bytes("ab");
        d.extend(utf16_bytes("cd"));
        d.push(7);
        assert_eq!(utf16_text(&d), "ab");
        // texte distant sans terminateur ni CRLF : corrigé pour les applications Windows
        let raw: Vec<u8> = "x\ny".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(normalize(CF_UNICODETEXT, raw), Some(utf16_bytes("x\r\ny")));
        assert_eq!(normalize(CF_TEXT, b"abc\0\0garbage".to_vec()), Some(b"abc\0".to_vec()));
        assert_eq!(normalize(CF_TEXT, b"abc".to_vec()), Some(b"abc\0".to_vec()));
    }

    #[test]
    fn dropfiles_round_trip() {
        let paths = vec![PathBuf::from(r"C:\Temp\été.txt"), PathBuf::from(r"C:\Temp\dossier")];
        let d = dropfiles(&paths);
        assert_eq!(u32::from_le_bytes(d[0..4].try_into().unwrap()), 20);
        assert_eq!(parse_dropfiles(&d), paths);
        // variante ANSI
        let mut ansi = d[..20].to_vec();
        ansi[16] = 0;
        ansi.extend(b"C:\\a.txt\0C:\\b\0\0");
        assert_eq!(parse_dropfiles(&ansi), vec![PathBuf::from(r"C:\a.txt"), PathBuf::from(r"C:\b")]);
        assert!(parse_dropfiles(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn dib_round_trip_and_validation() {
        let rgba: Vec<u8> = (0..3 * 2).flat_map(|i| [i as u8 * 10, 100, 200 - i as u8, 255]).collect();
        let dib = rgba_to_dib(3, 2, &rgba);
        assert!(dib_valid(&dib));
        assert_eq!(dib_to_rgba(&dib), Some((3, 2, rgba.clone())));
        // tronqué : refusé (protège les applications locales)
        assert!(!dib_valid(&dib[..dib.len() - 1]));
        assert_eq!(normalize(CF_DIB, dib[..50].to_vec()), None);
        assert_eq!(normalize(CF_DIB, dib.clone()), Some(dib.clone()));
        // en-tête absurde
        let mut bad = dib.clone();
        bad[14] = 7; // 7 bits par pixel
        assert!(!dib_valid(&bad));

        // 24 bits, lignes de haut en bas, remplissage de fin de ligne
        let mut d24 = rgba_to_dib(1, 1, &[0; 4])[..40].to_vec();
        d24[4..8].copy_from_slice(&3i32.to_le_bytes());
        d24[8..12].copy_from_slice(&(-2i32).to_le_bytes());
        d24[14] = 24;
        // ligne : 9 octets + 3 de remplissage
        d24.extend([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 0, 0, 0]);
        let (w, h, px) = dib_to_rgba(&d24).unwrap();
        assert_eq!((w, h), (3, 2));
        assert_eq!(&px[..4], &[3, 2, 1, 255]);
        assert_eq!(&px[12..16], &[12, 11, 10, 255]);

        // 16 bits 5-6-5 (BI_BITFIELDS) : blanc et rouge pur
        let mut d16 = rgba_to_dib(1, 1, &[0; 4])[..40].to_vec();
        d16[4..8].copy_from_slice(&2i32.to_le_bytes());
        d16[8..12].copy_from_slice(&1i32.to_le_bytes());
        d16[14] = 16;
        d16[16] = 3;
        for m in [0xF800u32, 0x07E0, 0x001F] {
            d16.extend(m.to_le_bytes());
        }
        d16.extend([0xFF, 0xFF, 0x00, 0xF8]);
        let (_, _, px) = dib_to_rgba(&d16).unwrap();
        assert_eq!(px, vec![255, 255, 255, 255, 255, 0, 0, 255]);
    }

    /// En-tête DIB : taille d'en-tête, largeur, hauteur, bits par pixel, compression.
    fn dib_header(size: u32, w: i32, h: i32, bpp: u16, compression: u32) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend(size.to_le_bytes());
        d.extend(w.to_le_bytes());
        d.extend(h.to_le_bytes());
        d.extend(1u16.to_le_bytes());
        d.extend(bpp.to_le_bytes());
        d.extend(compression.to_le_bytes());
        d.resize(size as usize, 0);
        d
    }

    #[test]
    fn dib_variants() {
        // 32 bits BI_BITFIELDS (en-tête de 40 octets + 3 masques), de haut en bas
        let mut d = dib_header(40, 2, -1, 32, 3);
        for m in [0x00FF_0000u32, 0x0000_FF00, 0x0000_00FF] {
            d.extend(m.to_le_bytes());
        }
        d.extend([0x11, 0x22, 0x33, 0x00, 0x44, 0x55, 0x66, 0x00]);
        assert_eq!(dib_to_rgba(&d), Some((2, 1, vec![0x33, 0x22, 0x11, 255, 0x66, 0x55, 0x44, 255])));

        // masques de 32 bits (serveur hostile ou exotique) : pas de débordement
        let mut d = dib_header(40, 1, 1, 32, 3);
        for m in [u32::MAX, 0, 0] {
            d.extend(m.to_le_bytes());
        }
        d.extend(u32::MAX.to_le_bytes());
        assert_eq!(dib_to_rgba(&d), Some((1, 1, vec![255, 255, 255, 255])));

        // DIBV5 (124 octets) : masques dans l'en-tête, alpha, profil de couleur après les pixels
        let mut v5 = dib_header(124, 1, 2, 32, 3);
        for (i, m) in [0x00FF_0000u32, 0x0000_FF00, 0x0000_00FF, 0xFF00_0000].into_iter().enumerate() {
            v5[40 + 4 * i..44 + 4 * i].copy_from_slice(&m.to_le_bytes());
        }
        v5[112..116].copy_from_slice(&132u32.to_le_bytes()); // bV5ProfileData
        v5[116..120].copy_from_slice(&16u32.to_le_bytes()); // bV5ProfileSize
        v5.extend([1, 2, 3, 0x80, 4, 5, 6, 0xFF]); // de bas en haut
        v5.extend([0xAB; 16]);
        assert!(dib_valid(&v5));
        assert_eq!(dib_to_rgba(&v5), Some((1, 2, vec![6, 5, 4, 255, 3, 2, 1, 0x80])));
        assert_eq!(normalize(CF_DIBV5, v5.clone()), Some(v5.clone()));

        // 24 bits de bas en haut, 8 bits à palette, 1 bit
        let mut d24 = dib_header(40, 1, 2, 24, 0);
        d24.extend([1, 2, 3, 0, 4, 5, 6, 0]);
        assert_eq!(dib_to_rgba(&d24), Some((1, 2, vec![6, 5, 4, 255, 3, 2, 1, 255])));
        let mut d8 = dib_header(40, 2, 1, 8, 0);
        d8[32..36].copy_from_slice(&2u32.to_le_bytes());
        d8.extend([10, 20, 30, 0, 40, 50, 60, 0, 1, 0, 0, 0]);
        assert_eq!(dib_to_rgba(&d8), Some((2, 1, vec![60, 50, 40, 255, 30, 20, 10, 255])));
        // index hors de la palette : refusé sans panique
        let mut bad = d8.clone();
        bad[48] = 9;
        assert_eq!(dib_to_rgba(&bad), None);
        // dimensions absurdes ou incohérentes
        assert!(!dib_valid(&dib_header(40, 0, 1, 32, 0)));
        assert!(!dib_valid(&dib_header(40, 70_000, 1, 32, 0)));
        assert!(!dib_valid(&dib_header(40, 1, i32::MIN, 32, 0)));
        assert!(!dib_valid(&dib_header(12, 1, 1, 32, 0)), "BITMAPCOREHEADER non pris en charge");
    }

    #[test]
    fn announced_formats_are_filtered() {
        let local = vec![
            (CF_TEXT, None),
            (CF_UNICODETEXT, None),
            (CF_OEMTEXT, None),
            (2, None), // CF_BITMAP : poignée GDI
            (CF_DIB, None),
            (CF_HDROP, None),
            (0xC001, Some("HTML Format".to_owned())),
            (0xC002, Some("Ole Private Data".to_owned())),
        ];
        let ids: Vec<u32> = announced(&local).iter().map(|f| f.id.value()).collect();
        assert_eq!(ids, vec![CF_UNICODETEXT, CF_DIB, 0xC001]);
        assert_eq!(announced(&local)[2].name.as_ref().unwrap().value(), "HTML Format");
        // texte 8 bits seul : conservé
        assert_eq!(announced(&[(CF_TEXT, None)]).len(), 1);
    }

    #[test]
    fn remote_file_names_are_sanitized() {
        let f = |name: &str, rel: Option<&str>| {
            let mut d = FileDescriptor::new(name);
            if let Some(r) = rel {
                d = d.with_relative_path(r);
            }
            safe_relative(&d)
        };
        assert_eq!(f("a.txt", None), Some(PathBuf::from("a.txt")));
        assert_eq!(f("b.txt", Some(r"dir\sub")), Some(PathBuf::from("dir").join("sub").join("b.txt")));
        assert_eq!(f("..", None), None);
        assert_eq!(f("x", Some(r"..\..")), None);
        assert_eq!(f("CON", None), None);
        assert_eq!(f(r"C:\Windows\x", None), None);
        assert_eq!(f("", None), None);
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(from_filetime(to_filetime(t).unwrap()), Some(t));
    }

    fn temp_tree() -> PathBuf {
        let root = std::env::temp_dir().join(format!("escale-clip-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("dossier").join("sous")).unwrap();
        std::fs::write(root.join("a.bin"), big(3 * CHUNK as usize + 123)).unwrap();
        std::fs::write(root.join("dossier").join("b.txt"), b"bonjour").unwrap();
        std::fs::write(root.join("dossier").join("sous").join("c.txt"), b"").unwrap();
        root
    }

    fn big(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn local_files_are_described_recursively() {
        let root = temp_tree();
        let (d, p) = describe_files(&[root.join("a.bin"), root.join("dossier")]);
        let names: Vec<(String, Option<String>)> = d.iter().map(|f| (f.name.clone(), f.relative_path.clone())).collect();
        assert_eq!(
            names,
            vec![
                ("a.bin".into(), None),
                ("dossier".into(), None),
                ("b.txt".into(), Some("dossier".into())),
                ("sous".into(), Some("dossier".into())),
                ("c.txt".into(), Some(r"dossier\sous".into())),
            ]
        );
        assert_eq!(d[0].file_size, Some(3 * CHUNK as u64 + 123));
        assert!(d[1].attributes.unwrap().contains(ClipboardFileAttributes::DIRECTORY));
        assert_eq!(p[2], root.join("dossier").join("b.txt"));
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- canal complet en mémoire : client (ce module) <-> serveur IronRDP

    #[derive(Debug)]
    pub(super) enum Srv {
        Copy(Vec<ClipboardFormat>),
        DataRequest(u32),
        Data(Option<Vec<u8>>),
        Files(Vec<FileDescriptor>),
        FileRequest(FileContentsRequest),
        FileData(u32, Option<Vec<u8>>),
    }

    /// Côté serveur : rappels enregistrés pour le test.
    #[derive(Debug)]
    pub(super) struct SrvBackend(pub(super) smpsc::Sender<Srv>);

    impl ironrdp_core::AsAny for SrvBackend {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    impl CliprdrBackend for SrvBackend {
        fn temporary_directory(&self) -> &str {
            "C:\\Temp"
        }
        fn client_capabilities(&self) -> Caps {
            Caps::STREAM_FILECLIP_ENABLED | Caps::FILECLIP_NO_FILE_PATHS | Caps::CAN_LOCK_CLIPDATA | Caps::HUGE_FILE_SUPPORT_ENABLED
        }
        fn on_ready(&mut self) {}
        fn on_request_format_list(&mut self) {}
        fn on_process_negotiated_capabilities(&mut self, _: Caps) {}
        fn on_remote_copy(&mut self, f: &[ClipboardFormat]) {
            let _ = self.0.send(Srv::Copy(f.to_vec()));
        }
        fn on_format_data_request(&mut self, r: FormatDataRequest) {
            let _ = self.0.send(Srv::DataRequest(r.format.value()));
        }
        fn on_format_data_response(&mut self, r: FormatDataResponse<'_>) {
            let _ = self.0.send(Srv::Data((!r.is_error()).then(|| r.data().to_vec())));
        }
        fn on_file_contents_request(&mut self, r: FileContentsRequest) {
            let _ = self.0.send(Srv::FileRequest(r));
        }
        fn on_file_contents_response(&mut self, r: FileContentsResponse<'_>) {
            let _ = self.0.send(Srv::FileData(r.stream_id(), (!r.is_error()).then(|| r.data().to_vec())));
        }
        fn on_lock(&mut self, _: LockDataId) {}
        fn on_unlock(&mut self, _: LockDataId) {}
        fn on_remote_file_list(&mut self, files: &[FileDescriptor], _: Option<u32>) {
            let _ = self.0.send(Srv::Files(files.to_vec()));
        }
    }

    struct Pair {
        client: CliprdrClient,
        server: CliprdrServer,
        link: Link,
        srv: smpsc::Receiver<Srv>,
        to_client: Vec<SvcMessage>,
        to_server: Vec<SvcMessage>,
    }

    fn deliver(to: &mut dyn SvcProcessor, msgs: Vec<SvcMessage>) -> Vec<SvcMessage> {
        msgs.iter().flat_map(|m| to.process(&m.encode_unframed_pdu().unwrap()).unwrap()).collect()
    }

    fn test_host(mem: &Mem) -> crate::model::Host {
        let mut host = crate::model::Host::default();
        host.id = uuid::Uuid::new_v4();
        mem.install(host.id);
        host
    }

    impl Pair {
        fn new(mem: &Mem) -> Pair {
            // `Link` crée une minuterie tokio
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let _guard = rt.enter();
            let (client, link) = open(&test_host(mem)).unwrap();
            let (tx, srv) = smpsc::channel();
            let mut server = CliprdrServer::new(Box::new(SrvBackend(tx)));
            let to_client = server.start().unwrap();
            Pair { client, server, link, srv, to_client, to_server: Vec::new() }
        }

        /// Fait circuler les messages jusqu'à ce que `step` renvoie une valeur.
        fn run<T>(&mut self, what: &str, mut step: impl FnMut(&mut CliprdrServer, Option<Srv>, &mut Vec<SvcMessage>) -> Option<T>) -> T {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                while let Ok(m) = self.link.rx.try_recv() {
                    if let Some(msgs) = apply(&mut self.client, ClipEvent::Message(m)) {
                        self.to_server.extend(Vec::from(msgs));
                    }
                }
                let out = deliver(&mut self.server, std::mem::take(&mut self.to_server));
                self.to_client.extend(out);
                let out = deliver(&mut self.client, std::mem::take(&mut self.to_client));
                self.to_server.extend(out);
                let ev = self.srv.try_recv().ok();
                let idle = ev.is_none();
                if let Some(v) = step(&mut self.server, ev, &mut self.to_client) {
                    return v;
                }
                assert!(Instant::now() < deadline, "délai dépassé : {what}");
                if idle {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    fn unicode() -> ClipboardFormat {
        ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)
    }

    #[test]
    fn text_and_images_both_ways_without_loop() {
        let mem = Mem::default();
        mem.copy_text("bonjour\nlocal");
        let mut p = Pair::new(&mem);

        // copie locale annoncée à l'initialisation, collée sur le serveur
        let got = p.run("texte local", |srv, ev, out| match ev {
            Some(Srv::Copy(f)) => {
                assert!(f.iter().any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT), "{f:?}");
                out.extend(Vec::from(srv.initiate_paste(ClipboardFormatId::CF_UNICODETEXT).unwrap()));
                None
            }
            Some(Srv::Data(d)) => Some(d),
            _ => None,
        });
        assert_eq!(got.as_deref().map(utf16_text).as_deref(), Some("bonjour\r\nlocal"));

        // copie sur le serveur : annoncée localement en rendu différé, sans données
        let mut sent = false;
        p.run("copie distante", |srv, _, out| {
            if !sent {
                sent = true;
                out.extend(Vec::from(srv.initiate_copy(&[unicode()]).unwrap()));
            }
            (mem.delayed() == vec![CF_UNICODETEXT]).then_some(())
        });
        // collage local : données demandées au serveur à ce moment
        let m = mem.clone();
        let paste = std::thread::spawn(move || m.paste(CF_UNICODETEXT));
        let mut copies = 0;
        p.run("collage local", |srv, ev, out| {
            match ev {
                Some(Srv::DataRequest(id)) => {
                    assert_eq!(id, CF_UNICODETEXT);
                    out.extend(Vec::from(srv.submit_format_data(OwnedFormatDataResponse::new_unicode_string("depuis le serveur é")).unwrap()));
                }
                Some(Srv::Copy(_)) => copies += 1,
                _ => {}
            }
            paste.is_finished().then_some(())
        });
        assert_eq!(paste.join().unwrap().as_deref().map(utf16_text).as_deref(), Some("depuis le serveur é"));

        // pas de boucle : le contenu reçu du serveur ne lui est jamais ré-annoncé
        let end = Instant::now() + Duration::from_millis(300);
        p.run("silence", |_, ev, _| {
            if matches!(ev, Some(Srv::Copy(_))) {
                copies += 1;
            }
            (Instant::now() > end).then_some(())
        });
        assert_eq!(copies, 0, "contenu distant ré-annoncé au serveur");

        // image locale (DIB) et format nommé (HTML) : transmis tels quels
        let dib = rgba_to_dib(2, 2, &[9; 16]);
        let html = {
            let mut st = mem.0.lock().unwrap();
            st.names.push("HTML Format".into());
            0xC000 + st.names.len() as u32 - 1
        };
        mem.copy(vec![(CF_DIB, dib.clone()), (CF_UNICODETEXT, utf16_bytes("x")), (html, b"<b>gras</b>".to_vec())]);
        let got = p.run("image locale", |srv, ev, out| match ev {
            Some(Srv::Copy(f)) => {
                let named = f.iter().find(|f| f.name.as_ref().is_some_and(|n| n.value() == "HTML Format"));
                assert_eq!(named.map(|f| f.id.value()), Some(html));
                out.extend(Vec::from(srv.initiate_paste(ClipboardFormatId::CF_DIB).unwrap()));
                None
            }
            Some(Srv::Data(d)) => Some(d),
            _ => None,
        });
        assert_eq!(got, Some(dib));

        // image distante malformée : jamais posée localement
        let mut sent = false;
        p.run("image distante", |srv, _, out| {
            if !sent {
                sent = true;
                out.extend(Vec::from(srv.initiate_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_DIB)]).unwrap()));
            }
            (mem.delayed() == vec![CF_DIB]).then_some(())
        });
        let m = mem.clone();
        let paste = std::thread::spawn(move || m.paste(CF_DIB));
        p.run("collage image", |srv, ev, out| {
            if let Some(Srv::DataRequest(_)) = ev {
                out.extend(Vec::from(srv.submit_format_data(OwnedFormatDataResponse::new_data(vec![40, 0, 0, 0, 1])).unwrap()));
            }
            paste.is_finished().then_some(())
        });
        assert_eq!(paste.join().unwrap(), None);
    }

    // --- fil presse-papiers seul, serveur simulé

    type Out = mpsc::UnboundedReceiver<ClipboardMessage>;

    fn worker() -> (Worker, MemOs, smpsc::Sender<ToLocal>, Out) {
        let (tx, rx) = smpsc::channel();
        let (out_tx, out) = mpsc::unbounded_channel();
        (Worker::new(rx, out_tx), MemOs(Mem::default()), tx, out)
    }

    /// Serveur simulé : répond aux `n` prochaines demandes de données (format distant -> données).
    fn answer(mut out: Out, tx: smpsc::Sender<ToLocal>, n: usize, data: impl Fn(u32) -> Option<Vec<u8>> + Send + 'static) -> std::thread::JoinHandle<Out> {
        std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(20);
            let mut left = n;
            while left > 0 && Instant::now() < end {
                match out.try_recv() {
                    Ok(ClipboardMessage::SendInitiatePaste(id)) => {
                        left -= 1;
                        let _ = tx.send(ToLocal::DataResponse(data(id.value())));
                    }
                    Ok(_) => {}
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
            out
        })
    }

    #[test]
    fn text_paste_gives_up_quickly_and_skips_late_answers() {
        let (mut w, mut os, tx, out) = worker();
        w.remote_copy(&mut os, &[unicode(), ClipboardFormat::new(ClipboardFormatId::CF_DIB)]);
        assert_eq!(os.0.delayed(), vec![CF_UNICODETEXT, CF_DIB]);

        // serveur muet : le collage de texte (peut-être dans Escale, interface figée) abandonne vite
        let t = Instant::now();
        assert_eq!(w.render(&mut os, CF_UNICODETEXT), None);
        assert!(t.elapsed() < Duration::from_secs(3), "attente de {:?}", t.elapsed());

        // la réponse tardive arrive, puis une nouvelle demande : la vieille réponse est écartée
        tx.send(ToLocal::DataResponse(Some(utf16_bytes("ancienne")))).unwrap();
        let srv = answer(out, tx.clone(), 1, |_| Some(utf16_bytes("nouvelle")));
        assert_eq!(w.render(&mut os, CF_UNICODETEXT).as_deref().map(utf16_text).as_deref(), Some("nouvelle"));
        let out = srv.join().unwrap();

        // réponse tardive traitée par la boucle (entre deux collages) : écartée aussi
        let srv = answer(out, tx.clone(), 1, |_| None);
        let t = Instant::now();
        assert_eq!(w.render(&mut os, CF_UNICODETEXT), None, "refus du serveur");
        let mut out = srv.join().unwrap();
        assert!(t.elapsed() < Duration::from_secs(1));
        let dib = rgba_to_dib(1, 1, &[1, 2, 3, 255]);
        assert_eq!(w.render(&mut os, CF_UNICODETEXT), None, "serveur muet");
        tx.send(ToLocal::DataResponse(Some(utf16_bytes("tardive")))).unwrap();
        while let Some(ev) = w.try_next() {
            w.handle(&mut os, ev);
        }
        while out.try_recv().is_ok() {}
        let d = dib.clone();
        let srv = answer(out, tx.clone(), 1, move |_| Some(d.clone()));
        assert_eq!(w.render(&mut os, CF_DIB), Some(dib));
        let out = srv.join().unwrap();

        // session fermée : réponse immédiate (vide)
        drop(out);
        let t = Instant::now();
        assert_eq!(w.render(&mut os, CF_UNICODETEXT), None);
        assert!(t.elapsed() < Duration::from_millis(200));
        assert!(w.quit);
    }

    #[test]
    fn end_of_session_leaves_only_received_data() {
        let (mut w, mut os, tx, out) = worker();
        let html = os.register("HTML Format").unwrap();
        let mut f_html = ClipboardFormat::new(ClipboardFormatId::new(0xC123));
        f_html = f_html.with_name(ClipboardFormatName::new("HTML Format"));
        w.remote_copy(&mut os, &[unicode(), ClipboardFormat::new(ClipboardFormatId::CF_DIB), f_html]);
        assert!(w.texts.contains(&html) && w.texts.contains(&CF_UNICODETEXT) && !w.texts.contains(&CF_DIB));

        let srv = answer(out, tx.clone(), 1, |_| Some(utf16_bytes("reçu")));
        assert!(w.render(&mut os, CF_UNICODETEXT).is_some());
        let out = srv.join().unwrap();

        // session encore ouverte : les formats manquants (hors fichiers) sont demandés
        let dib = rgba_to_dib(1, 1, &[1, 2, 3, 255]);
        let d = dib.clone();
        let srv = answer(out, tx.clone(), 2, move |id| match id {
            CF_DIB => Some(d.clone()),
            _ => Some(b"<b>x</b>".to_vec()),
        });
        let all = w.render_all(&mut os);
        let _out = srv.join().unwrap();
        let ids: Vec<u32> = all.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![CF_UNICODETEXT, CF_DIB, html]);

        // nouvelle copie distante puis fin de session : seules les données reçues restent
        w.remote_copy(&mut os, &[unicode(), ClipboardFormat::new(ClipboardFormatId::CF_DIB)]);
        assert!(w.rendered.is_empty(), "données de la copie précédente oubliées");
        tx.send(ToLocal::Quit).unwrap();
        assert!(w.render(&mut os, CF_DIB).is_none());
        assert!(w.quit);
        assert!(w.render_all(&mut os).is_empty(), "rien de reçu : presse-papiers vidé");
    }

    #[test]
    fn clipboard_thread_stops_with_its_session() {
        let mem = Mem::default();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _guard = rt.enter();
        let (client, link) = open(&test_host(&mem)).unwrap();
        let tx = mem.0.lock().unwrap().link.clone().unwrap();
        assert!(tx.send(ToLocal::Ready).is_ok(), "fil en marche");
        drop(link);
        drop(client);
        let end = Instant::now() + Duration::from_secs(5);
        while tx.send(ToLocal::Ready).is_ok() {
            assert!(Instant::now() < end, "le fil presse-papiers survit à la session");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn huge_file_offsets_are_64_bits() {
        use ironrdp_core::{ReadCursor, decode_cursor};
        // au-delà de 4 Gio : position transmise sur 64 bits
        let req = FileContentsRequest { stream_id: 1, index: 0, flags: FileContentsFlags::RANGE, position: 5 << 30, requested_size: CHUNK, data_id: None };
        let bytes = ironrdp_core::encode_vec(&req).unwrap();
        let back: FileContentsRequest = decode_cursor(&mut ReadCursor::new(&bytes)).unwrap();
        assert_eq!(back.position, 5 << 30);
        // lecture au-delà de la fin d'un fichier local (raccourci depuis la copie) : vide, sans erreur
        let root = temp_tree();
        let (mut w, ..) = worker();
        w.local_files = vec![root.join("dossier").join("b.txt")];
        let resp = w.serve_file(&req);
        assert!(!resp.is_error());
        assert!(resp.data().is_empty());
        let resp = w.serve_file(&FileContentsRequest { position: 3, requested_size: 100, ..req });
        assert_eq!(resp.data(), b"jour");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn files_both_ways() {
        let root = temp_tree();
        let mem = Mem::default();
        let mut p = Pair::new(&mem);
        // canal initialisé (presse-papiers vide)
        p.run("initialisation", |_, ev, _| matches!(ev, Some(Srv::Copy(_))).then_some(()));

        // copie locale de fichiers -> liste puis contenu lus par le serveur
        mem.copy(vec![(CF_HDROP, dropfiles(&[root.join("a.bin"), root.join("dossier")]))]);
        let files = p.run("liste de fichiers", |srv, ev, out| match ev {
            Some(Srv::Copy(f)) => {
                let id = f.iter().find(|f| f.name.as_ref().is_some_and(|n| n.value() == FILE_LIST)).expect("FileGroupDescriptorW").id;
                out.extend(Vec::from(srv.initiate_paste(id).unwrap()));
                None
            }
            Some(Srv::Files(files)) => Some(files),
            _ => None,
        });
        assert_eq!(files.len(), 5);
        assert_eq!(files[2].name, "b.txt");
        let req = |index, flags, position, size| FileContentsRequest { stream_id: 7, index, flags, position, requested_size: size, data_id: None };
        let mut step = 0;
        let got = p.run("contenu", |srv, ev, out| {
            if step == 0 {
                step = 1;
                out.extend(Vec::from(srv.request_file_contents(req(2, FileContentsFlags::SIZE, 0, 8)).unwrap()));
            }
            match ev {
                Some(Srv::FileData(7, Some(d))) if step == 1 => {
                    assert_eq!(d, 7u64.to_le_bytes());
                    step = 2;
                    out.extend(Vec::from(srv.request_file_contents(req(2, FileContentsFlags::RANGE, 3, 4)).unwrap()));
                    None
                }
                Some(Srv::FileData(7, d)) if step == 2 => Some(d),
                _ => None,
            }
        });
        assert_eq!(got.as_deref(), Some(&b"jour"[..]));

        // fichiers copiés sur le serveur -> téléchargés au collage local (CF_HDROP)
        let content = big(2 * CHUNK as usize + 5);
        let remote = vec![
            FileDescriptor::new("x.bin").with_file_size(content.len() as u64),
            FileDescriptor::new("d").with_attributes(ClipboardFileAttributes::DIRECTORY),
            FileDescriptor::new("y.txt").with_relative_path("d").with_file_size(2),
        ];
        let mut sent = false;
        p.run("copie de fichiers distante", |srv, _, out| {
            if !sent {
                sent = true;
                out.extend(Vec::from(srv.initiate_file_copy(remote.clone()).unwrap()));
            }
            (mem.delayed() == vec![CF_HDROP]).then_some(())
        });
        let m = mem.clone();
        let paste = std::thread::spawn(move || m.paste(CF_HDROP));
        p.run("téléchargement", |srv, ev, out| {
            if let Some(Srv::FileRequest(r)) = ev {
                assert!(r.flags.contains(FileContentsFlags::RANGE), "taille connue : pas de requête SIZE");
                let data = match r.index {
                    0 => content[r.position as usize..r.position as usize + r.requested_size as usize].to_vec(),
                    2 => b"ok".to_vec(),
                    i => panic!("fichier inattendu {i}"),
                };
                out.extend(Vec::from(srv.submit_file_contents(FileContentsResponse::new_data_response(r.stream_id, data)).unwrap()));
            }
            paste.is_finished().then_some(())
        });
        let drop = paste.join().unwrap().expect("CF_HDROP");
        let paths = parse_dropfiles(&drop);
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert_eq!(std::fs::read(&paths[0]).unwrap(), content);
        assert_eq!(std::fs::read(paths[1].join("y.txt")).unwrap(), b"ok");
        assert!(paths[0].starts_with(clip_dir()));
        let _ = std::fs::remove_dir_all(paths[0].parent().unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Session complète (`rdp::spawn`, TCP, TLS + NLA) contre un serveur IronRDP doté du presse-papiers.
#[cfg(test)]
mod session_tests {
    use super::tests::{Srv, SrvBackend};
    use super::*;
    use crate::desktop::DesktopCmd;
    use crate::ssh::Event;
    use ironrdp_cliprdr::backend::CliprdrBackendFactory;
    use ironrdp_server::{CliprdrServerFactory, DesktopSize, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates, ServerEvent, ServerEventSender};

    struct Display;
    struct Updates;

    #[async_trait::async_trait]
    impl RdpServerDisplayUpdates for Updates {
        async fn next_update(&mut self) -> anyhow::Result<Option<ironrdp_server::DisplayUpdate>> {
            std::future::pending().await
        }
    }

    #[async_trait::async_trait]
    impl RdpServerDisplay for Display {
        async fn size(&mut self) -> DesktopSize {
            DesktopSize { width: 64, height: 48 }
        }
        async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
            Ok(Box::new(Updates))
        }
    }

    type Sender = Arc<std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<ServerEvent>>>>;

    struct Factory(smpsc::Sender<Srv>, Sender);

    impl CliprdrBackendFactory for Factory {
        fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
            Box::new(SrvBackend(self.0.clone()))
        }
    }
    impl ServerEventSender for Factory {
        fn set_sender(&mut self, sender: tokio::sync::mpsc::UnboundedSender<ServerEvent>) {
            *self.1.lock().unwrap() = Some(sender);
        }
    }
    impl CliprdrServerFactory for Factory {}

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_shares_text_both_ways() {
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
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (srv_tx, srv_rx) = smpsc::channel();
        let server_events: Sender = Default::default();
        let mut srv = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], port))
            .with_hybrid(tokio_rustls::TlsAcceptor::from(Arc::new(config)), pub_key)
            .with_no_input()
            .with_display_handler(Display)
            .with_cliprdr_factory(Some(Box::new(Factory(srv_tx, server_events.clone()))))
            .build();
        srv.set_credentials(Some(ironrdp_pdu::rdp::client_info::Credentials { username: "alice".into(), password: "s3cret".into(), domain: None }));
        tokio::task::spawn_local(async move {
            let _ = srv.run().await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mem = Mem::default();
        mem.copy_text("copié ici\nligne 2");
        let mut host = crate::model::Host::default();
        host.id = uuid::Uuid::new_v4();
        host.protocol = crate::model::Protocol::Rdp;
        host.hostname = "localhost".into();
        host.port = port;
        host.username = "alice".into();
        host.password = "s3cret".into();
        mem.install(host.id);
        let share = std::env::temp_dir().join(format!("escale-rdpclip-{}", uuid::Uuid::new_v4()));
        let handle = crate::rdp::spawn(vec![host], (64, 48), share.clone(), eframe::egui::Context::default());

        let deadline = Instant::now() + Duration::from_secs(30);
        let to_server = |m: ClipboardMessage| {
            let tx = server_events.lock().unwrap().clone().expect("canal du serveur");
            tx.send(ServerEvent::Clipboard(m)).unwrap();
        };
        // attend un rappel du serveur en acceptant le certificat
        let next = || async {
            loop {
                while let Ok(ev) = handle.rx.try_recv() {
                    match ev {
                        Event::VerifyHostKey { reply, .. } => {
                            let _ = reply.send(true);
                        }
                        Event::Closed(e) => panic!("session fermée : {e:?}"),
                        _ => {}
                    }
                }
                if let Ok(ev) = srv_rx.try_recv() {
                    return ev;
                }
                assert!(Instant::now() < deadline, "délai dépassé");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        // copie locale -> annoncée à l'ouverture de session -> collée sur le serveur
        loop {
            if let Srv::Copy(f) = next().await
                && f.iter().any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT)
            {
                break;
            }
        }
        to_server(ClipboardMessage::SendInitiatePaste(ClipboardFormatId::CF_UNICODETEXT));
        let data = loop {
            if let Srv::Data(d) = next().await {
                break d.expect("texte local");
            }
        };
        assert_eq!(utf16_text(&data), "copié ici\r\nligne 2");

        // copie sur le serveur -> rendu différé local -> collage local
        to_server(ClipboardMessage::SendInitiateCopy(vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]));
        while mem.delayed() != vec![CF_UNICODETEXT] {
            assert!(Instant::now() < deadline, "copie distante non annoncée");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let m = mem.clone();
        let paste = std::thread::spawn(move || m.paste(CF_UNICODETEXT));
        loop {
            if let Srv::DataRequest(id) = next().await {
                assert_eq!(id, CF_UNICODETEXT);
                break;
            }
        }
        to_server(ClipboardMessage::SendFormatData(OwnedFormatDataResponse::new_unicode_string("du serveur ✓")));
        while !paste.is_finished() {
            assert!(Instant::now() < deadline, "collage local sans réponse");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(paste.join().unwrap().as_deref().map(utf16_text).as_deref(), Some("du serveur ✓"));

        // pas de ré-annonce du contenu reçu
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!srv_rx.try_iter().any(|e| matches!(e, Srv::Copy(_))), "contenu distant ré-annoncé");

        handle.tx.send(DesktopCmd::Close).unwrap();
        let _ = std::fs::remove_dir_all(&share);
    }

    /// Serveur RDP de test avec presse-papiers : port, rappels, envoi de messages au client.
    async fn server() -> (u16, smpsc::Receiver<Srv>, Sender) {
        use tokio_rustls::rustls;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pub_key = cert.signing_key.public_key_raw().to_vec();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], der).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (srv_tx, srv_rx) = smpsc::channel();
        let events: Sender = Default::default();
        let mut srv = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_hybrid(tokio_rustls::TlsAcceptor::from(Arc::new(config)), pub_key)
            .with_no_input()
            .with_display_handler(Display)
            .with_cliprdr_factory(Some(Box::new(Factory(srv_tx, events.clone()))))
            .build();
        srv.set_credentials(Some(ironrdp_pdu::rdp::client_info::Credentials { username: "alice".into(), password: "s3cret".into(), domain: None }));
        tokio::task::spawn_local(async move {
            if let Ok((s, _)) = listener.accept().await {
                let _ = srv.run_connection(s).await;
            }
        });
        (port, srv_rx, events)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_sessions_share_with_their_own_server() {
        tokio::task::LocalSet::new().run_until(two_sessions()).await;
    }

    async fn two_sessions() {
        struct Side {
            mem: Mem,
            rx: smpsc::Receiver<Srv>,
            events: Sender,
            handle: crate::desktop::DesktopHandle,
            share: PathBuf,
        }
        let mut sides = Vec::new();
        for text in ["un", "deux"] {
            let (port, rx, events) = server().await;
            let mem = Mem::default();
            mem.copy_text(text);
            let mut host = crate::model::Host::default();
            host.id = uuid::Uuid::new_v4();
            host.protocol = crate::model::Protocol::Rdp;
            host.hostname = "localhost".into();
            host.port = port;
            host.username = "alice".into();
            host.password = "s3cret".into();
            mem.install(host.id);
            let share = std::env::temp_dir().join(format!("escale-rdpclip-{}", uuid::Uuid::new_v4()));
            let handle = crate::rdp::spawn(vec![host], (64, 48), share.clone(), eframe::egui::Context::default());
            sides.push(Side { mem, rx, events, handle, share });
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let to_server = |s: &Side, m: ClipboardMessage| {
            let tx = s.events.lock().unwrap().clone().expect("canal du serveur");
            tx.send(ServerEvent::Clipboard(m)).unwrap();
        };
        // prochain rappel du serveur de `i` (certificats acceptés pour les deux sessions)
        async fn next(sides: &[Side], i: usize, deadline: Instant) -> Srv {
            loop {
                for s in sides {
                    while let Ok(ev) = s.handle.rx.try_recv() {
                        match ev {
                            Event::VerifyHostKey { reply, .. } => {
                                let _ = reply.send(true);
                            }
                            Event::Closed(e) => panic!("session fermée : {e:?}"),
                            _ => {}
                        }
                    }
                }
                if let Ok(ev) = sides[i].rx.try_recv() {
                    return ev;
                }
                assert!(Instant::now() < deadline, "délai dépassé (session {i})");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        // chaque session annonce la copie locale de son presse-papiers à son propre serveur
        for (i, text) in ["un", "deux"].into_iter().enumerate() {
            loop {
                if let Srv::Copy(f) = next(&sides, i, deadline).await
                    && f.iter().any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT)
                {
                    break;
                }
            }
            to_server(&sides[i], ClipboardMessage::SendInitiatePaste(ClipboardFormatId::CF_UNICODETEXT));
            let data = loop {
                if let Srv::Data(d) = next(&sides, i, deadline).await {
                    break d.expect("texte local");
                }
            };
            assert_eq!(utf16_text(&data), text, "session {i}");
        }

        // copie sur le serveur 2 : seul le presse-papiers de la session 2 est concerné
        to_server(&sides[1], ClipboardMessage::SendInitiateCopy(vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]));
        while sides[1].mem.delayed() != vec![CF_UNICODETEXT] {
            assert!(Instant::now() < deadline, "copie distante non annoncée");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sides[0].mem.delayed().is_empty());

        // fermeture de la session 1 : son fil presse-papiers s'arrête, la session 2 continue
        let link = sides[0].mem.0.lock().unwrap().link.clone().unwrap();
        sides[0].handle.tx.send(DesktopCmd::Close).unwrap();
        while link.send(ToLocal::Ready).is_ok() {
            assert!(Instant::now() < deadline, "fil presse-papiers de la session 1 toujours actif");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let first = sides.remove(0);
        let m = sides[0].mem.clone();
        let paste = std::thread::spawn(move || m.paste(CF_UNICODETEXT));
        loop {
            if let Srv::DataRequest(id) = next(&sides, 0, deadline).await {
                assert_eq!(id, CF_UNICODETEXT);
                break;
            }
        }
        to_server(&sides[0], ClipboardMessage::SendFormatData(OwnedFormatDataResponse::new_unicode_string("du serveur 2")));
        while !paste.is_finished() {
            assert!(Instant::now() < deadline, "collage local sans réponse");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(paste.join().unwrap().as_deref().map(utf16_text).as_deref(), Some("du serveur 2"));
        assert!(!first.rx.try_iter().any(|e| matches!(e, Srv::DataRequest(_))), "rien demandé au serveur 1");

        sides[0].handle.tx.send(DesktopCmd::Close).unwrap();
        for s in [first].iter().chain(&sides) {
            let _ = std::fs::remove_dir_all(&s.share);
        }
    }
}

/// Vrai presse-papiers Windows (modifie le presse-papiers de l'utilisateur, restauré ensuite) :
/// `cargo test rdpclip -- --ignored`.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn recv(out: &mut mpsc::UnboundedReceiver<ClipboardMessage>, what: &str) -> ClipboardMessage {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(m) = out.try_recv() {
                return m;
            }
            assert!(Instant::now() < end, "délai dépassé : {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[ignore]
    fn real_clipboard_both_ways() {
        let mut cb = arboard::Clipboard::new().unwrap();
        let saved = cb.get_text().ok();

        let (out_tx, mut out) = mpsc::unbounded_channel();
        let (tx, rx) = smpsc::channel();
        let (wake, files) = win::start(Worker::new(rx, out_tx)).expect("fenêtre du presse-papiers");
        assert!(files);
        let send = |m: ToLocal| {
            tx.send(m).unwrap();
            wake();
        };
        send(ToLocal::Caps(Caps::STREAM_FILECLIP_ENABLED));
        send(ToLocal::Ready);

        // copie locale (autre application) -> annoncée, puis lue à la demande
        cb.set_text("local ✓\nfin").unwrap();
        let formats = loop {
            if let ClipboardMessage::SendInitiateCopy(f) = recv(&mut out, "annonce de la copie locale") {
                break f;
            }
        };
        assert!(formats.iter().any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT), "{formats:?}");
        assert!(!formats.iter().any(|f| f.id.value() == CF_TEXT), "texte 8 bits filtré");
        send(ToLocal::DataRequest(CF_UNICODETEXT));
        let ClipboardMessage::SendFormatData(r) = recv(&mut out, "données locales") else { panic!("réponse attendue") };
        assert_eq!(utf16_text(r.data()), "local ✓\r\nfin");

        // copie distante -> rendu différé : les données ne sont demandées qu'au collage
        send(ToLocal::RemoteFormats(vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]));
        std::thread::sleep(Duration::from_millis(300));
        assert!(out.try_recv().is_err(), "ni demande de données ni ré-annonce avant le collage");
        let responder = {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut seen = Vec::new();
                let end = Instant::now() + Duration::from_secs(3);
                while Instant::now() < end {
                    match out.try_recv() {
                        Ok(ClipboardMessage::SendInitiatePaste(id)) => {
                            assert_eq!(id, ClipboardFormatId::CF_UNICODETEXT);
                            tx.send(ToLocal::DataResponse(Some(utf16_bytes("distant ✓")))).unwrap();
                            seen.push("paste");
                        }
                        Ok(ClipboardMessage::SendInitiateCopy(_)) => seen.push("copy"),
                        Ok(_) => seen.push("autre"),
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
                seen
            })
        };
        let pasted = cb.get_text();
        let seen = responder.join().unwrap();
        send(ToLocal::Quit);
        // presse-papiers de l'utilisateur restauré
        if let Some(t) = saved {
            std::thread::sleep(Duration::from_millis(200));
            let _ = cb.set_text(t);
        }
        assert_eq!(pasted.unwrap().replace("\r\n", "\n"), "distant ✓");
        assert_eq!(seen, vec!["paste"], "une seule demande, aucune ré-annonce");
    }

    /// Fin de session avec une copie distante annoncée : le texte déjà collé reste, l'image jamais
    /// demandée disparaît (pas de format « mort »), et le fil s'arrête.
    #[test]
    #[ignore]
    fn real_clipboard_end_of_session() {
        use windows_sys::Win32::System::DataExchange::IsClipboardFormatAvailable;
        let mut cb = arboard::Clipboard::new().unwrap();
        let saved = cb.get_text().ok();

        let (out_tx, mut out) = mpsc::unbounded_channel();
        let (tx, rx) = smpsc::channel();
        let (wake, _) = win::start(Worker::new(rx, out_tx)).expect("fenêtre du presse-papiers");
        let send = |m: ToLocal| {
            tx.send(m).unwrap();
            wake();
        };
        send(ToLocal::Ready);
        send(ToLocal::RemoteFormats(vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT), ClipboardFormat::new(ClipboardFormatId::CF_DIB)]));
        std::thread::sleep(Duration::from_millis(300));
        while out.try_recv().is_ok() {}
        let responder = {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(3);
                while Instant::now() < end {
                    match out.try_recv() {
                        Ok(ClipboardMessage::SendInitiatePaste(_)) => {
                            tx.send(ToLocal::DataResponse(Some(utf16_bytes("gardé ✓")))).unwrap();
                            return out;
                        }
                        _ => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
                out
            })
        };
        let pasted = cb.get_text();
        let mut out = responder.join().unwrap();
        // fin de session : la fenêtre est détruite
        let t = Instant::now();
        send(ToLocal::Quit);
        std::thread::sleep(Duration::from_millis(300));
        let text = cb.get_text();
        let dib = unsafe { IsClipboardFormatAvailable(CF_DIB) } != 0;
        let asked = out.try_recv().is_ok();
        if let Some(t) = saved {
            let _ = cb.set_text(t);
        }
        assert_eq!(pasted.unwrap().replace("\r\n", "\n"), "gardé ✓");
        assert_eq!(text.unwrap().replace("\r\n", "\n"), "gardé ✓", "texte conservé après la session");
        assert!(!dib, "format jamais reçu retiré");
        assert!(!asked, "rien demandé au serveur après la fin de session");
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
