//! Gestionnaire de fichiers d'une session, en deux colonnes : ce PC à gauche, l'appareil distant à
//! droite (SFTP en SSH, dossier partagé en RDP). On navigue dans chacune et on glisse les fichiers de
//! l'une à l'autre (ou dans un dossier de la même colonne pour les déplacer).
//!
//! Les dossiers inaccessibles ne sont pas affichés ; y accéder malgré tout (chemin tapé) affiche un
//! refus explicite plutôt qu'une erreur technique.

use crate::theme::*;
use crate::widgets::{self as w, Icon, Kind};
use eframe::egui::{self, Align2, Color32, FontId, Rect, RichText, Sense, Stroke, Vec2, pos2, vec2};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::StatusCode;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Handle;
use tokio::sync::oneshot;

/// Message affiché quand l'utilisateur n'a pas les droits nécessaires.
pub const DENIED: &str = "Vous n'avez pas le droit d'accéder à cet emplacement.";

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) dir: bool,
    pub(crate) size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Local,
    Remote,
}

impl Side {
    fn other(self) -> Side {
        match self {
            Side::Local => Side::Remote,
            Side::Remote => Side::Local,
        }
    }
}

/// Échec de lecture d'un dossier.
#[derive(Debug, PartialEq)]
pub(crate) enum ListError {
    Denied,
    Missing,
    Other(String),
}

impl ListError {
    fn message(&self, path: &str) -> String {
        match self {
            ListError::Denied => format!("Accès refusé à « {path} » : {}", DENIED.to_lowercase()),
            ListError::Missing => format!("« {path} » n'existe pas."),
            ListError::Other(e) => format!("Lecture de « {path} » impossible : {e}"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Remote {
    s: Arc<SftpSession>,
    /// Identité de l'utilisateur distant (propriétaire de son dossier personnel).
    uid: Option<u32>,
    gid: Option<u32>,
}

/// Système de fichiers d'une colonne.
#[derive(Clone)]
enum Fs {
    /// Tout ce PC (chemins absolus ; « » = liste des lecteurs sous Windows).
    Local,
    /// Dossier partagé avec un bureau RDP (chemins relatifs « a/b »).
    Shared(PathBuf),
    Sftp(Remote),
    /// Session SFTP en cours d'ouverture.
    Opening,
    Unavailable(String),
}

impl Fs {
    fn join(&self, dir: &str, name: &str) -> String {
        match self {
            Fs::Local => Path::new(dir).join(name).to_string_lossy().into_owned(),
            Fs::Shared(_) if dir.is_empty() => name.to_string(),
            Fs::Shared(_) => format!("{dir}/{name}"),
            _ if dir.ends_with('/') => format!("{dir}{name}"),
            _ => format!("{dir}/{name}"),
        }
    }

    fn parent(&self, dir: &str) -> Option<String> {
        match self {
            Fs::Local => {
                if dir.is_empty() {
                    return None;
                }
                match Path::new(dir).parent() {
                    Some(p) => Some(p.to_string_lossy().into_owned()),
                    // racine d'un lecteur : on remonte à la liste des lecteurs
                    None if cfg!(windows) => Some(String::new()),
                    None => None,
                }
            }
            Fs::Shared(_) if dir.is_empty() => None,
            Fs::Shared(_) => Some(dir.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default()),
            _ if dir == "/" || dir.is_empty() => None,
            _ => Some(match dir.trim_end_matches('/').rsplit_once('/') {
                Some(("", _)) | None => "/".into(),
                Some((p, _)) => p.to_string(),
            }),
        }
    }

    fn display(&self, dir: &str) -> String {
        match self {
            Fs::Local if dir.is_empty() => "Ce PC".into(),
            Fs::Shared(_) if dir.is_empty() => "Escale".into(),
            Fs::Shared(_) => format!("Escale/{dir}"),
            _ => dir.to_string(),
        }
    }

    /// Chemin sur ce PC (colonnes locales et dossier partagé).
    fn local_path(&self, path: &str) -> Option<PathBuf> {
        match self {
            Fs::Local => Some(PathBuf::from(path)),
            Fs::Shared(root) => Some(confined(root, path)),
            _ => None,
        }
    }

    fn is_local(&self) -> bool {
        matches!(self, Fs::Local | Fs::Shared(_))
    }
}

/// Chemin relatif rattaché à `root`, sans jamais en sortir.
fn confined(root: &Path, rel: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for c in rel.split(['/', '\\']).filter(|c| !c.is_empty() && *c != "." && *c != ".." && !c.contains(':')) {
        p.push(c);
    }
    p
}

struct Pane {
    fs: Fs,
    title: String,
    subtitle: String,
    cwd: String,
    path_input: String,
    entries: Vec<Entry>,
    loading: bool,
    /// Dernière lecture demandée (les réponses plus anciennes sont ignorées).
    generation: u64,
    message: Option<(bool, String)>,
    selected: BTreeSet<String>,
    anchor: Option<usize>,
    rename: Option<(String, String)>,
    new_dir: Option<String>,
    confirm_delete: Option<Vec<Entry>>,
    last_list: f64,
}

impl Pane {
    fn new(fs: Fs, title: &str, subtitle: &str) -> Self {
        Self {
            fs,
            title: title.into(),
            subtitle: subtitle.into(),
            cwd: String::new(),
            path_input: String::new(),
            entries: Vec::new(),
            loading: false,
            generation: 0,
            message: None,
            selected: BTreeSet::new(),
            anchor: None,
            rename: None,
            new_dir: None,
            confirm_delete: None,
            last_list: f64::NEG_INFINITY,
        }
    }

    fn selection(&self) -> Vec<Entry> {
        self.entries.iter().filter(|e| self.selected.contains(&e.name)).cloned().collect()
    }
}

struct Transfer {
    name: String,
    upload: bool,
    total: u64,
    done: Arc<AtomicU64>,
    result: Option<Result<(), String>>,
}

enum Msg {
    Ready(Result<Remote, String>, String),
    Listing { side: Side, generation: u64, path: String, result: Result<Vec<Entry>, ListError> },
    Done { side: Side, error: Option<String> },
    Transfer { id: usize, dest: Side, result: Result<(), String> },
}

/// Éléments glissés d'une colonne.
#[derive(Clone)]
struct Drag {
    side: Side,
    entries: Vec<Entry>,
}

enum Op {
    Open(Side, String),
    Up(Side),
    Refresh(Side),
    Mkdir(Side, String),
    Rename(Side, String, String),
    Delete(Side, Vec<Entry>),
    /// Copie vers l'autre colonne, dans le dossier `dest`.
    Transfer { from: Side, entries: Vec<Entry>, dest: String },
    /// Déplacement dans un dossier de la même colonne.
    MoveInto(Side, Vec<Entry>, String),
    Explorer(Side),
}

pub struct FileManager {
    local: Pane,
    remote: Pane,
    rt: Handle,
    ctx: egui::Context,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    transfers: Vec<Transfer>,
    /// Fichiers déposés avant que la session SFTP soit prête.
    pending: Vec<PathBuf>,
    /// État du lecteur partagé côté serveur (RDP).
    drive: Option<Arc<crate::rdpdr::DriveStatus>>,
    /// Premier transfert du lot en cours (progression d'ensemble affichée hors de la vue Fichiers).
    batch: usize,
    /// Lot terminé pendant que la vue Fichiers était cachée : pastille jusqu'à son ouverture.
    unseen: Option<Finished>,
}

/// Fin d'un lot de transferts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Finished {
    Ok,
    Failed,
}

fn home_dir() -> String {
    std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default()
}

impl FileManager {
    fn with(remote: Pane, rt: Handle, ctx: egui::Context) -> Self {
        let (tx, rx) = channel();
        let mut m = Self {
            local: Pane::new(Fs::Local, "Ce PC", &std::env::var("COMPUTERNAME").unwrap_or_default()),
            remote,
            rt,
            ctx,
            tx,
            rx,
            transfers: Vec::new(),
            pending: Vec::new(),
            batch: 0,
            unseen: None,
            drive: None,
        };
        m.list(Side::Local, home_dir());
        if m.remote.fs.is_local() {
            m.list(Side::Remote, String::new());
        }
        m
    }

    /// Côté distant en SFTP : `opening` reçoit la session ouverte sur la connexion SSH de l'onglet.
    pub fn sftp(opening: oneshot::Receiver<Result<SftpSession, String>>, host: &str, rt: Handle, ctx: egui::Context) -> Self {
        let m = Self::with(Pane::new(Fs::Opening, host, "SFTP"), rt, ctx);
        let (tx, c) = (m.tx.clone(), m.ctx.clone());
        m.rt.spawn(async move {
            let r = match opening.await {
                Ok(Ok(s)) => {
                    let home = s.canonicalize(".").await.unwrap_or_else(|_| "/".into());
                    let me = s.metadata(home.clone()).await.ok();
                    let remote = Remote { uid: me.as_ref().and_then(|m| m.uid), gid: me.as_ref().and_then(|m| m.gid), s: Arc::new(s) };
                    let _ = tx.send(Msg::Ready(Ok(remote), home));
                    c.request_repaint();
                    return;
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err("Session fermée".into()),
            };
            let _ = tx.send(Msg::Ready(r, String::new()));
            c.request_repaint();
        });
        m
    }

    /// Côté distant = dossier partagé avec un bureau RDP.
    pub fn shared(root: PathBuf, drive: Option<Arc<crate::rdpdr::DriveStatus>>, host: &str, rt: Handle, ctx: egui::Context) -> Self {
        let _ = std::fs::create_dir_all(&root);
        let mut m = Self::with(Pane::new(Fs::Shared(root), host, "Dossier partagé avec le bureau distant"), rt, ctx);
        m.drive = drive;
        m
    }

    pub fn unavailable(reason: &str, host: &str, rt: Handle, ctx: egui::Context) -> Self {
        Self::with(Pane::new(Fs::Unavailable(reason.into()), host, ""), rt, ctx)
    }

    pub fn is_sftp(&self) -> bool {
        matches!(self.remote.fs, Fs::Opening | Fs::Sftp(_))
    }

    pub fn busy(&self) -> bool {
        self.transfers.iter().any(|t| t.result.is_none())
    }

    /// Avancement du lot de transferts en cours, de 0 à 1 (`None` : taille totale inconnue).
    pub fn progress(&self) -> Option<f32> {
        let (mut done, mut total) = (0u64, 0u64);
        for t in self.transfers.iter().skip(self.batch) {
            if t.total == 0 && t.result.is_none() {
                return None;
            }
            total += t.total;
            done += if t.result.is_some() { t.total } else { t.done.load(Ordering::Relaxed).min(t.total) };
        }
        (total > 0).then(|| done as f32 / total as f32)
    }

    /// Lot terminé depuis la dernière ouverture de la vue Fichiers.
    pub fn unseen(&self) -> Option<Finished> {
        self.unseen
    }

    /// Traitement des messages quand la vue Fichiers est cachée : les transferts se terminent et
    /// les fichiers déposés partent même depuis la console.
    pub fn tick(&mut self, now: f64) {
        self.pump(now);
    }

    /// Fichiers de ce PC (glissés depuis l'explorateur) à envoyer dans le dossier distant courant.
    pub fn upload(&mut self, files: Vec<PathBuf>) {
        match self.remote.fs {
            Fs::Opening => self.pending.extend(files),
            Fs::Unavailable(_) => {}
            _ => {
                let items = files
                    .into_iter()
                    .filter_map(|p| {
                        let m = std::fs::metadata(&p).ok()?;
                        let name = p.file_name()?.to_string_lossy().into_owned();
                        Some((p.to_string_lossy().into_owned(), Entry { name, dir: m.is_dir(), size: m.len() }))
                    })
                    .collect();
                let dest = self.remote.cwd.clone();
                self.start_transfers(Fs::Local, items, Side::Remote, dest);
            }
        }
    }

    fn pane(&mut self, side: Side) -> &mut Pane {
        match side {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    // ------------------------------------------------------------ lecture des dossiers

    fn list(&mut self, side: Side, path: String) {
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        let p = self.pane(side);
        p.loading = true;
        p.generation += 1;
        let generation = p.generation;
        let fs = p.fs.clone();
        let dir = fs.local_path(&path).unwrap_or_default();
        let drives = matches!(fs, Fs::Local) && path.is_empty();
        let path2 = path.clone();
        let send = move |result| {
            let _ = tx.send(Msg::Listing { side, generation, path, result });
            ctx.request_repaint();
        };
        match fs {
            Fs::Local | Fs::Shared(_) => {
                self.rt.spawn_blocking(move || send(if drives { Ok(list_drives()) } else { list_local(&dir) }));
            }
            Fs::Sftp(r) => {
                self.rt.spawn(async move { send(sftp_list(&r.s, &path2, r.uid, r.gid).await) });
            }
            _ => self.pane(side).loading = false,
        }
    }

    fn pump(&mut self, now: f64) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Ready(Ok(r), home) => {
                    self.remote.fs = Fs::Sftp(r);
                    self.list(Side::Remote, home);
                }
                Msg::Ready(Err(e), _) => self.remote.fs = Fs::Unavailable(e),
                Msg::Listing { side, generation, path, result } => {
                    let p = self.pane(side);
                    if generation != p.generation {
                        continue;
                    }
                    p.loading = false;
                    p.last_list = now;
                    match result {
                        Ok(mut v) => {
                            v.sort_by_key(|e| (!e.dir, e.name.to_lowercase()));
                            if p.cwd != path {
                                p.selected.clear();
                                p.anchor = None;
                                p.message = None;
                            } else {
                                // sélection conservée pour ce qui existe encore
                                p.selected.retain(|n| v.iter().any(|e| e.name == *n));
                            }
                            p.entries = v;
                            p.cwd = path.clone();
                            p.path_input = p.fs.display(&path);
                        }
                        Err(e) => {
                            // dossier refusé ou absent : on reste où l'on était
                            p.message = Some((true, e.message(&p.fs.display(&path))));
                            p.path_input = p.fs.display(&p.cwd);
                        }
                    }
                }
                Msg::Done { side, error } => {
                    if let Some(e) = error {
                        self.pane(side).message = Some((true, e));
                    }
                    let cwd = self.pane(side).cwd.clone();
                    self.list(side, cwd);
                }
                Msg::Transfer { id, dest, result } => {
                    if let Some(t) = self.transfers.get_mut(id) {
                        t.result = Some(result);
                    }
                    if !self.busy() {
                        let failed = self.transfers.iter().skip(self.batch).any(|t| t.result.as_ref().is_some_and(|r| r.is_err()));
                        self.unseen = Some(if failed { Finished::Failed } else { Finished::Ok });
                    }
                    let cwd = self.pane(dest).cwd.clone();
                    self.list(dest, cwd);
                }
            }
        }
        // session prête : envoi des fichiers déposés entre-temps
        if matches!(self.remote.fs, Fs::Sftp(_)) && !self.pending.is_empty() && !self.remote.loading {
            let files = std::mem::take(&mut self.pending);
            self.upload(files);
        }
    }

    // ------------------------------------------------------------ opérations

    fn spawn_done(&self, side: Side, fut: impl std::future::Future<Output = Result<(), String>> + Send + 'static) {
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        self.rt.spawn(async move {
            let error = fut.await.err();
            let _ = tx.send(Msg::Done { side, error });
            ctx.request_repaint();
        });
    }

    fn done_now(&self, side: Side, r: Result<(), String>) {
        let _ = self.tx.send(Msg::Done { side, error: r.err() });
    }

    /// Copie `items` (chemin source, entrée) de `src` vers le dossier `dest` de la colonne `to`.
    fn start_transfers(&mut self, src: Fs, items: Vec<(String, Entry)>, to: Side, dest: String) {
        let dst = self.pane(to).fs.clone();
        // nouveau lot : la progression d'ensemble repart de zéro
        if !self.busy() {
            self.batch = self.transfers.len();
        }
        for (from, e) in items {
            let dest = dest.clone();
            let done = Arc::new(AtomicU64::new(0));
            let id = self.transfers.len();
            self.transfers.push(Transfer {
                name: e.name.clone(),
                upload: to == Side::Remote,
                total: if e.dir { local_size_hint(&src, &from) } else { e.size },
                done: done.clone(),
                result: None,
            });
            let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
            let finish = move |result: Result<(), String>| {
                let _ = tx.send(Msg::Transfer { id, dest: to, result });
                ctx.request_repaint();
            };
            match (&src, &dst) {
                (s, d) if s.is_local() && d.is_local() => {
                    let (Some(from), Some(dir)) = (s.local_path(&from), d.local_path(&dest)) else {
                        self.transfers.pop();
                        continue;
                    };
                    // vers le dossier partagé : les coffres d'Escale ne partent jamais au serveur
                    let private = matches!(d, Fs::Shared(_)).then(crate::vault::root);
                    self.rt.spawn_blocking(move || {
                        finish(copy_local_item(&from, &dir, &e.name, private.as_deref(), &done).map_err(|err| transfer_error(&e.name, &err)))
                    });
                }
                (s, Fs::Sftp(r)) if s.is_local() => {
                    let Some(from) = s.local_path(&from) else {
                        self.transfers.pop();
                        continue;
                    };
                    let r = r.clone();
                    self.rt.spawn(async move {
                        let target = unique_remote(&r.s, &dest, &e.name).await;
                        finish(sftp_upload(&r.s, &from, &target, &done).await.map_err(|err| transfer_error(&e.name, &err)))
                    });
                }
                (Fs::Sftp(r), d) if d.is_local() => {
                    let Some(dir) = d.local_path(&dest) else {
                        self.transfers.pop();
                        continue;
                    };
                    let r = r.clone();
                    self.rt.spawn(async move {
                        let target = unique_local(&dir, &e.name);
                        let res = if e.dir {
                            sftp_download_tree(&r.s, &from, &target, &done).await
                        } else {
                            sftp_download(&r.s, &from, &target, &done).await
                        };
                        finish(res.map_err(|err| transfer_error(&e.name, &err)))
                    });
                }
                _ => {
                    self.transfers.pop();
                }
            }
        }
    }

    fn apply(&mut self, op: Op) {
        match op {
            Op::Open(side, path) => {
                // chemin tapé avec des « / » : forme native de Windows
                let mut path = if cfg!(windows) && matches!(self.pane(side).fs, Fs::Local) { path.replace('/', "\\") } else { path };
                // « C: » seul désigne le dossier courant du lecteur : on vise sa racine
                if cfg!(windows) && path.len() == 2 && path.ends_with(':') {
                    path.push('\\');
                }
                self.list(side, path)
            }
            Op::Refresh(side) => {
                let cwd = self.pane(side).cwd.clone();
                self.list(side, cwd);
            }
            Op::Up(side) => {
                let p = self.pane(side);
                if let Some(parent) = p.fs.parent(&p.cwd) {
                    self.list(side, parent);
                }
            }
            Op::Transfer { from, entries, dest } => {
                let p = self.pane(from);
                let fs = p.fs.clone();
                let items = entries.into_iter().map(|e| (fs.join(&p.cwd, &e.name), e)).collect();
                self.start_transfers(fs, items, from.other(), dest);
            }
            Op::Explorer(side) => {
                let p = self.pane(side);
                if let Some(dir) = p.fs.local_path(&p.cwd) {
                    #[cfg(windows)]
                    let _ = std::process::Command::new("explorer").arg(&dir).spawn();
                    #[cfg(target_os = "macos")]
                    let _ = std::process::Command::new("open").arg(&dir).spawn();
                    #[cfg(all(unix, not(target_os = "macos")))]
                    let _ = std::process::Command::new("xdg-open").arg(&dir).spawn();
                }
            }
            Op::Mkdir(side, name) => {
                let p = self.pane(side);
                let path = p.fs.join(&p.cwd, &name);
                match p.fs.clone() {
                    Fs::Sftp(r) => self.spawn_done(side, async move { r.s.create_dir(path).await.map_err(|e| op_error("Création du dossier", &sftp_msg(&e))) }),
                    fs => {
                        let r = fs.local_path(&path).map(std::fs::create_dir).unwrap_or(Ok(()));
                        self.done_now(side, r.map_err(|e| op_error("Création du dossier", &io_msg(&e))));
                    }
                }
            }
            Op::Rename(side, old, new) => {
                let p = self.pane(side);
                let (from, to) = (p.fs.join(&p.cwd, &old), p.fs.join(&p.cwd, &new));
                self.move_paths(side, vec![(from, to)], "Renommage");
            }
            Op::MoveInto(side, entries, folder) => {
                let p = self.pane(side);
                let moves = entries.iter().map(|e| (p.fs.join(&p.cwd, &e.name), p.fs.join(&folder, &e.name))).collect();
                self.move_paths(side, moves, "Déplacement");
            }
            Op::Delete(side, entries) => {
                let p = self.pane(side);
                let paths: Vec<(String, bool)> = entries.iter().map(|e| (p.fs.join(&p.cwd, &e.name), e.dir)).collect();
                match p.fs.clone() {
                    Fs::Sftp(r) => self.spawn_done(side, async move {
                        for (path, dir) in paths {
                            let res = if dir { sftp_remove_tree(&r.s, &path).await } else { r.s.remove_file(path.clone()).await.map_err(|e| sftp_msg(&e)) };
                            res.map_err(|e| op_error("Suppression", &e))?;
                        }
                        Ok(())
                    }),
                    fs => {
                        let mut r = Ok(());
                        for (path, dir) in paths {
                            let Some(p) = fs.local_path(&path) else { continue };
                            if let Err(e) = if dir { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) } {
                                r = Err(op_error("Suppression", &io_msg(&e)));
                                break;
                            }
                        }
                        self.done_now(side, r);
                    }
                }
            }
        }
    }

    fn move_paths(&mut self, side: Side, moves: Vec<(String, String)>, what: &'static str) {
        match self.pane(side).fs.clone() {
            Fs::Sftp(r) => self.spawn_done(side, async move {
                for (from, to) in moves {
                    r.s.rename(from, to).await.map_err(|e| op_error(what, &sftp_msg(&e)))?;
                }
                Ok(())
            }),
            fs => {
                let mut res = Ok(());
                for (from, to) in moves {
                    let (Some(a), Some(b)) = (fs.local_path(&from), fs.local_path(&to)) else { continue };
                    if b.exists() {
                        res = Err(format!("{what} impossible : « {} » existe déjà.", b.file_name().unwrap_or_default().to_string_lossy()));
                        break;
                    }
                    if let Err(e) = std::fs::rename(&a, &b) {
                        res = Err(op_error(what, &io_msg(&e)));
                        break;
                    }
                }
                self.done_now(side, res);
            }
        }
    }

    // ------------------------------------------------------------ interface

    /// Les deux colonnes et les transferts, dans toute la zone disponible.
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        self.pump(now);
        // la vue est ouverte : la fin des transferts y est visible
        self.unseen = None;
        // le dossier partagé peut changer depuis le bureau distant : relecture régulière
        if matches!(self.remote.fs, Fs::Shared(_)) {
            if !self.remote.loading && now - self.remote.last_list > 2.0 {
                let cwd = self.remote.cwd.clone();
                self.list(Side::Remote, cwd);
            }
            ui.ctx().request_repaint_after(std::time::Duration::from_secs(2));
        }
        if self.busy() {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(120));
        }

        let full = ui.available_rect_before_wrap();
        let transfers_h = if self.transfers.is_empty() { 0.0 } else { 40.0 + 44.0 * self.transfers.len().min(3) as f32 };
        let gap = 10.0;
        let panes = Rect::from_min_max(full.min, pos2(full.right(), full.bottom() - transfers_h - if transfers_h > 0.0 { gap } else { 0.0 }));
        let half = (panes.width() - gap) / 2.0;
        let left = Rect::from_min_size(panes.min, vec2(half, panes.height()));
        let right = Rect::from_min_max(pos2(left.right() + gap, panes.top()), panes.max);

        let mut ops = Vec::new();
        let dragging = egui::DragAndDrop::payload::<Drag>(ui.ctx());
        for (side, rect) in [(Side::Local, left), (Side::Remote, right)] {
            ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                self.pane_ui(ui, side, rect, dragging.as_deref(), &mut ops);
            });
        }
        if transfers_h > 0.0 {
            let r = Rect::from_min_max(pos2(full.left(), full.bottom() - transfers_h), full.max);
            ui.scope_builder(egui::UiBuilder::new().max_rect(r), |ui| self.transfers_ui(ui, r));
        }
        ui.allocate_rect(full, Sense::hover());

        // aperçu des éléments glissés sous le pointeur
        if let (Some(d), Some(p)) = (dragging, ui.ctx().pointer_latest_pos()) {
            let label = if d.entries.len() == 1 { d.entries[0].name.clone() } else { format!("{} éléments", d.entries.len()) };
            let painter = ui.ctx().layer_painter(egui::LayerId::new(egui::Order::Tooltip, egui::Id::new("file-drag")));
            let galley = painter.layout_no_wrap(label, FontId::proportional(12.5), TEXT);
            let r = Rect::from_min_size(p + vec2(14.0, 10.0), galley.size() + vec2(34.0, 12.0));
            painter.rect(r, 8.0, ELEVATED, Stroke::new(1.0, BORDER_STRONG), egui::StrokeKind::Inside);
            let icon = if d.entries.iter().any(|e| e.dir) { Icon::Folder } else { Icon::File };
            w::paint_icon(&painter, Rect::from_center_size(pos2(r.left() + 14.0, r.center().y), Vec2::splat(14.0)), icon, ACCENT);
            painter.galley(pos2(r.left() + 26.0, r.top() + 6.0), galley, TEXT);
        }

        for op in ops {
            self.apply(op);
        }
    }

    fn pane_ui(&mut self, ui: &mut egui::Ui, side: Side, rect: Rect, dragging: Option<&Drag>, ops: &mut Vec<Op>) {
        let other_cwd = self.pane(side.other()).cwd.clone();
        let other_ready = matches!(self.pane(side.other()).fs, Fs::Local | Fs::Shared(_) | Fs::Sftp(_));
        let drive = self.drive.clone();
        let drive_status = drive.as_deref();
        let p = self.pane(side);
        // dépôt possible ici : venant de l'autre colonne
        let drop_from_other = dragging.is_some_and(|d| d.side != side) && matches!(p.fs, Fs::Local | Fs::Shared(_) | Fs::Sftp(_));
        let over = drop_from_other && ui.rect_contains_pointer(rect);
        ui.painter().rect(
            rect,
            12.0,
            SURFACE,
            Stroke::new(if over { 1.5 } else { 1.0 }, if over { ACCENT } else { BORDER }),
            egui::StrokeKind::Inside,
        );
        let inner = rect.shrink2(vec2(14.0, 12.0));
        // colonne trop petite pour être utilisable : seulement son cadre
        if inner.width() < 160.0 || inner.height() < 120.0 {
            return;
        }
        let mut ui = ui.new_child(egui::UiBuilder::new().max_rect(inner).layout(egui::Layout::top_down(egui::Align::Min)));
        let ui = &mut ui;
        let width = inner.width();

        // --- en-tête
        ui.horizontal(|ui| {
            let (icon, tint) = if side == Side::Local { (Icon::Monitor, ACCENT_2) } else { (Icon::Server, ACCENT) };
            let (r, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
            ui.painter().rect_filled(r, 9.0, tint.gamma_multiply(0.12));
            w::paint_icon(ui.painter(), r.shrink(9.0), icon, tint);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(RichText::new(&p.title).font(bold(14.0)));
                if !p.subtitle.is_empty() {
                    ui.label(RichText::new(&p.subtitle).size(11.5).color(MUTED));
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                if matches!(p.fs, Fs::Local | Fs::Shared(_) | Fs::Sftp(_)) {
                    if w::icon_button(ui, Icon::Refresh, "Actualiser").clicked() {
                        ops.push(Op::Refresh(side));
                    }
                    if !(matches!(p.fs, Fs::Local) && p.cwd.is_empty()) && w::icon_button(ui, Icon::FolderPlus, "Nouveau dossier").clicked() {
                        p.new_dir = Some(String::new());
                    }
                    if p.fs.is_local() && !p.cwd.is_empty() && w::icon_button(ui, Icon::External, "Ouvrir dans l'explorateur").clicked() {
                        ops.push(Op::Explorer(side));
                    }
                }
            });
        });
        ui.add_space(10.0);

        match &p.fs {
            Fs::Opening => {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.add(egui::Spinner::new().size(22.0).color(ACCENT));
                    ui.add_space(8.0);
                    ui.label(RichText::new("Ouverture de la session SFTP…").color(TEXT_DIM));
                });
                return;
            }
            Fs::Unavailable(reason) => {
                w::callout(ui, Icon::Warning, WARN, reason);
                return;
            }
            _ => {}
        }

        // --- état du lecteur partagé côté serveur (RDP)
        if let (Fs::Shared(_), Some(d)) = (&p.fs, drive_status) {
            drive_banner(ui, d, width);
            ui.add_space(6.0);
        }

        // --- chemin
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            let can_up = p.fs.parent(&p.cwd).is_some();
            ui.add_enabled_ui(can_up, |ui| {
                if w::icon_button(ui, Icon::Up, "Dossier parent").clicked() {
                    ops.push(Op::Up(side));
                }
            });
            if matches!(p.fs, Fs::Shared(_)) {
                ui.label(RichText::new(p.fs.display(&p.cwd)).monospace().size(12.0).color(TEXT_DIM));
            } else {
                let r = ui.add(
                    egui::TextEdit::singleline(&mut p.path_input)
                        .font(FontId::monospace(12.0))
                        .margin(egui::Margin::symmetric(8, 7))
                        .desired_width(f32::INFINITY),
                );
                // le focus ne vient que d'un clic
                if r.gained_focus() && !ui.input(|i| i.pointer.any_pressed() || i.pointer.any_down()) {
                    r.surrender_focus();
                }
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    let typed = p.path_input.trim().to_string();
                    let target = if matches!(p.fs, Fs::Local) && typed == "Ce PC" { String::new() } else { typed };
                    ops.push(Op::Open(side, target));
                }
            }
        });
        ui.add_space(6.0);

        // --- sélection : transfert, renommage, suppression
        let sel = p.selection();
        let bar_h = 34.0;
        ui.allocate_ui_with_layout(vec2(width, bar_h), egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if sel.is_empty() {
                let hint = if side == Side::Local { "Glissez vers la droite pour envoyer" } else { "Glissez vers la gauche pour récupérer" };
                ui.label(RichText::new(hint).size(12.0).color(MUTED));
                return;
            }
            let label = if side == Side::Local { "Envoyer" } else { "Récupérer" };
            let icon = if side == Side::Local { Icon::Forward } else { Icon::Back };
            let can = other_ready && !(side == Side::Remote && other_cwd.is_empty());
            ui.add_enabled_ui(can, |ui| {
                if w::button_h(ui, Kind::Primary, Some(icon), label, 0.0, 30.0)
                    .on_hover_text(if side == Side::Local { "Copier vers le dossier distant ouvert" } else { "Copier vers le dossier de ce PC ouvert" })
                    .clicked()
                {
                    ops.push(Op::Transfer { from: side, entries: sel.clone(), dest: other_cwd.clone() });
                }
            });
            let n = sel.len();
            ui.label(RichText::new(if n == 1 { "1 élément".to_string() } else { format!("{n} éléments") }).size(12.0).color(TEXT_DIM));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                if w::icon_button(ui, Icon::Trash, "Supprimer").clicked() {
                    p.confirm_delete = Some(sel.clone());
                }
                if n == 1 && w::icon_button(ui, Icon::Edit, "Renommer").clicked() {
                    p.rename = Some((sel[0].name.clone(), sel[0].name.clone()));
                }
            });
        });
        ui.add_space(4.0);

        if let Some((err, msg)) = &p.message {
            let mut close = false;
            ui.horizontal(|ui| {
                let col = if *err { DANGER } else { ACCENT };
                egui::Frame::new()
                    .fill(col.gamma_multiply(0.10))
                    .stroke(Stroke::new(1.0, col.gamma_multiply(0.35)))
                    .corner_radius(RADIUS)
                    .inner_margin(egui::Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.set_width(width - 20.0);
                        ui.horizontal(|ui| {
                            w::icon_size(ui, if *err { Icon::Lock } else { Icon::Check }, 15.0, col);
                            ui.scope(|ui| {
                                ui.set_max_width(width - 90.0);
                                ui.add(egui::Label::new(RichText::new(msg).size(12.5).color(TEXT)).wrap());
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                close = w::icon_button_sized(ui, Icon::Close, 22.0, "").clicked();
                            });
                        });
                    });
            });
            if close {
                p.message = None;
            }
            ui.add_space(6.0);
        }

        // --- nouveau dossier
        if let Some(name) = &mut p.new_dir {
            let mut done = None;
            ui.horizontal(|ui| {
                let r = w::input(ui, name, "Nom du nouveau dossier", false, width - 72.0);
                r.request_focus();
                if (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) || w::icon_button(ui, Icon::Check, "Créer").clicked() {
                    done = Some(true);
                }
                if w::icon_button(ui, Icon::Close, "Annuler").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    done = Some(false);
                }
            });
            match done {
                Some(true) if valid_name(name) => {
                    ops.push(Op::Mkdir(side, name.trim().to_string()));
                    p.new_dir = None;
                }
                Some(false) => p.new_dir = None,
                _ => {}
            }
            ui.add_space(6.0);
        }

        // --- confirmation de suppression
        if let Some(list) = p.confirm_delete.clone() {
            w::card().inner_margin(egui::Margin::same(12)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let what = match list.as_slice() {
                    [e] if e.dir => format!("le dossier « {} » et tout son contenu", e.name),
                    [e] => format!("« {} »", e.name),
                    l => format!("{} éléments", l.len()),
                };
                let place = if side == Side::Local { "de ce PC" } else { "de l'appareil distant" };
                ui.label(RichText::new(format!("Supprimer définitivement {what} {place} ?")).color(TEXT));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if w::button_h(ui, Kind::Danger, Some(Icon::Trash), "Supprimer", 0.0, 32.0).clicked() {
                        ops.push(Op::Delete(side, list.clone()));
                        p.confirm_delete = None;
                        p.selected.clear();
                    }
                    if w::button_h(ui, Kind::Ghost, None, "Annuler", 0.0, 32.0).clicked() {
                        p.confirm_delete = None;
                    }
                });
            });
            ui.add_space(6.0);
        }

        // --- liste
        let list_rect = Rect::from_min_max(ui.cursor().min, inner.max.max(ui.cursor().min));
        let area = ui.interact(list_rect, ui.id().with(("files-area", side as u8)), Sense::click());
        let mut dropped_on_row = false;
        egui::ScrollArea::vertical().id_salt(("file-list", side as u8)).max_height(list_rect.height()).auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            if p.loading && p.entries.is_empty() {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| ui.add(egui::Spinner::new().color(ACCENT)));
            } else if p.entries.is_empty() {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| {
                    w::icon_size(ui, Icon::Folder, 24.0, MUTED);
                    ui.label(RichText::new("Dossier vide").color(MUTED));
                });
            }
            let entries = p.entries.clone();
            for (i, e) in entries.iter().enumerate() {
                if let Some((old, new)) = &mut p.rename {
                    if *old == e.name {
                        let mut done = None;
                        ui.horizontal(|ui| {
                            let r = w::input(ui, new, "Nouveau nom", false, ui.available_width() - 72.0);
                            r.request_focus();
                            if (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) || w::icon_button(ui, Icon::Check, "Renommer").clicked() {
                                done = Some(true);
                            }
                            if w::icon_button(ui, Icon::Close, "Annuler").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                done = Some(false);
                            }
                        });
                        match done {
                            Some(true) if valid_name(new) => {
                                if new.trim() != old {
                                    ops.push(Op::Rename(side, old.clone(), new.trim().to_string()));
                                }
                                p.rename = None;
                            }
                            Some(false) => p.rename = None,
                            _ => {}
                        }
                        continue;
                    }
                }
                let selected = p.selected.contains(&e.name);
                let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::click_and_drag());
                // cible de dépôt : un dossier, depuis l'autre colonne ou depuis celle-ci (déplacement)
                let target_ok = e.dir && dragging.is_some_and(|d| d.side != side || !d.entries.iter().any(|x| x.name == e.name));
                let drop_hover = target_ok && resp.dnd_hover_payload::<Drag>().is_some();
                let hover = ui.rect_contains_pointer(rect);
                let fill = if drop_hover {
                    ACCENT.gamma_multiply(0.18)
                } else if selected {
                    ACCENT_2.gamma_multiply(0.16)
                } else if hover && dragging.is_none() {
                    HOVER.gamma_multiply(0.55)
                } else {
                    Color32::TRANSPARENT
                };
                ui.painter().rect_filled(rect, 7.0, fill);
                let painter = ui.painter();
                let ic = Rect::from_center_size(pos2(rect.left() + 16.0, rect.center().y), Vec2::splat(16.0));
                let drive = matches!(p.fs, Fs::Local) && p.cwd.is_empty();
                let icon = if drive { Icon::Server } else if e.dir { Icon::Folder } else { Icon::File };
                w::paint_icon(painter, ic, icon, if e.dir { ACCENT } else { TEXT_DIM });
                let clip = painter.with_clip_rect(Rect::from_min_max(rect.min + vec2(32.0, 0.0), rect.right_bottom() - vec2(78.0, 0.0)));
                let col = if e.name.starts_with('.') { MUTED } else { TEXT };
                clip.text(pos2(rect.left() + 32.0, rect.center().y), Align2::LEFT_CENTER, &e.name, FontId::proportional(13.0), col);
                if !e.dir {
                    painter.text(rect.right_center() - vec2(10.0, 0.0), Align2::RIGHT_CENTER, human_size(e.size), FontId::proportional(11.5), MUTED);
                }

                // sélection : clic, Ctrl+clic, Maj+clic
                if resp.clicked() || (resp.drag_started() && !selected) {
                    let m = ui.input(|i| i.modifiers);
                    if m.ctrl && resp.clicked() {
                        if !p.selected.remove(&e.name) {
                            p.selected.insert(e.name.clone());
                        }
                        p.anchor = Some(i);
                    } else if m.shift && resp.clicked() {
                        let a = p.anchor.unwrap_or(i);
                        let (lo, hi) = (a.min(i), a.max(i));
                        p.selected = entries[lo..=hi].iter().map(|x| x.name.clone()).collect();
                    } else {
                        p.selected = [e.name.clone()].into();
                        p.anchor = Some(i);
                    }
                }
                if resp.double_clicked() {
                    if e.dir {
                        ops.push(Op::Open(side, p.fs.join(&p.cwd, &e.name)));
                    } else if other_ready && !(side == Side::Remote && other_cwd.is_empty()) {
                        // double-clic sur un fichier : copie vers l'autre colonne
                        ops.push(Op::Transfer { from: side, entries: vec![e.clone()], dest: other_cwd.clone() });
                    }
                }
                // glisser : la sélection entière si l'élément en fait partie
                if !drive {
                    let payload = if selected { p.selection() } else { vec![e.clone()] };
                    resp.dnd_set_drag_payload(Drag { side, entries: payload });
                }
                if target_ok {
                    if let Some(d) = resp.dnd_release_payload::<Drag>() {
                        dropped_on_row = true;
                        let folder = p.fs.join(&p.cwd, &e.name);
                        if d.side == side {
                            ops.push(Op::MoveInto(side, d.entries.clone(), folder));
                        } else {
                            ops.push(Op::Transfer { from: d.side, entries: d.entries.clone(), dest: folder });
                        }
                    }
                }
                resp.context_menu(|ui| {
                    ui.set_min_width(170.0);
                    if e.dir && ui.button("Ouvrir").clicked() {
                        ops.push(Op::Open(side, p.fs.join(&p.cwd, &e.name)));
                        ui.close();
                    }
                    let to = if side == Side::Local { "Envoyer vers l'appareil distant" } else { "Récupérer sur ce PC" };
                    if !drive && other_ready && ui.button(to).clicked() {
                        let items = if selected { p.selection() } else { vec![e.clone()] };
                        ops.push(Op::Transfer { from: side, entries: items, dest: other_cwd.clone() });
                        ui.close();
                    }
                    if !drive && ui.button("Renommer").clicked() {
                        p.rename = Some((e.name.clone(), e.name.clone()));
                        ui.close();
                    }
                    if !drive {
                        ui.separator();
                        if ui.button(RichText::new("Supprimer").color(DANGER)).clicked() {
                            p.confirm_delete = Some(if selected { p.selection() } else { vec![e.clone()] });
                            ui.close();
                        }
                    }
                });
            }
        });
        // dépôt sur le fond de la colonne : dans le dossier ouvert
        if !dropped_on_row && drop_from_other && !(matches!(p.fs, Fs::Local) && p.cwd.is_empty()) {
            if let Some(d) = area.dnd_release_payload::<Drag>() {
                ops.push(Op::Transfer { from: d.side, entries: d.entries.clone(), dest: p.cwd.clone() });
            }
        }
        if area.clicked() {
            p.selected.clear();
        }
    }

    fn transfers_ui(&mut self, ui: &mut egui::Ui, rect: Rect) {
        ui.painter().rect(rect, 12.0, SURFACE, Stroke::new(1.0, BORDER), egui::StrokeKind::Inside);
        if rect.width() < 120.0 {
            return;
        }
        let inner = rect.shrink2(vec2(14.0, 8.0));
        let mut ui = ui.new_child(egui::UiBuilder::new().max_rect(inner).layout(egui::Layout::top_down(egui::Align::Min)));
        ui.horizontal(|ui| {
            let running = self.transfers.iter().filter(|t| t.result.is_none()).count();
            let title = if running > 0 { format!("TRANSFERTS · {running} en cours") } else { "TRANSFERTS".into() };
            ui.label(RichText::new(title).font(bold(11.0)).color(MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if running == 0 && w::link(ui, "Effacer").clicked() {
                    self.transfers.clear();
                    self.batch = 0;
                }
            });
        });
        egui::ScrollArea::vertical().id_salt("transfers").auto_shrink([false, false]).show(&mut ui, |ui| {
            for t in self.transfers.iter().rev() {
                transfer_row(ui, t);
            }
        });
    }
}

/// Ce que le bureau distant fait du lecteur partagé.
fn drive_banner(ui: &mut egui::Ui, d: &crate::rdpdr::DriveStatus, width: f32) {
    use crate::rdpdr::DriveState;
    let client = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "ce PC".into());
    let (icon, col, text) = match d.state() {
        DriveState::Accepted => (
            Icon::Check,
            ACCENT,
            format!(
                "Visible sur le bureau distant : Ce PC › « Escale sur {client} » (\\\\tsclient\\Escale).{}",
                if d.requests() > 0 { " Le serveur l'utilise." } else { "" }
            ),
        ),
        DriveState::Refused => (
            Icon::Lock,
            DANGER,
            "Le serveur a refusé le lecteur partagé : la redirection des lecteurs est désactivée dans sa configuration (stratégie « Ne pas autoriser la redirection des lecteurs »).".into(),
        ),
        DriveState::Waiting if d.logged_on() => (
            Icon::Warning,
            WARN,
            "Le serveur n'a pas pris en compte le lecteur. La redirection des lecteurs est peut-être désactivée côté serveur.".into(),
        ),
        DriveState::Waiting => (Icon::Refresh, MUTED, "En attente de l'ouverture de la session Windows sur le bureau distant…".into()),
    };
    egui::Frame::new()
        .fill(col.gamma_multiply(0.10))
        .stroke(Stroke::new(1.0, col.gamma_multiply(0.30)))
        .corner_radius(RADIUS)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_width(width - 20.0);
            ui.horizontal(|ui| {
                w::icon_size(ui, icon, 15.0, col);
                ui.add(egui::Label::new(RichText::new(text).size(12.0).color(TEXT_DIM)).wrap());
            });
        });
    if d.state() == DriveState::Waiting {
        ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
    }
}

fn transfer_row(ui: &mut egui::Ui, t: &Transfer) {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::hover());
    let p = ui.painter();
    let ic = Rect::from_center_size(pos2(rect.left() + 10.0, rect.top() + 13.0), Vec2::splat(14.0));
    let (icon, col) = match &t.result {
        Some(Err(_)) => (Icon::Warning, DANGER),
        Some(Ok(())) => (Icon::Check, ACCENT),
        None => (if t.upload { Icon::Upload } else { Icon::Download }, ACCENT_2),
    };
    w::paint_icon(p, ic, icon, col);
    let done = t.done.load(Ordering::Relaxed);
    let dir = if t.upload { "vers l'appareil distant" } else { "vers ce PC" };
    let label = match &t.result {
        Some(Err(e)) => format!("{} — {e}", t.name),
        _ => format!("{}  ·  {dir}", t.name),
    };
    let clip = p.with_clip_rect(Rect::from_min_max(rect.min + vec2(26.0, 0.0), rect.right_bottom() - vec2(80.0, 0.0)));
    clip.text(pos2(rect.left() + 26.0, rect.top() + 13.0), Align2::LEFT_CENTER, label, FontId::proportional(12.5), if t.result.as_ref().is_some_and(|r| r.is_err()) { DANGER } else { TEXT });
    let status = match &t.result {
        Some(Ok(())) => human_size(t.total.max(done)),
        Some(Err(_)) => "Échec".into(),
        None if t.total > 0 => format!("{} %", (done * 100 / t.total).min(100)),
        None => human_size(done),
    };
    p.text(pos2(rect.right() - 4.0, rect.top() + 13.0), Align2::RIGHT_CENTER, status, FontId::proportional(11.5), MUTED);
    let bar = Rect::from_min_max(pos2(rect.left() + 26.0, rect.top() + 26.0), pos2(rect.right() - 4.0, rect.top() + 30.0));
    p.rect_filled(bar, 2.0, BORDER);
    let frac = match &t.result {
        Some(_) => 1.0,
        None if t.total > 0 => (done as f32 / t.total as f32).min(1.0),
        None => 0.0,
    };
    if frac > 0.0 {
        p.rect_filled(Rect::from_min_max(bar.min, pos2(bar.left() + bar.width() * frac, bar.bottom())), 2.0, col);
    }
    if let Some(Err(e)) = &t.result {
        resp.on_hover_text(e);
    }
}

// ---------------------------------------------------------------- messages d'erreur

fn io_msg(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::PermissionDenied { DENIED.into() } else { e.to_string() }
}

fn sftp_msg(e: &russh_sftp::client::error::Error) -> String {
    match e {
        russh_sftp::client::error::Error::Status(s) if s.status_code == StatusCode::PermissionDenied => DENIED.into(),
        russh_sftp::client::error::Error::Status(s) if s.status_code == StatusCode::NoSuchFile => "élément introuvable".into(),
        e if e.to_string().to_lowercase().contains("permission") => DENIED.into(),
        e => e.to_string(),
    }
}

fn op_error(what: &str, msg: &str) -> String {
    if msg == DENIED { format!("{what} refusé : {}", DENIED.to_lowercase()) } else { format!("{what} impossible : {msg}") }
}

fn transfer_error(name: &str, msg: &str) -> String {
    if msg == DENIED { format!("vous n'avez pas le droit de copier « {name} » à cet emplacement") } else { msg.to_string() }
}

// ---------------------------------------------------------------- utilitaires

fn valid_name(n: &str) -> bool {
    let n = n.trim();
    !n.is_empty() && n != "." && n != ".." && !n.contains(['/', '\\'])
}

pub fn human_size(n: u64) -> String {
    const U: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} o") } else { format!("{v:.1} {}", U[i]).replace('.', ",") }
}

/// « nom (2).ext » si « nom.ext » existe déjà.
fn numbered(name: &str, n: u32) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

fn unique_local(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    (2..).map(|n| dir.join(numbered(name, n))).find(|p| !p.exists()).unwrap_or(first)
}

async fn unique_remote(s: &SftpSession, dir: &str, name: &str) -> String {
    let join = |n: &str| if dir.ends_with('/') { format!("{dir}{n}") } else { format!("{dir}/{n}") };
    if !s.try_exists(join(name)).await.unwrap_or(false) {
        return join(name);
    }
    for n in 2..1000 {
        let cand = join(&numbered(name, n));
        if !s.try_exists(cand.clone()).await.unwrap_or(false) {
            return cand;
        }
    }
    join(name)
}

fn local_size(p: &Path) -> u64 {
    match std::fs::metadata(p) {
        Ok(m) if m.is_dir() => std::fs::read_dir(p).map(|rd| rd.flatten().map(|e| local_size(&e.path())).sum()).unwrap_or(0),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

/// Taille totale d'un dossier local pour la progression (0 si distant : inconnue).
fn local_size_hint(fs: &Fs, path: &str) -> u64 {
    fs.local_path(path).map(|p| local_size(&p)).unwrap_or(0)
}

#[cfg(windows)]
fn hidden(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x2 != 0 // FILE_ATTRIBUTE_HIDDEN
}

#[cfg(not(windows))]
fn hidden(_: &std::fs::Metadata) -> bool {
    false
}

/// Lecteurs de ce PC (Windows) ; « / » ailleurs.
fn list_drives() -> Vec<Entry> {
    #[cfg(windows)]
    {
        let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
        (0..26u8)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| Entry { name: format!("{}:\\", (b'A' + i) as char), dir: true, size: 0 })
            .collect()
    }
    #[cfg(not(windows))]
    vec![Entry { name: "/".into(), dir: true, size: 0 }]
}

/// Contenu d'un dossier de ce PC, sans les dossiers inaccessibles ni les éléments masqués.
pub(crate) fn list_local(dir: &Path) -> Result<Vec<Entry>, ListError> {
    let rd = std::fs::read_dir(dir).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => ListError::Denied,
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => ListError::Missing,
        _ => ListError::Other(e.to_string()),
    })?;
    Ok(rd
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            // métadonnées de la cible pour les liens ; lien cassé : ignoré
            let m = std::fs::metadata(&path).ok()?;
            let lm = e.metadata().ok()?;
            if hidden(&lm) {
                return None;
            }
            if m.is_dir() && std::fs::read_dir(&path).is_err() {
                return None; // pas le droit d'y entrer : on ne le montre pas
            }
            Some(Entry { name: e.file_name().to_string_lossy().into_owned(), dir: m.is_dir(), size: if m.is_dir() { 0 } else { m.len() } })
        })
        .collect())
}

fn canonical(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

/// Copie `from` dans le dossier `dir` (sous le nom `name`, rendu unique). Refuse un dossier copié
/// dans lui-même : sans ce contrôle, la copie récursive redécouvre sans fin ce qu'elle vient de
/// créer (ex. le dossier du coffre glissé dans son propre sous-dossier « Partage ») jusqu'au
/// débordement de pile, qui tue l'application. `private` (dossier des coffres) n'est jamais copié.
fn copy_local_item(from: &Path, dir: &Path, name: &str, private: Option<&Path>, done: &AtomicU64) -> Result<(), String> {
    let (src, into) = (canonical(from), canonical(dir));
    if into.starts_with(&src) {
        return Err("Un dossier ne peut pas être copié dans lui-même.".into());
    }
    let private = private.map(canonical);
    if private.as_ref().is_some_and(|v| src.starts_with(v)) {
        return Err("Les fichiers des coffres d'Escale ne sont jamais partagés.".into());
    }
    local_copy(from, &unique_local(dir, name), private.as_deref(), done)
}

/// Copie locale (fichier ou dossier récursif) avec progression ; le dossier `skip` est ignoré.
fn local_copy(src: &Path, dst: &Path, skip: Option<&Path>, done: &AtomicU64) -> Result<(), String> {
    use std::io::{Read, Write};
    let m = std::fs::metadata(src).map_err(|e| io_msg(&e))?;
    if m.is_dir() {
        if skip.is_some_and(|s| canonical(src) == s) {
            return Ok(());
        }
        std::fs::create_dir_all(dst).map_err(|e| io_msg(&e))?;
        for e in std::fs::read_dir(src).map_err(|e| io_msg(&e))?.flatten() {
            local_copy(&e.path(), &dst.join(e.file_name()), skip, done)?;
        }
        return Ok(());
    }
    let mut r = std::fs::File::open(src).map_err(|e| io_msg(&e))?;
    let mut f = std::fs::File::create(dst).map_err(|e| io_msg(&e))?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = r.read(&mut buf).map_err(|e| io_msg(&e))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n]).map_err(|e| io_msg(&e))?;
        done.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(())
}

/// L'utilisateur distant peut-il probablement entrer dans ce dossier (bits de droits) ?
/// Sans certitude (groupes secondaires, ACL), le dossier est vérifié en l'ouvrant.
fn likely_accessible(m: &russh_sftp::client::fs::Metadata, uid: Option<u32>, gid: Option<u32>) -> bool {
    let Some(mode) = m.permissions else { return true };
    if uid == Some(0) {
        return true;
    }
    let need = if uid.is_some() && m.uid == uid {
        0o500
    } else if gid.is_some() && m.gid == gid {
        0o050
    } else {
        0o005
    };
    mode & need == need
}

/// Contenu d'un dossier distant, sans les dossiers où l'utilisateur ne peut pas entrer.
pub(crate) async fn sftp_list(s: &SftpSession, path: &str, uid: Option<u32>, gid: Option<u32>) -> Result<Vec<Entry>, ListError> {
    let rd = s.read_dir(path).await.map_err(|e| match &e {
        russh_sftp::client::error::Error::Status(st) if st.status_code == StatusCode::PermissionDenied => ListError::Denied,
        russh_sftp::client::error::Error::Status(st) if st.status_code == StatusCode::NoSuchFile => ListError::Missing,
        e => ListError::Other(e.to_string()),
    })?;
    let join = |n: &str| if path.ends_with('/') { format!("{path}{n}") } else { format!("{path}/{n}") };
    let mut out = Vec::new();
    for e in rd {
        let name = e.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let mut m = e.metadata();
        // lien symbolique : on suit la cible
        if m.is_symlink() {
            match s.metadata(join(&name)).await {
                Ok(t) => m = t,
                Err(_) => continue,
            }
        }
        let dir = m.is_dir();
        if dir && !likely_accessible(&m, uid, gid) && s.read_dir(join(&name)).await.is_err() {
            continue; // accès refusé : masqué
        }
        out.push(Entry { name, dir, size: if dir { 0 } else { m.len() } });
    }
    Ok(out)
}

pub(crate) fn sftp_upload<'a>(
    s: &'a SftpSession,
    local: &'a Path,
    remote: &'a str,
    done: &'a AtomicU64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let m = tokio::fs::metadata(local).await.map_err(|e| io_msg(&e))?;
        if m.is_dir() {
            if !s.try_exists(remote).await.unwrap_or(false) {
                s.create_dir(remote).await.map_err(|e| sftp_msg(&e))?;
            }
            let mut rd = tokio::fs::read_dir(local).await.map_err(|e| io_msg(&e))?;
            while let Some(e) = rd.next_entry().await.map_err(|e| io_msg(&e))? {
                let child = format!("{remote}/{}", e.file_name().to_string_lossy());
                sftp_upload(s, &e.path(), &child, done).await?;
            }
            return Ok(());
        }
        let mut src = tokio::fs::File::open(local).await.map_err(|e| io_msg(&e))?;
        let mut dst = s.create(remote).await.map_err(|e| sftp_msg(&e))?;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = src.read(&mut buf).await.map_err(|e| io_msg(&e))?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n]).await.map_err(|e| io_msg(&e))?;
            done.fetch_add(n as u64, Ordering::Relaxed);
        }
        dst.shutdown().await.map_err(|e| io_msg(&e))
    })
}

pub(crate) async fn sftp_download(s: &SftpSession, remote: &str, local: &Path, done: &AtomicU64) -> Result<(), String> {
    let mut src = s.open(remote).await.map_err(|e| sftp_msg(&e))?;
    let mut dst = tokio::fs::File::create(local).await.map_err(|e| io_msg(&e))?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = src.read(&mut buf).await.map_err(|e| io_msg(&e))?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await.map_err(|e| io_msg(&e))?;
        done.fetch_add(n as u64, Ordering::Relaxed);
    }
    dst.flush().await.map_err(|e| io_msg(&e))
}

/// Téléchargement d'un dossier distant complet (les sous-dossiers refusés sont ignorés).
fn sftp_download_tree<'a>(
    s: &'a SftpSession,
    remote: &'a str,
    local: &'a Path,
    done: &'a AtomicU64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let rd = s.read_dir(remote).await.map_err(|e| sftp_msg(&e))?;
        tokio::fs::create_dir_all(local).await.map_err(|e| io_msg(&e))?;
        for e in rd {
            let name = e.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let child = format!("{remote}/{name}");
            let target = local.join(&name);
            let mut m = e.metadata();
            if m.is_symlink() {
                match s.metadata(child.clone()).await {
                    Ok(t) => m = t,
                    Err(_) => continue,
                }
            }
            if m.is_dir() {
                match sftp_download_tree(s, &child, &target, done).await {
                    Err(e) if e == DENIED => continue,
                    r => r?,
                }
            } else {
                sftp_download(s, &child, &target, done).await?;
            }
        }
        Ok(())
    })
}

fn sftp_remove_tree<'a>(s: &'a SftpSession, path: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        for e in s.read_dir(path).await.map_err(|e| sftp_msg(&e))? {
            let name = e.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let child = format!("{path}/{name}");
            if e.metadata().is_dir() {
                sftp_remove_tree(s, &child).await?;
            } else {
                s.remove_file(child).await.map_err(|e| sftp_msg(&e))?;
            }
        }
        s.remove_dir(path).await.map_err(|e| sftp_msg(&e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_names_and_numbering() {
        assert_eq!(human_size(512), "512 o");
        assert_eq!(human_size(1536), "1,5 Ko");
        assert!(valid_name("rapport.pdf"));
        assert!(!valid_name(".."));
        assert!(!valid_name("a/b"));
        assert_eq!(numbered("rapport.pdf", 2), "rapport (2).pdf");
        assert_eq!(numbered("LISEZMOI", 3), "LISEZMOI (3)");
        assert_eq!(numbered(".bashrc", 2), ".bashrc (2)");
    }

    #[test]
    fn paths_per_filesystem() {
        let shared = Fs::Shared(PathBuf::from("base"));
        assert_eq!(shared.join("", "a"), "a");
        assert_eq!(shared.join("a", "b"), "a/b");
        assert_eq!(shared.parent("a/b").as_deref(), Some("a"));
        assert_eq!(shared.parent("a").as_deref(), Some(""));
        assert_eq!(shared.parent(""), None);
        assert_eq!(shared.local_path("a/../../b"), Some(PathBuf::from("base").join("a").join("b")));

        let sftp = Fs::Opening;
        assert_eq!(sftp.join("/home/u", "x"), "/home/u/x");
        assert_eq!(sftp.join("/", "etc"), "/etc");
        assert_eq!(sftp.parent("/home/u").as_deref(), Some("/home"));
        assert_eq!(sftp.parent("/home").as_deref(), Some("/"));
        assert_eq!(sftp.parent("/"), None);

        #[cfg(windows)]
        {
            assert_eq!(Fs::Local.parent("C:\\").as_deref(), Some(""));
            assert_eq!(Fs::Local.parent("C:\\Users").as_deref(), Some("C:\\"));
            assert_eq!(Fs::Local.join("", "C:\\"), "C:\\");
            assert!(list_drives().iter().any(|d| d.name == "C:\\"));
        }
    }

    #[test]
    fn local_listing_and_unique_names() {
        let root = std::env::temp_dir().join(format!("escale-files-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("dossier")).unwrap();
        std::fs::write(root.join("a.txt"), b"abc").unwrap();
        let list = list_local(&root).unwrap();
        assert!(list.iter().any(|e| e.name == "dossier" && e.dir));
        assert!(list.iter().any(|e| e.name == "a.txt" && e.size == 3));
        assert_eq!(unique_local(&root, "a.txt"), root.join("a (2).txt"));
        assert_eq!(unique_local(&root, "b.txt"), root.join("b.txt"));
        assert_eq!(list_local(&root.join("absent")).unwrap_err(), ListError::Missing);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn copy_into_share_never_recurses_nor_leaks_the_vault() {
        // Escale\Coffre1\{vault.escale, Partage\srv} : le coffre glissé dans son propre partage
        let root = std::env::temp_dir().join(format!("escale-copy-{}", uuid::Uuid::new_v4()));
        let vault = root.join("Escale").join("Coffre1");
        let share = vault.join("Partage").join("srv");
        std::fs::create_dir_all(&share).unwrap();
        std::fs::write(vault.join("vault.escale"), b"secret").unwrap();
        std::fs::write(root.join("doc.txt"), b"abc").unwrap();
        let done = AtomicU64::new(0);
        let esc = root.join("Escale");
        assert!(copy_local_item(&vault, &share, "Coffre1", None, &done).unwrap_err().contains("lui-même"));
        assert!(copy_local_item(&vault, &root, "Coffre1", Some(&esc), &done).unwrap_err().contains("coffres"));
        // dossier qui contient les coffres : copié sans eux
        let out = root.join("out");
        std::fs::create_dir_all(&out).unwrap();
        copy_local_item(&root.join("doc.txt"), &out, "doc.txt", Some(&esc), &done).unwrap();
        assert_eq!(std::fs::read(out.join("doc.txt")).unwrap(), b"abc");
        let other = std::env::temp_dir().join(format!("escale-copy-out-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&other).unwrap();
        copy_local_item(&root, &other, "tout", Some(&esc), &done).unwrap();
        assert!(other.join("tout").join("doc.txt").is_file());
        assert!(!other.join("tout").join("Escale").exists(), "dossier des coffres jamais copié");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn unix_permission_bits() {
        let meta = |mode: u32, uid: u32, gid: u32| russh_sftp::client::fs::Metadata { permissions: Some(mode), uid: Some(uid), gid: Some(gid), ..Default::default() };
        // propriétaire
        assert!(likely_accessible(&meta(0o40700, 1000, 1000), Some(1000), Some(1000)));
        // dossier d'un autre utilisateur fermé aux autres
        assert!(!likely_accessible(&meta(0o40700, 0, 0), Some(1000), Some(1000)));
        // ouvert à tous
        assert!(likely_accessible(&meta(0o40755, 0, 0), Some(1000), Some(1000)));
        // root voit tout
        assert!(likely_accessible(&meta(0o40700, 1000, 1000), Some(0), Some(0)));
    }
}
