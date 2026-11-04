//! Redirection de lecteur RDP (MS-RDPEFS) : un dossier local apparaît sur le bureau distant
//! (« Ce PC › Escale sur … », ou `\\tsclient\Escale`) pour y déposer ou en récupérer des fichiers.
//!
//! Le serveur ne peut jamais sortir de ce dossier : chaque chemin reçu est reconstruit composant
//! par composant, `..` et les noms de lecteur / flux (`:`) sont refusés.

use ironrdp_core::impl_as_any;
use ironrdp_pdu::{PduResult, encode_err};
use ironrdp_rdpdr::RdpdrBackend;
use ironrdp_rdpdr::pdu::RdpdrPdu;
use ironrdp_rdpdr::pdu::efs::*;
use ironrdp_rdpdr::pdu::esc::{ScardCall, ScardIoCtlCode};
use ironrdp_svc::SvcMessage;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Identifiant du lecteur annoncé au serveur.
pub const DRIVE_ID: u32 = 1;
pub const DRIVE_NAME: &str = "Escale";

/// État du lecteur partagé vu du serveur, affiché dans la vue Fichiers.
#[derive(Default, Debug)]
pub struct DriveStatus {
    /// 0 : en attente, 1 : accepté, 2 : refusé par le serveur.
    state: std::sync::atomic::AtomicU8,
    /// Le serveur a signalé l'ouverture de la session Windows (moment où il demande les lecteurs).
    logged_on: std::sync::atomic::AtomicBool,
    /// Requêtes reçues sur le lecteur (le serveur l'utilise).
    requests: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DriveState {
    Waiting,
    Accepted,
    Refused,
}

impl DriveStatus {
    pub fn state(&self) -> DriveState {
        match self.state.load(std::sync::atomic::Ordering::Relaxed) {
            1 => DriveState::Accepted,
            2 => DriveState::Refused,
            _ => DriveState::Waiting,
        }
    }

    pub fn logged_on(&self) -> bool {
        self.logged_on.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn requests(&self) -> u64 {
        self.requests.load(std::sync::atomic::Ordering::Relaxed)
    }
}

struct Handle {
    path: PathBuf,
    file: Option<File>,
    dir: bool,
    delete_on_close: bool,
    /// Entrées restant à énumérer (QueryDirectory).
    listing: VecDeque<PathBuf>,
}

pub struct DriveBackend {
    root: PathBuf,
    status: std::sync::Arc<DriveStatus>,
    next_id: u32,
    handles: HashMap<u32, Handle>,
}

impl std::fmt::Debug for DriveBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriveBackend").field("root", &self.root).field("open", &self.handles.len()).finish()
    }
}

impl_as_any!(DriveBackend);

impl DriveBackend {
    pub fn new(root: PathBuf, status: std::sync::Arc<DriveStatus>) -> Self {
        Self { root, status, next_id: 1, handles: HashMap::new() }
    }

    /// Chemin local d'un chemin distant (`\dossier\fichier.txt`), confiné au dossier partagé.
    pub fn resolve(&self, remote: &str) -> Option<PathBuf> {
        let mut p = self.root.clone();
        for c in remote.split(['\\', '/']) {
            if c.is_empty() || c == "." {
                continue;
            }
            if c == ".." || c.contains([':', '\0']) {
                return None;
            }
            p.push(c);
        }
        Some(p)
    }

    fn create(&mut self, req: DeviceCreateRequest) -> Vec<SvcMessage> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let io = req.device_io_request.clone();
        let reply = |status: NtStatus, info: Information| {
            vec![SvcMessage::from(RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                device_io_reply: DeviceIoResponse::new(io.clone(), status),
                file_id: if status == NtStatus::SUCCESS { id } else { 0 },
                information: info,
            }))]
        };
        let Some(path) = self.resolve(&req.path) else {
            return reply(NtStatus::ACCESS_DENIED, Information::empty());
        };
        let disp = req.create_disposition;
        let opts = req.create_options.bits();
        let want_dir = opts & CreateOptions::FILE_DIRECTORY_FILE.bits() != 0;
        let want_file = opts & CreateOptions::FILE_NON_DIRECTORY_FILE.bits() != 0;
        let delete_on_close = opts & CreateOptions::FILE_DELETE_ON_CLOSE.bits() != 0;
        let meta = fs::metadata(&path).ok();
        let exists = meta.is_some();
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let created = Information::from_bits_retain(2); // FILE_CREATED

        if exists && disp == CreateDisposition::FILE_CREATE {
            return reply(NtStatus::OBJECT_NAME_COLLISION, Information::empty());
        }
        if !exists && (disp == CreateDisposition::FILE_OPEN || disp == CreateDisposition::FILE_OVERWRITE) {
            return reply(NtStatus::NO_SUCH_FILE, Information::empty());
        }
        if exists && !is_dir && want_dir {
            return reply(NtStatus::NOT_A_DIRECTORY, Information::empty());
        }
        if is_dir && want_file {
            return reply(NtStatus::ACCESS_DENIED, Information::empty());
        }

        if is_dir || (!exists && want_dir) {
            if !exists && fs::create_dir(&path).is_err() {
                return reply(NtStatus::ACCESS_DENIED, Information::empty());
            }
            self.handles.insert(id, Handle { path, file: None, dir: true, delete_on_close, listing: VecDeque::new() });
            return reply(NtStatus::SUCCESS, if exists { Information::FILE_OPENED } else { created });
        }

        let truncate = matches!(
            disp,
            CreateDisposition::FILE_SUPERSEDE | CreateDisposition::FILE_OVERWRITE | CreateDisposition::FILE_OVERWRITE_IF
        );
        let mut o = OpenOptions::new();
        o.read(true).write(true);
        match disp {
            CreateDisposition::FILE_CREATE => {
                o.create_new(true);
            }
            CreateDisposition::FILE_OPEN_IF | CreateDisposition::FILE_SUPERSEDE | CreateDisposition::FILE_OVERWRITE_IF => {
                o.create(true);
            }
            _ => {}
        }
        if truncate {
            o.truncate(true);
        }
        // lecture seule en repli (fichier protégé en écriture) quand rien ne doit être créé ni vidé
        let file = o.open(&path).or_else(|e| {
            if exists && !truncate && e.kind() == io::ErrorKind::PermissionDenied {
                File::open(&path)
            } else {
                Err(e)
            }
        });
        match file {
            Ok(file) => {
                let info = if !exists {
                    created
                } else if truncate {
                    Information::FILE_OVERWRITTEN
                } else {
                    Information::FILE_OPENED
                };
                self.handles.insert(id, Handle { path, file: Some(file), dir: false, delete_on_close, listing: VecDeque::new() });
                reply(NtStatus::SUCCESS, info)
            }
            Err(e) => reply(io_status(&e), Information::empty()),
        }
    }

    fn file(&mut self, id: u32) -> Option<&mut File> {
        let h = self.handles.get_mut(&id)?;
        if h.file.is_none() && !h.dir {
            // rouvert après un renommage
            h.file = OpenOptions::new().read(true).write(true).open(&h.path).or_else(|_| File::open(&h.path)).ok();
        }
        h.file.as_mut()
    }

    fn read(&mut self, req: DeviceReadRequest) -> Vec<SvcMessage> {
        let io = req.device_io_request;
        let (status, data) = match self.file(io.file_id) {
            None => (NtStatus::NO_SUCH_FILE, Vec::new()),
            Some(f) => match read_at(f, req.offset, req.length.min(16 << 20) as usize) {
                Ok(d) => (NtStatus::SUCCESS, d),
                Err(e) => (io_status(&e), Vec::new()),
            },
        };
        vec![SvcMessage::from(RdpdrPdu::DeviceReadResponse(DeviceReadResponse {
            device_io_reply: DeviceIoResponse::new(io, status),
            read_data: data,
        }))]
    }

    fn write(&mut self, req: DeviceWriteRequest) -> Vec<SvcMessage> {
        let io = req.device_io_request;
        let (status, len) = match self.file(io.file_id) {
            None => (NtStatus::NO_SUCH_FILE, 0),
            Some(f) => match f.seek(SeekFrom::Start(req.offset)).and_then(|_| f.write_all(&req.write_data)) {
                Ok(()) => (NtStatus::SUCCESS, req.write_data.len() as u32),
                Err(e) => (io_status(&e), 0),
            },
        };
        vec![SvcMessage::from(RdpdrPdu::DeviceWriteResponse(DeviceWriteResponse {
            device_io_reply: DeviceIoResponse::new(io, status),
            length: len,
        }))]
    }

    fn close(&mut self, req: DeviceCloseRequest) -> Vec<SvcMessage> {
        if let Some(h) = self.handles.remove(&req.device_io_request.file_id) {
            drop(h.file);
            if h.delete_on_close {
                let _ = if h.dir { fs::remove_dir(&h.path) } else { fs::remove_file(&h.path) };
            }
        }
        vec![SvcMessage::from(RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
            device_io_response: DeviceIoResponse::new(req.device_io_request, NtStatus::SUCCESS),
        }))]
    }

    fn query_information(&mut self, req: ServerDriveQueryInformationRequest) -> Vec<SvcMessage> {
        let io = req.device_io_request;
        let meta = self.handles.get(&io.file_id).map(|h| (fs::metadata(&h.path), h.path.clone(), h.delete_on_close));
        let (status, buffer) = match meta {
            None => (NtStatus::NO_SUCH_FILE, None),
            Some((Err(e), ..)) => (io_status(&e), None),
            Some((Ok(m), path, pending)) => {
                let attrs = attributes(&m, &path);
                let lvl = req.file_info_class_lvl;
                if lvl == FileInformationClassLevel::FILE_BASIC_INFORMATION {
                    let (c, a, w) = times(&m);
                    let info = FileBasicInformation { creation_time: c, last_access_time: a, last_write_time: w, change_time: w, file_attributes: attrs };
                    (NtStatus::SUCCESS, Some(FileInformationClass::Basic(info)))
                } else if lvl == FileInformationClassLevel::FILE_STANDARD_INFORMATION {
                    let size = if m.is_dir() { 0 } else { m.len() as i64 };
                    let info = FileStandardInformation {
                        allocation_size: size,
                        end_of_file: size,
                        number_of_links: 1,
                        delete_pending: if pending { Boolean::True } else { Boolean::False },
                        directory: if m.is_dir() { Boolean::True } else { Boolean::False },
                    };
                    (NtStatus::SUCCESS, Some(FileInformationClass::Standard(info)))
                } else if lvl == FileInformationClassLevel::FILE_ATTRIBUTE_TAG_INFORMATION {
                    (NtStatus::SUCCESS, Some(FileInformationClass::AttributeTag(FileAttributeTagInformation { file_attributes: attrs, reparse_tag: 0 })))
                } else {
                    (NtStatus::NOT_SUPPORTED, None)
                }
            }
        };
        vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryInformationResponse(ClientDriveQueryInformationResponse {
            device_io_response: DeviceIoResponse::new(io, status),
            buffer,
        }))]
    }

    fn query_directory(&mut self, req: ServerDriveQueryDirectoryRequest) -> Vec<SvcMessage> {
        let io = req.device_io_request;
        let initial = req.initial_query != 0;
        if initial {
            // `\dossier\motif` : on énumère le dossier et on garde ce qui correspond au motif
            let (parent, pattern) = match req.path.rfind(['\\', '/']) {
                Some(i) => (&req.path[..i], &req.path[i + 1..]),
                None => ("", req.path.as_str()),
            };
            let entries: VecDeque<PathBuf> = match self.resolve(parent) {
                Some(dir) if pattern.contains(['*', '?']) => fs::read_dir(&dir)
                    .map(|rd| {
                        let mut v: Vec<PathBuf> = rd
                            .flatten()
                            .filter(|e| wildcard(pattern, &e.file_name().to_string_lossy()))
                            .map(|e| e.path())
                            .collect();
                        v.sort();
                        v.into()
                    })
                    .unwrap_or_default(),
                Some(dir) => {
                    let p = dir.join(pattern);
                    if p.exists() { VecDeque::from([p]) } else { VecDeque::new() }
                }
                None => VecDeque::new(),
            };
            if let Some(h) = self.handles.get_mut(&io.file_id) {
                h.listing = entries;
            }
        }
        let next = self.handles.get_mut(&io.file_id).and_then(|h| h.listing.pop_front());
        let not_found = if initial { NtStatus::NO_SUCH_FILE } else { NtStatus::NO_MORE_FILES };
        let (status, buffer) = match next.and_then(|p| fs::metadata(&p).ok().map(|m| (p, m))) {
            None => (not_found, None),
            Some((p, m)) => {
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let attrs = attributes(&m, &p);
                let (c, a, w) = times(&m);
                let size = if m.is_dir() { 0 } else { m.len() as i64 };
                let lvl = req.file_info_class_lvl;
                let info = if lvl == FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION {
                    Some(FileInformationClass::BothDirectory(FileBothDirectoryInformation::new(c, a, w, w, size, attrs, name)))
                } else if lvl == FileInformationClassLevel::FILE_FULL_DIRECTORY_INFORMATION {
                    Some(FileInformationClass::FullDirectory(FileFullDirectoryInformation::new(c, a, w, w, size, attrs, name)))
                } else if lvl == FileInformationClassLevel::FILE_DIRECTORY_INFORMATION {
                    Some(FileInformationClass::Directory(FileDirectoryInformation::new(c, a, w, w, size, attrs, name)))
                } else if lvl == FileInformationClassLevel::FILE_NAMES_INFORMATION {
                    Some(FileInformationClass::Names(FileNamesInformation::new(name)))
                } else {
                    None
                };
                match info {
                    Some(i) => (NtStatus::SUCCESS, Some(i)),
                    None => (NtStatus::NOT_SUPPORTED, None),
                }
            }
        };
        vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryDirectoryResponse(ClientDriveQueryDirectoryResponse {
            device_io_reply: DeviceIoResponse::new(io, status),
            buffer,
        }))]
    }

    fn query_volume(&mut self, req: ServerDriveQueryVolumeInformationRequest) -> Vec<SvcMessage> {
        let (total, free) = disk_space(&self.root);
        // unités d'allocation de 4 Kio
        let (total, free) = ((total / 4096) as i64, (free / 4096) as i64);
        let lvl = req.fs_info_class_lvl;
        let buffer = if lvl == FileSystemInformationClassLevel::FILE_FS_VOLUME_INFORMATION {
            Some(FileSystemInformationClass::FileFsVolumeInformation(FileFsVolumeInformation {
                volume_creation_time: 0,
                volume_serial_number: 0x0E5C_A1E0,
                supports_objects: Boolean::False,
                volume_label: DRIVE_NAME.to_owned(),
            }))
        } else if lvl == FileSystemInformationClassLevel::FILE_FS_SIZE_INFORMATION {
            Some(FileSystemInformationClass::FileFsSizeInformation(FileFsSizeInformation {
                total_alloc_units: total,
                available_alloc_units: free,
                sectors_per_alloc_unit: 8,
                bytes_per_sector: 512,
            }))
        } else if lvl == FileSystemInformationClassLevel::FILE_FS_FULL_SIZE_INFORMATION {
            Some(FileSystemInformationClass::FileFsFullSizeInformation(FileFsFullSizeInformation {
                total_alloc_units: total,
                caller_available_alloc_units: free,
                actual_available_alloc_units: free,
                sectors_per_alloc_unit: 8,
                bytes_per_sector: 512,
            }))
        } else if lvl == FileSystemInformationClassLevel::FILE_FS_ATTRIBUTE_INFORMATION {
            Some(FileSystemInformationClass::FileFsAttributeInformation(FileFsAttributeInformation {
                file_system_attributes: FileSystemAttributes::FILE_CASE_PRESERVED_NAMES | FileSystemAttributes::FILE_UNICODE_ON_DISK,
                max_component_name_len: 255,
                file_system_name: "NTFS".to_owned(),
            }))
        } else if lvl == FileSystemInformationClassLevel::FILE_FS_DEVICE_INFORMATION {
            Some(FileSystemInformationClass::FileFsDeviceInformation(FileFsDeviceInformation {
                device_type: 0x07, // FILE_DEVICE_DISK
                characteristics: Characteristics::FILE_REMOTE_DEVICE | Characteristics::FILE_DEVICE_IS_MOUNTED,
            }))
        } else {
            None
        };
        let status = if buffer.is_some() { NtStatus::SUCCESS } else { NtStatus::NOT_SUPPORTED };
        vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryVolumeInformationResponse(ClientDriveQueryVolumeInformationResponse {
            device_io_reply: DeviceIoResponse::new(req.device_io_request, status),
            buffer,
        }))]
    }

    fn set_information(&mut self, req: ServerDriveSetInformationRequest) -> PduResult<Vec<SvcMessage>> {
        let id = req.device_io_request.file_id;
        let status = match &req.set_buffer {
            FileInformationClass::Rename(info) => match (self.resolve(&info.file_name), self.handles.contains_key(&id)) {
                (None, _) => NtStatus::ACCESS_DENIED,
                (_, false) => NtStatus::NO_SUCH_FILE,
                (Some(to), true) => {
                    if to.exists() && info.replace_if_exists == Boolean::False {
                        NtStatus::OBJECT_NAME_COLLISION
                    } else {
                        let h = self.handles.get_mut(&id).expect("vérifié");
                        h.file = None; // Windows refuse de renommer un fichier ouvert sans partage
                        match fs::rename(&h.path, &to) {
                            Ok(()) => {
                                h.path = to;
                                NtStatus::SUCCESS
                            }
                            Err(e) => io_status(&e),
                        }
                    }
                }
            },
            FileInformationClass::Disposition(d) => match self.handles.get_mut(&id) {
                Some(h) => {
                    // suppression effective à la fermeture, comme sous Windows
                    if h.dir && d.delete_pending != 0 && fs::read_dir(&h.path).is_ok_and(|mut r| r.next().is_some()) {
                        NtStatus::DIRECTORY_NOT_EMPTY
                    } else {
                        h.delete_on_close = d.delete_pending != 0;
                        NtStatus::SUCCESS
                    }
                }
                None => NtStatus::NO_SUCH_FILE,
            },
            FileInformationClass::EndOfFile(info) => match self.file(id) {
                Some(f) => match f.set_len(info.end_of_file.max(0) as u64) {
                    Ok(()) => NtStatus::SUCCESS,
                    Err(e) => io_status(&e),
                },
                None => NtStatus::NO_SUCH_FILE,
            },
            // horodatages, attributs, préallocation : sans effet ici
            _ => NtStatus::SUCCESS,
        };
        Ok(vec![SvcMessage::from(RdpdrPdu::ClientDriveSetInformationResponse(
            ClientDriveSetInformationResponse::new(&req, status).map_err(|e| encode_err!(e))?,
        ))])
    }
}

impl RdpdrBackend for DriveBackend {
    fn handle_server_device_announce_response(&mut self, pdu: ServerDeviceAnnounceResponse) -> PduResult<()> {
        if pdu.device_id == DRIVE_ID {
            let ok = pdu.result_code == NtStatus::SUCCESS;
            self.status.state.store(if ok { 1 } else { 2 }, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    fn handle_user_logged_on(&mut self, _rdpdr: &mut ironrdp_rdpdr::Rdpdr) -> PduResult<Vec<SvcMessage>> {
        self.status.logged_on.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(Vec::new())
    }

    fn handle_scard_call(&mut self, _req: DeviceControlRequest<ScardIoCtlCode>, _call: ScardCall) -> PduResult<()> {
        Ok(())
    }

    fn handle_drive_io_request(&mut self, req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
        self.status.requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(match req {
            ServerDriveIoRequest::ServerCreateDriveRequest(r) => self.create(r),
            ServerDriveIoRequest::DeviceReadRequest(r) => self.read(r),
            ServerDriveIoRequest::DeviceWriteRequest(r) => self.write(r),
            ServerDriveIoRequest::DeviceCloseRequest(r) => self.close(r),
            ServerDriveIoRequest::ServerDriveQueryInformationRequest(r) => self.query_information(r),
            ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(r) => self.query_directory(r),
            ServerDriveIoRequest::ServerDriveQueryVolumeInformationRequest(r) => self.query_volume(r),
            ServerDriveIoRequest::ServerDriveSetInformationRequest(r) => return self.set_information(r),
            ServerDriveIoRequest::DeviceControlRequest(r) => vec![SvcMessage::from(RdpdrPdu::DeviceControlResponse(DeviceControlResponse {
                device_io_reply: DeviceIoResponse::new(r.header, NtStatus::SUCCESS),
                output_buffer: None,
            }))],
            // notification de changement : reste en attente (réponse facultative) ; verrous : ignorés
            ServerDriveIoRequest::ServerDriveNotifyChangeDirectoryRequest(_) | ServerDriveIoRequest::ServerDriveLockControlRequest(_) => Vec::new(),
        })
    }
}

// ---------------------------------------------------------------- canal protégé

/// Canal RDPDR qui ne coupe jamais la session : une requête qu'IronRDP ne sait pas décoder
/// (classe d'information inconnue…) reçoit une réponse « non pris en charge », comme le ferait
/// mstsc, au lieu de remonter une erreur fatale.
#[derive(Debug)]
pub struct SafeRdpdr(pub ironrdp_rdpdr::Rdpdr);

impl_as_any!(SafeRdpdr);

impl ironrdp_svc::SvcProcessor for SafeRdpdr {
    fn channel_name(&self) -> ironrdp_pdu::gcc::ChannelName {
        self.0.channel_name()
    }

    fn compression_condition(&self) -> ironrdp_svc::CompressionCondition {
        self.0.compression_condition()
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        self.0.start()
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        match self.0.process(payload) {
            Ok(m) => Ok(m),
            Err(_) => Ok(refuse_io(payload).map(|r| vec![SvcMessage::from(r)]).unwrap_or_default()),
        }
    }
}

impl ironrdp_svc::SvcClientProcessor for SafeRdpdr {}

/// Réponse « STATUS_NOT_SUPPORTED » à une requête d'E/S (DR_DEVICE_IOREQUEST), sinon rien.
fn refuse_io(payload: &[u8]) -> Option<Vec<u8>> {
    let u16_at = |i: usize| payload.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |i: usize| payload.get(i..i + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    // RDPDR_CTYP_CORE, PAKID_CORE_DEVICE_IOREQUEST
    if u16_at(0)? != 0x4472 || u16_at(2)? != 0x4952 {
        return None;
    }
    let (device_id, completion_id, major) = (u32_at(4)?, u32_at(12)?, u32_at(16)?);
    let mut out = Vec::with_capacity(21);
    out.extend_from_slice(&0x4472u16.to_le_bytes());
    out.extend_from_slice(&0x4943u16.to_le_bytes()); // PAKID_CORE_DEVICE_IOCOMPLETION
    out.extend_from_slice(&device_id.to_le_bytes());
    out.extend_from_slice(&completion_id.to_le_bytes());
    out.extend_from_slice(&0xC000_00BBu32.to_le_bytes()); // STATUS_NOT_SUPPORTED
    // corps minimal propre à chaque type de requête (longueur nulle)
    let body = match major {
        0x03 | 0x05 | 0x0A | 0x0E => 4, // lecture, requêtes d'information, contrôle
        _ => 5,                         // création, écriture, définition, répertoires, fermeture, verrous
    };
    out.extend(std::iter::repeat_n(0u8, body));
    Some(out)
}

// ---------------------------------------------------------------- utilitaires

fn read_at(f: &mut File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0; len];
    let mut n = 0;
    while n < len {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    buf.truncate(n);
    Ok(buf)
}

fn io_status(e: &io::Error) -> NtStatus {
    match e.kind() {
        io::ErrorKind::NotFound => NtStatus::NO_SUCH_FILE,
        io::ErrorKind::PermissionDenied => NtStatus::ACCESS_DENIED,
        io::ErrorKind::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        io::ErrorKind::DirectoryNotEmpty => NtStatus::DIRECTORY_NOT_EMPTY,
        io::ErrorKind::NotADirectory => NtStatus::NOT_A_DIRECTORY,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

/// Correspondance de motif DOS (`*`, `?`), insensible à la casse.
pub fn wildcard(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    // `*.*` désigne tous les fichiers, même sans extension
    if p == ['*', '.', '*'] {
        return true;
    }
    let (mut i, mut j, mut star, mut mark) = (0, 0, None, 0);
    while j < n.len() {
        if i < p.len() && (p[i] == '?' || p[i] == n[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == '*')
}

fn filetime(t: io::Result<SystemTime>) -> i64 {
    // 100 ns depuis le 1er janvier 1601
    match t.ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) {
        Some(d) => (d.as_nanos() / 100) as i64 + 116_444_736_000_000_000,
        None => 0,
    }
}

/// (création, dernier accès, dernière écriture)
fn times(m: &fs::Metadata) -> (i64, i64, i64) {
    let w = filetime(m.modified());
    let c = match filetime(m.created()) {
        0 => w,
        c => c,
    };
    (c, filetime(m.accessed()), w)
}

fn attributes(m: &fs::Metadata, path: &Path) -> FileAttributes {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let _ = path;
        // mêmes valeurs que FILE_ATTRIBUTE_* ; 0x80 = NORMAL quand rien d'autre
        let a = FileAttributes::from_bits_truncate(m.file_attributes() & 0x7FFF);
        if a.is_empty() { FileAttributes::FILE_ATTRIBUTE_ARCHIVE } else { a }
    }
    #[cfg(not(windows))]
    {
        let mut a = if m.is_dir() { FileAttributes::FILE_ATTRIBUTE_DIRECTORY } else { FileAttributes::FILE_ATTRIBUTE_ARCHIVE };
        if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
            a |= FileAttributes::FILE_ATTRIBUTE_HIDDEN;
        }
        if m.permissions().readonly() {
            a |= FileAttributes::FILE_ATTRIBUTE_READONLY;
        }
        a
    }
}

/// (total, libre) en octets du volume qui contient `path`.
fn disk_space(path: &Path) -> (u64, u64) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        if unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) } != 0 {
            return (total, avail);
        }
    }
    let _ = path;
    (1 << 40, 1 << 39)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside_the_shared_folder() {
        let b = DriveBackend::new(PathBuf::from("base"), Default::default());
        assert_eq!(b.resolve("\\docs\\a.txt"), Some(PathBuf::from("base").join("docs").join("a.txt")));
        assert_eq!(b.resolve(""), Some(PathBuf::from("base")));
        assert_eq!(b.resolve("\\.\\x"), Some(PathBuf::from("base").join("x")));
        assert_eq!(b.resolve("\\..\\secret"), None);
        assert_eq!(b.resolve("\\docs\\..\\..\\x"), None);
        assert_eq!(b.resolve("\\C:\\Windows"), None);
        assert_eq!(b.resolve("\\a.txt:stream"), None);
    }

    fn io(file_id: u32, major: MajorFunction) -> DeviceIoRequest {
        DeviceIoRequest { device_id: DRIVE_ID, file_id, completion_id: 1, major_function: major, minor_function: MinorFunction::IRP_MN_QUERY_DIRECTORY }
    }

    fn create(b: &mut DriveBackend, path: &str, disposition: CreateDisposition, options: CreateOptions) -> Option<u32> {
        let id = b.next_id;
        b.create(DeviceCreateRequest {
            device_io_request: io(0, MajorFunction::Create),
            desired_access: DesiredAccess::FILE_READ_DATA_OR_FILE_LIST_DIRECTORY | DesiredAccess::FILE_WRITE_DATA_OR_FILE_ADD_FILE,
            allocation_size: 0,
            file_attributes: FileAttributes::FILE_ATTRIBUTE_ARCHIVE,
            shared_access: SharedAccess::FILE_SHARE_READ,
            create_disposition: disposition,
            create_options: options,
            path: path.into(),
        });
        b.handles.contains_key(&id).then_some(id)
    }

    #[test]
    fn server_operations_on_the_shared_folder() {
        let root = std::env::temp_dir().join(format!("escale-rdpdr-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let mut b = DriveBackend::new(root.clone(), Default::default());
        let none = CreateOptions::empty();

        // dossier puis fichier créés par le serveur
        let d = create(&mut b, "\\docs", CreateDisposition::FILE_CREATE, CreateOptions::FILE_DIRECTORY_FILE).unwrap();
        assert!(root.join("docs").is_dir());
        let f = create(&mut b, "\\docs\\a.txt", CreateDisposition::FILE_CREATE, CreateOptions::FILE_NON_DIRECTORY_FILE).unwrap();
        b.write(DeviceWriteRequest { device_io_request: io(f, MajorFunction::Write), offset: 0, write_data: b"bonjour".to_vec() });
        b.write(DeviceWriteRequest { device_io_request: io(f, MajorFunction::Write), offset: 3, write_data: b"SOIR".to_vec() });
        assert_eq!(fs::read(root.join("docs").join("a.txt")).unwrap(), b"bonSOIR");
        assert_eq!(read_at(b.file(f).unwrap(), 3, 100).unwrap(), b"SOIR");
        // un fichier existant ne peut pas être « créé » à nouveau
        assert!(create(&mut b, "\\docs\\a.txt", CreateDisposition::FILE_CREATE, none.clone()).is_none());

        // énumération avec motif
        b.query_directory(ServerDriveQueryDirectoryRequest {
            device_io_request: io(d, MajorFunction::DirectoryControl),
            file_info_class_lvl: FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION,
            initial_query: 1,
            path: "\\docs\\*".into(),
        });
        // la première entrée est renvoyée, il n'en reste pas d'autre
        assert!(b.handles[&d].listing.is_empty());

        // renommage (fichier ouvert), puis suppression à la fermeture
        b.set_information(ServerDriveSetInformationRequest {
            device_io_request: io(f, MajorFunction::SetInformation),
            set_buffer: FileInformationClass::Rename(FileRenameInformation { replace_if_exists: Boolean::False, file_name: "\\docs\\b.txt".into() }),
        })
        .unwrap();
        assert!(!root.join("docs").join("a.txt").exists());
        assert_eq!(fs::read(root.join("docs").join("b.txt")).unwrap(), b"bonSOIR");
        b.set_information(ServerDriveSetInformationRequest {
            device_io_request: io(f, MajorFunction::SetInformation),
            set_buffer: FileInformationClass::Disposition(FileDispositionInformation { delete_pending: 1 }),
        })
        .unwrap();
        assert!(root.join("docs").join("b.txt").exists(), "supprimé seulement à la fermeture");
        b.close(DeviceCloseRequest { device_io_request: io(f, MajorFunction::Close) });
        assert!(!root.join("docs").join("b.txt").exists());

        // impossible de sortir du dossier partagé
        assert!(create(&mut b, "\\..\\evasion.txt", CreateDisposition::FILE_OPEN_IF, none.clone()).is_none());
        assert!(!root.parent().unwrap().join("evasion.txt").exists());
        // ouverture d'un fichier absent
        assert!(create(&mut b, "\\absent.txt", CreateDisposition::FILE_OPEN, none).is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_requests_are_refused_without_breaking_the_session() {
        use ironrdp_svc::SvcProcessor as _;
        let backend = DriveBackend::new(PathBuf::from("base"), Default::default());
        let mut ch = SafeRdpdr(ironrdp_rdpdr::Rdpdr::new(Box::new(backend), "PC".into()).with_drives(Some(vec![(DRIVE_ID, DRIVE_NAME.into())])));
        // IRP_MJ_SET_INFORMATION avec une classe inconnue d'IronRDP (FileValidDataLengthInformation = 39)
        let mut irp = vec![0x72, 0x44, 0x52, 0x49];
        for v in [DRIVE_ID, 5, 7, 6, 0, 39, 8] {
            irp.extend_from_slice(&u32::to_le_bytes(v));
        }
        irp.extend_from_slice(&[0; 24]);
        irp.extend_from_slice(&[0; 8]);
        assert!(ch.0.process(&irp).is_err(), "IronRDP seul échoue sur cette requête");
        let out = ch.process(&irp).expect("le canal protégé ne coupe pas la session");
        assert_eq!(out.len(), 1);
        let bytes = out[0].encode_unframed_pdu().unwrap();
        assert_eq!(&bytes[..4], &[0x72, 0x44, 0x43, 0x49]);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 7, "même identifiant de requête");
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 0xC000_00BB);
        // un paquet illisible quelconque est simplement ignoré
        assert!(ch.process(&[1, 2, 3]).unwrap().is_empty());
    }

    #[test]
    fn dos_wildcards() {
        assert!(wildcard("*", "rapport.pdf"));
        assert!(wildcard("*.*", "LISEZMOI"));
        assert!(wildcard("*.PDF", "rapport.pdf"));
        assert!(wildcard("r?pport*", "rapport.pdf"));
        assert!(!wildcard("*.txt", "rapport.pdf"));
        assert!(wildcard("rapport.pdf", "Rapport.PDF"));
    }
}
