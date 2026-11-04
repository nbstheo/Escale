//! Tests de bout en bout : serveurs SSH russh en mémoire (bastion + cible).

use crate::model::{Auth, Host, Protocol, VaultData};
use crate::ssh::{Cmd, Event};
use crate::vault::Vault;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Pty};
use russh_sftp::protocol::{Attrs, Data, File as SftpFile, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Default)]
struct TestServer {
    password: String,
    key: Option<PublicKey>,
    name: &'static str,
    sessions: Vec<ChannelId>,
    /// Canaux de session en attente d'un shell ou d'un sous-système.
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    /// Système de fichiers du serveur SFTP en mémoire : chemin -> contenu.
    fs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Scripts reçus sur l'entrée standard des commandes `exec` (`sh`).
    scripts: Arc<Mutex<Vec<String>>>,
}

/// Serveur SFTP minimal en mémoire (racine /home/test, fichiers à plat).
struct MemSftp {
    fs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    listed: bool,
}

fn status(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "fr".into() }
}

fn file_attrs(size: u64, dir: bool) -> FileAttributes {
    FileAttributes { size: Some(size), permissions: Some(if dir { 0o40755 } else { 0o100644 }), ..Default::default() }
}

impl russh_sftp::server::Handler for MemSftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _version: u32, _ext: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, _path: String) -> Result<Name, Self::Error> {
        Ok(Name { id, files: vec![SftpFile::dummy("/home/test")] })
    }

    async fn open(&mut self, id: u32, filename: String, flags: OpenFlags, _a: FileAttributes) -> Result<Handle, Self::Error> {
        let mut fs = self.fs.lock().unwrap();
        if flags.contains(OpenFlags::CREATE) || flags.contains(OpenFlags::TRUNCATE) {
            fs.insert(filename.clone(), Vec::new());
        } else if !fs.contains_key(&filename) {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(Handle { id, handle: filename })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        let mut fs = self.fs.lock().unwrap();
        let f = fs.get_mut(&handle).ok_or(StatusCode::NoSuchFile)?;
        let end = offset as usize + data.len();
        if f.len() < end {
            f.resize(end, 0);
        }
        f[offset as usize..end].copy_from_slice(&data);
        Ok(status(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let fs = self.fs.lock().unwrap();
        let f = fs.get(&handle).ok_or(StatusCode::NoSuchFile)?;
        if offset as usize >= f.len() {
            return Err(StatusCode::Eof);
        }
        let end = (offset as usize + len as usize).min(f.len());
        Ok(Data { id, data: f[offset as usize..end].to_vec() })
    }

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
        Ok(status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.listed = false;
        Ok(Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        if self.listed {
            return Err(StatusCode::Eof);
        }
        self.listed = true;
        let prefix = format!("{}/", handle.trim_end_matches('/'));
        let fs = self.fs.lock().unwrap();
        let files = fs
            .iter()
            .filter_map(|(p, d)| p.strip_prefix(&prefix).map(|n| SftpFile::new(n, file_attrs(d.len() as u64, false))))
            .collect();
        Ok(Name { id, files })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let fs = self.fs.lock().unwrap();
        match fs.get(&path) {
            Some(d) => Ok(Attrs { id, attrs: file_attrs(d.len() as u64, false) }),
            None if path == "/home/test" => Ok(Attrs { id, attrs: file_attrs(0, true) }),
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        self.stat(id, handle).await
    }
}

impl server::Server for TestServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
    fn handle_session_error(&mut self, e: <Self::Handler as server::Handler>::Error) {
        eprintln!("[srv {}] erreur session : {e:?}", self.name);
    }
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<server::Auth, Self::Error> {
        Ok(if password == self.password { server::Auth::Accept } else { server::Auth::reject() })
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<server::Auth, Self::Error> {
        let ok = self.key.as_ref().is_some_and(|k| k.key_data() == key.key_data());
        Ok(if ok { server::Auth::Accept } else { server::Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.sessions.push(channel.id());
        self.channels.lock().unwrap().insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        let ch = self.channels.lock().unwrap().remove(&channel);
        match ch {
            Some(ch) if name == "sftp" => {
                // ce canal ne porte plus de shell
                self.sessions.retain(|c| *c != channel);
                session.channel_success(channel)?;
                russh_sftp::server::run(ch.into_stream(), MemSftp { fs: self.fs.clone(), listed: false }).await;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    /// `sh` : lit le script jusqu'à la fin de l'entrée, le garde, puis répond « code 0 ».
    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let ch = self.channels.lock().unwrap().remove(&channel);
        let (Some(mut ch), b"sh") = (ch, command) else { return session.channel_failure(channel) };
        self.sessions.retain(|c| *c != channel);
        session.channel_success(channel)?;
        let scripts = self.scripts.clone();
        tokio::spawn(async move {
            let mut script = Vec::new();
            while let Some(msg) = ch.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => script.extend_from_slice(&data),
                    russh::ChannelMsg::Eof => break,
                    _ => {}
                }
            }
            scripts.lock().unwrap().push(String::from_utf8_lossy(&script).into_owned());
            let _ = ch.exit_status(0).await;
            let _ = ch.eof().await;
            let _ = ch.close().await;
        });
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _oa: &str,
        _op: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let addr = format!("{host}:{port}");
        reply.accept().await;
        tokio::spawn(async move {
            if let Ok(mut tcp) = TcpStream::connect(addr).await {
                                let mut stream = channel.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
            }
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _c: u32,
        _r: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        // le shell répond par `data()` : l'objet canal n'est plus nécessaire
        self.channels.lock().unwrap().remove(&channel);
        session.channel_success(channel)?;
        session.data(channel, format!("WELCOME {}\r\n", self.name).into_bytes())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if !self.sessions.contains(&channel) {
            return Ok(());
        }
        if data == b"exit" {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            return session.close(channel);
        }
        session.data(channel, format!("echo:{}", String::from_utf8_lossy(data)).into_bytes())
    }
}

async fn start(server: TestServer) -> u16 {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut s = server;
    tokio::spawn(async move {
        let running = s.run_on_socket(config, &socket);
        let _ = running.await;
    });
    port
}

struct Run {
    tx: mpsc::UnboundedSender<Cmd>,
    rx: std::sync::mpsc::Receiver<Event>,
    task: tokio::task::JoinHandle<Result<(), String>>,
    fingerprints: Vec<String>,
}

fn launch(chain: Vec<Host>) -> Run {
    let (tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, rx) = std::sync::mpsc::channel();
    let events = crate::ssh::test_events(ev_tx);
    let task = tokio::spawn(crate::ssh::run_for_test(chain, 80, 24, cmd_rx, events));
    Run { tx, rx, task, fingerprints: Vec::new() }
}

impl Run {
    /// Attend un texte dans la sortie (en acceptant les clés serveur).
    async fn expect_output(&mut self, needle: &str) -> String {
        let mut all = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            while let Ok(ev) = self.rx.try_recv() {
                match ev {
                    Event::Output(d) => all.push_str(&String::from_utf8_lossy(&d)),
                    Event::VerifyHostKey { fingerprint, reply, .. } => {
                        self.fingerprints.push(fingerprint);
                        let _ = reply.send(true);
                    }
                    Event::Closed(e) => panic!("session fermée : {e:?} / sortie : {all}"),
                    Event::Status(s) => all.push_str(&format!("[{s}]")),
                    _ => {}
                }
            }
            if all.contains(needle) {
                return all;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("'{needle}' non reçu, fps={} sortie : {all}", self.fingerprints.len());
    }

    async fn finish(mut self) -> Result<(), String> {
        let task = &mut self.task;
        loop {
            while let Ok(ev) = self.rx.try_recv() {
                if let Event::VerifyHostKey { reply, .. } = ev {
                    let _ = reply.send(true);
                }
            }
            if task.is_finished() {
                return task.await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn host(name: &str, port: u16) -> Host {
    let mut h = Host::default();
    h.label = name.into();
    h.hostname = "127.0.0.1".into();
    h.port = port;
    h.username = "test".into();
    h
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_password() {
    let port = start(TestServer { password: "secret".into(), key: None, name: "solo", sessions: vec![], ..Default::default() }).await;
    let mut h = host("solo", port);
    h.password = "secret".into();
    let mut run = launch(vec![h]);
    run.expect_output("WELCOME solo").await;
    run.tx.send(Cmd::Data(b"hello".to_vec())).unwrap();
    run.expect_output("echo:hello").await;
    assert_eq!(run.fingerprints.len(), 1);
    assert!(run.fingerprints[0].starts_with("SHA256:"));
    run.tx.send(Cmd::Data(b"exit".to_vec())).unwrap();
    assert_eq!(run.finish().await, Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_is_rejected() {
    let port = start(TestServer { password: "secret".into(), key: None, name: "solo", sessions: vec![], ..Default::default() }).await;
    let mut h = host("solo", port);
    h.password = "nope".into();
    let err = launch(vec![h]).finish().await.unwrap_err();
    assert!(err.contains("Authentification refusée"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jump_chain_with_key() {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap().to_string();

    let bastion1 = start(TestServer { password: "b1".into(), key: None, name: "bastion1", sessions: vec![], ..Default::default() }).await;
    let bastion2 = start(TestServer { password: "b2".into(), key: None, name: "bastion2", sessions: vec![], ..Default::default() }).await;
    let target = start(TestServer { password: String::new(), key: Some(key.public_key().clone()), name: "cible", sessions: vec![], ..Default::default() }).await;

    let mut b1 = host("b1", bastion1);
    b1.password = "b1".into();
    let mut b2 = host("b2", bastion2);
    b2.password = "b2".into();
    b2.jump = Some(b1.id);
    let mut t = host("cible", target);
    t.auth = Auth::Key;
    t.private_key = pem;
    t.jump = Some(b2.id);

    let data = VaultData { hosts: vec![t.clone(), b1.clone(), b2.clone()], ..Default::default() };
    let chain = data.chain(t.id).unwrap();
    assert_eq!(chain.iter().map(|h| h.label.as_str()).collect::<Vec<_>>(), ["b1", "b2", "cible"]);

    let mut run = launch(chain);
    run.expect_output("WELCOME cible").await;
    run.tx.send(Cmd::Data(b"via-jump".to_vec())).unwrap();
    run.expect_output("echo:via-jump").await;
    assert_eq!(run.fingerprints.len(), 3, "une vérification de clé par saut");
    run.tx.send(Cmd::Close).unwrap();
    assert_eq!(run.finish().await, Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_key_skips_prompt_and_rejection_aborts() {
    let port = start(TestServer { password: "pw".into(), key: None, name: "k", sessions: vec![], ..Default::default() }).await;
    let mut h = host("k", port);
    h.password = "pw".into();

    // 1re connexion : on récupère l'empreinte
    let mut run = launch(vec![h.clone()]);
    run.expect_output("WELCOME k").await;
    let fp = run.fingerprints[0].clone();
    run.tx.send(Cmd::Close).unwrap();
    run.finish().await.unwrap();

    // empreinte connue : aucune demande
    h.known_key = Some(fp);
    let mut run = launch(vec![h.clone()]);
    run.expect_output("WELCOME k").await;
    assert!(run.fingerprints.is_empty());
    run.tx.send(Cmd::Close).unwrap();
    run.finish().await.unwrap();

    // empreinte différente + refus de l'utilisateur : connexion annulée
    h.known_key = Some("SHA256:autre".into());
    let (tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (ev_tx, rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(crate::ssh::run_for_test(vec![h], 80, 24, cmd_rx, crate::ssh::test_events(ev_tx)));
    let mut previous = None;
    loop {
        if let Ok(Event::VerifyHostKey { previous: p, reply, .. }) = rx.try_recv() {
            previous = p;
            let _ = reply.send(false);
        }
        if task.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(tx);
    assert_eq!(previous.as_deref(), Some("SHA256:autre"));
    let err = task.await.unwrap().unwrap_err();
    assert!(err.contains("Clé serveur refusée"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_upload_list_download_over_the_session() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let server = TestServer { password: "pw".into(), name: "fichiers", ..Default::default() };
    let fs = server.fs.clone();
    let port = start(server).await;
    let mut h = host("fichiers", port);
    h.password = "pw".into();
    let mut run = launch(vec![h]);
    run.expect_output("WELCOME fichiers").await;

    // SFTP ouvert sur la connexion du terminal, sans nouvelle authentification
    let (reply, opening) = oneshot::channel();
    run.tx.send(Cmd::OpenSftp(reply)).unwrap();
    let sftp = tokio::time::timeout(Duration::from_secs(10), opening).await.unwrap().unwrap().unwrap();
    assert_eq!(sftp.canonicalize(".").await.unwrap(), "/home/test");

    // plusieurs blocs de 256 Kio
    let dir = std::env::temp_dir().join(format!("escale-sftp-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let local = dir.join("rapport.bin");
    let content: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&local, &content).unwrap();
    let done = AtomicU64::new(0);
    crate::files::sftp_upload(&sftp, &local, "/home/test/rapport.bin", &done).await.unwrap();
    assert_eq!(done.load(Ordering::Relaxed), content.len() as u64);
    assert_eq!(fs.lock().unwrap().get("/home/test/rapport.bin"), Some(&content));

    let list = crate::files::sftp_list(&sftp, "/home/test", None, None).await.unwrap();
    assert!(list.iter().any(|e| e.name == "rapport.bin" && e.size == content.len() as u64 && !e.dir));

    let back = dir.join("retour.bin");
    crate::files::sftp_download(&sftp, "/home/test/rapport.bin", &back, &AtomicU64::new(0)).await.unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), content);
    let _ = std::fs::remove_dir_all(&dir);

    // le terminal continue de fonctionner à côté
    run.tx.send(Cmd::Data(b"encore".to_vec())).unwrap();
    run.expect_output("echo:encore").await;
    run.tx.send(Cmd::Close).unwrap();
    assert_eq!(run.finish().await, Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graphical_target_is_reached_through_an_ssh_jump() {
    // service TCP quelconque (serveur RDP / VNC simulé) : renvoie ce qu'il reçoit en majuscules
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let svc_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b.to_ascii_uppercase()).await.unwrap();
        }
    });
    let bastion = start(TestServer { password: "b".into(), name: "bastion", ..Default::default() }).await;
    let mut b = host("bastion", bastion);
    b.password = "b".into();
    let mut t = host("bureau", svc_port);
    t.protocol = Protocol::Rdp;
    t.jump = Some(b.id);
    let data = VaultData { hosts: vec![b.clone(), t.clone()], ..Default::default() };
    let chain = data.chain(t.id).unwrap();

    let (ev_tx, rx) = std::sync::mpsc::channel();
    let events = crate::ssh::test_events(ev_tx);
    let accept = tokio::spawn(async move {
        loop {
            match rx.try_recv() {
                Ok(Event::VerifyHostKey { reply, .. }) => {
                    let _ = reply.send(true);
                    return;
                }
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    });
    let (mut stream, jumps) = crate::ssh::open_stream(&chain, &events).await.unwrap();
    accept.await.unwrap();
    assert_eq!(jumps.len(), 1, "seul le bastion est une connexion SSH");
    stream.write_all(b"hello").await.unwrap();
    let mut out = [0u8; 5];
    stream.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, b"HELLO");
    crate::ssh::disconnect(&jumps).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jump_key_accepted_once_is_not_asked_again_on_reconnect() {
    // reconnexion RDP à travers un rebond : la clé acceptée à la première connexion est retenue
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let svc_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let bastion = start(TestServer { password: "b".into(), name: "bastion", ..Default::default() }).await;
    let mut b = host("bastion", bastion);
    b.password = "b".into();
    let mut t = host("bureau", svc_port);
    t.protocol = Protocol::Rdp;
    t.jump = Some(b.id);
    let data = VaultData { hosts: vec![b.clone(), t.clone()], ..Default::default() };
    let mut chain = data.chain(t.id).unwrap();

    let (ev_tx, rx) = std::sync::mpsc::channel();
    let events = crate::ssh::test_events(ev_tx);
    let prompts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let p = prompts.clone();
    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            if let Event::VerifyHostKey { reply, .. } = ev {
                p.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = reply.send(true);
            }
        }
    });
    for _ in 0..2 {
        let (_stream, jumps) = crate::ssh::open_stream_learning(&mut chain, &events).await.unwrap();
        crate::ssh::disconnect(&jumps).await;
    }
    assert_eq!(prompts.load(std::sync::atomic::Ordering::SeqCst), 1, "clé du rebond demandée une seule fois");
    assert!(chain[0].known_key.as_deref().is_some_and(|k| k.starts_with("SHA256:")));
}

#[test]
fn jumps_must_be_ssh_and_old_vaults_still_load() {
    let mut rdp = host("rdp", 3389);
    rdp.protocol = Protocol::Rdp;
    let mut t = host("t", 22);
    t.jump = Some(rdp.id);
    let data = VaultData { hosts: vec![rdp.clone(), t.clone()], ..Default::default() };
    assert!(data.chain(t.id).err().unwrap().contains("n'est pas un hôte SSH"));
    // une cible graphique seule est valide
    assert_eq!(data.chain(rdp.id).unwrap().len(), 1);

    // hôte enregistré avant l'arrivée de RDP / VNC
    let json = r#"{"id":"67e55044-10b1-426f-9247-bb680e5fe0c8","label":"x","hostname":"h","port":22,"username":"u"}"#;
    let old: Host = serde_json::from_str(json).unwrap();
    assert_eq!(old.protocol, Protocol::Ssh);
    assert!(old.domain.is_empty());

    rdp.hostname = "srv".into();
    rdp.username = "admin".into();
    rdp.domain = "CORP".into();
    assert_eq!(rdp.address(), "CORP\\admin@srv");
    let mut vnc = host("vnc", 5901);
    vnc.protocol = Protocol::Vnc;
    assert_eq!(vnc.address(), "127.0.0.1:5901");
}

#[test]
fn chain_detects_cycles() {
    let mut a = host("a", 1);
    let mut b = host("b", 2);
    a.jump = Some(b.id);
    b.jump = Some(a.id);
    let data = VaultData { hosts: vec![a.clone(), b], ..Default::default() };
    assert!(data.chain(a.id).is_err());
}

#[test]
fn recent_hosts_history() {
    let hosts: Vec<Host> = (0..10).map(|i| host(&format!("h{i}"), 1)).collect();
    let ids: Vec<_> = hosts.iter().map(|h| h.id).collect();
    let mut data = VaultData { hosts, ..Default::default() };
    data.touch_recent(ids[0]);
    data.touch_recent(ids[1]);
    data.touch_recent(ids[0]);
    assert_eq!(data.recent, [ids[0], ids[1]], "le plus récent en tête, sans doublon");
    for id in &ids {
        data.touch_recent(*id);
    }
    assert_eq!(data.recent.len(), crate::model::RECENT_MAX);
    assert_eq!(data.recent[0], ids[9]);
    // hôte supprimé : retiré de l'historique au passage suivant
    data.hosts.retain(|h| h.id != ids[8]);
    data.touch_recent(ids[0]);
    assert!(!data.recent.contains(&ids[8]));
    // coffre enregistré avant l'historique
    let old: VaultData = serde_json::from_str(r#"{"hosts":[]}"#).unwrap();
    assert!(old.recent.is_empty());
}

#[test]
fn vault_roundtrip_and_wrong_password() {
    let dir = std::env::temp_dir().join(format!("escale-test-{}", uuid::Uuid::new_v4()));
    let path = dir.join("vault.escale");
    let vault = Vault::create_at(path.clone(), "maître-correct").unwrap();
    let mut h = host("srv", 22);
    h.password = "TOPSECRET-pw".into();
    let data = VaultData { hosts: vec![h], ..Default::default() };
    vault.save(&data).unwrap();

    let raw = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("TOPSECRET"), "données en clair dans le fichier !");
    assert!(Vault::open_at(path.clone(), "mauvais").is_err());
    let (_, back) = Vault::open_at(path.clone(), "maître-correct").unwrap();
    assert_eq!(back.hosts[0].password, "TOPSECRET-pw");

    // altération d'un octet -> rejet
    let mut bad = raw.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    std::fs::write(&path, bad).unwrap();
    assert!(Vault::open_at(path.clone(), "maître-correct").is_err());
    let _ = std::fs::remove_dir_all(dir);
}


#[test]
fn pin_single_attempt_then_master_password() {
    use crate::pin::{self, PinError};
    let dir = std::env::temp_dir().join(format!("escale-pin-{}", uuid::Uuid::new_v4()));
    let path = dir.join("vault.escale");
    let vault = Vault::create_at(path.clone(), "maître-correct").unwrap();
    let mut data = VaultData::default();
    data.pin = Some("482913".into());
    vault.save(&data).unwrap();

    assert!(pin::enable(&vault, "12345").is_err(), "5 chiffres refusés");
    assert!(pin::enable(&vault, "12a456").is_err(), "lettres refusées");
    pin::enable(&vault, "482913").unwrap();
    assert!(pin::is_enabled(&path));

    // bon PIN : ouvre le coffre et reste actif
    let (_, back) = pin::unlock(path.clone(), "482913").ok().expect("PIN correct");
    assert_eq!(back.pin.as_deref(), Some("482913"));
    assert!(pin::is_enabled(&path));

    // mauvais PIN : refusé et désactivé immédiatement
    assert!(matches!(pin::unlock(path.clone(), "000000"), Err(PinError::Wrong)));
    assert!(!pin::is_enabled(&path));
    // même le bon PIN ne marche plus
    assert!(matches!(pin::unlock(path.clone(), "482913"), Err(PinError::Unavailable(_))));

    // mot de passe maître -> réactivation avec le PIN conservé dans le coffre
    let (v, d) = Vault::open_at(path.clone(), "maître-correct").unwrap();
    pin::enable(&v, d.pin.as_deref().unwrap()).unwrap();
    assert!(pin::unlock(path.clone(), "482913").is_ok());

    // le fichier PIN ne contient pas la clé en clair et n'est pas lisible tel quel
    let raw = std::fs::read(pin::pin_path(&path)).unwrap();
    assert!(!raw.windows(8).any(|w| w == b"ESCPIN01"), "fichier PIN non protégé par DPAPI");

    // changement de mot de passe : l'ancien fichier PIN ne doit plus ouvrir le coffre
    let mut v = v;
    v.change_password("nouveau-maître", &d).unwrap();
    assert!(pin::unlock(path.clone(), "482913").is_err());
    pin::enable(&v, "482913").unwrap();
    assert!(pin::unlock(path.clone(), "482913").is_ok());
    let _ = std::fs::remove_dir_all(dir);
}




#[test]
fn pin_bound_to_its_own_vault() {
    use crate::pin::{self, PinError};
    let dir = std::env::temp_dir().join(format!("escale-multi-{}", uuid::Uuid::new_v4()));
    let (a, b) = (dir.join("Coffre1").join("vault.escale"), dir.join("Coffre2").join("vault.escale"));
    let va = Vault::create_at(a.clone(), "maître-a").unwrap();
    let vb = Vault::create_at(b.clone(), "maître-b").unwrap();
    pin::enable(&va, "111111").unwrap();
    pin::enable(&vb, "222222").unwrap();

    // le PIN du coffre B, même correct pour B, n'ouvre pas le coffre A
    assert!(matches!(pin::unlock(a.clone(), "222222"), Err(PinError::Wrong)));
    pin::enable(&va, "111111").unwrap();

    // fichier PIN de A copié à la place de celui de B : refusé (lié à l'en-tête du coffre A)
    std::fs::copy(pin::pin_path(&a), pin::pin_path(&b)).unwrap();
    assert!(pin::unlock(b.clone(), "111111").is_err());
    // chaque coffre reste ouvrable avec son propre PIN
    assert!(pin::unlock(a.clone(), "111111").is_ok());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_installed_through_the_session_then_used_to_connect() {
    let server = TestServer { password: "pw".into(), name: "mdp", ..Default::default() };
    let scripts = server.scripts.clone();
    let port = start(server).await;
    let mut h = host("mdp", port);
    h.password = "pw".into();
    let mut run = launch(vec![h]);
    run.expect_output("WELCOME mdp").await;

    // clé ajoutée par un canal à part
    let (private, public) = crate::ssh::generate_key().unwrap();
    assert!(public.starts_with("ssh-ed25519 "), "{public}");
    let (reply, done) = oneshot::channel();
    run.tx.send(Cmd::InstallKey(public.clone(), reply)).unwrap();
    let r = tokio::time::timeout(Duration::from_secs(10), done).await.unwrap().unwrap();
    assert_eq!(r, Ok(()));
    let script = scripts.lock().unwrap().pop().unwrap();
    assert!(script.contains(&format!("printf '%s\\n' '{public}' >> \"$f\"")), "{script}");
    // le terminal reste utilisable
    run.tx.send(Cmd::Data(b"apres".to_vec())).unwrap();
    run.expect_output("echo:apres").await;
    run.tx.send(Cmd::Close).unwrap();
    run.finish().await.unwrap();

    // serveur qui n'accepte que cette clé : l'hôte en mode clé (mot de passe faux) s'y connecte
    let pk = PublicKey::from_openssh(&public).unwrap();
    let port = start(TestServer { password: "autre".into(), key: Some(pk), name: "cle", ..Default::default() }).await;
    let mut h = host("cle", port);
    h.auth = Auth::Key;
    h.private_key = private.to_string();
    h.password = "pw".into();
    let mut run = launch(vec![h]);
    run.expect_output("WELCOME cle").await;
    run.tx.send(Cmd::Close).unwrap();
    run.finish().await.unwrap();
}

/// Profil VPN vers un serveur WireGuard de test qui relaie `10.66.0.1:22` vers `forward`.
async fn vpn_to(forward: u16) -> crate::model::VpnProfile {
    let (sk, ck) = (crate::vpn::generate_private_key(), crate::vpn::generate_private_key());
    let fwd = std::net::SocketAddr::from(([127, 0, 0, 1], forward));
    let port = crate::vpn::test_server(&sk, &crate::vpn::public_key(&ck).unwrap(), "10.66.0.1/24", 22, fwd).await;
    let mut p = crate::model::VpnProfile::default();
    p.name = "Client A".into();
    p.wireguard.private_key = ck;
    p.wireguard.address = "10.66.0.2/32".into();
    p.wireguard.peer_public_key = crate::vpn::public_key(&sk).unwrap();
    p.wireguard.endpoint = format!("127.0.0.1:{port}");
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vpn_then_jump_then_target() {
    // VPN → bastion (joint à son adresse dans le VPN) → cible SSH derrière le bastion
    let bastion = start(TestServer { password: "b".into(), name: "bastion", ..Default::default() }).await;
    let target = start(TestServer { password: "t".into(), name: "cible", ..Default::default() }).await;
    let vpn = vpn_to(bastion).await;
    let mut b = host("bastion", 22);
    b.hostname = "10.66.0.1".into();
    b.password = "b".into();
    let mut t = host("cible", target);
    t.password = "t".into();
    t.jump = Some(b.id);
    // le VPN est choisi sur la cible : il sert à la première connexion, celle du bastion
    t.vpn = Some(vpn.id);
    let data = VaultData { hosts: vec![b.clone(), t.clone()], vpns: vec![vpn.clone()], ..Default::default() };
    let chain = data.chain(t.id).unwrap();
    assert_eq!(chain[0].route_vpn.as_ref().map(|v| v.id), Some(vpn.id));
    assert!(chain[1].route_vpn.is_none());

    let mut run = launch(chain);
    let out = run.expect_output("WELCOME cible").await;
    assert!(out.contains("via le VPN « Client A »"), "{out}");
    run.tx.send(Cmd::Data(b"vpn".to_vec())).unwrap();
    run.expect_output("echo:vpn").await;
    run.tx.send(Cmd::Close).unwrap();
    assert_eq!(run.finish().await, Ok(()));

    // hôte seul derrière le VPN
    let mut solo = b.clone();
    solo.vpn = Some(vpn.id);
    let data = VaultData { hosts: vec![solo.clone()], vpns: vec![vpn.clone()], ..Default::default() };
    let mut run = launch(data.chain(solo.id).unwrap());
    run.expect_output("WELCOME bastion").await;
    run.tx.send(Cmd::Close).unwrap();
    assert_eq!(run.finish().await, Ok(()));
}

#[test]
fn one_vpn_per_chain_and_old_vaults_load() {
    let (v1, v2) = (crate::model::VpnProfile::default(), crate::model::VpnProfile::default());
    let mut b = host("b", 22);
    b.vpn = Some(v1.id);
    let mut t = host("t", 22);
    t.jump = Some(b.id);
    t.vpn = Some(v2.id);
    let mut data = VaultData { hosts: vec![b.clone(), t.clone()], vpns: vec![v1.clone(), v2.clone()], ..Default::default() };
    assert!(data.chain(t.id).err().unwrap().contains("un seul VPN"));
    // même VPN des deux côtés : accepté
    data.hosts[1].vpn = Some(v1.id);
    assert!(data.chain(t.id).is_ok());
    // profil supprimé
    data.vpns.clear();
    assert!(data.chain(t.id).err().unwrap().contains("VPN introuvable"));

    // coffre d'avant les VPN ; profil sérialisé sans les champs facultatifs
    let old: VaultData = serde_json::from_str(r#"{"hosts":[]}"#).unwrap();
    assert!(old.vpns.is_empty());
    let json = r#"{"id":"67e55044-10b1-426f-9247-bb680e5fe0c8","name":"x"}"#;
    let p: crate::model::VpnProfile = serde_json::from_str(json).unwrap();
    assert_eq!(p.kind, crate::model::VpnKind::WireGuard);
    // le profil résolu n'est jamais écrit dans le coffre
    let mut h = host("h", 22);
    h.route_vpn = Some(Arc::new(v1));
    assert!(!serde_json::to_string(&h).unwrap().contains("route_vpn"));
}

mod openvpn;
