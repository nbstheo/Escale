//! Mesures réseau d'une session, affichées à côté de la session (colonne de droite, barre flottante) :
//! octets échangés sur la connexion (débits reçu / envoyé) et latence vers l'hôte.
//! - Débits : le flux de la première connexion (TCP direct ou VPN) est enveloppé dans `Counted`.
//! - Latence : ping SSH quand la session en a un (`ping_loop`), sinon le temps d'aller-retour mesuré
//!   par la pile TCP de Windows sur la connexion elle-même (`watch_tcp`, aucun trafic ajouté).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

/// Intervalle entre deux pings SSH, et délai au-delà duquel l'hôte est dit sans réponse.
const PING_EVERY: Duration = Duration::from_secs(3);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Valeur de `ping_us` quand le dernier ping est resté sans réponse (0 = pas encore de mesure).
const LOST: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Latency {
    /// Pas (encore) de mesure : connexion par VPN sans SSH, première seconde d'une session.
    Unknown,
    Ms(u32),
    /// Le dernier ping est resté sans réponse.
    Lost,
}

/// Compteurs d'une session, partagés entre sa tâche réseau et l'interface.
#[derive(Default)]
pub struct NetStats {
    rx: AtomicU64,
    tx: AtomicU64,
    /// Dernier ping SSH en microsecondes (0 : aucun, `LOST` : sans réponse).
    ping_us: AtomicU32,
    /// Aller-retour mesuré par TCP en microsecondes (0 : inconnu).
    tcp_us: AtomicU32,
    meter: Mutex<Meter>,
}

/// Débits lissés sur une seconde, recalculés à la demande de l'interface.
#[derive(Default)]
struct Meter {
    at: Option<Instant>,
    rx: u64,
    tx: u64,
    down: f64,
    up: f64,
}

impl NetStats {
    fn set_ping(&self, rtt: Option<Duration>) {
        let us = match rtt {
            Some(d) => (d.as_micros().min((LOST - 1) as u128) as u32).max(1),
            None => LOST,
        };
        self.ping_us.store(us, Relaxed);
    }

    /// Latence à afficher : le ping SSH s'il existe (il détecte aussi une liaison muette), sinon TCP.
    pub fn latency(&self) -> Latency {
        let ms = |us: u32| Latency::Ms(us.div_ceil(1000));
        match (self.ping_us.load(Relaxed), self.tcp_us.load(Relaxed)) {
            (LOST, _) => Latency::Lost,
            (0, 0) => Latency::Unknown,
            (0, tcp) => ms(tcp),
            (ping, _) => ms(ping),
        }
    }

    /// Débits (reçu, envoyé) en octets par seconde, mis à jour une fois par seconde.
    pub fn rates(&self) -> (f64, f64) {
        self.rates_at(Instant::now())
    }

    fn rates_at(&self, now: Instant) -> (f64, f64) {
        let (rx, tx) = (self.rx.load(Relaxed), self.tx.load(Relaxed));
        let Ok(mut m) = self.meter.lock() else { return (0.0, 0.0) };
        match m.at {
            None => (m.at, m.rx, m.tx) = (Some(now), rx, tx),
            Some(at) => {
                let dt = now.saturating_duration_since(at).as_secs_f64();
                if dt >= 1.0 {
                    m.down = rx.saturating_sub(m.rx) as f64 / dt;
                    m.up = tx.saturating_sub(m.tx) as f64 / dt;
                    (m.at, m.rx, m.tx) = (Some(now), rx, tx);
                }
            }
        }
        (m.down, m.up)
    }
}

/// « 840 o/s », « 1,2 ko/s », « 12 Mo/s ».
pub fn fmt_rate(bps: f64) -> String {
    let f = |v: f64| if v < 10.0 { format!("{v:.1}").replace('.', ",") } else { format!("{v:.0}") };
    if bps < 1000.0 {
        format!("{bps:.0} o/s")
    } else if bps < 1e6 {
        format!("{} ko/s", f(bps / 1e3))
    } else {
        format!("{} Mo/s", f(bps / 1e6))
    }
}

/// Flux qui compte les octets lus et écrits. `_watch` arrête la mesure TCP associée quand le flux est fermé.
pub struct Counted<S> {
    inner: S,
    stats: Arc<NetStats>,
    _watch: Option<oneshot::Sender<()>>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, stats: Arc<NetStats>, watch: Option<oneshot::Sender<()>>) -> Self {
        Self { inner, stats, _watch: watch }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            self.stats.rx.fetch_add((buf.filled().len() - before) as u64, Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            self.stats.tx.fetch_add(*n as u64, Relaxed);
        }
        r
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            self.stats.tx.fetch_add(*n as u64, Relaxed);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Ping périodique d'une session SSH : `ping` renvoie faux quand la connexion est fermée (la mesure
/// s'arrête alors, sans jamais terminer : à utiliser comme branche d'un `select!`).
pub async fn ping_loop<F, Fut>(stats: &NetStats, ping: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    ping_loop_every(stats, PING_EVERY, PING_TIMEOUT, ping).await
}

async fn ping_loop_every<F, Fut>(stats: &NetStats, every: Duration, timeout: Duration, mut ping: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    loop {
        tokio::time::sleep(every).await;
        let sent = Instant::now();
        match tokio::time::timeout(timeout, ping()).await {
            Ok(true) => stats.set_ping(Some(sent.elapsed())),
            Ok(false) => std::future::pending::<()>().await,
            Err(_) => stats.set_ping(None),
        }
    }
}

/// Relève chaque seconde l'aller-retour mesuré par TCP sur `tcp`, jusqu'à ce que l'émetteur renvoyé
/// soit lâché (fermeture du flux). `None` si la socket ne peut pas être dupliquée.
pub fn watch_tcp(tcp: &tokio::net::TcpStream, stats: &Arc<NetStats>) -> Option<oneshot::Sender<()>> {
    // copie du descripteur : la relève ne dépend pas de qui détient le flux, et se ferme avec lui
    let dup = socket2::SockRef::from(tcp).try_clone().ok()?;
    let (stop, mut stopped) = oneshot::channel::<()>();
    let stats = stats.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                _ = tick.tick() => {
                    if let Some(us) = tcp_rtt(&dup) {
                        stats.tcp_us.store(us.max(1), Relaxed);
                    }
                }
            }
        }
        stats.tcp_us.store(0, Relaxed);
    });
    Some(stop)
}

/// Temps d'aller-retour lissé de la connexion, en microsecondes (`SIO_TCP_INFO`, Windows 10 1703+).
#[cfg(windows)]
fn tcp_rtt(s: &socket2::Socket) -> Option<u32> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_TCP_INFO, TCP_INFO_v0, WSAIoctl};
    let version = 0u32;
    let mut got = 0u32;
    // SAFETY : tampons locaux aux tailles annoncées ; la socket reste ouverte tant que `s` vit.
    let (rc, info) = unsafe {
        let mut info: TCP_INFO_v0 = std::mem::zeroed();
        let rc = WSAIoctl(
            s.as_raw_socket() as _,
            SIO_TCP_INFO,
            (&raw const version).cast(),
            size_of::<u32>() as u32,
            (&raw mut info).cast(),
            size_of::<TCP_INFO_v0>() as u32,
            &mut got,
            std::ptr::null_mut(),
            None,
        );
        (rc, info)
    };
    (rc == 0 && info.RttUs > 0).then_some(info.RttUs)
}

#[cfg(not(windows))]
fn tcp_rtt(_: &socket2::Socket) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn rates_are_formatted_in_french_units() {
        assert_eq!(fmt_rate(0.0), "0 o/s");
        assert_eq!(fmt_rate(840.4), "840 o/s");
        assert_eq!(fmt_rate(1234.0), "1,2 ko/s");
        assert_eq!(fmt_rate(84_000.0), "84 ko/s");
        assert_eq!(fmt_rate(2_500_000.0), "2,5 Mo/s");
        assert_eq!(fmt_rate(12_000_000.0), "12 Mo/s");
    }

    #[test]
    fn latency_prefers_the_ssh_ping_and_reports_a_silent_link() {
        let s = NetStats::default();
        assert_eq!(s.latency(), Latency::Unknown);
        s.tcp_us.store(23_400, Relaxed);
        assert_eq!(s.latency(), Latency::Ms(24));
        s.set_ping(Some(Duration::from_micros(41_000)));
        assert_eq!(s.latency(), Latency::Ms(41));
        s.set_ping(Some(Duration::ZERO));
        assert_eq!(s.latency(), Latency::Ms(1));
        s.set_ping(None);
        assert_eq!(s.latency(), Latency::Lost);
    }

    #[test]
    fn rates_are_averaged_over_at_least_a_second() {
        let s = NetStats::default();
        let t0 = Instant::now();
        assert_eq!(s.rates_at(t0), (0.0, 0.0));
        s.rx.fetch_add(3000, Relaxed);
        s.tx.fetch_add(500, Relaxed);
        // moins d'une seconde : la valeur affichée ne bouge pas
        assert_eq!(s.rates_at(t0 + Duration::from_millis(400)), (0.0, 0.0));
        assert_eq!(s.rates_at(t0 + Duration::from_secs(2)), (1500.0, 250.0));
        assert_eq!(s.rates_at(t0 + Duration::from_secs(3)), (0.0, 0.0));
    }

    #[tokio::test]
    async fn counted_stream_counts_both_directions() {
        let stats = Arc::new(NetStats::default());
        let (a, mut b) = tokio::io::duplex(1024);
        let mut a = Counted::new(a, stats.clone(), None);
        a.write_all(b"bonjour").await.unwrap();
        let mut buf = [0u8; 7];
        b.read_exact(&mut buf).await.unwrap();
        b.write_all(b"ok").await.unwrap();
        let mut buf = [0u8; 2];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!((stats.rx.load(Relaxed), stats.tx.load(Relaxed)), (2, 7));
    }

    #[tokio::test]
    async fn tcp_round_trip_time_is_read_from_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            while s.read_exact(&mut buf).await.is_ok() {
                s.write_all(&buf).await.unwrap();
            }
        });
        let stats = Arc::new(NetStats::default());
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let watch = watch_tcp(&tcp, &stats);
        assert!(watch.is_some());
        let mut c = Counted::new(tcp, stats.clone(), watch);
        for _ in 0..3 {
            c.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            c.read_exact(&mut buf).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(matches!(stats.latency(), Latency::Ms(_)), "{:?}", stats.latency());
        // flux fermé : la relève s'arrête et la mesure est effacée
        drop(c);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(stats.latency(), Latency::Unknown);
        server.abort();
    }

    #[tokio::test]
    async fn ping_loop_measures_then_reports_a_lost_link() {
        // 2e ping sans réponse : « sans réponse » après le délai, puis la mesure reprend
        let (every, timeout) = (Duration::from_millis(40), Duration::from_millis(120));
        let stats = NetStats::default();
        let n = std::cell::Cell::new(0);
        let pings = ping_loop_every(&stats, every, timeout, || {
            n.set(n.get() + 1);
            let k = n.get();
            async move {
                if k == 2 {
                    std::future::pending::<()>().await;
                }
                true
            }
        });
        tokio::pin!(pings);
        let step = Duration::from_millis(5);
        let wait_for = async |want: fn(Latency) -> bool, pings: &mut Pin<&mut _>| {
            for _ in 0..400 {
                if want(stats.latency()) {
                    return true;
                }
                let _ = tokio::time::timeout(step, &mut *pings).await;
            }
            false
        };
        assert!(wait_for(|l| matches!(l, Latency::Ms(_)), &mut pings).await);
        assert!(wait_for(|l| l == Latency::Lost, &mut pings).await);
        assert!(wait_for(|l| matches!(l, Latency::Ms(_)), &mut pings).await);
    }
}
