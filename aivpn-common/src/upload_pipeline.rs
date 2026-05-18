//! Shared upload pipeline for AIVPN clients.
//!
//! Both the CLI client and Android core use this module to avoid duplicating
//! the biased-select + burst-drain + keepalive upload loop.

use std::future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::client_wire::{build_inner_packet, build_zero_mdh_packet};
use crate::crypto::SessionKeys;
use crate::error::{Error, Result};
use crate::protocol::{ControlPayload, InnerType};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;

// ──────────── Configuration ────────────

/// Tuneable knobs for the upload pipeline shared by all clients.
pub struct UploadConfig {
    /// Maximum additional packets to drain from the channel after the first
    /// recv without yielding back to the async executor.
    pub burst_size: usize,
    /// How often a health keepalive is sent.
    ///
    /// Keepalives are allowed to preempt data once their interval is due so
    /// tunnel liveness checks do not starve behind a saturated upload queue.
    pub keepalive_interval: Duration,
    /// Optional interval for retransmitting the session-init control packet
    /// until the caller marks the server handshake complete.
    pub handshake_retry_interval: Option<Duration>,
    /// Shared completion flag used with `handshake_retry_interval`.
    pub handshake_complete: Option<Arc<AtomicBool>>,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            burst_size: 63,
            keepalive_interval: Duration::from_secs(25),
            handshake_retry_interval: None,
            handshake_complete: None,
        }
    }
}

// ──────────── Trait: pluggable packet encryption ────────────

/// Platform-specific packet encryption and framing.
///
/// The CLI client implements this via its MimicryEngine (variable MDH,
/// traffic-shaped padding, FSM updates). Android implements it via
/// [`ZeroMdhEncryptor`] (fixed zero-length MDH, random padding).
pub trait PacketEncryptor: Send {
    /// Encrypt a TUN data payload into a ready-to-send UDP datagram.
    fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>>;
    /// Encrypt a keepalive control message into a ready-to-send UDP datagram.
    fn encrypt_keepalive(&mut self) -> Result<Vec<u8>>;
    /// Encrypt a handshake retry control message.
    ///
    /// Most clients do not need a distinct packet here. The CLI SOCKS/TUN
    /// client overrides this to include its obfuscated ephemeral public key so
    /// either a lost init packet or a lost ServerHello can be recovered.
    fn encrypt_handshake_retry(&mut self) -> Result<Vec<u8>> {
        self.encrypt_keepalive()
    }
    /// Called after a data datagram has been successfully sent.
    /// Use this for stats tracking, FSM transitions, etc.
    fn on_data_sent(&mut self, payload_len: usize);
}

// ──────────── Ready-made encryptor: zero MDH ────────────

/// Encryptor using `build_zero_mdh_packet` — suitable for Android and any
/// client that does not require Mimicry traffic shaping.
pub struct ZeroMdhEncryptor {
    keys: SessionKeys,
    counter: u64,
    seq: u16,
}

impl ZeroMdhEncryptor {
    pub fn new(keys: SessionKeys, counter: u64, seq: u16) -> Self {
        Self { keys, counter, seq }
    }
}

impl PacketEncryptor for ZeroMdhEncryptor {
    fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let inner = build_inner_packet(InnerType::Data, self.seq, payload);
        self.seq = self.seq.wrapping_add(1);
        build_zero_mdh_packet(&self.keys, &mut self.counter, &inner, None)
    }

    fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
        let keepalive = ControlPayload::Keepalive.encode()?;
        let inner = build_inner_packet(InnerType::Control, self.seq, &keepalive);
        self.seq = self.seq.wrapping_add(1);
        build_zero_mdh_packet(&self.keys, &mut self.counter, &inner, None)
    }

    fn on_data_sent(&mut self, _payload_len: usize) {}
}

// ──────────── The upload loop ────────────

/// Returns true for transient OS-level errors where retrying immediately
/// or just dropping the packet is safer than triggering a full reconnect.
fn is_transient_send_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        NetworkUnreachable | HostUnreachable | NetworkDown | AddrNotAvailable | Interrupted
    )
}

/// Send helper that tolerates transient network errors (e.g. mid-switch on mobile).
/// Returns Ok(()) on success or transient error (logged, packet dropped).
/// Returns Err only on fatal errors (e.g. EBADF = socket closed).
async fn send_tolerant(udp: &UdpSocket, data: &[u8]) -> Result<()> {
    match udp.send(data).await {
        Ok(_) => Ok(()),
        Err(e) if is_transient_send_error(&e) => {
            tracing::debug!("upload: transient send error (dropped packet): {e}");
            Ok(())
        }
        Err(e) => Err(Error::Io(e)),
    }
}

async fn optional_interval_tick(interval: &mut Option<time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => future::pending::<()>().await,
    }
}

/// Run the upload loop: pull TUN packets from `rx`, encrypt via `enc`, send
/// over `udp`. Uses biased `select!` to keep handshake retries and health
/// keepalives from starving behind data, plus a burst-drain after the first
/// recv to amortise per-packet scheduler overhead.
///
/// Returns `Err` on fatal I/O or channel close. Never returns `Ok` — the
/// caller is expected to `.abort()` the task when the session ends.
pub async fn run_upload_loop(
    rx: &mut mpsc::Receiver<Vec<u8>>,
    udp: &Arc<UdpSocket>,
    enc: &mut impl PacketEncryptor,
    config: &UploadConfig,
) -> Result<()> {
    let mut ka_interval = time::interval(config.keepalive_interval);
    let mut handshake_retry_interval = config.handshake_retry_interval.map(time::interval);
    let mut data_packet_count: u64 = 0;
    ka_interval.tick().await; // skip the immediate first tick
    if let Some(interval) = &mut handshake_retry_interval {
        interval.tick().await; // skip the immediate first tick
    }

    loop {
        let should_retry_handshake = handshake_retry_interval.is_some()
            && config
                .handshake_complete
                .as_ref()
                .is_some_and(|complete| !complete.load(Ordering::SeqCst));

        tokio::select! {
            biased;

            // Session-init retry: disabled by default. When enabled, this
            // branch keeps the handshake recoverable if the first UDP init or
            // the first ServerHello is lost. Keep it above data while the
            // handshake is incomplete so a busy TUN queue cannot starve it.
            _ = optional_interval_tick(&mut handshake_retry_interval), if should_retry_handshake => {
                let encrypted = enc.encrypt_handshake_retry()?;
                send_tolerant(udp, &encrypted).await?;
            }

            // Health keepalive. Keep this above data: local SOCKS reconnect
            // heuristics rely on inbound server traffic, and a busy upload
            // queue must not suppress keepalive ACKs indefinitely.
            _ = ka_interval.tick() => {
                let encrypted = if should_retry_handshake {
                    enc.encrypt_handshake_retry()?
                } else {
                    enc.encrypt_keepalive()?
                };
                send_tolerant(udp, &encrypted).await?;
            }

            // ── Data path ──
            maybe_pkt = rx.recv() => {
                let pkt_data = match maybe_pkt {
                    Some(p) => p,
                    None => return Err(Error::Channel("TUN->UDP channel closed".into())),
                };

                let encrypted = enc.encrypt_data(&pkt_data)?;
                send_tolerant(udp, &encrypted).await?;
                data_packet_count = data_packet_count.wrapping_add(1);
                enc.on_data_sent(pkt_data.len());

                // Burst drain: process up to burst_size without yielding
                for _ in 0..config.burst_size {
                    match rx.try_recv() {
                        Ok(pkt) => {
                            let encrypted = enc.encrypt_data(&pkt)?;
                            send_tolerant(udp, &encrypted).await?;
                            data_packet_count = data_packet_count.wrapping_add(1);
                            enc.on_data_sent(pkt.len());
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            return Err(Error::Channel("TUN->UDP channel closed".into()));
                        }
                    }
                }
            }

        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;

    struct SlowDataEncryptor;

    impl PacketEncryptor for SlowDataEncryptor {
        fn encrypt_data(&mut self, _payload: &[u8]) -> Result<Vec<u8>> {
            std::thread::sleep(Duration::from_millis(2));
            Ok(vec![b'D'])
        }

        fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
            Ok(vec![b'K'])
        }

        fn on_data_sent(&mut self, _payload_len: usize) {}
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keepalive_preempts_saturated_data_queue() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .connect(receiver.local_addr().unwrap())
            .await
            .unwrap();
        let sender = Arc::new(sender);

        let (tx, mut rx) = mpsc::channel(1024);
        for _ in 0..1024 {
            tx.send(vec![1]).await.unwrap();
        }

        let mut enc = SlowDataEncryptor;
        let config = UploadConfig {
            burst_size: 0,
            keepalive_interval: Duration::from_millis(5),
            handshake_retry_interval: None,
            handshake_complete: None,
        };
        let task =
            tokio::spawn(async move { run_upload_loop(&mut rx, &sender, &mut enc, &config).await });

        let mut buf = [0u8; 1];
        let saw_keepalive = timeout(Duration::from_millis(250), async {
            loop {
                let n = receiver.recv(&mut buf).await.unwrap();
                if n == 1 && buf[0] == b'K' {
                    break true;
                }
            }
        })
        .await
        .unwrap_or(false);

        task.abort();
        assert!(
            saw_keepalive,
            "keepalive should be sent even while data is continuously ready"
        );
    }
}
