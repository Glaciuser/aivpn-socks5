# AIVPN

Traditional VPNs are dead. ISPs and state-level firewalls (like GFW) detect WireGuard and OpenVPN in milliseconds just by looking at packet sizes, timing intervals, and handshake patterns. You can encrypt your payload with whatever cipher you want — DPI systems don't care about the content, they block the *shape* of the connection itself.

**AIVPN** is my answer to modern deep packet inspection. We don't just encrypt packets — we disguise them as real application traffic. Your ISP sees a Zoom call or TikTok scrolling, when in reality it's a fully encrypted tunnel.

## Supported Platforms

| Platform | Server | Client | Full Tunnel | Notes |
|----------|--------|--------|-------------|-------|
| **Linux** | ✅ | ✅ | ✅ | Primary platform, TUN via `/dev/net/tun` |
| **macOS** | — | ✅ | ✅ | Via `utun` kernel interface, auto route config |
| **Windows** | — | ✅ | ✅ | Via [Wintun](https://www.wintun.net/) driver |

## The Main Feature: Neural Resonance (AI)

The most interesting thing under the hood is our AI module called **Neural Resonance**.
We didn't drag a 400 MB LLM into the project that would eat all the RAM on a cheap VPS. Instead:

- **Baked Mask Encoder:** For each mask profile (WebRTC codec, QUIC protocol) we trained and "baked" a micro neural network (MLP 64→128→64) directly into the binary. It weighs only ~66 KB!
- **Real-time analysis:** This neural net analyzes entropy and IAT (inter-arrival times) of incoming UDP packets on the fly.
- **Hunting censors:** If the ISP's DPI system tries to probe our server (Active Probing) or starts throttling packets, the neural module detects a spike in reconstruction error (MSE).
- **Auto mask rotation:** As soon as the AI determines the current mask is compromised (e.g. `webrtc_zoom` got flagged), the server and client *seamlessly* reshape traffic to a backup mask (e.g. `dns_over_udp`). Zero disconnects!

## Other Cool Stuff

- **Zero-RTT & PFS:** No classic handshake for sniffers to catch. Data flows from the very first packet. And Perfect Forward Secrecy is built in — keys rotate on the fly, so even if the server gets seized, old traffic dumps can't be decrypted.
- **O(1) cryptographic session tags:** We never transmit a session ID in the clear. Instead, every packet carries a dynamic cryptographic tag derived from a timestamp and a secret key. The server finds the right client instantly, but to any observer it's just noise.
- **Written in Rust:** Fast, memory-safe, no leaks. The entire client binary is ~2.5 MB. Runs comfortably on a $5 VPS.

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/infosave2007/aivpn.git
cd aivpn
```

### 2. Build (requires Rust 1.75+)

The project is split into workspaces: `aivpn-common` (crypto & masks), `aivpn-server`, and `aivpn-client`.

```bash
# Same command on all platforms:
cargo build --release
```

> On Windows, make sure you have [Wintun](https://www.wintun.net/) installed — download `wintun.dll` and place it next to the binary.

### 3. Server (Linux only)

SSH into your VPS, generate a key:

```bash
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
```

Start it up:

```bash
sudo ./target/release/aivpn-server --listen 0.0.0.0:443 --key-file /etc/aivpn/server.key
```

Enable NAT:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
```

Or use Docker (everything is already configured in `docker-compose.yml`):

```bash
docker-compose up -d
```

### 4. Client

On startup, the server prints its public key to the console. Copy it and plug it into the client command:

#### Linux

```bash
sudo ./target/release/aivpn-client \
    --server YOUR_VPS_IP:443 \
    --server-key SERVER_PUBLIC_KEY_BASE64
```

Full tunnel mode (route all traffic through VPN):

```bash
sudo ./target/release/aivpn-client \
    --server YOUR_VPS_IP:443 \
    --server-key SERVER_PUBLIC_KEY_BASE64 \
    --full-tunnel
```

#### macOS

Same deal, `cargo build --release` produces a native binary:

```bash
sudo ./target/release/aivpn-client \
    --server YOUR_VPS_IP:443 \
    --server-key SERVER_PUBLIC_KEY_BASE64
```

> macOS will auto-configure the `utun` interface and routes via `ifconfig` / `route`.

#### Windows

Download `wintun.dll` from [WireGuard/wintun](https://www.wintun.net/) and place it next to the `.exe`:

```
aivpn-client.exe
wintun.dll
```

Run from PowerShell **as Administrator**:

```powershell
.\aivpn-client.exe --server YOUR_VPS_IP:443 --server-key SERVER_PUBLIC_KEY_BASE64
```

Full tunnel:

```powershell
.\aivpn-client.exe --server YOUR_VPS_IP:443 --server-key SERVER_PUBLIC_KEY_BASE64 --full-tunnel
```

> The client auto-configures routes via `route add` and cleans them up on exit.

## Cross-compilation

Build the client for any platform from your current machine:

```bash
# Linux target from macOS/Windows
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# Windows target from Linux/macOS
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

## Project Structure

```
aivpn/
├── aivpn-common/src/
│   ├── crypto.rs        # X25519, ChaCha20-Poly1305, BLAKE3
│   ├── mask.rs          # Mimicry profiles (WebRTC, QUIC, DNS)
│   └── protocol.rs      # Packet format, inner types
├── aivpn-client/src/
│   ├── client.rs        # Core client logic
│   ├── tunnel.rs        # TUN interface (Linux / macOS / Windows)
│   └── mimicry.rs       # Traffic shaping engine
├── aivpn-server/src/
│   ├── gateway.rs       # UDP gateway, MaskCatalog, resonance loop
│   ├── neural.rs        # Baked Mask Encoder, AnomalyDetector
│   ├── nat.rs           # NAT forwarder (iptables)
│   ├── key_rotation.rs  # Session key rotation
│   └── metrics.rs       # Prometheus monitoring
├── Dockerfile
├── docker-compose.yml
└── build.sh
```

## Contributing

Want to dig into the code or train your own mask for the neural module? Jump in:

- Mask engine: [`aivpn-common/src/mask.rs`](aivpn-common/src/mask.rs)
- Neural weights & anomaly detector: [`aivpn-server/src/neural.rs`](aivpn-server/src/neural.rs)
- Cross-platform TUN module: [`aivpn-client/src/tunnel.rs`](aivpn-client/src/tunnel.rs)
- Tests (100+): `cargo test`

PRs are welcome! We're especially looking for people with traffic analysis experience to capture dumps from popular apps and train new profiles for Neural Resonance.

---

License — MIT. Use it, fork it, bypass censorship responsibly.
