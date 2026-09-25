# NexWire Protocol ⚡

> High-performance, low-latency, zero-allocation custom VPN protocol built in Go.

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square&logo=linux)](#)
[![Security](https://img.shields.io/badge/Crypto-ChaCha20--Poly1305-green?style=flat-square)](#)

**NexWire** is a modern, high-performance network protocol and service designed for constructing secure, encrypted VPN tunnels. Engineered with an absolute focus on minimal latency, maximum throughput, and robustness against active DPI probing and replay attacks.

## Key Features 🚀

- **Zero-Allocation Pipeline:** Utilizes asynchronous buffer pools (`sync.Pool`) to process packets with zero Garbage Collection (GC) allocations during active data transfer.
- **Modern Cryptography Suite:**
  - **PFS (Perfect Forward Secrecy):** Key exchanges leveraging ECDH over **Curve25519** elliptic curves.
  - **HKDF + ChaCha20-Poly1305:** Hardware-accelerated symmetric AEAD encryption guaranteeing frame authenticity and confidentiality.
- **Anti-Replay Protection:** Sequence tracking backed by a 64-bit sliding window bitmask.
- **Asynchronous Worker Pools:** Multithreaded concurrent packet handling scaling evenly across all available CPU cores.
- **Anti-DPI & Stealth Design:** Eliminates cleartext protocol headers and validates initial handshakes via HMAC-SHA256 to prevent active network scanner identification.
- **Cross-Platform Readiness:** Unified Go codebase with native Linux TUN driver interaction and Windows stub layers.

## Protocol Architecture 📐

```text
[ Application / OS Stack ]
          │
          ▼
┌──────────────────────┐
│ Virtual TUN Device   │ ← Layer 3 Packet Capture
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ NexWire Engine       │ ← Curve25519 ECDH / ChaCha20-Poly1305 AEAD
└──────────┬───────────┘
           │
           ▼
   Encrypted UDP Frames
         + HMAC
           │
           ▼
┌──────────────────────┐
│ UDP Socket           │ ← Public Network Transport
└──────────────────────┘
```

## Quick Start 🛠️

### Prerequisites

- **Linux** (Kernel 4.x+) or **Windows**
- `root` / Administrator privileges (required to provision virtual network interfaces)
- **Go 1.22+** (for building from source)

### 1. Build from Source

Clone the repository and compile the optimized binary:

```bash
git clone https://github.com/your-username/NexWire.git
cd NexWire

# Fetch dependencies
go mod tidy

# Build native Linux binary
go build -trimpath -ldflags="-s -w" -o nexwire
```

To cross-compile for Windows target (`.exe`):

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
go build -trimpath -ldflags="-s -w" -o nexwire.exe
```

## ⚙️ Configuration (`config.json`)

Create a `config.json` file in the same directory as the binary:

```json
{
  "mode": "server",
  "listen_addr": "0.0.0.0:8443",
  "remote_addr": "1.2.3.4:8443",
  "tun_name": "nexwire0",
  "tun_ip": "10.8.0.1/24",
  "psk": "Your-Ultra-Secure-PreSharedKey-ChangeMe!",
  "workers": 4,
  "mtu": 1420,
  "keepalive_sec": 25
}
```

### Configuration Parameters

| Option | Description |
|---|---|
| `mode` | Operation mode: `"server"` or `"client"` |
| `listen_addr` | Host IP and UDP port to bind for listening (server mode) |
| `remote_addr` | External IP and UDP port of the remote server (client mode) |
| `tun_name` | Identifier name for the virtual TUN interface |
| `tun_ip` | Assigned internal IP address within the VPN subnet (in CIDR notation) |
| `psk` | Pre-Shared Key used for authenticating the initial handshake phase |
| `workers` | Number of parallel worker goroutines handling packet streams |
| `mtu` | Maximum Transmission Unit size for the TUN interface (Default: `1420`) |
| `keepalive_sec` | Keepalive interval in seconds |

## 💻 Execution

> ⚠️ **Note:** Root privileges are mandatory for manipulating network adapters.

### Running the Server (Linux)

```bash
# 1. Launch NexWire in server mode
sudo ./nexwire -mode=server -config=config.json

# 2. Enable IPv4 Forwarding and NAT masquerading
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Running the Client

Set `"mode": "client"`, specify the server's public IP in `remote_addr`, assign a unique internal IP address (e.g., `10.8.0.2/24`) in `tun_ip`, and run:

```bash
sudo ./nexwire -mode=client -config=config.json
```

## 🔒 Security Posture

NexWire adheres strictly to the **Security by Design** methodology:

- Zero unencrypted protocol metadata exposed in transit.
- Malformed or unauthenticated UDP datagrams are immediately dropped without returning response packets, frustrating network reconnaissance scanners.
- Automatic session key destruction and background cleanup routines for stale connections.
