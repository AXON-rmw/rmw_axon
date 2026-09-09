# AXON configuration reference

Normal same-host and LAN use requires only:

```bash
export RMW_IMPLEMENTATION=rmw_axon
```

All other settings are optional. Restart Axon nodes and `axon_daemon` after
changing transport or security settings.

## Runtime variables

| Variable | Default | Description |
| --- | --- | --- |
| `RMW_IMPLEMENTATION` | — | Set to `rmw_axon` to select Axon. |
| `AXON_DAEMON_PATH` | automatic | Path to `axon_daemon`; Axon otherwise searches the installation, `PATH`, and local build outputs. |
| `AXON_DAEMON_PORT` | `7402`, then `7404-7420` | TCP/UDP port for graph queries and daemon synchronization. |
| `AXON_DAEMON_PORT_RANGE` | — | Inclusive alternative daemon port range, such as `7500-7520`. |
| `AXON_DAEMON_PEERS` | — | Comma-separated static daemon peers (`host:port`) when multicast is blocked. |
| `AXON_DAEMON_PID_FILE` | `/tmp/axon_daemon.pid` | Daemon PID file. |
| `AXON_ADVERTISE_ADDRS` | automatic | Comma-separated IPv4 addresses advertised to peers; useful behind NAT. |
| `AXON_QUIC_PORT` | `0` | Fixed session QUIC UDP port; `0` lets the OS choose. |
| `AXON_QUIC_PORT_RANGE` | — | Inclusive QUIC UDP range, such as `17500-17599`. |
| `AXON_MAX_MESSAGE_SIZE` | selected by type | Maximum serialized message size. Defaults include Image 8 MB, CompressedImage 4 MB, PointCloud2 16 MB, OccupancyGrid 4 MB, and other topics 64 KB. |
| `AXON_RING_BUFFER_SIZE_MB` | `256` | Maximum shared-memory data budget per topic ring. |
| `AXON_COMPRESSION` | enabled | zstd compression for remote payloads over 1 KiB; use `0`, `false`, `no`, or `off` to disable. |
| `AXON_COMPRESSION_LEVEL` | `1` | zstd compression level. |
| `AXON_SECURITY_MODE` | `classic` | Strictly `classic` or `qkd`; peers with different modes do not connect. |
| `AXON_QUIC_CIPHER` | `chacha20` | `chacha20` or `aes256` for QUIC 1-RTT traffic. |
| `AXON_ACL_PUBLISH` | — | Comma-separated allowed publish globs; unset means unrestricted. |
| `AXON_ACL_SUBSCRIBE` | — | Comma-separated allowed subscribe globs; unset means unrestricted. |
| `AXON_QUIC_SEND_WINDOW` | `16777216` | QUIC connection send window in bytes. |
| `AXON_QUIC_STREAM_WINDOW` | `67108864` | Per-stream QUIC receive window in bytes. |
| `AXON_QUIC_MAX_UDP_PAYLOAD` | `1200` | Maximum QUIC UDP payload; the default avoids common Wi-Fi fragmentation. |
| `AXON_GRAPH_DISCOVERY_WAIT_MS` | `1500` | First graph-query wait for short-lived ROS CLI commands; `0` disables it. |
| `AXON_WAIT_POLL_MS` | services/clients `10`, otherwise `100` | Maximum epoll slice before polling shared-memory readiness. |

## QKD variables

A build made with `-DAXON_QKD_ROLE=1` or `2` installs the corresponding beta
profile, so manual QKD variables are normally unnecessary for beta testing.
Explicit values take precedence over the installed profile.

| Variable | Default | Description |
| --- | --- | --- |
| `AXON_QKD_KME_BASE_URL` | selected profile | Local KME URL ending at `/api/v1/keys`. |
| `AXON_QKD_LOCAL_SAE_ID` | selected profile | SAE identity represented by this host. |
| `AXON_QKD_PEER_SAE_ID` | discovered | Remote SAE fallback for static-peer deployments. |
| `AXON_QKD_CA_CERT` | selected profile | PEM CA certificate used to verify the KME. |
| `AXON_QKD_CLIENT_CERT` | selected profile | PEM client certificate for KME mutual TLS. |
| `AXON_QKD_CLIENT_KEY` | selected profile | Private key matching the KME client certificate. |
| `AXON_QKD_PROFILE_DIR` | automatic | Profile override; Axon also checks `$HOME/.config/axon/qkd` and the ROS package installation. |
| `AXON_QKD_REQUEST_TIMEOUT_MS` | `3000` | KME HTTPS timeout, clamped to 100-60000 ms. |
| `AXON_QKD_ALLOW_INSECURE_HTTP` | `false` | Allows HTTP only for isolated local tests. |

See [`QKD.md`](QKD.md) for deployment and [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md)
for the trust boundaries.

## Access-control example

```bash
export AXON_ACL_PUBLISH="/robot1/*,/diagnostics"
export AXON_ACL_SUBSCRIBE="/robot1/*"
```

## Bundled rustls fork

Axon vendors the pinned `rustls-axon` fork under
`third_party/rustls-axon/rustls`. A normal Axon clone includes it; no second
clone, SSH key, or `CARGO_NET_GIT_FETCH_WITH_CLI` setting is required. The
exact fork revision and update procedure are documented in
[`THIRD_PARTY_RUSTLS.md`](THIRD_PARTY_RUSTLS.md).

## Docker networking

Use at least `--shm-size=1g`. Host networking is the simplest option when a
container communicates with another physical computer:

```bash
docker run -it --rm --network host --shm-size=1g rmw_axon:humble
```

When bridge/NAT networking is required, publish the daemon and QUIC ports and
set `AXON_ADVERTISE_ADDRS` to an address reachable by the peer.
