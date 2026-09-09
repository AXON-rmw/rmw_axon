# AXON Architecture and Source Map

Technical reference for the AXON internals: how the two layers fit together,
what each source file owns, how data and control flow through the system, and
where the tests for each area live.

For cryptography and the security profiles, see
[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md). For QKD deployment, see
[`QKD.md`](QKD.md). For the security threat model and claims, see
[`POST_QUANTUM_SECURITY.md`](POST_QUANTUM_SECURITY.md).

## Contents

1. [Two-layer design](#two-layer-design)
2. [Repository layout](#repository-layout)
3. [The Rust core, file by file](#the-rust-core-file-by-file)
4. [The C++ RMW layer, file by file](#the-c-rmw-layer-file-by-file)
5. [Control plane vs data plane](#control-plane-vs-data-plane)
6. [Data path: publishing a message](#data-path-publishing-a-message)
7. [Control path: discovery and graph](#control-path-discovery-and-graph)
8. [Session and entity model](#session-and-entity-model)
9. [Shared-memory layout](#shared-memory-layout)
10. [Wait sets and file descriptors](#wait-sets-and-file-descriptors)
11. [Where the tests are](#where-the-tests-are)
12. [Build pipeline](#build-pipeline)

## Two-layer design

AXON separates the **ROS 2 middleware contract** from **transport policy**:

```
   rcl / rclcpp / rclpy / ros2 CLI / RViz / Gazebo
                      |
                      v
   +-------------------------------------------+
   |  rmw_axon (C++)  — ROS-facing rmw_* API     |   ~5.0k lines
   |  FastCDR type support, handle lifecycle    |
   +-------------------------------------------+
                      |  extern "C" FFI (axon_session_*)
                      v
   +-------------------------------------------+
   |  axon_core (Rust) — all transport logic    |   ~23.5k lines
   |  SHM rings | QUIC | sessions | graph | QoS |
   |  security | serialization | wait sets      |
   +-------------------------------------------+
             |                        |
       POSIX SHM                    QUIC/UDP
     (same host)                  (remote host)
                                       |
                              +------------------+
                              |   axon_daemon    |  discovery + graph sync
                              +------------------+
```

The C++ layer contains no networking logic. The Rust layer never links against
ROS 2 headers. The FFI boundary is the only coupling point, which keeps the
transport testable in isolation (`cargo test --locked`) without a ROS
installation.

## Repository layout

| Path | Purpose |
|---|---|
| `axon_core/src/` | Rust transport core (library) |
| `axon_core/src/bin/axon_daemon.rs` | Discovery daemon binary |
| `axon_core/tests/` | Rust integration test suites |
| `axon_core/build.rs` | Cargo build script |
| `rmw_axon/src/*.cpp` | ROS 2 `rmw_*` C API implementation |
| `rmw_axon/include/rmw_axon/` | C API header and internal C++ helpers |
| `rmw_axon/CMakeLists.txt` | Builds Rust via cargo, links the shared library |
| `rmw_axon/plugin_description.xml` | pluginlib export for `rmw_implementation` |
| `docker/` | Dockerfile for per-distro images |
| `.github/workflows/` | CI: Rust suite plus one job per ROS 2 distro |
| `.github/scripts/functional_test.sh` | End-to-end functional test used by every CI job |
| `docs/` | This documentation |

## The Rust core, file by file

Module declarations live in [`axon_core/src/lib.rs`](../axon_core/src/lib.rs).
Line counts are approximate and indicate where complexity concentrates.

### Transport

| File | Lines | Responsibility |
|---|---:|---|
| `local.rs` | 1487 | POSIX SHM ring buffers: `shm_open`/`mmap`, slot allocation, publisher/subscriber cursors, `eventfd` signaling, overwrite recovery. The same-host data plane. |
| `quic_transport.rs` | 1635 | QUIC endpoints via `quinn`: mandatory hybrid ML-KEM classic mode, QKD external-PSK mode, 256-bit traffic cipher selection, connection pool, streams, and flow-control tuning. |
| `compress.rs` | 147 | zstd compression of remote payloads above 1 KiB, plus the `FLAG_COMPRESSED` wire flag. |
| `subscriber_queue.rs` | 238 | Bounded per-subscriber receive queues for remote data, with depth policies for large sensor types. |
| `resource.rs` | 122 | Leaky-bucket rate limiter for optional per-topic bandwidth caps. |
| `scm.rs` | 251 | `SCM_RIGHTS` file-descriptor passing over Unix sockets, used to hand eventfds between processes. |

### Session and ROS semantics

| File | Lines | Responsibility |
|---|---:|---|
| `session/mod.rs` | 2127 | Session lifecycle, entity registration (publishers, subscriptions, services), the central `Session` struct, and most session-level unit tests. |
| `session/graph.rs` | 1409 | Graph construction and introspection queries backing `ros2 topic/node/service`. |
| `session/service.rs` | 1022 | Service request/response routing, client/server reference counting, response ownership per client. |
| `session/subscribe.rs` | 803 | Subscription take path, queue draining, QoS-aware delivery. |
| `session/publish.rs` | 548 | Publish path: local ring write and remote fan-out of serialized payloads. |
| `session/routing.rs` | 606 | Decides whether a peer is local (SHM) or remote (QUIC) and maintains route tables. |
| `session/events.rs` | 24 | Session-level event plumbing. |
| `qos.rs` | 487 | QoS profile representation, policy defaults, and publisher/subscription compatibility checks. |
| `events.rs` | 371 | Deadline and liveliness monitoring, QoS event bookkeeping. |
| `filter.rs` | 69 | Content filtering for subscriptions. |
| `graph_cache.rs` | 113 | Thin cache facade over daemon-provided graph data. |
| `types.rs` | 150 | Core types: `NodeId`, `TopicHash`, `QosProfile`, entity metadata, `fxhash`. |
| `serialize.rs` | 63 | CDR serialization helpers via the `cdr-encoding` crate. |
| `wait.rs` | 222 | `epoll`-based wait set multiplexing subscription, service, and guard-condition eventfds, with optional timerfd polling. |

### Discovery daemon

| File | Lines | Responsibility |
|---|---:|---|
| `bin/axon_daemon.rs` | 2146 | Daemon entry point: argument parsing, daemonization, socket binding, peer accept loop, graph sync scheduling, QKD negotiation driving, security-profile enforcement. |
| `daemon/peer_sync.rs` | 1028 | Daemon-to-daemon graph sync protocol: request/response encoding, node merging, `handle_sync_payload`. |
| `daemon/discovery_shm.rs` | 910 | Shared-memory registry that local sessions and the daemon use to exchange graph and match information. |
| `daemon/rpc.rs` | 554 | XML-RPC server answering graph queries from local ROS CLI tools. |
| `daemon/peer_discovery.rs` | 325 | UDP multicast/broadcast HELLO and QKD bootstrap control delivery, including advertised SAE ID and security mode. |
| `daemon/handler.rs` | 218 | Per-connection request handling helpers. |

### Security

| File | Lines | Responsibility |
|---|---:|---|
| `security.rs` | 220 | ACL engine, audit logging, pass-through wire helpers, and strict runtime validation. |
| `qkd.rs` | 1396 | ETSI GS QKD 014 KME client, daemon-pair key negotiation messages, and the user-only SHM key store. |
| `security_mode.rs` | 110 | Strict `classic` / `qkd` mode parsing and ChaCha20/AES-256 traffic cipher selection. |
| `third_party/rustls-axon` | pinned vendored fork | rustls 0.23.40 plus the narrow TLS 1.3 external-PSK API used by QKD mode. |

### FFI

| File | Lines | Responsibility |
|---|---:|---|
| `c_bridge.rs` | 2167 | Core multi-session C API: `axon_session_create`, publish, take, ACL, configuration. |
| `c_bridge_graph.rs` | 1598 | Graph introspection C API. |
| `c_bridge_service.rs` | 845 | Service and client C API. |

## The C++ RMW layer, file by file

| File | Lines | Responsibility |
|---|---:|---|
| `src/misc_stubs.cpp` | 1383 | The long tail of the `rmw_*` surface: features that are no-ops, unsupported, or thin passthroughs. |
| `src/pubsub.cpp` | 554 | `rmw_create_publisher`/`subscription`, publish, take. |
| `src/service.cpp` | 513 | Services and clients. |
| `src/wait.cpp` | 454 | `rmw_wait`, wait-set construction, event handling. |
| `src/graph.cpp` | 344 | Graph introspection entry points. |
| `src/guard_condition.cpp` | 311 | Guard conditions and their eventfds. |
| `src/node.cpp` | 113 | Node creation and destruction. |
| `src/serialization.cpp` | 101 | FastCDR serialization with DDS_CDR encapsulation. |
| `src/init_shutdown.cpp` | 95 | `rmw_init` / `rmw_shutdown` and context setup. |
| `include/rmw_axon/internal.hpp` | 1060 | Internal helpers: FastCDR type-support selection, handle wrappers, conversions. |
| `include/rmw_axon/rmw_axon.h` | 55 | The C API surface exposed by the Rust core. |

## Control plane vs data plane

This distinction is the single most useful mental model when debugging AXON.

| | Control plane | Data plane |
|---|---|---|
| Owner | `axon_daemon` + `daemon/` | `local.rs` (SHM), `quic_transport.rs` (QUIC) |
| Transport | UDP multicast HELLO, QUIC control streams, SHM registry, XML-RPC | SHM rings, QUIC data streams |
| Answers | "Which peers and endpoints exist?" | "Move these bytes" |
| Failure looks like | Topic missing from `ros2 topic list`, wrong type, wrong endpoint count | Topic listed but `echo` receives nothing, `hz` reports zero |

A graph can be correct while a route is unreachable, and a route can be healthy
while a wait set fails to wake. Diagnose them separately.

## Data path: publishing a message

1. The application calls `rclcpp::Publisher::publish`, which reaches
   `rmw_publish` in [`rmw_axon/src/pubsub.cpp`](../rmw_axon/src/pubsub.cpp).
2. The C++ layer serializes the message with FastCDR
   ([`serialization.cpp`](../rmw_axon/src/serialization.cpp)) and calls the FFI
   publish entry point in [`c_bridge.rs`](../axon_core/src/c_bridge.rs).
3. [`session/publish.rs`](../axon_core/src/session/publish.rs) looks up routes
   through [`session/routing.rs`](../axon_core/src/session/routing.rs).
4. **Local subscribers**: the payload is written into the topic's SHM ring
   ([`local.rs`](../axon_core/src/local.rs)) and the subscriber eventfd is
   signaled. No encryption, no copy through the kernel network stack.
5. **Remote subscribers**: the payload is optionally zstd-compressed
   ([`compress.rs`](../axon_core/src/compress.rs)) and queued to the per-peer
   QUIC sender
   ([`quic_transport.rs`](../axon_core/src/quic_transport.rs)).
6. In QKD `messages10` mode the sender wraps each remote sample in `AXQKD001`,
   rotating its KME material every 10 outgoing messages, before QUIC writes it.
   QKD `session` omits this extra envelope. QUIC then encrypts and
   integrity-protects the remote stream. On the receiving host the QUIC worker
   verifies the per-message envelope, decrypts the stream, decompresses the payload, and
   pushes it into the subscriber queue
   ([`subscriber_queue.rs`](../axon_core/src/subscriber_queue.rs)), signaling the
   subscription eventfd so `rmw_wait` returns.

In QKD `messages10` mode each remote application message has an `AXQKD001` AEAD
envelope sealed with KME material rotated every 10 messages. In both QKD
strategies the TLS binder authenticates possession of the daemon-pair bootstrap
PSK. In classic mode the current self-signed
certificate verifier does not authenticate peer identity; see
[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md).

The remote send pipeline keeps only the newest sample per `(peer, topic)`, which
favors freshness for sensor streams. Same-host SHM delivery honors the ring
depth instead.

## Control path: discovery and graph

1. On first use a session auto-spawns `axon_daemon` if none is running
   (`AXON_DAEMON_PATH`, PID file `/tmp/axon_daemon.pid`).
2. The daemon binds UDP on `0.0.0.0:<port>` for peer traffic and TCP on
   `127.0.0.1:<port>` for local XML-RPC graph queries. TCP is intentionally
   loopback-only: it serves local CLI tools, not remote peers
   (`bind_daemon_endpoints` in
   [`bin/axon_daemon.rs`](../axon_core/src/bin/axon_daemon.rs)).
3. HELLO datagrams are multicast to `239.255.0.2:7403`, with a broadcast
   fallback on every non-loopback IPv4 interface
   ([`daemon/peer_discovery.rs`](../axon_core/src/daemon/peer_discovery.rs)).
   A HELLO carries the daemon ID, addresses, domains, generation, the QKD SAE ID
   when in QKD mode, and the security profile byte.
4. Discovered peers are connected over QUIC and graph state is exchanged with
   the sync protocol in
   [`daemon/peer_sync.rs`](../axon_core/src/daemon/peer_sync.rs).
5. Local sessions publish their entities into the SHM registry
   ([`daemon/discovery_shm.rs`](../axon_core/src/daemon/discovery_shm.rs)); the
   daemon merges local and remote views and answers introspection queries.

Peers advertising a different security profile are ignored, and the rejection is
logged. Run the daemon with `--foreground` to see this and other diagnostics.

## Session and entity model

Every `rmw_init`/`rmw_shutdown` pair is an isolated **session** with its own
transport endpoints and graph cache. Sessions are identified by an integer used
across the FFI, so one process can hold several.

Topics are identified by a 64-bit `TopicHash` (`fxhash` over the topic name in
[`types.rs`](../axon_core/src/types.rs)). SHM object names include the ROS
domain, so `ROS_DOMAIN_ID` isolation is enforced at the operating-system object
level rather than by filtering.

Services map to **two internal topics**, one for requests and one for
responses, with type-bounded allocation
([`session/service.rs`](../axon_core/src/session/service.rs)). Actions build on
services and topics and need no separate transport.

Known limitation: endpoints created by several nodes in one process are
attributed to the most recently created node, so `ros2 topic info -v` can
misattribute endpoints of component containers.

AXON implements the statically typed RMW paths exercised by its supported ROS 2
distributions. Jazzy-era dynamic-message take and serialization-support APIs
explicitly return `RMW_RET_UNSUPPORTED`. AXON also uses its own discovery and
QUIC protocols, so it is not DDS/RTPS wire-compatible with DDS-based RMWs.

The core exposes an internal zero-copy byte-slot API, but those buffers contain
serialized CDR data and are not initialized ROS message objects. Consequently,
the C++ RMW layer does not advertise typed loaned-message support.

## Shared-memory layout

Objects created under `/dev/shm`:

| Name pattern | Created by | Contents |
|---|---|---|
| `axon_domain_<domain>_topic_<hash>` | Sessions | Topic ring buffer: header, slot table, payload slots |
| `axon_daemon` | Daemon | Local discovery/graph registry |
| `axon_qkd_keys` | Daemon (QKD mode) | Bootstrap daemon-pair keys, user-only permissions; rotating message keys are fetched from the KME and never stored here |

Ring sizing is bounded by `AXON_RING_BUFFER_SIZE_MB` (default 256 MB per ring
budget) and slot counts are clamped for large message types. `/clock` keeps a
burst-tolerant minimum depth even when QoS depth is 1, so Gazebo clock bursts do
not starve consumers.

Stale objects from a previous run are detected and reused or recreated. When
debugging, removing `/dev/shm/axon_*` and the daemon PID file returns the system
to a clean state.

## Wait sets and file descriptors

[`wait.rs`](../axon_core/src/wait.rs) builds a Linux `epoll` set over the
eventfds of subscriptions, services, clients, and guard conditions, plus an
optional timerfd. `AXON_WAIT_POLL_MS` bounds the epoll slice before AXON polls
SHM readiness directly; it defaults to 10 ms when the wait contains
services or clients, and 100 ms otherwise. The shorter service slice exists
because cross-process eventfd wakeups are not always available, and long slices
caused false Nav2 lifecycle timeouts.

Descriptor accounting matters: every subscription and service consumes
descriptors, and long-running RViz/Gazebo sessions can expose leaks that short
tests do not. `AXON_TRACE_FDS` enables descriptor tracing.

Known limitation: QoS events (deadline, liveliness, incompatibility) are only
observable by polling `rmw_take_event`; they do not wake wait sets, so rclcpp
event callbacks do not fire.

## Where the tests are

### Rust unit tests

Inline `#[cfg(test)]` modules, run with
`cargo test --locked --manifest-path axon_core/Cargo.toml --lib`. Distribution by file:

| Tests | File | Covers |
|---:|---|---|
| 43 | `session/mod.rs` | Entity registration, session lifecycle, routing decisions |
| 32 | `c_bridge.rs` | FFI contract, session handles, ACL entry points |
| 17 | `local.rs` | Ring creation, wraparound, overwrite recovery, keep-all |
| 16 | `qos.rs` | Policy defaults and compatibility matrix |
| 16 | `daemon/discovery_shm.rs` | SHM registry records, staleness |
| 9 | `daemon/rpc.rs` | XML-RPC request/response encoding |
| 7 | `daemon/peer_sync.rs` | Sync request/response codec, node merging |
| 6 | `wait.rs` | epoll registration and wakeups |
| 6 | `subscriber_queue.rs` | Queue depth and drop policy |
| 8 | `qkd.rs` | KME URL construction, key validation, SHM store, daemon-pair negotiation |
| 5 | `daemon/peer_discovery.rs` | HELLO encode/decode, backward compatibility |
| 5 | `daemon/handler.rs` | Connection handling |
| 1 | `security.rs` | pass-through payload behavior without a second encryption layer |
| 4 | `resource.rs` | Leaky bucket |
| 2 | `security_mode.rs` | strict mode/cipher parsing, no silent downgrade |
| 4 | `quic_transport.rs` | certificate generation, exact ML-KEM/QKD provider policy, shutdown |
| 3 | `filter.rs`, `events.rs`, `compress.rs` | Filtering, QoS events, zstd round trip |
| 2 | `session/graph.rs`, `serialize.rs`, `scm.rs` | Graph queries, CDR, fd passing |

### Rust integration suites

In `axon_core/tests/`, run with `cargo test --locked --manifest-path axon_core/Cargo.toml`:

| Suite | Lines | Covers |
|---|---:|---|
| `daemon_integration.rs` | 338 | Daemon startup, discovery, graph sync between daemons |
| `remote_integration.rs` | 325 | Remote routing, compression, subscriber queues |
| `quic_integration.rs` | 278 | QUIC connect, streams, shutdown, reconnection |
| `cross_process_shm.rs` | 60 | SHM ring across real process boundaries |
| `qkd_quic_psk.rs` | 117 | Real QUIC external-PSK round trips with both traffic ciphers and fail-closed behavior |

Run a single area:

```bash
cargo test --locked --manifest-path axon_core/Cargo.toml --lib qkd
cargo test --locked --manifest-path axon_core/Cargo.toml --test qkd_quic_psk
```

### Functional and CI tests

[`.github/scripts/functional_test.sh`](../.github/scripts/functional_test.sh)
exercises the real ROS 2 stack: publish/subscribe, an AddTwoInts service round
trip, and graph introspection. It is shared by every per-distro CI workflow in
[`.github/workflows/`](../.github/workflows) and can be run locally after
sourcing the workspace.

CI runs `rust.yml` for the Rust core plus `<distro>-build-test.yml` for each
supported ROS 2 distribution, each inside the official `ros:<distro>` image.

## Build pipeline

```bash
# As a ROS 2 package (invokes cargo, then links libaxon_core.a)
colcon build --packages-select rmw_axon

# Rust core only, no ROS installation required
cargo build --locked --manifest-path axon_core/Cargo.toml --release
```

`rmw_axon/CMakeLists.txt` runs `cargo build --release --locked` on `axon_core` first,
then links the resulting static library into the `rmw_axon` shared library and
installs the `axon_daemon` binary into `lib/`. CMake always builds the Rust side
in release mode, so a debug colcon build still links an optimized core.
