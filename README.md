# rmw_axon

<div align="center">

**A purpose-built ROS 2 middleware (RMW) that pairs a high-performance Rust transport core with a C++ ROS 2 adapter** — shared-memory ring buffers on the same host, QUIC between hosts, daemon-based discovery, ROS 2 graph introspection, service routing over internal topics, and selectable ML-KEM or QKD key establishment.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/license/apache-2-0)
[![Code Size](https://img.shields.io/github/languages/code-size/AXON-rmw/rmw_axon.svg)](https://github.com/AXON-rmw/rmw_axon)
[![Last Commit](https://img.shields.io/github/last-commit/AXON-rmw/rmw_axon.svg)](https://github.com/AXON-rmw/rmw_axon/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/AXON-rmw/rmw_axon)](https://github.com/AXON-rmw/rmw_axon/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/AXON-rmw/rmw_axon)](https://github.com/AXON-rmw/rmw_axon/pulls)
[![Contributors](https://img.shields.io/github/contributors/AXON-rmw/rmw_axon.svg)](https://github.com/AXON-rmw/rmw_axon/graphs/contributors)
[![Rust](https://github.com/AXON-rmw/rmw_axon/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/AXON-rmw/rmw_axon/actions/workflows/rust.yml)
[![Docs](https://github.com/AXON-rmw/rmw_axon/actions/workflows/docs.yml/badge.svg?branch=main)](https://AXON-rmw.github.io/rmw_axon/)

| ROS 2 Distro | Build and Test |
| :----------: | :------------: |
| **Humble** | [![Humble Build and Test](https://github.com/AXON-rmw/rmw_axon/actions/workflows/humble-build-test.yml/badge.svg?branch=main)](https://github.com/AXON-rmw/rmw_axon/actions/workflows/humble-build-test.yml) |
| **Iron** | [![Iron Build and Test](https://github.com/AXON-rmw/rmw_axon/actions/workflows/iron-build-test.yml/badge.svg?branch=main)](https://github.com/AXON-rmw/rmw_axon/actions/workflows/iron-build-test.yml) |
| **Jazzy** | [![Jazzy Build and Test](https://github.com/AXON-rmw/rmw_axon/actions/workflows/jazzy-build-test.yml/badge.svg?branch=main)](https://github.com/AXON-rmw/rmw_axon/actions/workflows/jazzy-build-test.yml) |
| **Kilted** | [![Kilted Build and Test](https://github.com/AXON-rmw/rmw_axon/actions/workflows/kilted-build-test.yml/badge.svg?branch=main)](https://github.com/AXON-rmw/rmw_axon/actions/workflows/kilted-build-test.yml) |
| **Lyrical** | [![Lyrical Build and Test](https://github.com/AXON-rmw/rmw_axon/actions/workflows/lyrical-build-test.yml/badge.svg?branch=main)](https://github.com/AXON-rmw/rmw_axon/actions/workflows/lyrical-build-test.yml) |
| **Rolling** | [![Rolling Build and Test](https://github.com/AXON-rmw/rmw_axon/actions/workflows/rolling-build-test.yml/badge.svg?branch=main)](https://github.com/AXON-rmw/rmw_axon/actions/workflows/rolling-build-test.yml) |

</div>

## Overview

Axon replaces the default ROS 2 middleware while keeping the normal ROS 2 APIs:
`rclcpp`, `rclpy`, topics, services, actions, QoS and graph tools continue to
work as usual. The transport is selected with `RMW_IMPLEMENTATION=rmw_axon`.

- Processes on one host use POSIX shared-memory rings.
- Different hosts use encrypted QUIC/UDP.
- `axon_daemon` provides discovery and synchronises the distributed ROS graph.

Axon is Linux-specific and is not DDS/RTPS wire-compatible with other ROS 2
middleware implementations.

## Install

### Requirements

- ROS 2 and `colcon` (Humble or another supported distribution).
- A Rust toolchain with `cargo` available in `PATH`.
- Network access for the normal Rust dependencies and, when using QKD, the
  configured KME endpoint.

### Build from source

The following example uses ROS 2 Humble. Replace `humble` with the distribution
installed on the machine.

```bash
source /opt/ros/humble/setup.bash

mkdir -p ~/axon_ws/src
git clone https://github.com/AXON-rmw/rmw_axon.git ~/axon_ws/src/rmw_axon

cd ~/axon_ws
rosdep install --from-paths src --ignore-src -r -y
colcon build --packages-select rmw_axon
source install/setup.bash
export RMW_IMPLEMENTATION=rmw_axon
```

Source the ROS and workspace setup files, and export `RMW_IMPLEMENTATION`, in
each terminal that launches an Axon node. After the first build, no extra
middleware process or application changes are required for normal use.

## Run

A same-host smoke test can use the standard ROS 2 demo nodes:

```bash
# Terminal 1
source /opt/ros/humble/setup.bash
source ~/axon_ws/install/setup.bash
export RMW_IMPLEMENTATION=rmw_axon
ros2 run demo_nodes_cpp listener

# Terminal 2: repeat the three setup lines, then run:
ros2 run demo_nodes_cpp talker
```

For a two-host deployment, build and source Axon on both machines, use the same
`ROS_DOMAIN_ID`, and start the ROS nodes normally:

```bash
export ROS_DOMAIN_ID=90
export RMW_IMPLEMENTATION=rmw_axon
```

Discovery normally uses multicast. If the network blocks it, point each daemon
at the other host with `AXON_DAEMON_PEERS=host:7402`.

## Security modes

All communicating Axon daemons must use the same security mode and traffic
cipher. Restart the Axon nodes after changing security variables.

### Classic (default)

```bash
export AXON_SECURITY_MODE=classic
```

Classic mode uses TLS 1.3 over QUIC with hybrid X25519 + ML-KEM-768 key
establishment and ChaCha20-Poly1305 traffic encryption by default. It encrypts
the transport but does not currently authenticate peer identity; see the
[cryptography notes](docs/CRYPTOGRAPHY.md) for the threat boundary.

### QKD

QKD mode integrates an ETSI GS QKD 014 key-management endpoint. Axon obtains a
key from the KME and uses it as the external PSK for the QUIC TLS 1.3 session.
Choose one application-key strategy:

```bash
export AXON_SECURITY_MODE=qkd
export AXON_QKD_KEY_MODE=messages10  # one fresh KME key per 10 outgoing messages
# export AXON_QKD_KEY_MODE=session   # one key for the QUIC session
```

The distinction between local and remote traffic is important: processes on
the same host normally use shared memory, so a local talker/listener does not
exercise the remote KME or consume QKD message keys. To validate the QKD data
path, use two different hosts or two isolated containers/IPC namespaces, with
one QKD profile at each endpoint. The two endpoints then communicate through
different Axon daemons over QUIC.

For the bundled QuKayDee beta test profiles, build the two endpoints as
separate installations:

```bash
# Endpoint 1
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=1

# Endpoint 2
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=2
```

The profiles are simulator credentials for integration tests, not production
identity provisioning. QuKayDee validates the KME/SAE API and key lifecycle; it
does not provide a physical quantum channel. For custom or production
credentials, follow [`docs/QKD.md`](docs/QKD.md).

## Configuration

The defaults are suitable for a same-host test or a small LAN. The most common
variables are:

| Variable | Default | Purpose |
| --- | --- | --- |
| `RMW_IMPLEMENTATION` | — | Select `rmw_axon`. |
| `ROS_DOMAIN_ID` | ROS 2 default | Isolate independent ROS systems. |
| `AXON_SECURITY_MODE` | `classic` | Select `classic` or `qkd`. |
| `AXON_QUIC_CIPHER` | `chacha20` | Select `chacha20` or `aes256`. |
| `AXON_DAEMON_PEERS` | automatic discovery | Static `host:port` peers when multicast is unavailable. |
| `AXON_COMPRESSION` | enabled | Set to `0` to disable remote zstd compression. |

See the [complete configuration reference](docs/CONFIGURATION.md) for QKD,
network, memory and tuning options.

## Docker

Build and run a standard Axon image:

```bash
docker build -f docker/Dockerfile \
  --build-arg ROS_DISTRO=humble \
  -t rmw_axon:humble .

docker run -it --rm --network host --shm-size=1g rmw_axon:humble
```

For a QKD test, build one image with `AXON_QKD_ROLE=1` and another with
`AXON_QKD_ROLE=2`, run them in separate containers with isolated IPC, and set
`AXON_SECURITY_MODE=qkd` in both. The complete two-endpoint procedure is in
[`docs/QKD.md`](docs/QKD.md).

## Limitations

- Same-host shared-memory payloads are not encrypted.
- Discovery announcements are not authenticated.
- Remote delivery favours the newest frame; under backpressure, intermediate
  samples can be dropped even for `RELIABLE` or `KEEP_ALL` topics.
- Dynamic types, typed ROS loaned messages and some QoS event callbacks are not
  supported yet.

See [Architecture](docs/ARCHITECTURE.md) and
[Cryptography](docs/CRYPTOGRAPHY.md) for the exact behaviour and security
boundaries.

## Testing and documentation

```bash
cargo test --locked --manifest-path axon_core/Cargo.toml

source /opt/ros/humble/setup.bash
colcon build --packages-select rmw_axon
source install/setup.bash
.github/scripts/functional_test.sh
```

- [Architecture and source map](docs/ARCHITECTURE.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [QKD deployment](docs/QKD.md)
- [Manual security validation](docs/MANUAL_SECURITY_VALIDATION.md)
- [Validation baseline](docs/VALIDATION.md)
- [Generated Rust API](https://AXON-rmw.github.io/rmw_axon/)

## License

Apache-2.0. See [`LICENSE`](LICENSE).
