# AXON validation

This document lists checks for the Axon middleware itself. External robotics
applications, simulators, and private experiment logs are intentionally kept
out of this repository.

## Automated baseline

- Rust formatting, strict Clippy, and rustdoc pass with the pinned lockfile.
- `cargo test --locked --all-targets` passes the Axon unit and integration
  suites; one timing-sensitive cross-session test remains explicitly ignored
  unless an isolated live daemon is provided.
- The ROS 2 functional script covers pub/sub, an AddTwoInts service call, and
  graph introspection through `rmw_axon`.
- The QKD QUIC integration test exercises the external-PSK handshake and
  rejects missing or mismatched key material.
- The Docker image builds with the bundled `rustls-axon` subtree and does not
  require an SSH agent or a second repository.

## Scope and limitations

- Same-host ROS traffic uses POSIX shared memory and does not exercise remote
  QUIC or KME message-key delivery.
- QKD tests use the ETSI QKD 014 API and simulator credentials; they do not
  represent a physical QKD link.
- Two-host QKD, Docker networking, and other ROS distributions require the
  procedures in [`MANUAL_SECURITY_VALIDATION.md`](MANUAL_SECURITY_VALIDATION.md)
  and should be reported with their exact environment.

## Reproduce the core checks

```bash
cargo fmt --manifest-path axon_core/Cargo.toml -- --check
cargo clippy --locked --manifest-path axon_core/Cargo.toml \
  --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path axon_core/Cargo.toml --all-targets

source /opt/ros/humble/setup.bash
colcon build --packages-select rmw_axon
source install/setup.bash
.github/scripts/functional_test.sh
```

Build the portable image with:

```bash
docker build -f docker/Dockerfile \
  --build-arg ROS_DISTRO=humble \
  -t rmw_axon:humble .
```

Security-mode and two-host procedures are maintained separately in
[`MANUAL_SECURITY_VALIDATION.md`](MANUAL_SECURITY_VALIDATION.md).
