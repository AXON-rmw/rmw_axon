# Manual validation of classic and QKD modes

This procedure makes the selected AXON security mode, SAE identity, KME
authentication, QKD negotiation, QUIC connection, and ROS message delivery
visible in the terminal.

## What the script proves

For `classic`, a successful two-host run shows:

- `axon_daemon: security mode classic`;
- discovery of the remote AXON daemon;
- a successful daemon-to-daemon QUIC connection;
- ROS messages arriving at the remote listener.

For `qkd`, it additionally shows:

- the installed SAE role;
- successful mutual-TLS authentication to the QuKayDee KME;
- `QKD session ... established` or `imported QKD key`;
- a successful QUIC connection after QKD key negotiation.

Receiving messages on one PC alone is not proof of the remote security path:
same-host AXON traffic uses shared memory. Use two physical hosts for the
end-to-end checks below.

## 1. Build the required variant

### Normal classic build

```bash
cd "$HOME/axon_ws"
colcon build --packages-select rmw_axon
```

This installs no SAE identity. `classic` is AXON's runtime default.

### QKD host 1

```bash
cd "$HOME/axon_ws"
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=1
```

### QKD host 2

```bash
cd "$HOME/axon_ws"
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=2
```

## 2. Prepare both terminals

Run this on both machines:

```bash
source /opt/ros/humble/setup.bash
source "$HOME/axon_ws/install/setup.bash"
cd "$HOME/axon_ws/src/rmw_axon"
```

If the repository itself is the colcon workspace (for example
`$HOME/rmw_axon/install/setup.bash` exists), the validation script can load
that local installation automatically. Sourcing it explicitly is still useful
for normal `ros2` commands outside the script.

Use the same `ROS_DOMAIN_ID` on both machines:

```bash
export ROS_DOMAIN_ID=90
```

The quick `startup` check uses a separate temporary port and can coexist with an
already running AXON daemon. The `listener` and `talker` end-to-end checks
refuse to kill or reuse an existing daemon. Before those checks, stop your
current ROS nodes and then stop that daemon:

```bash
pgrep -a axon_daemon
pkill -x axon_daemon
```

`pkill` stops every AXON daemon owned by the current user, so run it only after
closing other AXON work.

## 3. Run talker and listener together on one machine

For a visible classic demonstration with one command:

```bash
./scripts/validate_security_mode.sh classic demo
```

The script launches both ROS nodes, prints `Publishing` and `I heard`, and
finishes automatically. It can reuse an already running daemon when its mode
matches.

On a QKD build, use the installed role:

```bash
./scripts/validate_security_mode.sh qkd demo 1  # host built as SAE 1
./scripts/validate_security_mode.sh qkd demo 2  # host built as SAE 2
```

The QKD demo also verifies the installed profile and KME mutual TLS. The ROS
messages themselves use shared memory because both nodes are on one host, so
this local command is not proof of remote QKD transport.

## 4. Optional daemon-only startup checks

Check a normal/classic installation:

```bash
./scripts/validate_security_mode.sh classic startup
```

Expected evidence:

```text
[ OK ] Normal installation contains no SAE profile
axon_daemon: security mode classic
== STARTUP CHECK PASSED ==
```

Check QKD host 1:

```bash
./scripts/validate_security_mode.sh qkd startup 1
```

Check QKD host 2:

```bash
./scripts/validate_security_mode.sh qkd startup 2
```

Expected QKD evidence includes:

```text
[ OK ] Installed profile: SAE 1
[ OK ] KME accepted the SAE certificate over mutual TLS
axon_daemon: QKD mode enabled for SAE sae-1
axon_daemon: security mode qkd
== STARTUP CHECK PASSED ==
```

The SAE number is `2` on the second host.

## 5. End-to-end classic test

Start the listener on the first host:

```bash
./scripts/validate_security_mode.sh classic listener
```

Within 60 seconds, start the talker on the second host:

```bash
./scripts/validate_security_mode.sh classic talker
```

The listener must finish with:

```text
[ OK ] Remote AXON daemon discovered
[ OK ] Daemon-to-daemon QUIC connection established
[ OK ] Listener received ROS messages from the remote host
== END-TO-END classic TEST PASSED ==
```

## 6. End-to-end QKD test

The first host must have been built with `AXON_QKD_ROLE=1`; run:

```bash
./scripts/validate_security_mode.sh qkd listener 1
```

Within 60 seconds, on the host built with `AXON_QKD_ROLE=2`, run:

```bash
./scripts/validate_security_mode.sh qkd talker 2
```

Both terminals must show:

```text
[ OK ] KME accepted the SAE certificate over mutual TLS
[ OK ] Remote AXON daemon discovered
[ OK ] Daemon-to-daemon QUIC connection established
[ OK ] QKD key was negotiated through the KME flow
== END-TO-END qkd TEST PASSED ==
```

The daemon log also contains one side of the key exchange:

```text
axon_daemon: QKD session ... established with daemon ...
```

or:

```text
axon_daemon: imported QKD key ... for daemon ...
```

Only the public `key_ID` is printed; the QKD key itself is never logged.

## 7. Networks without multicast discovery

By default, AXON uses multicast `239.255.0.2:7403` and daemon UDP port `7402`.
If multicast is blocked, specify the other host's reachable IP on both
machines.

First host, where the second host is `192.168.1.22`:

```bash
AXON_TEST_PEER=192.168.1.22:7402 \
  ./scripts/validate_security_mode.sh qkd listener 1
```

Second host, where the first host is `192.168.1.21`:

```bash
AXON_TEST_PEER=192.168.1.21:7402 \
  ./scripts/validate_security_mode.sh qkd talker 2
```

Replace the addresses with the real host addresses. The same option works for
the classic test. In QKD mode the script also assigns the expected remote SAE
automatically (`sae-2` from host 1 and `sae-1` from host 2); no additional QKD
environment variable is required.

## 8. Negative tests

These checks demonstrate fail-closed behavior.

### QKD requested from a normal build

On a normal build with no SAE:

```bash
./scripts/validate_security_mode.sh qkd startup 1
```

Expected result:

```text
[FAIL] No installed QKD profile. Run: cd ... && colcon build --packages-select rmw_axon --cmake-args -DAXON_QKD_ROLE=1
```

### Wrong SAE selected

On a host compiled with role 1:

```bash
./scripts/validate_security_mode.sh qkd startup 2
```

Expected result:

```text
[FAIL] This installation contains SAE 1, not SAE 2
```

### Mismatched modes

Run `classic listener` on one host and `qkd talker 2` on the other. AXON must
log an incompatible security profile and the script must fail without reporting
a QUIC/QKD end-to-end success. This demonstrates that QKD does not silently
fall back to classic.

## Logs and troubleshooting

Each run prints the directory containing its complete logs, for example:

```text
/tmp/axon-security-qkd.ABC123/daemon.log
/tmp/axon-security-qkd.ABC123/listener.log
```

Common causes of failure:

- the workspace was not sourced after rebuilding;
- both hosts were built with the same SAE;
- an old `axon_daemon` is still running;
- different `ROS_DOMAIN_ID` values are in use;
- UDP ports `7402` or `7403` are blocked;
- multicast is unavailable and `AXON_TEST_PEER` was not set;
- the QuKayDee account, certificates, or key stream have expired.
