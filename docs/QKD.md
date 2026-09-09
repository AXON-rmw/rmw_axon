# Native QKD Mode

## Purpose

QKD mode replaces the classic X25519+ML-KEM-768 TLS key exchange. A daemon-pair
key from the KME authenticates the TLS 1.3 QUIC bootstrap. `session` uses that
exchange only and lets QUIC derive its traffic keys. `messages10` additionally
seals every remote ROS message in an AEAD envelope and rotates its KME key after
10 outgoing messages. QKD bytes are never sent on the wire and are not used as
a one-time pad.

## Beta build for two hosts

The repository includes the two QuKayDee identities used by the beta test, but
neither identity is selected by default. A normal build:

```bash
colcon build --packages-select rmw_axon
```

installs no SAE profile. AXON consequently starts in its default `classic`
mode, and requesting `qkd` fails closed unless another profile or explicit QKD
configuration is available.

For a two-machine QKD beta test, compile the first host with:

```bash
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=1
```

Compile the second host with:

```bash
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=2
```

After sourcing each workspace, select QKD with:

```bash
export RMW_IMPLEMENTATION=rmw_axon
export AXON_SECURITY_MODE=qkd
export AXON_QKD_KEY_MODE=messages10
```

Or select the standard mode with:

```bash
export RMW_IMPLEMENTATION=rmw_axon
export AXON_SECURITY_MODE=classic
```

Changing mode requires restarting the AXON nodes and daemon. All communicating
hosts must use the same mode, QKD key strategy, and traffic cipher.

On one ordinary host, all ROS processes share one AXON daemon and local topic
traffic uses the shared-memory ring. That path has no peer SAE and therefore
does not consume a QKD message key. The QKD role (`AXON_QKD_ROLE=1` or `2`)
identifies the SAE/KME profile used by a daemon when it talks to a *different*
daemon. To exercise both roles on one physical machine, run two isolated
containers/IPC namespaces (or two separate hosts) with one profile in each;
two daemons cannot share the same QKD store.

The selected build profile is installed under `share/rmw_axon/qkd`. AXON
discovers it from the sourced ROS/colcon prefix or from `AXON_DAEMON_PATH`;
the daemon can also resolve it relative to its installed executable. No KME
URL, SAE ID, or certificate-path variable is needed at runtime. The profiles
are intentionally limited to `sae-1`/`kme-1` and `sae-2`/`kme-2` on the
configured QuKayDee beta account.

These bundled simulator credentials prioritize rapid beta deployment over
identity secrecy. They must be replaced for production or for any evaluation
whose authentication claim assumes an SAE private key known only to one host.

## Custom or production deployment

Each host needs an ETSI GS QKD 014 KME endpoint, one SAE identity, the KME CA
certificate, its SAE certificate and private key, and a key stream shared with
the peer SAE. Explicit configuration overrides the bundled beta profile:

```bash
export AXON_SECURITY_MODE=qkd
export AXON_QKD_KME_BASE_URL="https://kme-1.example/api/v1/keys"
export AXON_QKD_LOCAL_SAE_ID="sae-1"
export AXON_QKD_CA_CERT="$HOME/.config/axon/qkd/server-ca.crt"
export AXON_QKD_CLIENT_CERT="$HOME/.config/axon/qkd/sae-1.crt"
export AXON_QKD_CLIENT_KEY="$HOME/.config/axon/qkd/sae-1.key"
```

`AXON_QKD_MAX_IN_FLIGHT` limits simultaneous KME requests per process (default
`4`, range `1..32`). Set it to `1` for low-rate API simulators. Message-key
rotation in `messages10` is fixed at 10 outgoing messages and is not
configurable. Every message receives a fresh random AES-GCM nonce. Select one
of the only two supported strategies with `AXON_QKD_KEY_MODE=session|messages10`;
the default is `messages10`.

Alternatively, `AXON_QKD_PROFILE_DIR` may point to a directory containing
`profile`, the KME CA, and the matching SAE certificate and key. Explicit
`AXON_QKD_*` KME/SAE variables take precedence over every profile.

## Establishment flow

1. Daemons discover each other and advertise `qkd` plus their SAE IDs.
2. The daemon with the lower daemon ID asks its KME for a key targeting the
   remote SAE (`enc_keys`).
3. It sends only the returned `key_ID` and its SAE ID to the peer over the
   discovery control socket.
4. The peer asks its KME for that identifier (`dec_keys`) and stores the
   matching 256-bit value.
5. The peer acknowledges the public identifier. Announcements and ACKs are
   retried through discovery heartbeats.
6. Each side derives a TLS-specific PSK with HKDF-SHA256.
7. QUIC starts a TLS 1.3 external-PSK handshake without any EC or ML-KEM key
   share.
8. The TLS binder proves that both peers hold the same KME key. QUIC derives
   unique handshake and 1-RTT traffic keys for each connection.
9. In `messages10`, the sender requests a KME key, uses it for 10 outgoing
   message envelopes with independent nonces, and then rotates it. The receiver
   retrieves each new key with `dec_keys` before AEAD verification. In
   `session`, this application-envelope step is omitted.

The public UDP control exchange is bootstrap metadata, not a secret transport.
Spoofing it cannot produce a valid TLS binder, although it can cause denial of
service. KME HTTPS uses mutual TLS and remains a separate trust boundary.

## Failure behavior

QKD mode stops remote setup when:

- either KME is unavailable;
- the SAE or key-stream configuration is wrong;
- the peer does not advertise QKD mode;
- the peer cannot retrieve the announced `key_ID`;
- the TLS external-PSK identity is unknown;
- binder verification fails.

There is no fallback to classic ML-KEM, a file PSK, or plaintext. If a required
message key cannot be obtained or verified, that message is rejected. The KME
is therefore intentionally on the remote publish/service path. A new
daemon-pair session still requires the bootstrap KME exchange.

Because this is TLS 1.3 PSK-only (`psk_ke`), QKD mode does not add an
independent ephemeral Diffie-Hellman secret. The daemon-pair key must be erased
at session end: disclosure of that key can compromise recorded traffic from the
same session. Classic mode instead derives its session through ephemeral
X25519+ML-KEM-768.

## Local test KME

HTTP is accepted only when explicitly enabled:

```bash
export AXON_QKD_ALLOW_INSECURE_HTTP=1
export AXON_QKD_KME_BASE_URL="http://127.0.0.1:8080/api/v1/keys"
```

Use this solely for isolated automated tests. It does not represent a secure or
physical-QKD deployment.

## Security interpretation

QuKayDee and similar services reproduce KME/SAE APIs and key lifecycle but do
not turn a normal Internet link into a physical quantum channel. Claims for a
paper must distinguish:

- API-level QKD integration validated with a simulator;
- physical QKD security, which requires real QKD hardware and a justified KME
  trust model;
- post-quantum software key establishment in classic mode through ML-KEM.
