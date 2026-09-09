# AXON Cryptography

## Security model

AXON protects remote ROS 2 traffic inside QUIC. QKD supports either one KME
bootstrap key per QUIC session or an additional application envelope whose KME
key rotates every 10 outgoing messages. Local
shared-memory traffic does not enter QUIC and is protected by the local Unix
account and SHM permissions.

AXON supports exactly two key-establishment modes:

| Mode | TLS 1.3 key establishment | Fallback |
| --- | --- | --- |
| `classic` | Hybrid X25519 + ML-KEM-768 | None |
| `qkd` | ETSI QKD 014 key imported as an external PSK using `psk_ke` | None |

Both modes use normal QUIC 1-RTT packet protection. Select the traffic cipher
with `AXON_QUIC_CIPHER=chacha20|aes256`. ChaCha20-Poly1305 is the default.
AES-128-GCM is not offered as a TLS traffic suite.

The per-message QKD envelope applies only to remote QUIC traffic. Nodes on the
same host use the shared-memory ring, so no QKD key is needed for that local
path. A single-host test therefore validates QKD startup/profile handling but
not the remote KME message-key exchange unless two isolated daemons are used.

Key establishment, traffic encryption, and peer authentication are different
properties:

| Mode | Key establishment | Traffic protection | Peer identity |
| --- | --- | --- | --- |
| `classic` | Hybrid X25519+ML-KEM-768 | QUIC AEAD | Not authenticated: the ephemeral self-signed certificate is accepted without a configured trust root |
| `qkd` | External PSK obtained through the KME flow | QUIC AEAD | TLS binder authenticates possession of the same QKD-derived PSK |

Consequently, `classic` supports a post-quantum confidentiality claim against
passive capture under the ML-KEM assumptions, but not an authenticated-channel
claim against an active man-in-the-middle. Correct peer authentication requires
a future certificate, pinned-key, or equivalent identity mechanism.

QUIC v1 requires AES-128-GCM to derive Initial packet keys. Those keys protect
public, temporary handshake Initial packets and are independent from the
negotiated 1-RTT suite that protects ROS data. This protocol requirement cannot
be replaced by AES-256 or ChaCha20.

## Classic mode

```bash
export AXON_SECURITY_MODE=classic
export AXON_QUIC_CIPHER=chacha20
```

The rustls provider contains one key-exchange group:
`X25519MLKEM768`. A peer that cannot negotiate the hybrid group is rejected.
There is no X25519-only, P-256, or P-384 fallback.

`X25519MLKEM768` combines a classical X25519 secret and an ML-KEM-768 secret in
the TLS key schedule. This protects against a failure in either individual
component while providing post-quantum key-establishment security under the
assumptions of ML-KEM.

The server certificate is generated at runtime and the client currently uses a
custom verifier that accepts it without checking a trust anchor or pinned
identity. The TLS transcript and records are internally integrity-protected, but
they are not bound to an independently authenticated AXON peer. An active
attacker able to intercept discovery and transport traffic can therefore
establish separate encrypted sessions with each side.

## QKD mode

```bash
export AXON_SECURITY_MODE=qkd
export AXON_QUIC_CIPHER=chacha20
export AXON_QKD_KEY_MODE=messages10  # or session
```

For the bundled two-host QuKayDee beta test, compile one workspace with
`-DAXON_QKD_ROLE=1` and the other with `-DAXON_QKD_ROLE=2`. A normal build
selects neither SAE. See [`QKD.md`](QKD.md) for the exact `colcon` commands.

The daemon obtains a 256-bit key from its KME. The peer obtains the matching
key by its public `key_ID`. AXON applies HKDF-SHA256 with the domain label
`AXON-QKD-TLS13-EXTERNAL-PSK-v1`, then gives the derived value and a namespaced
identity to TLS 1.3.

The QKD TLS provider has an empty key-exchange group list. The client sends
`psk_ke`, no `supported_groups`, and no `key_share`. The server selects the
external PSK only after resolving its identity and verifying the TLS binder.
The handshake cannot fall back to X25519, ML-KEM, a certificate-only exchange,
or plaintext.

The bootstrap key identifier is not secret and is announced before QUIC starts.
Per-message envelopes likewise carry only a key identifier and SAE metadata;
the raw KME keys are never sent between AXON peers. A spoofed announcement or
ACK can cause retries, but it cannot create the TLS binder without the key.

QKD mode intentionally uses TLS 1.3 `psk_ke`, so it has no independent
Diffie-Hellman forward secrecy. Its security depends on the QKD session key
remaining secret and being erased after the daemon session. Compromise of that
key can expose captured traffic from the same session. Classic mode retains
hybrid ephemeral key establishment through X25519+ML-KEM-768, but currently
lacks peer-identity authentication.

The bundled QuKayDee credentials favor rapid simulator deployment. Because
they are distributed as test fixtures, they do not provide production-grade
exclusive SAE identity; replace them before making that authentication claim.

## QKD message envelope

The `messages10` strategy uses a small `AXQKD001` envelope around each remote topic, service, and
action payload. It contains the wire context, a random nonce, sender SAE, and
KME `key_ID`, followed by AES-256-GCM ciphertext. The receiver obtains the
matching key from its KME and rejects context mismatches, authentication
failures, and malformed envelopes. QUIC remains the authenticated transport
and protects the envelope in transit; classic mode does not add this envelope.
Each KME key protects exactly 10 outgoing messages and each message uses an
independent random nonce.

## Fail-closed behavior

Startup rejects:

- any `AXON_SECURITY_MODE` other than `classic` or `qkd`;
- any `AXON_QUIC_CIPHER` other than `chacha20` or `aes256`;
- obsolete `AXON_SECURITY_PROFILE`, `AXON_ENCRYPTION_MODE`, or
  `AXON_ENCRYPTION_KEY` variables;
- QKD mode without a complete KME/SAE configuration.

Connection setup rejects:

- peers advertising a different security mode;
- classic peers that do not negotiate X25519+ML-KEM-768;
- QKD peers without a locally available daemon-pair key;
- unknown external-PSK identities or incorrect binders.

Fail-closed mode and cipher negotiation prevents silent fallback. It does not
fix classic mode's missing identity validation and should not be described as
protection against an active man-in-the-middle.

## rustls patch

rustls 0.23.40 does not expose TLS 1.3 external PSKs through its public API.
AXON therefore vendors the `rustls-axon` fork, based on the official
`v/0.23.40` tag and pinned to an immutable upstream commit. The fork adds a
narrow API:

- `ExternalPsk`, which stores a public identity and zeroized secret;
- `ResolvesExternalPsk`, used by the server;
- external-binder derivation with the RFC 8446 `ext binder` label;
- PSK-only client/server handshake paths without a key share.

The rest of TLS record and QUIC packet protection remains rustls/quinn code.
The fork must be rebased and audited whenever the pinned rustls version changes.
Its source is included under `third_party/rustls-axon`, so build and CI
machines do not need access to a second repository.

## Test coverage

- `security_mode` unit tests reject invalid modes and AES-128 selection.
- `quic_transport` unit tests pin the exact classic group, QKD's empty group
  list, both allowed 256-bit traffic suites, and shutdown behavior.
- `qkd_quic_psk` performs real QUIC round trips with an external QKD PSK using
  both traffic ciphers, and rejects missing or mismatched key material.
- Existing QUIC, service, daemon, SHM, graph, and ROS end-to-end suites validate
  the surrounding transport behavior.
