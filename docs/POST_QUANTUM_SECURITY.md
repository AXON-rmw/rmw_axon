# Scope of AXON's Post-Quantum Security Claims

AXON now exposes two alternative, fail-closed key-establishment modes:

- `classic`: mandatory hybrid X25519+ML-KEM-768;
- `qkd`: QKD-derived TLS 1.3 external PSK, with no X25519 or ML-KEM exchange.

Both modes encrypt ROS traffic once through QUIC using ChaCha20-Poly1305 or
AES-256-GCM. They are alternatives, not stacked layers. See
[`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) for the protocol design and
[`QKD.md`](QKD.md) for deployment.

## Claims supported by the current implementation

- Classic mode enforces hybrid X25519+ML-KEM-768 key establishment without a
  classical-only fallback.
- QKD mode imports a 256-bit KME key into TLS 1.3 as an external PSK and proves
  possession through the TLS binder.
- Both modes restrict ROS 1-RTT traffic to ChaCha20-Poly1305 or AES-256-GCM.
- Invalid modes, obsolete encryption variables, missing QKD configuration, and
  mismatched peer modes fail closed.

## Claims not supported

- **Classic mode is not an authenticated channel.** Its ephemeral self-signed
  certificate is accepted without a trust root or pinned peer identity. The
  implementation therefore does not currently resist an active
  man-in-the-middle.
- **A QKD simulator is not physical QKD.** QuKayDee validates the ETSI API and
  key-lifecycle integration, not a quantum optical channel.
- **Bundled beta SAE credentials are not production identity provisioning.**
  Once the test credentials are distributed with the source, possession no
  longer identifies one exclusive host. Production authentication claims
  require separately provisioned SAE credentials.
- **The KME path is not made post-quantum by AXON.** The security of KME HTTPS,
  SAE credentials, KME storage, and the physical QKD network remains outside
  the AXON transport.
- **QKD PSK-only mode has no independent Diffie-Hellman forward secrecy.**
  Disclosure of a daemon-pair key can expose recorded traffic from that
  session.
- **Local SHM traffic is not encrypted.** It relies on host isolation and SHM
  permissions.

## Recommended scientific wording

Describe classic mode as providing **hybrid post-quantum key establishment and
encrypted transport against passive capture, under the security assumptions of
ML-KEM-768**. Do not claim end-to-end authenticated post-quantum security until
peer identity validation is implemented and evaluated.

Describe QKD mode as an **ETSI GS QKD 014 integration that imports KME-derived
key material into TLS 1.3 external-PSK key establishment**. State whether the
evaluation used QuKayDee or physical QKD hardware. A physical-quantum guarantee
depends on the QKD devices, KME design, SAE authentication, and deployment
threat model, not only on AXON. Treat the bundled `AXON_QKD_ROLE=1|2` profiles
as simulator test fixtures, not evidence of production credential secrecy.
