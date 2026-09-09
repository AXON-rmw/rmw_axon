# AXON external-PSK patch

This branch is based on upstream rustls `v/0.23.40`. It adds the narrow TLS 1.3
external-PSK API required by AXON's QKD transport mode.

## Scope

- A client can provide one external PSK identity and secret.
- A server can resolve external PSKs by identity.
- External binders use the RFC 8446 `ext binder` label.
- External-PSK handshakes use `psk_ke` without a key share.
- TLS 1.3 resumption behavior remains separate and uses `res binder`.

The patch does not implement PSK provisioning, key rotation, peer discovery, or
QKD. AXON owns those responsibilities and passes key material to rustls.

## Security properties

The server selects an external PSK only after resolving the offered identity and
verifying its binder in constant time. An unknown identity or incorrect binder
aborts the handshake. External-PSK mode deliberately has no independent
Diffie-Hellman forward secrecy; the application must protect and erase the PSK
according to its threat model.

## Maintenance

AXON must pin this repository by an immutable commit hash. Upstream rustls
updates should be rebased onto their corresponding release tag, reviewed as a
small patch, and validated with both the rustls test suite and AXON's real QUIC
external-PSK integration tests.
