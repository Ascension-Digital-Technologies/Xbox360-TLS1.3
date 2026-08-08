# Changelog

## 1.0.0 — 2026-08-07

Initial public release.

XboxTLS13 v1.0.0 provides a dependency-free TLS 1.3 client profile for Xbox 360/XDK projects, including AES-128-GCM/SHA-256 records, X25519 and P-256 key exchange, HelloRetryRequest, native RSA-PSS and P-256 ECDSA verification, supported-profile X.509 validation, SNI/ALPN, compact XTS1 trust stores, alerts, `KeyUpdate`, fragmented handshake handling, buffered application reads, and an Xbox HTTPS example.

The repository also includes portable host tests, an optional OpenSSL reference verifier, CMake presets/install support, and Linux/Windows CI.

Xbox/XDK adapter code still requires validation with the proprietary XDK and real hardware.
