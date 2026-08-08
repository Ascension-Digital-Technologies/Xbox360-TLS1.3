# XboxTLS13

XboxTLS13 is a TLS 1.3 client for Xbox 360 projects built with the Microsoft Xbox 360 XDK.

This repository is an **Xbox 360 XDK solution first**. Open `XboxTLS13.sln`, select `Debug | Xbox 360` or `Release | Xbox 360`, and build. The solution contains the TLS static library and a real Xbox application project that produces a `.xex`.

The CMake files are still included, but they are for host-side tests and CI. You do not need CMake to build the Xbox 360 target.

XboxTLS13 is an independent open-source project and does not include any Microsoft XDK files.

## Xbox 360 solution

The solution contains two projects:

```text
XboxTLS13
    Static library containing TLS 1.3, cryptography, X.509, and Xbox networking.

XboxTLS13Demo
    Xbox 360 Application that links XboxTLS13 and builds to XboxTLS13Demo.xex.
```

The XDK project files live under `xdk/`, while `XboxTLS13.sln` is at the repository root.

## Build the XEX

### Visual Studio

1. Install/configure the Xbox 360 XDK and its Visual Studio integration.
2. Open `XboxTLS13.sln`.
3. Select either:
   - `Debug | Xbox 360`
   - `Release | Xbox 360`
4. Set `XboxTLS13Demo` as the startup project.
5. Build the solution.

The intended output is:

```text
bin\Release\XboxTLS13.lib
bin\Release\XboxTLS13Demo.xex
```

or the matching `Debug` directory.

### Command line

From an Xbox 360 XDK command prompt:

```bat
build-xex.bat
```

For a debug build:

```bat
build-xex.bat debug
```

The script checks that the XDK environment is present and builds the `Xbox 360` solution configuration with MSBuild.

## XEX configuration

The executable project includes:

```text
xdk/XboxTLS13Demo/xex.xml
```

It contains the ImageXex configuration used by the sample executable. The current title ID is a development/homebrew placeholder; change it to the title ID appropriate for your own project before distributing anything based on the demo.

The actual TLS library is a `.lib`. That is intentional: applications link the library, while `XboxTLS13Demo` demonstrates a complete `.xex` target.


## xkelib dependency

The Xbox target includes the `xkelib` compatibility package under:

```text
external/xkelib/
```

It is used for Xbox kernel declarations/imports that are not exposed by every XDK header set. In particular, `XeCryptRandom` is declared by `xkelib` and linked through `xkelib.lib`.

The Xbox project files already add `external\xkelib` to their include paths and link `xkelib.lib` into the XEX target, so you should not need to copy it into your global XDK installation.


## Drop-in embedding API

For most Xbox projects, you do not need to wire `Xbox360Platform`, `Xbox360SocketStream`, `NativeServerAuthVerifier`, and `TlsClient` manually anymore.

Use the high-level Xbox wrapper:

```cpp
#include "xboxtls/xboxtls.h"

using namespace xboxtls;

XboxTlsClient tls;

if (tls.initialize() != XT_OK)
    return;

if (tls.connect("example.com") != XT_OK)
    return;

const char request[] =
    "GET / HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Connection: close\r\n\r\n";

tls.send(request, sizeof(request) - 1);

char buffer[1024];
size_t received = 0;

while (tls.receive(buffer, sizeof(buffer), &received) == XT_OK) {
    // Use the decrypted bytes in buffer[0..received).
}

tls.close();
```

`initialize()` uses `game:\roots.xts` by default. `connect()` defaults to port 443 and ALPN `http/1.1`.

The wrapper owns:

- Xbox networking startup and cleanup
- the TCP socket
- the TLS connection state
- the native certificate verifier
- trust-store memory
- reconnect/reset handling

If your project needs custom transport or verifier behavior, the lower-level `TlsClient` API is still available.

### Embedding in an existing XEX

The cleanest option is to add the `XboxTLS13` project from `XboxTLS13.sln` to your existing solution and add a project reference from your XEX project.

Then include:

```cpp
#include "xboxtls/xboxtls.h"
```

Your XEX project needs access to:

```text
include\
external\xkelib\
```

and it needs `xkelib.lib` available to the linker. The XboxTLS13 project already contains the rest of the TLS implementation.


## Advanced embedding options

The two-call path still works:

```cpp
XboxTlsClient tls;
tls.initialize();
tls.connect("example.com");
```

For projects that need tighter control, use `XboxTlsOptions`:

```cpp
XboxTlsOptions options;
options.trust_store_path = "game:\\certs\\roots.xts";
options.port = 443;

// Single protocol or comma-separated preference order.
options.alpn = "h2,http/1.1";
options.require_alpn = true;

// Prefer P-256 first instead of the default X25519.
options.preferred_group = GROUP_SECP256R1;

// Add zero-byte TLSInnerPlaintext padding to application records.
options.application_record_padding = 32;

// Applied to the connected Xbox socket. Zero keeps the platform default.
options.send_timeout_ms = 10000;
options.receive_timeout_ms = 15000;

// Optional 32-byte SHA-256 hash of the DER leaf certificate.
// This is checked in addition to normal chain + hostname validation.
options.certificate_sha256_pin = expected_leaf_sha256;

options.auto_reconnect = true;
options.send_close_notify = true;
options.request_peer_key_update = false;

XboxTlsClient tls;

if (tls.initialize(options) != XT_OK)
    return;

if (tls.connect("api.example.com", options) != XT_OK) {
    printf("TLS error: %d alert=%u/%u\n",
           (int)tls.last_error(),
           (unsigned)tls.last_alert_level(),
           (unsigned)tls.last_alert_description());
    return;
}
```

### Available controls

`XboxTlsOptions` currently exposes:

- `trust_store_path`
- `port`
- `alpn`
- `require_alpn`
- `preferred_group` (`GROUP_X25519` or `GROUP_SECP256R1`)
- `application_record_padding` (clamped to 255 bytes)
- `send_timeout_ms`
- `receive_timeout_ms`
- `certificate_sha256_pin`
- `auto_reconnect`
- `send_close_notify`
- `request_peer_key_update`

ALPN accepts either one protocol:

```cpp
options.alpn = "http/1.1";
```

or a comma-separated preference list:

```cpp
options.alpn = "h2,http/1.1";
```

The wire format is a normal TLS ALPN protocol-name list; the comma-separated string is only the convenient C++ configuration format.

### Certificate pinning

Pinning does not replace trust validation. XboxTLS13 first validates the certificate chain and hostname, then compares the SHA-256 digest of the DER leaf certificate when a pin is configured.

```cpp
xt_u8 pin[32] = {
    // expected SHA-256 digest
};

options.certificate_sha256_pin = pin;
```

A pin mismatch returns `XT_ERR_VERIFY`.

### Manual traffic-key rotation

```cpp
tls.key_update();
```

To rotate the local application traffic key and ask the peer to update its sending key too:

```cpp
tls.key_update(true);
```

### Runtime trust-store reload

```cpp
tls.reload_trust_store("game:\\certs\\new-roots.xts");
```

### Connection statistics

```cpp
const XboxTlsStats& stats = tls.stats();

printf("sent: %llu\n", stats.bytes_sent);
printf("received: %llu\n", stats.bytes_received);
printf("connect attempts: %u\n", stats.connect_attempts);
printf("successful connections: %u\n", stats.successful_connections);
printf("failed connections: %u\n", stats.failed_connections);
printf("key updates: %u\n", stats.key_updates_sent);
```

Use `tls.reset_stats()` to clear the counters.

The lower-level `TlsClient` API is still available when you need a custom transport, verifier, or direct protocol control.

## Running the demo

`XboxTLS13Demo.xex` performs an authenticated TLS 1.3 HTTPS request.

Before running it, create a trust store from DER root certificates:

```sh
python dev/dev/tools/make_trust_store.py roots.xts root1.der root2.der
```

Deploy the resulting file beside the XEX as:

```text
game:\roots.xts
```

The example in `xdk/XboxTLS13Demo/main.cpp` then:

1. starts Xbox networking,
2. loads `roots.xts`,
3. resolves and connects to `example.com:443`,
4. performs the TLS 1.3 handshake,
5. verifies the certificate and hostname,
6. sends an HTTP request,
7. receives encrypted application data until the connection closes.

## Supported TLS profile

v1.0.0 currently implements:

- TLS 1.3
- `TLS_AES_128_GCM_SHA256`
- X25519
- secp256r1 / P-256 ECDH
- HelloRetryRequest
- SNI
- ALPN
- RSA-PSS/SHA-256 authentication
- P-256 ECDSA/SHA-256 authentication
- supported-profile DER/X.509 chain validation
- hostname/SAN validation
- compact `XTS1` trust stores
- fragmented handshake reassembly
- TLS alerts and `close_notify`
- `KeyUpdate`
- buffered application reads

Unsupported security-critical algorithms and malformed input fail closed.

## Project layout

```text
XboxTLS13.sln                Xbox 360 Visual Studio solution
build-xex.bat                Xbox 360 command-line build
xdk/
  XboxTLS13/                 Xbox static-library project
  XboxTLS13Demo/             Xbox application/XEX project
    xex.xml                  XEX image configuration

include/xboxtls/             Public headers
src/
  crypto/                    Portable cryptographic code
  tls/                       TLS 1.3 protocol and connection state
  x509/                      DER/X.509 and trust-store handling
  verifier/native/           Dependency-free native verifier
  platform/xbox360/          Xbox networking and entropy adapter

xdk/XboxTLS13Demo/main.cpp   XEX demo entry point
dev/```

## Host tests

CMake is used only for portable validation and CI.

Dependency-free tests:

```sh
cmake --preset portable
cmake --build --preset portable
ctest --preset portable
```

The default host preset also builds the optional OpenSSL reference verifier when OpenSSL is installed:

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

OpenSSL is not linked into the Xbox 360 TLS library.

## XDK compatibility

The Xbox-specific code is isolated to:

```text
include/xboxtls/xbox360_platform.h
src/platform/xbox360/platform_xbox360.cpp
xdk/
```

The adapter uses Xbox Winsock/XNet and `XeCryptRandom`. There is no `rand()` fallback for TLS key material.

Xbox 360 XDK revisions can differ in their Visual Studio integration and exact SDK declarations. The portable host implementation and tests can be validated here, but the final `.xex` project still has to be built with the XDK revision installed on your Windows development machine. If that build exposes an XDK-specific project or API difference, it should be fixed in `xdk/` or the Xbox platform adapter rather than changing the TLS core.

See `xdk/README.md` for the target-side checklist.

## Security

TLS and certificate-validation code is security-sensitive. XboxTLS13 has host-side regression and differential tests, but it has not received an independent cryptographic audit. Validate the exact Xbox build on hardware before relying on it for sensitive production traffic.

See `SECURITY.md` for vulnerability reporting.

## License

MIT. See `LICENSE`.
