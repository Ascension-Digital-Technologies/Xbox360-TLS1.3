# Xbox 360 XDK integration

The repository already contains the Xbox 360 solution and projects. You should not need to create a generic C++ project and manually add every source file.

## Open the solution

Open:

```text
XboxTLS13.sln
```

The solution has these Xbox 360 configurations:

```text
Debug | Xbox 360
Release | Xbox 360
```

`XboxTLS13` builds the reusable static library.

`XboxTLS13Demo` is an Xbox 360 **Application** project and is the project that produces the XEX.

## Expected output

A Release build is intended to produce:

```text
bin\Release\XboxTLS13.lib
bin\Release\XboxTLS13Demo.xex
```

The Debug configuration uses `bin\Debug\`.

The executable project includes its ImageXex configuration at:

```text
xdk\XboxTLS13Demo\xex.xml
```

If your particular XDK Visual Studio integration exposes the ImageXex configuration through a project-property field, point that field at this file. Different XDK releases used slightly different Visual Studio property integrations, which is why the file is kept beside the XEX project instead of mixing XEX metadata into the TLS source.

## Build script

Run from an Xbox 360 XDK command prompt:

```bat
build-xex.bat
```

or:

```bat
build-xex.bat debug
```

The script expects `XEDK` to be set by the XDK environment.

## Platform APIs

Only the Xbox adapter should directly depend on the XDK:

```text
include\xboxtls\xbox360_platform.h
src\platform\xbox360\platform_xbox360.cpp
```

It uses:

- Xbox networking startup/cleanup through the XDK Winsock/XNet declarations
- Xbox Winsock-compatible TCP sockets
- `XeCryptRandom` through the bundled `external\\xkelib` compatibility headers/import library
- Xbox system time

Keep XDK-specific fixes there. Do not spread XDK headers or `_XBOX` special cases throughout the TLS, crypto, or X.509 implementation.

## Trust store

Generate an `XTS1` trust store on the development PC:

```sh
python tools/make_trust_store.py roots.xts root1.der root2.der
```

Deploy it as:

```text
game:\roots.xts
```

The sample intentionally fails instead of disabling verification when the trust store is missing or invalid.

## Hardware validation checklist

After the XEX builds, verify these paths on real hardware:

- X25519 TLS 1.3 handshake
- P-256 HelloRetryRequest handshake
- RSA-PSS certificate authentication
- P-256 ECDSA certificate authentication
- valid hostname acceptance
- hostname mismatch rejection
- untrusted root rejection
- expired certificate rejection
- fragmented handshake records
- `KeyUpdate`
- small application receive buffers
- peer `close_notify`
- malformed record rejection

The host CMake tests do not replace this target-side validation.
