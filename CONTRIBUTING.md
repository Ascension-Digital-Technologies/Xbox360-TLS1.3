# Contributing

Contributions are welcome, especially fixes that improve Xbox 360 compatibility, protocol correctness, parser robustness, or test coverage.

A few rules keep the project maintainable:

- keep the portable library C++98-compatible and dependency-free,
- keep Xbox/XDK-specific code inside the Xbox platform adapter,
- do not add insecure fallbacks for entropy, certificate validation, hostname checks, or cryptographic failures,
- do not advertise algorithms the native implementation cannot actually process,
- add regression tests for protocol, parser, certificate, or cryptographic changes,
- run both the portable and reference test configurations before opening a pull request.

```sh
cmake --preset portable
cmake --build --preset portable
ctest --preset portable

cmake --preset default
cmake --build --preset default
ctest --preset default
```

OpenSSL is allowed only in the optional host reference verifier and its tests. The `xboxtls13` target itself must continue to build without it.

Please keep changes focused. Generated files, build output, proprietary XDK material, unrelated binaries, and progress-note documentation do not belong in the repository.
