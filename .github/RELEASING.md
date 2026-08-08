# Releasing XboxTLS13

Keep releases simple and reproducible.

## Before tagging

Run both supported host configurations:

```sh
cmake --preset portable
cmake --build --preset portable
ctest --preset portable

cmake --preset default
cmake --build --preset default
ctest --preset default
```

Then verify:

- the version in `CMakeLists.txt` matches the public version macros,
- the source tree contains no build directories or generated binaries,
- no private keys or generated trust stores are committed,
- no proprietary XDK headers, libraries, or SDK files are present,
- `CHANGELOG.md` describes the release,
- the Xbox adapter still remains isolated from the portable core.

For an Xbox-validated release, also record the XDK revision and the hardware/server combinations used for interoperability testing.

## Tag and publish

Tag the tested commit as `vMAJOR.MINOR.PATCH`, create the GitHub release from that tag, and attach checksums for any manually packaged archives.

Do not maintain duplicate per-version release documents in the repository. GitHub Releases and `CHANGELOG.md` are the release history.
