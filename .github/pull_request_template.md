## Summary

Describe the change and why it is needed.

## Verification

- [ ] `ctest --preset portable` passes
- [ ] `ctest --preset default` passes when OpenSSL is available
- [ ] No insecure verification/entropy fallback was introduced
- [ ] New protocol/parser behavior has tests
- [ ] Portable core remains C++98-compatible
