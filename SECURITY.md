# Security

XboxTLS13 implements security-sensitive protocol and cryptographic code. If you find a vulnerability that could affect confidentiality, integrity, certificate validation, authentication, or key material, please report it privately instead of opening a public issue.

For a public GitHub repository, enable **Private vulnerability reporting** in the repository security settings and use GitHub's vulnerability-reporting flow.

Security fixes target the current release line.

The library is designed to fail closed when it encounters malformed input or an unsupported security-critical algorithm. That is not a substitute for an independent audit. Before using XboxTLS13 for security-sensitive production traffic, validate the target build on real hardware and perform parser fuzzing, side-channel review, and external cryptographic review.
