# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in confidential-ml-transport, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use one of these channels:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/cyntrisec/confidential-ml-transport/security/advisories/new)
2. **Email**: contact@cyntrisec.com

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix**: Depends on severity; critical issues prioritized

## Scope

- **Handshake and session security** (3-message mutual handshake, session key derivation, channel binding)
- **Cryptographic implementation** (HPKE, ChaCha20-Poly1305 AEAD, Ed25519 verification)
- **Frame codec** (binary framing, size limits, parser strictness, memory-allocation bounds)
- **Attestation verification** (Nitro NSM documents, TDX DCAP quotes, SEV-SNP and Azure SEV-SNP reports, certificate chain and CRL validation, measurement pinning)
- **Key material handling** (zeroization, session key lifecycle)
- **Security profile enforcement** (fail-closed `Production` defaults, expected-measurement policy)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes       |
| < 0.6   | No        |

## Security Design

For the security-relevant design decisions (frame-size limits, parser strictness, memory-allocation strategy, key material protection), see [`docs/SECURITY_DESIGN.md`](docs/SECURITY_DESIGN.md).
