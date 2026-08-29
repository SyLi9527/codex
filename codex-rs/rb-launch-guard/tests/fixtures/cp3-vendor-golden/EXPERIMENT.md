# CP3 vendor golden provenance

This fixture was reproduced locally with:

```sh
python3 codex-rs/rb-launch-guard/tests/fixtures/cp3-vendor-golden/generate.py
```

Recorded producer:

- OpenSSL `3.6.3 9 Jun 2026` (`Library: OpenSSL 3.6.3 9 Jun 2026`)
- Python standard library for fixed-width big-endian framing, SHA-256, and
  base64url-no-pad encoding
- decoded bundle SHA-256:
  `c3efbc77e60cb9b7a798be5a815cb4c09349b286f0098bcada5d055eada4fd6c`

The script contains fixed PKCS#8 Ed25519 test keys and prints their SHA-256
digests with the complete carrier. It uses OpenSSL `pkey` for public-key
derivation and `pkeyutl -sign -rawin` for signatures. It has no network access,
runtime dependency, Cargo target, or Bazel target.
