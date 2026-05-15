# RFC 9580 Coverage (Current State)

This note summarizes current implementation status for features related to
RFC 4880, RFC 5581, RFC 6637, and draft RFC 4880bis / RFC 9580.

## Summary

- Stable base support is present for RFC 4880, RFC 5581, and RFC 6637.
- Partial support for draft RFC 4880bis features is present (mainly version 5 era features).
- RFC 9580 finalization coverage is incomplete, especially around version 6 semantics.

## Implemented (Confirmed)

1. Packet and subpacket IDs for AEAD-era features
- Tag 20 AEAD Encrypted Data Packet exists.
  - parse/tags/tag20.go
  - parse/values/tagid.go
- Subpacket 39 Preferred AEAD Ciphersuites exists.
  - parse/tags/sub39.go
  - parse/values/subpacketid.go
- Subpacket 33 Issuer Fingerprint exists with v4/v5 handling notes.
  - parse/tags/sub33.go

2. AEAD algorithm model
- AEAD algorithm IDs and IV/tag lengths are modeled.
  - parse/values/aeadid.go

3. S2K Argon2 support
- S2K ID 4 Argon2 parsing exists.
  - parse/s2k/s2k.go
  - parse/values/s2kid.go

4. Version 5 packet handling (draft marker)
- Version model treats 5 as draft for multiple packet families.
  - parse/values/version.go
- Secret key and secret subkey tests include Version 5 (draft) examples.
  - parse/tags/tag05_test.go
  - parse/tags/tag07_test.go

5. SEIPD v2 parser path exists
- Tag 18 supports version 1 and version 2 parsing branches.
  - parse/tags/tag18.go

## Partial / Inconsistent

1. Chunk size interpretation differs between Tag 18 and Tag 20
- Tag 20 converts encoded chunk parameter to actual size (1 << (c + 6)).
  - parse/tags/tag20.go
- Tag 18 currently exposes the raw one-octet value as plain integer.
  - parse/tags/tag18.go

2. Draft-oriented wording remains in output and tests
- Version 5 is labeled as draft in the Version model.
  - parse/values/version.go
- Existing expected outputs in tests reflect draft wording.
  - parse/tags/tag05_test.go
  - parse/tags/tag07_test.go

## Missing / Likely Gaps for RFC 9580

1. Version 6-oriented paths are not visible in version helpers
- Current helper constructors only encode old/current/draft sets around v4/v5.
  - parse/values/version.go

2. Key-version gated fingerprint handling may be too narrow
- One-pass signature packet path currently only accepts key version 5.
  - parse/tags/tag04.go
- Public-key encrypted session key packet path recognizes key version 4/5 only.
  - parse/tags/tag01.go

3. No obvious v6-focused tests or test vectors in parser tests
- Current tests include v5 vectors and draft labels.
  - parse/tags/tag02_test.go
  - parse/tags/tag05_test.go
  - parse/tags/tag07_test.go

## Proposed Implementation Order (Small PR Units)

1. Normalize feature inventory in docs and wording
- Decide whether Version 5 should still be surfaced as draft in user-visible output.

2. Align chunk size behavior
- Make Tag 18 chunk-size rendering consistent with Tag 20.
- Add/adjust tests for expected value format.

3. Add v6 version model and packet handling gates
- Extend version helpers for v6-aware labeling where required.
- Update tag01/tag04 key-version checks and fingerprint-length logic as needed.

4. Add test vectors for v6 paths
- Introduce focused parser tests before broad refactors.

5. Update README and architecture notes
- Keep claimed support level synchronized with actual parser behavior.

## Validation Checklist per PR

- task test
- task govulncheck
- Expected output snapshots updated only where behavior intentionally changed
