# RFC 9580 Coverage (Current State)

This note summarizes current implementation status for features related to
RFC 4880, RFC 5581, RFC 6637, and RFC 9580.

## Summary

- Stable base support is present for RFC 4880, RFC 5581, and RFC 6637.
- RFC 9580-related parser paths are partially implemented, including key version
  6 routing in major packet families.
- Remaining work is mostly policy and corpus expansion (wording, vectors, docs).

## Implemented (Confirmed)

1. Packet and subpacket IDs for AEAD-era features
- Tag 20 AEAD Encrypted Data Packet exists.
  - parse/tags/tag20.go
  - parse/values/tagid.go
- Subpacket 39 Preferred AEAD Ciphersuites exists.
  - parse/tags/sub39.go
  - parse/values/subpacketid.go
- Subpacket 33 Issuer Fingerprint and Subpacket 35 Intended Recipient Fingerprint
  support key version 4/5/6 length notes.
  - parse/tags/sub33.go
  - parse/tags/sub35.go

2. AEAD and S2K model coverage
- AEAD algorithm IDs and IV/tag lengths are modeled.
  - parse/values/aeadid.go
- S2K ID 4 Argon2 parsing exists.
  - parse/s2k/s2k.go
  - parse/values/s2kid.go

3. Version model and v6-aware helpers
- Version helpers are v6-aware for major packet families.
  - parse/values/version.go
- Current helper mapping includes v6 in "current" sets, while v5 remains
  "draft" by current project policy.
  - parse/values/version.go

4. Key-version dependent parser routing
- v6 routes are handled in v5-style parsing paths where packet layout matches.
  - parse/tags/tag01.go
  - parse/tags/tag02.go
  - parse/tags/tag03.go
  - parse/tags/tag04.go
  - parse/tags/pubkey.go
  - parse/tags/seckey.go

5. SEIPD v2 chunk-size rendering alignment
- Tag 18 now renders chunk size consistently with Tag 20 semantics
  ($2^{c+6}$, with raw octet dump retained).
  - parse/tags/tag18.go
  - parse/tags/tag18_test.go

6. v6-focused tests
- Focused and route-level tests for v6 key-version behavior are present.
  - parse/tags/key_version_test.go

## Partial / Inconsistent

1. Draft-oriented wording remains in output and tests
- Version 5 is still labeled as "draft" in output.
  - parse/values/version.go
- Existing expected outputs keep draft wording where v5 packets are used.
  - parse/tags/tag05_test.go
  - parse/tags/tag07_test.go

2. Real-world v6 vector coverage is still narrow
- Current v6 tests are mostly focused/minimal route checks.
- Larger corpus vectors and realistic packet snapshots are still desirable.

## Remaining Gaps (Likely Next PR Units)

1. Decide and document v5/v6 wording policy
- Keep "draft" for v5 or move to neutral/stable wording depending on project
  compatibility policy.

2. Expand v6 test corpus
- Add realistic vectors for signature, key, and encrypted packet families.
- Prefer fixture-based tests where feasible.

3. Sync user-facing docs
- Keep README and architecture notes aligned with current parser behavior and
  RFC 9580 scope.

## Validation Checklist per PR

- task test
- task govulncheck
- Expected output snapshots updated only where behavior intentionally changed
