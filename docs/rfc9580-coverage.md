# RFC 9580 Coverage (Current State)

This note summarizes current implementation status for features related to
RFC 9580 and LibrePGP (draft).

## Summary

- Stable base support is present for packet forms standardized in RFC 9580.
- RFC 9580-related parser paths are partially implemented, including key version
  6 routing in major packet families.
- Version wording policy is now fixed: v4/v6 are `current`, v5 is `draft`.
- Remaining work is mostly corpus expansion and user-facing docs sync.

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

7. Version wording policy (finalized)
- v4 and v6 are treated as `current` packet versions.
  - v4 is treated as current in this project policy.
  - v6 aligns with RFC 9580.
- v5 is treated as `draft` for compatibility policy reasons.
  - RFC 9580 does not assign v5 packet versions.
  - v5 remains associated with ongoing LibrePGP draft discussions.

## Partial / Inconsistent

1. Real-world v6 vector coverage is still narrow
- Current v6 tests are mostly focused/minimal route checks.
- Larger corpus vectors and realistic packet snapshots are still desirable.

## Remaining Gaps (Likely Next PR Units)

1. Expand v6 test corpus
- Add realistic vectors for signature, key, and encrypted packet families.
- Prefer fixture-based tests where feasible.

2. Sync user-facing docs
- Keep README and architecture notes aligned with current parser behavior and
  RFC 9580 scope.

## Validation Checklist per PR

- task test
- task govulncheck
- Expected output snapshots updated only where behavior intentionally changed
