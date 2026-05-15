# Architecture Overview

This document explains internal boundaries and data flow for `gpgpdump`.
It is intended for maintainers who need to add packet support or refactor code safely.

## Scope

- Target: packet parsing and rendering pipeline, plus CLI orchestration.
- Non-target: release automation details and end-user command tutorial.

## Package Responsibilities

- `main`: process entry point; wires stdin/stdout/stderr to facade.
- `facade`: CLI command tree, flag handling, input source selection, output mode selection.
- `parse`: parser lifecycle, armor detection/decoding, packet iteration.
- `parse/tags`: packet tag dispatch and tag-specific parse implementation.
- `parse/result`: output-neutral parse result model (`Info` / `Item`) and text/JSON rendering.
- `hkp`, `github`, `facade/fetch`: remote key/data acquisition for CLI subcommands.

## Data Flow

1. `main` calls `facade.Execute` with process IO streams.
2. `facade` builds parse context from flags and selects input source (file, clipboard, stdin).
3. `parse.New` normalizes input reader (armor-aware).
4. `Parser.Parse` loops opaque packets and delegates each packet to `parse/tags`.
5. Tag parsers append structured `result.Item` values into `result.Info`.
6. `facade` renders the same `result.Info` as plain text or JSON.

## Layer Boundaries

- Parsing logic stays in `parse` and `parse/tags`.
- CLI-specific concerns stay in `facade` and command files.
- Output format differences (text vs JSON) must be renderer concerns, not parser concerns.
- Fetching remote data is isolated from packet parsing.

## Invariants

- The parser should produce one canonical structured result model (`result.Info`).
- Text and JSON outputs must represent the same parsed information.
- New RFC support should be additive when possible.
- Existing CLI flags and exported APIs should remain backward compatible unless explicitly planned.

## RFC 9580 Extension Points

- Add/extend packet handlers in `parse/tags/tag*.go`.
- Add/extend subpacket handlers in `parse/tags/sub*.go`.
- Update value mappings in `parse/values` for new identifiers/labels.
- Keep unknown or unsupported elements observable as structured output instead of silently dropping them.

## Change Checklist

When changing parser/tag behavior:

1. Update or add tests near the affected package.
2. Verify plain-text and JSON output consistency.
3. Update `README.md` examples if visible output changed.
4. Run local checks:

```text
task test
task govulncheck
```
