# Copilot Instructions for `goark/gpgpdump`

## Project purpose

`gpgpdump` is a CLI and library to parse and visualize OpenPGP packet data.
It supports plain-text and JSON output for packet inspection and debugging.

## Scope and compatibility

- Keep behavior compatible with existing RFC 4880 packet parsing unless the change is explicitly for new spec support.
- Treat RFC 9580 and LibrePGP draft related changes as additive when possible.
- Avoid breaking exported APIs and CLI flags without clear migration notes.

## Architecture overview

- `parse/`: core parser and packet decoding pipeline.
- `parse/tags/`: packet and subpacket tag-specific decoding.
- `result/`: output model and rendering support.
- `facade/`: CLI-facing orchestration and fetch integrations.
- `hkp/`, `github/`: key acquisition from HKP and GitHub.

Keep parsing logic in parser/tag packages and avoid pushing protocol details into CLI command layers.

## Error handling

- Use `github.com/goark/errs` for wrapped/contextual errors.
- Prefer returning errors with enough context (packet tag, subpacket tag, offset, or source).
- Preserve `errors.Is` behavior for callers.

## Coding style

- Write idiomatic Go with simple, explicit control flow.
- Keep comments concise and in English.
- Avoid broad refactors unrelated to the target packet/feature.

## Testing and validation

- Add or update tests for parser and tag behavior changes.
- Prefer local validation with Taskfile. Use `task` (no arguments) as the default full check.
- For parser-focused changes, run narrow package tests first, then full validation.

## Pull request workflow

- Use small, focused PR units. Avoid bundling unrelated changes.
- Before creating a PR, run local validation with `task` by default.
- After CI checks pass, merge to `master` and delete both remote and local working branches.
- If GitHub Actions is degraded/stuck, prefer waiting for recovery; if needed, retrigger checks with a minimal empty commit.

## Documentation

- Keep `README.md` examples aligned with actual CLI behavior.
- When changing packet rendering or CLI flags, update examples and option descriptions.

## Release and workflow notes

- `build` workflow runs on tag push matching `v*`.
- `ci` and `CodeQL` workflows run on `master` pushes and pull requests.
- Create release tags in `vMAJOR.MINOR.PATCH` format.
