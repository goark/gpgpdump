# Contributing

Thanks for contributing to `gpgpdump`.

## Development flow

1. Create a small, focused branch from `master`.
2. Keep each PR limited to one topic.
3. Run local checks with:

```bash
task
```

4. Open a PR and wait for `ci` and `CodeQL` checks to pass.
5. Merge to `master`.
6. Delete the working branch on both remote and local.

## Coding and review policy

- Keep parser logic in `parse/` and `parse/tags/`.
- Avoid broad refactors unrelated to the target change.
- Keep comments concise and in English.
- Preserve compatibility of exported APIs and CLI flags unless a change is intentional and documented.

## Spec policy

- Treat RFC 9580 packet behavior as current OpenPGP behavior.
- Treat version 5 packet behavior as draft policy in this project.
- Handle RFC 9580 and LibrePGP draft differences additively when practical.

## Testing guidance

- Prefer adding or updating tests together with behavior changes.
- For parser-specific work, run narrow package tests first, then run `task`.

## Troubleshooting CI

- If GitHub Actions is degraded, wait for status recovery first.
- If checks stay queued after recovery, retrigger runs (for example, by pushing a minimal empty commit).
