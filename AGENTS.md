# Agent guidance

This is a **public** repository. Never add anything specific to a deployment: hostnames, IP addresses, network
layouts, identity provider client IDs, or secrets. Deployment configuration belongs in each consuming service's own
repository. Use `example.com` names in documentation and tests.

## Rules

- Security properties are covered by the tests: `tests/test_gateway.py` (end to end, path isolation, headers, audit),
  `tests/test_verifier.py` (token validation per RFC 8725 / RFC 9068), `tests/test_signing.py` (discovery, algorithm
  detection) and `tests/test_config.py`. Any change to authentication, header handling or configuration validation
  needs a matching test, and all tests must pass (`uv run pytest`). `uv run ruff check .` and `uv run ty check` must
  also pass; CI runs all three. Ruff and ty settings are in `pyproject.toml`.
- The project is managed with uv. Direct dependencies are pinned exactly (`==`) in `pyproject.toml`, runtime in
  `dependencies` and test, lint and type-check tools in the `dev` dependency group. Every dependency is locked by hash
  in `uv.lock`. Change dependencies with `uv add`/`uv remove` or by editing `pyproject.toml` and running `uv lock`, and
  never edit `uv.lock` by hand. For runtime dependencies, prefer releases at least two weeks old. Dev tools (test, lint
  and type-check) may use the latest release, since they never ship in the image.
- The base and uv images are pinned by digest, and GitHub Actions by commit SHA with the version in a comment. Keep
  the uv version in the `Dockerfile` and the CI workflow the same.
- Keep the gateway generic, with no upstream- or IdP-specific behaviour in code. Policy goes in the TOML config file,
  runtime settings (host, port, log level, config path) in environment variables, and secrets only in files named by
  the config (never inline). IdP-specific guidance belongs in `docs/idp/`.
- The code is a package in `src/enodia/`: `config.py` (config file, environment and validation),
  `server.py` (issuer discovery, token validation, one proxy per upstream, path dispatch, audit log) and `cli.py`
  (entry point, health check). `__init__.py` re-exports the public API.
- Token validation is done by `GatewayVerifier`, not FastMCP's `JWTVerifier` (which lacks clock skew, `nbf`/`iat` and
  `typ` checks). It reuses private FastMCP helpers for key lookup; re-check them whenever FastMCP is upgraded.
- Releases follow [docs/releasing.md](docs/releasing.md): `uv run scripts/release.py prepare <type>` opens a
  `chore/release-<version>` pull request that bumps `CHANGELOG.md`, `pyproject.toml` and `uv.lock`. Merging it creates a
  draft GitHub release, and publishing that release (plus approving the `release` environment) publishes the image.
  Never edit release versions by hand, push `v*` tags, or create releases yourself. Agents may run
  `scripts/release.py prepare ... --dry-run`, but run it without `--dry-run` only when explicitly told to.
  `scripts/release.py` is stdlib-only Python and is tested in `tests/test_release_script.py`. The `kac` changelog
  CLI is pinned by hash in `tools/kac/package-lock.json`; change it only through `npm install --package-lock-only`.

## Changelog (`CHANGELOG.md`)

Maintain `CHANGELOG.md` using the Keep a Changelog 2.0 format
(`[keepachangelog.com](https://keepachangelog.com/en/2.0.0/)`).

### What to Include

- **User-facing changes only:** Derive entries from net diffs that affect UI, UX, workflows, permissions, integrations,
  or observable performance.
- **Categories:** Group entries under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security`.
- **Outcome-first wording:** Describe what changed for the user and why (e.g., "Added CSV export to the Invoices page"
  rather than "Implemented ExportButton component").
- **Flag disruptions:** Explicitly call out breaking changes to webhooks, public endpoints, URLs, or required user
  actions.

### What to Exclude

- Component refactors, state management rewrites, or CSS cleanups with no visual or behavioral change.
- Dependency bumps, build config tweaks, CI/CD pipelines, and test suites (unless fixing a user-facing bug or
  vulnerability).
- Feature-flagged code that is disabled by default for all users.

### Workflow & Versioning

- Add entries under `## [Unreleased]` at the top of `CHANGELOG.md`.
- Do not create dated release sections (`YYYY-MM-DD`) or version tags yourself: `scripts/release.py prepare` turns
  `[Unreleased]` into the release section and leaves a new empty `[Unreleased]` above it.
- Releases are refused if `[Unreleased]` is empty, so record every user-facing change there.
