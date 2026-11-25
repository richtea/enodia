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
- Releases: update `version` in `pyproject.toml` (`__version__` is read from the package metadata) and `CHANGELOG.md`,
  run `uv lock`, then tag
  `vX.Y.Z`. CI publishes the image only for tags.
