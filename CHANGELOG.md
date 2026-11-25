# Changelog

## 0.2.0 (unreleased)

Breaking: configuration moves from environment variables to a TOML file. See README.md.

- Renamed from `mcp-oauth-gateway` to Enodia: package, command and image `enodia`, Python package `enodia`, loggers
  `enodia` and `enodia.audit`, default config file `/etc/enodia/config.toml`.
- One gateway serves several upstreams, each at `/<name>/mcp` with its own protected resource metadata, upstream token,
  audiences, and optional required scopes and claim. The gateway refuses configurations in which two upstreams would
  accept the same tokens.
- Policy is read from a TOML file (`CONFIG_FILE`, default `/etc/enodia/config.toml`); unknown keys and
  inline tokens are refused. `HOST`, `PORT` and `LOG_LEVEL` stay environment variables.
- Signing keys are found through OpenID Connect discovery (the metadata's issuer must match exactly) instead of an
  assumed `/.well-known/jwks.json`, and the algorithm is detected from the JWKS unless configured.
- Token validation follows RFC 8725 and RFC 9068: `exp`, `iss`, `aud` and `sub` are required; `exp`, `nbf` and `iat`
  are checked with a configurable clock skew allowance; the `typ` header must be `at+jwt` unless other types are
  allowed, in which case ID tokens are rejected by content; `iss` is compared exactly (a trailing slash is no longer
  stripped); keys declaring another algorithm are ignored.
- The `401` challenge asks for the shared scopes as well as an upstream's required scopes.
- `advertised_scope_prefix` advertises required scopes in a different form from the one checked in the token, as
  RFC 9728 intends (`scopes_supported` lists request values). Entra ID needs it: clients request
  `api://<client-id>/<scope>`, and the token's `scp` carries `<scope>`.
- Audit lines include the upstream name. The health check probes every upstream path.
- Setup guides for Keycloak, Entra ID, Authentik, Pocket ID, Authelia and Kanidm in `docs/idp/`.

## 0.1.0 (unreleased)

- First release: JWT validation against a JWKS, RFC 9728 discovery, a static upstream token with no client header
  forwarding, a JSON audit log, a container health check, and refusal of unsafe configuration.
- FastMCP 4.1.8 on Python 3.13.
