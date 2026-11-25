# Identity provider setup

The gateway is a resource server: it validates JWT access tokens that your identity provider (IdP) issues to MCP
clients. These guides cover what to configure at each IdP and the matching gateway config.

| Provider | Guide |
| --- | --- |
| Keycloak | [keycloak.md](keycloak.md) |
| Microsoft Entra ID | [entra-id.md](entra-id.md) |
| Authentik | [authentik.md](authentik.md) |
| Pocket ID | [pocket-id.md](pocket-id.md) |
| Authelia | [authelia.md](authelia.md) |
| Kanidm | [kanidm.md](kanidm.md) |

IdPs change between versions. Each guide names the release it was checked against (from source and documentation,
not a running instance) and marks anything it could not confirm. Check those points against the version you run, and
decode a real access token (for example with `step crypto jwt inspect --insecure`) before relying on them.

## What every IdP must provide

- **JWT access tokens** signed with an asymmetric algorithm (RS256, ES256, ...). Opaque access tokens cannot be
  validated by the gateway.
- **One issuer** for all upstreams. The gateway trusts exactly one `issuer` and compares it with the `iss` claim
  character for character, including any trailing slash.
- **OpenID Connect discovery** at `<issuer>/.well-known/openid-configuration`, naming that exact issuer and a
  `jwks_uri`. If it is missing, set `jwks_uri` in the gateway config.
- **A `kid` and `alg` on each signing key** in the JWKS. If the keys omit `alg`, set `algorithm` in the gateway config.

## Telling upstreams apart

A token for one upstream must not be accepted by another. The gateway gives you three tools, and refuses to start
if two upstreams share an audience and neither requires something the other does not.

### Audience (`aud`)

The audience says which resource a token was issued for. It is the mechanism the MCP specification intends: clients
send the RFC 8707 `resource` parameter (`https://mcp.example.com/github/mcp`) and the IdP puts it in `aud`.

- **Default:** each upstream accepts `<public_url>/<name>/mcp`.
- **IdPs that ignore `resource`** usually set `aud` to the OAuth client ID. Then you need one OAuth client per upstream
  and `audience = ["<client id>"]` on each upstream.
- **IdPs with a fixed audience per API** (Entra ID) can share one audience between upstreams and use scopes instead.

### Scope (`required_scopes`)

Each upstream requires a scope, such as `mcp:github`. The gateway advertises it in the upstream's metadata and `401`
challenge, so MCP clients request it automatically. Scopes work with most IdPs and let one OAuth client serve every
upstream.

Requiring a scope also means a user who consents to several scopes gets one token usable at several upstreams. That
is expected: the IdP granted access to each.

### Claim (`required_claim`)

The token must carry a claim value, such as `groups` containing `mcp-github`. This is about who the user is, not
which resource the token was issued for, so it doubles as an access rule. Not every IdP can put custom claims or
groups in access tokens.

## Token type (`typ`)

RFC 9068 access tokens carry the header `typ: at+jwt`, and resource servers must check it so that an ID token (which
the client also receives, and whose audience is the client ID) cannot be used as an access token. The gateway requires
`at+jwt` by default.

Some IdPs send `typ: JWT` or no `typ` at all. For those, set `accepted_token_types = ["at+jwt", "JWT"]` or
`accept_missing_token_type = true`. The gateway then rejects ID tokens by content instead: it refuses tokens carrying
`nonce`, `at_hash`, `c_hash` or a payload `typ` of `ID`, and requires a non-empty `scope` or `scp` claim.

## Scopes clients request

`scopes_supported` (default `openid offline_access`) is what the gateway tells clients to request, plus each upstream's
required scopes. `openid` is needed by most IdPs for a login to proceed; `offline_access` asks for a refresh token so
clients can renew without logging the user in again.

Required scopes are advertised as written unless `advertised_scope_prefix` is set. Use it when the IdP names scopes
differently in requests and in tokens, as Entra ID does (`api://<client-id>/github` requested, `github` in `scp`).

Clients also send the upstream's URL (`https://mcp.example.com/<name>/mcp`) as the RFC 8707 `resource` parameter. Do
not use a client, proxy or workaround that strips it: it lets the IdP refuse a malicious MCP server that advertises
another API's scopes.
