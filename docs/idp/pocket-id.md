# Pocket ID

Requires Pocket ID v2.13.0 or later. Checked against the v2.19.3 source.

## Summary

| Item | Value |
| --- | --- |
| Issuer | `https://id.example.com` (one per instance) |
| Discovery | Yes, at `<issuer>/.well-known/openid-configuration` |
| Token `typ` | `at+jwt` (RFC 9068 access tokens since v2.13.0) |
| RFC 8707 `resource` | Supported through **APIs** (since v2.10.0). The resource must name an API the client may use |
| Audience | The requested API's resource, plus the issuer when an identity scope such as `openid` is granted |
| Scopes | Unknown scopes are refused (`invalid_scope`), not ignored |
| Recommended discriminator | Audience: one API per upstream, using the gateway's default audiences |

## How it works

Pocket ID's APIs are resource servers with their own permissions, modelled on Auth0's. When a client sends
`resource=https://mcp.example.com/github/mcp`, Pocket ID looks up the API with that resource, checks that the client is
allowed to use it, and issues a token with that resource as `aud`. A trailing slash on the resource is ignored. An
unknown resource is refused with `invalid_target`, and a client without access to the API with `access_denied`.

MCP clients send each upstream's URL as `resource`, so one API per upstream gives each upstream its own audience. That
is the gateway's default audience, so no `audience` or `required_scopes` settings are needed, and one OAuth client can
serve every upstream.

## Setup

1. **APIs → Add**, one per upstream:
   - `MCP GitHub`, resource `https://mcp.example.com/github/mcp`;
   - `MCP Gitea`, resource `https://mcp.example.com/gitea/mcp`.

   The resource must equal `<public_url>/<name>/mcp`. Permissions are optional; the gateway does not need any.
2. **OIDC Clients → Add**: `MCP client`, with your MCP client's callback URLs. Restrict it to the groups allowed to use
   it (**Allowed user groups**).
3. Allow the client to use both APIs.

```toml
issuer = "https://id.example.com"
public_url = "https://mcp.example.com"

[[upstream]]
name = "github"
url = "http://github-mcp:3000/mcp"
token_file = "/run/secrets/github_token"
resource_name = "GitHub"

[[upstream]]
name = "gitea"
url = "http://gitea-mcp:8080/mcp"
token_file = "/run/secrets/gitea_token"
resource_name = "Gitea"
```

## Notes

- **Restricting upstreams per user.** Access to an API is granted per client, not per user. To limit who can use an
  upstream, give it its own OAuth client restricted to the right groups, allowed to use only that upstream's API.
- **Scopes.** Pocket ID refuses scopes it does not know. If you add `required_scopes`, define them as permissions on the
  upstream's API and grant them to the client. Otherwise clients following the gateway's metadata fail to sign in.
- **Issuer in `aud`.** Tokens granted `openid` also list the issuer in `aud`, so they can be used at Pocket ID's
  userinfo endpoint. The gateway accepts this: it only requires one of the upstream's audiences to be present.
- **Scope claims.** Tokens carry the granted scopes in both `scope` (space-delimited) and `scp` (an array). The gateway
  reads `scope` first.
- **Versions before v2.13.0** issue access tokens without a `typ` header and have no APIs before v2.10.0. Upgrade
  rather than setting `accept_missing_token_type`.

## Security advisory

[CVE-2026-62662](https://github.com/advisories/GHSA-q4xm-p75h-h9p3): versions v1.11.0 to v2.9.0 let any client use the
client credentials grant to obtain a token for any audience. This is fixed in v2.10.0, which the version requirement
above already covers.

## Background

- [Pocket ID v2.10.0](https://github.com/pocket-id/pocket-id/releases/tag/v2.10.0): APIs added
  ([#1542](https://github.com/pocket-id/pocket-id/pull/1542)).
- [Pocket ID v2.13.0](https://github.com/pocket-id/pocket-id/releases/tag/v2.13.0): RFC 9068 access tokens.
- [Pocket ID v2.14.0](https://github.com/pocket-id/pocket-id/releases/tag/v2.14.0): trailing slashes in resources
  ignored.
