# Keycloak

Checked against the Keycloak 26.8.2 source and documentation, not a running instance. See the
[Keycloak MCP guide](https://www.keycloak.org/securing-apps/mcp-authz-server).

## Summary

| Item | Value |
| --- | --- |
| Issuer | `https://id.example.com/realms/<realm>` (one per realm) |
| Discovery | Yes, at `<issuer>/.well-known/openid-configuration` |
| Token `typ` | `JWT` by default; `at+jwt` with a per-client option (since 26.2) |
| RFC 8707 `resource` | Experimental, behind `--features=resource-indicators`. Ignored when the feature is off |
| Recommended discriminator | Audience per upstream (Audience mapper), or scope per upstream |

## Option A: audience per upstream (recommended)

For each upstream, create an optional **client scope** that adds the upstream's URL to the audience:

1. **Client scopes → Create client scope**: name `mcp-github`, type *Optional*, protocol OpenID Connect.
2. In the scope, **Mappers → Configure a new mapper → Audience**: *Included Custom Audience*
   `https://mcp.example.com/github/mcp`, *Add to access token* on.
3. Add the scope to the MCP client (for example Claude Code's client) as an **optional** client scope.

Then list each scope name as the upstream's required scope, so the gateway tells clients to request it:

```toml
issuer = "https://id.example.com/realms/home"
public_url = "https://mcp.example.com"
accepted_token_types = ["at+jwt", "JWT"]

[[upstream]]
name = "github"
url = "http://github-mcp:3000/mcp"
token_file = "/run/secrets/github_token"
resource_name = "GitHub"
required_scopes = ["mcp-github"]

[[upstream]]
name = "gitea"
url = "http://gitea-mcp:8080/mcp"
token_file = "/run/secrets/gitea_token"
resource_name = "Gitea"
required_scopes = ["mcp-gitea"]
```

The audience then differs per upstream (the default `<public_url>/<name>/mcp`), and the scope makes the client ask
for it. This is the setup Keycloak's MCP guide describes for when resource indicators are off.

### With the experimental `resource-indicators` feature

Start Keycloak with `--features=resource-indicators`. Keycloak then checks the `resource` parameter MCP clients send:

1. Register each upstream as a client and set its `resource_url` attribute to `https://mcp.example.com/<name>/mcp`.
   Keycloak documents setting this through the Admin REST API or a realm import.
2. On the MCP client, add an **Audience** mapper per upstream with *Included Client Audience* set to that upstream's
   client.

A request whose `resource` matches gets a token whose `aud` holds only that value; anything else is refused with
`invalid_target`. The required scopes are then optional. The feature is experimental and may change between releases.

## Option B: shared audience, scope per upstream

Create one Audience mapper with a single audience (for example `https://mcp.example.com`) on a default client scope,
and one optional client scope per upstream with no mapper. Then set `audience = ["https://mcp.example.com"]` on every
upstream, plus a distinct `required_scopes` on each.

## Notes

- **Token type:** by default Keycloak sends `typ: JWT`, so the example sets `accepted_token_types = ["at+jwt", "JWT"]`.
  Since 26.2 you can instead turn on **Clients → (MCP client) → Advanced → Fine grain OpenID Connect configuration →
  Use "at+jwt" as access token header type** and remove the setting, which keeps the gateway's strict default. The
  option is per client and off by default, so clients created by dynamic registration don't have it. With `JWT`
  accepted, the gateway screens out ID tokens by content; Keycloak access tokens carry a `scope` claim, which that
  screening requires.
- **Restricting users:** add a group membership mapper (claim `groups`, *Add to access token* on, *Full group path*
  off) and set `required_claim = { name = "groups", value = "mcp-github" }`.
- **Signing algorithm:** Keycloak's JWKS includes `alg` on each key, so detection works. An `RSA-OAEP` encryption key
  in the same JWKS is ignored.
