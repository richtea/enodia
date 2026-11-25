# Kanidm

See Kanidm's [OAuth2 integration guide](https://kanidm.github.io/kanidm/stable/integrations/oauth2.html). Checked
against the Kanidm 1.12.1 source, not a running instance.

## Summary

| Item | Value |
| --- | --- |
| Issuer | Per client: `https://idm.example.com/oauth2/openid/<client>` |
| Discovery | Yes, at `<issuer>/.well-known/openid-configuration` |
| Token format | RFC 9068 JWT, ES256 (RS256 only with legacy crypto enabled) |
| Token `typ` | `at+jwt` |
| RFC 8707 `resource` | Ignored by the authorization flow; used only in token exchange |
| Audience | The client name (`mcp` below) |
| Recommended discriminator | One client, one scope per upstream (scope maps) |

## Why one client

Kanidm gives each OAuth2 client its own issuer and signing keys, and the gateway trusts a single issuer. Use one client
for all upstreams and tell them apart by scope. Kanidm's scope maps are granted by group membership, so they also
control who can use each upstream.

## Setup

```sh
kanidm system oauth2 create-public mcp "MCP gateway" https://mcp.example.com
kanidm system oauth2 add-redirect-url mcp http://localhost:33418/callback   # your MCP client's redirect URIs
kanidm system oauth2 enable-localhost-redirects mcp                          # if the client uses a localhost redirect
kanidm system oauth2 update-scope-map mcp mcp_users openid offline_access
kanidm system oauth2 update-sup-scope-map mcp mcp_github mcp:github
kanidm system oauth2 update-sup-scope-map mcp mcp_gitea mcp:gitea
```

Members of `mcp_github` can obtain `mcp:github`, and so on. Tokens carry the client name as `aud`; use it as the shared
audience:

```toml
issuer = "https://idm.example.com/oauth2/openid/mcp"
public_url = "https://mcp.example.com"

[[upstream]]
name = "github"
url = "http://github-mcp:3000/mcp"
token_file = "/run/secrets/github_token"
resource_name = "GitHub"
audience = ["mcp"]          # the client name
required_scopes = ["mcp:github"]

[[upstream]]
name = "gitea"
url = "http://gitea-mcp:8080/mcp"
token_file = "/run/secrets/gitea_token"
resource_name = "Gitea"
audience = ["mcp"]
required_scopes = ["mcp:gitea"]
```

## Notes

- **Scope maps vs supplemental scope maps:** with an ordinary scope map, a requested scope the user lacks fails the whole
  authorisation. With a supplemental map, it is simply left out and the gateway refuses the token, which gives a
  clearer error. Use supplemental maps for the per-upstream scopes.
- **Signing algorithm:** Kanidm signs with ES256 unless legacy crypto (RS256) is enabled for the client; detection
  should find it from the JWKS. If not, set `algorithm`.
- **Token type:** access tokens carry `typ: at+jwt`, so the gateway's default applies. They also carry `nonce` when the
  client sent one, which is harmless here because the gateway screens by content only when it accepts other types.
