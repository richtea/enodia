# Authelia

See Authelia's [OpenID Connect client](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/)
and [claims](https://www.authelia.com/integration/openid-connect/openid-connect-1.0-claims/) documentation. Requires a
version with JWT access tokens and claims policies (4.39 or later). Checked against the 4.39.28 source and
documentation, not a running instance.

## Summary

| Item | Value |
| --- | --- |
| Issuer | `https://auth.example.com` |
| Discovery | Yes, at `<issuer>/.well-known/openid-configuration` |
| Token `typ` | `at+jwt` (JWT access tokens, enabled by `access_token_signed_response_alg`) |
| RFC 8707 `resource` | Supported, alongside the `audience` parameter |
| Audience | The client ID, plus each granted audience and resource |
| Recommended discriminator | Audience per upstream, or a custom scope per upstream |

## Setup

Enable JWT access tokens on the MCP client and allow it the upstream audiences:

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: mcp-client
        client_name: MCP client
        public: true
        redirect_uris: ["http://localhost:33418/callback"]   # your MCP client's redirect URIs
        scopes: [openid, offline_access]
        audience:
          - https://mcp.example.com/github/mcp
          - https://mcp.example.com/gitea/mcp
        access_token_signed_response_alg: RS256
        authorization_policy: two_factor
```

The client's `audience` list is the set of audiences it may be granted. MCP clients request one by sending the
`resource` parameter (`https://mcp.example.com/github/mcp`), and Authelia adds it to `aud` after the client ID. That
is the gateway's default audience, so the gateway config needs no `audience` settings.

Keep `requested_audience_mode` at its default, `explicit`. With `implicit`, a request carrying neither `audience` nor
`resource` is granted every audience in the list, and the token works at every upstream.

```toml
issuer = "https://auth.example.com"
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

- **Custom scopes:** define scopes under `identity_providers.oidc.scopes`, allow them on the client, and list them as
  `required_scopes` per upstream with a shared audience.
- **Restricting users:** use Authelia's `authorization_policy` per client, or a claims policy whose `access_token` list
  includes `groups`, with `required_claim` on each upstream.
