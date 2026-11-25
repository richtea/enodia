# Authentik

Checked against the Authentik 2026.8.6 source, not a running instance.

## Summary

| Item | Value |
| --- | --- |
| Issuer | Per provider by default: `https://auth.example.com/application/o/<slug>/` (note the trailing slash) |
| Discovery | Yes, at `<issuer>.well-known/openid-configuration` |
| Token `typ` | `JWT` (Authentik sets no type for access tokens, so its JWT library's default applies) |
| RFC 8707 `resource` | Ignored by the authorization and token endpoints; refused only in token exchange |
| Access token contents | A copy of the ID token, plus `scope`, `azp` and `uid`. Includes `nonce` if the client sent one |
| Audience | The provider's client ID |
| Recommended discriminator | One provider, one scope per upstream |

## Limitation: clients that send a nonce

Authentik builds the access token from the ID token. If the MCP client sends a `nonce` in its authorization request,
the access token carries that `nonce` too. Because Authentik tokens have `typ: JWT`, the gateway must accept `JWT`,
and it then screens out ID tokens by content, which includes refusing any token with a `nonce`. Sign-in succeeds but
every request to the gateway gets `401`.

So Authentik works only with MCP clients that don't send a `nonce`. Plain OAuth clients using PKCE normally don't;
clients built on an OpenID Connect library often do. Check with your client: decode an access token and look for
`nonce`.

## Why one provider

Authentik gives each OAuth2 provider its own issuer (by default) and signing key, and the gateway trusts a single
issuer and key set. Use one
provider for all upstreams and tell them apart by scope. Its audience is the provider's client ID, shared by every
upstream.

## Setup

1. **Applications → Providers → Create → OAuth2/OpenID Provider**: client type as your MCP client needs, select a
   **signing key** (without one, Authentik signs with HS256, which the gateway refuses). Add your MCP client's
   redirect URIs.
2. **Customization → Property Mappings → Create → Scope Mapping**, one per upstream. Scope name `mcp:github`,
   expression `return {}` (the scope itself is what matters). Repeat for `mcp:gitea`.
3. On the provider, add these scope mappings plus the default `openid`, `profile` and `offline_access` mappings.
4. Bind the application to the groups allowed to use it.

```toml
issuer = "https://auth.example.com/application/o/mcp/"   # keep the trailing slash
public_url = "https://mcp.example.com"
accepted_token_types = ["at+jwt", "JWT"]

[[upstream]]
name = "github"
url = "http://github-mcp:3000/mcp"
token_file = "/run/secrets/github_token"
resource_name = "GitHub"
audience = ["<provider client id>"]
required_scopes = ["mcp:github"]

[[upstream]]
name = "gitea"
url = "http://gitea-mcp:8080/mcp"
token_file = "/run/secrets/gitea_token"
resource_name = "Gitea"
audience = ["<provider client id>"]
required_scopes = ["mcp:gitea"]
```

## Notes

- **Issuer exactness:** copy the issuer from the provider's *OpenID Configuration Issuer* field, including the
  trailing slash. The gateway compares it with `iss` exactly.
- **Token type:** Authentik access tokens carry `typ: JWT`, so keep `accepted_token_types = ["at+jwt", "JWT"]`. They
  carry a `scope` claim, which the gateway's ID-token screening requires.
- **Claims in the access token:** user claims from the scope mappings (such as `groups`) reach the access token only
  while the provider's **Include claims in id_token** option is on. It is on by default.
- **Restricting users per upstream:** a scope mapping can return a claim, for example
  `return {"mcp_github": ak_is_group_member(request.user, name="mcp-github")}`, though a `groups` claim from the
  `profile` mapping with `required_claim = { name = "groups", value = "mcp-github" }` is simpler.
