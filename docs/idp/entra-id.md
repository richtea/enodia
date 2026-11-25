# Microsoft Entra ID

## Summary

| Item | Value |
| --- | --- |
| Issuer | `https://login.microsoftonline.com/<tenant-id>/v2.0` (v2 tokens) |
| Discovery | Yes, at `<issuer>/.well-known/openid-configuration` |
| Token `typ` | Unverified: reported as `at+jwt` by some sources, `JWT` by others. Decode a token to check |
| RFC 8707 `resource` | Validated: must exactly match one of the API registration's Application ID URIs, otherwise AADSTS9010010 |
| Audience | The API's client ID (v2 tokens), fixed per app registration |
| Scope names | Requested as `api://<client-id>/<scope>`; the token's `scp` carries `<scope>` |
| Recommended discriminator | One API registration, one scope per upstream |

## Prerequisites

A **domain verified in your tenant** that covers the gateway's `public_url` host. MCP clients send each upstream's URL
(`https://mcp.example.com/github/mcp`) as the `resource` parameter, and Entra accepts it only if it is one of the API's
Application ID URIs. Entra allows `https://` Application ID URIs only on verified domains. Without one, the only URIs
available are `api://…`, which MCP clients do not send, and sign-in fails with AADSTS9010010.

## Why scopes, not audiences

Entra sets `aud` from the app registration that exposes the API, not from anything the client sends. You cannot give
each upstream its own audience unless you create one app registration per upstream. Entra's own model is one API with
several scopes, which maps directly onto the gateway's `required_scopes`.

## Setup

1. **App registrations → New registration**: `MCP gateway` (the API). Under **Manifest**, set
   `"requestedAccessTokenVersion": 2` so tokens use the v2 issuer.
2. **Expose an API**: set the Application ID URI to `api://<client-id>`, then add one scope per upstream: `github`,
   `gitea`.
3. **Add each upstream's URL as an Application ID URI.** In the manifest, `identifierUris` lists them:

   ```json
   "identifierUris": [
     "api://11111111-1111-1111-1111-111111111111",
     "https://mcp.example.com/github/mcp",
     "https://mcp.example.com/gitea/mcp"
   ]
   ```

   Each must match the `resource` value in the upstream's metadata character for character, with no trailing slash.
   The gateway advertises exactly `<public_url>/<name>/mcp`.
4. **Register the MCP client** (Entra does not support dynamic client registration) as a separate registration:
   - **Authentication → Allow public client flows: Yes** (`"isFallbackPublicClient": true`), so it can use PKCE without
     a secret;
   - add the client's loopback redirect URI under **Mobile and desktop applications**, not **Web**;
   - **API permissions**: add the `MCP gateway` delegated scopes and grant consent.
5. Optionally restrict users: **Enterprise applications → MCP gateway → Properties → Assignment required**.

```toml
issuer = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
public_url = "https://mcp.example.com"
advertised_scope_prefix = "api://11111111-1111-1111-1111-111111111111/"   # the API's Application ID URI + "/"

[[upstream]]
name = "github"
url = "http://github-mcp:3000/mcp"
token_file = "/run/secrets/github_token"
resource_name = "GitHub"
audience = ["11111111-1111-1111-1111-111111111111"]   # the API's client ID
required_scopes = ["github"]

[[upstream]]
name = "gitea"
url = "http://gitea-mcp:8080/mcp"
token_file = "/run/secrets/gitea_token"
resource_name = "Gitea"
audience = ["11111111-1111-1111-1111-111111111111"]
required_scopes = ["gitea"]
```

In the MCP client, set only the client ID; it takes the scopes from the gateway.

## What happens at sign-in

For the `github` upstream, the gateway's `401` challenge and metadata ask for
`openid offline_access api://11111111-1111-1111-1111-111111111111/github`. The client sends that as `scope`, with
`resource=https://mcp.example.com/github/mcp`. Entra checks that the resource is an Application ID URI of the
registration that owns the scope, and issues a token with `aud` = the API's client ID and `scp` = `github`. The gateway
checks `scp` for the short name, so the prefix never appears in `required_scopes`.

`advertised_scope_prefix` requires every upstream to have `required_scopes`: an upstream without one would advertise
only `openid offline_access`, and Entra would issue a Microsoft Graph token instead of one for your API.

## Known issues

- **Trailing slashes.** Entra compares `resource` exactly, and Application ID URIs cannot end in `/`. A client that
  normalises the URL to `https://mcp.example.com/github/mcp/` fails with AADSTS9010010. In March 2026 an Entra
  developer said a fix to ignore the trailing slash was in progress; until it ships, use a client that sends the URL
  unchanged.
- **Do not strip `resource`.** Some workarounds remove the parameter to avoid AADSTS9010010. Don't: it is what lets
  Entra refuse a malicious MCP server that advertises another API's scopes to obtain tokens for it.
- **Token type.** If your tokens carry `typ: JWT`, add `accepted_token_types = ["at+jwt", "JWT"]`. Entra access tokens
  carry `scp`, which the gateway's ID-token screening accepts.
- **Signing algorithm.** Entra's JWKS keys may omit `alg`. If the gateway cannot detect it, set `algorithm = "RS256"`.
- **Unverified:** that `aud` stays the client ID when `resource` is an `https://` Application ID URI (decode a token to
  check), and any limit on the number of Application ID URIs per registration.

## Background

- [MCP spec issue #1614](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1614): why MCP requires
  `resource`, and reports that Entra now validates it against Application ID URIs.
- [opencode issue #12308](https://github.com/anomalyco/opencode/issues/12308#issuecomment-4169317724): a working
  client setup (exact Application ID URI, public PKCE client).
