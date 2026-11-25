"""Enodia: OAuth gateway for MCP servers that only support a static bearer token.

The gateway serves one or more upstream MCP servers (Streamable HTTP), each at its own path `/<name>/mcp`. For each
upstream it:

- accepts only JWT access tokens that are signed by the issuer's keys (found through OIDC discovery) with a single
  asymmetric algorithm, carry an accepted `typ`, were issued by the configured issuer, are within their validity
  period (with a configurable clock skew allowance), carry one of the upstream's audiences, and satisfy any scopes or
  claim the upstream requires;
- answers unauthenticated requests with 401 and a WWW-Authenticate header pointing at its RFC 9728 protected resource
  metadata, served at /.well-known/oauth-protected-resource/<name>/mcp;
- calls the upstream with that upstream's static bearer token and never forwards the client's headers, so the
  client's access token is not passed upstream;
- logs one audit line per MCP request with the upstream, token subject, client ID, method and tool name.

Policy comes from a TOML file (CONFIG_FILE, default /etc/enodia/config.toml); runtime settings from
environment variables; secrets only from files. See README.md. Run `enodia --healthcheck` to probe a
running gateway from inside its container.
"""

from importlib.metadata import version

from .cli import healthcheck, main
from .config import Config, ConfigError, RequiredClaim, Upstream, load_config, upstream_paths
from .server import (
    AuditMiddleware,
    GatewayVerifier,
    KeySource,
    SigningSettings,
    StartupError,
    build_app,
    build_server,
    resolve_signing,
)

__version__ = version("enodia")

__all__ = [
    "AuditMiddleware",
    "Config",
    "ConfigError",
    "GatewayVerifier",
    "KeySource",
    "RequiredClaim",
    "SigningSettings",
    "StartupError",
    "Upstream",
    "__version__",
    "build_app",
    "build_server",
    "healthcheck",
    "load_config",
    "main",
    "resolve_signing",
    "upstream_paths",
]
