"""The gateway: key discovery, access token validation, one FastMCP proxy per upstream, and the audit log."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.auth import AccessToken, RemoteAuthProvider, TokenVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier, _has_unsupported_critical_headers, _import_key_for_algorithm
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.providers.proxy import ProxyClient
from fastmcp.utilities.auth import decode_jwt_header
from joserfc import jwt
from joserfc.errors import ClaimError, JoseError
from joserfc.jws import JWSRegistry
from starlette.applications import Starlette
from starlette.routing import Route

from .config import ASYMMETRIC_ALGORITHMS, Config, RequiredClaim, Upstream, normalize_token_type

logger = logging.getLogger("enodia")
audit_log = logging.getLogger("enodia.audit")

#: Claims that only ID tokens carry (OpenID Connect Core §2, §3.1.3.6, §3.3.2.11).
ID_TOKEN_CLAIMS = ("nonce", "at_hash", "c_hash")
_FETCH_TIMEOUT = 10


class StartupError(RuntimeError):
    """The gateway cannot start, for example because the issuer's metadata is unavailable or inconsistent."""


# --- Issuer metadata -----------------------------------------------------------------------------------------------


def _fetch_json(url: str) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT) as response:
        return json.loads(response.read())


def _metadata_urls(issuer: str) -> list[str]:
    """Where an issuer's metadata may live: OpenID Connect Discovery §4, then RFC 8414 §3."""
    parts = urlsplit(issuer)
    base = f"{parts.scheme}://{parts.netloc}"
    path = parts.path.rstrip("/")
    return [
        f"{issuer.rstrip('/')}/.well-known/openid-configuration",
        f"{base}/.well-known/oauth-authorization-server{path}",
    ]


def _require_scheme(what: str, url: str, allow_insecure: bool) -> None:
    scheme = urlsplit(url).scheme
    if scheme != "https" and not (allow_insecure and scheme == "http"):
        raise StartupError(f"{what} must use https: {url}")


def discover_jwks_uri(issuer: str, allow_insecure: bool) -> str:
    """Read `jwks_uri` from the issuer's metadata, checking that the metadata belongs to that issuer (RFC 8725 §3.8)."""
    errors = []
    for url in _metadata_urls(issuer):
        try:
            doc = _fetch_json(url)
        except (urllib.error.URLError, OSError, ValueError) as e:
            errors.append(f"{url}: {e}")
            continue
        if not isinstance(doc, dict):
            errors.append(f"{url}: not a JSON object")
            continue
        if doc.get("issuer") != issuer:
            # OpenID Connect Discovery §4.3 and RFC 8414 §3.3: the document must name exactly this issuer.
            raise StartupError(f"issuer metadata at {url} names issuer {doc.get('issuer')!r}, expected {issuer!r}")
        jwks_uri = doc.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise StartupError(f"issuer metadata at {url} has no jwks_uri")
        _require_scheme("jwks_uri", jwks_uri, allow_insecure)
        return jwks_uri
    raise StartupError("cannot read issuer metadata: " + "; ".join(errors))


def _signing_keys(jwks: Any) -> list[dict[str, Any]]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise StartupError("JWKS has no keys array")
    return [k for k in keys if isinstance(k, dict) and k.get("use", "sig") == "sig"]


def detect_algorithm(jwks: Any) -> str:
    """The single asymmetric algorithm that every signing key in the JWKS declares (never taken from a token)."""
    keys = _signing_keys(jwks)
    if not keys:
        raise StartupError("JWKS has no signing keys")
    algorithms = {k.get("alg") for k in keys}
    if None in algorithms or len(algorithms) != 1:
        raise StartupError(
            "cannot determine the signing algorithm from the JWKS (keys declare "
            f"{sorted(str(a) for a in algorithms)}); set algorithm in the config file"
        )
    algorithm = algorithms.pop()
    if algorithm not in ASYMMETRIC_ALGORITHMS:
        raise StartupError(f"JWKS keys use {algorithm!r}, which is not an accepted asymmetric algorithm")
    return algorithm


@dataclass(frozen=True)
class SigningSettings:
    jwks_uri: str
    algorithm: str
    algorithm_source: str


def resolve_signing(config: Config) -> SigningSettings:
    """Work out where the issuer's keys are and which algorithm to accept, from configuration or issuer metadata."""
    jwks_uri = config.jwks_uri or discover_jwks_uri(config.issuer, config.allow_insecure_urls)
    if config.algorithm:
        return SigningSettings(jwks_uri, config.algorithm, "config file")
    try:
        jwks = _fetch_json(jwks_uri)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise StartupError(f"cannot read JWKS from {jwks_uri}: {e}") from None
    return SigningSettings(jwks_uri, detect_algorithm(jwks), "JWKS")


# --- Token validation ----------------------------------------------------------------------------------------------


class KeySource(JWTVerifier):
    """Fetches and caches the issuer's signing keys; shared by every upstream's verifier.

    Reuses FastMCP's JWKS cache, refetch on unknown key IDs, and refresh rate limiting. Keys meant for encryption, or
    declaring an algorithm other than the accepted one, are dropped so that each key is only ever used with exactly one
    algorithm (RFC 8725 §3.1).
    """

    def __init__(self, signing: SigningSettings):
        super().__init__(jwks_uri=signing.jwks_uri, algorithm=signing.algorithm)

    async def _fetch_jwks(self) -> dict[str, Any]:
        jwks = await super()._fetch_jwks()
        keys = [k for k in _signing_keys(jwks) if k.get("alg", self.algorithm) == self.algorithm]
        return {"keys": keys}

    async def key_for(self, token: str) -> Any:
        return _import_key_for_algorithm(await self._get_verification_key(token), self.algorithm)


def _scopes(claims: dict[str, Any]) -> list[str]:
    """Scopes from `scope`, else `scp`; each may be a space-delimited string or an array (Entra, Pocket ID)."""
    for name in ("scope", "scp"):
        value = claims.get(name)
        if isinstance(value, str):
            return value.split()
        if isinstance(value, list):
            return [s for s in value if isinstance(s, str)]
    return []


class GatewayVerifier(TokenVerifier):
    """Validates access tokens for one upstream, following RFC 8725 and RFC 9068.

    FastMCP's JWTVerifier only checks `exp` when present and without leeway, ignores `nbf`, `iat` and `typ`, so this
    verifier does its own validation and uses the shared KeySource only for keys.
    """

    def __init__(self, *, keys: KeySource, config: Config, upstream: Upstream):
        super().__init__(required_scopes=list(upstream.required_scopes))
        self.keys = keys
        self.issuer = config.issuer
        self.audience = list(upstream.audience)
        self.required_claim: RequiredClaim | None = upstream.required_claim
        self.leeway = config.max_clock_skew_seconds
        self.accepted_types = frozenset(config.accepted_token_types)
        self.accept_missing_type = config.accept_missing_token_type
        self.screen_id_tokens = config.token_type_relaxed
        self.upstream = upstream.name

    def _reject(self, reason: str, *, warn: bool = False) -> AccessToken | None:
        """Log why a token was refused. Always returns None, so callers can `return self._reject(...)`."""
        (logger.warning if warn else logger.debug)("token rejected for upstream %s: %s", self.upstream, reason)
        return None

    def _type_acceptable(self, header: dict[str, Any]) -> bool:
        typ = header.get("typ")
        if typ is None:
            return self.accept_missing_type
        return isinstance(typ, str) and normalize_token_type(typ) in self.accepted_types

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = decode_jwt_header(token)
            if _has_unsupported_critical_headers(header):
                return self._reject("unsupported critical header")
            if not self._type_acceptable(header):
                return self._reject(f"token type {header.get('typ')!r} is not accepted")

            algorithm = self.keys.algorithm
            claims = jwt.decode(
                token,
                await self.keys.key_for(token),
                algorithms=[algorithm],
                registry=JWSRegistry(algorithms=[algorithm], strict_check_header=False),
            ).claims
            jwt.JWTClaimsRegistry(
                leeway=self.leeway,
                iss={"essential": True, "value": self.issuer},
                aud={"essential": True, "values": self.audience},
                exp={"essential": True},
                sub={"essential": True},
            ).validate(claims)
        except ClaimError as e:
            return self._reject(f"claim check failed: {e}", warn=getattr(e, "claim", None) in {"iss", "aud"})
        except (JoseError, ValueError, TypeError, KeyError) as e:
            return self._reject(f"invalid token: {e}")

        scopes = _scopes(claims)
        if self.screen_id_tokens:
            # Without an explicit at+jwt type, tell ID tokens apart by content (RFC 8725 §3.11, RFC 9068 §4).
            if any(name in claims for name in ID_TOKEN_CLAIMS) or str(claims.get("typ", "")).upper() == "ID":
                return self._reject("looks like an ID token", warn=True)
            if not scopes:
                return self._reject("no scope claim, so it cannot be told apart from an ID token")
        if not set(self.required_scopes) <= set(scopes):
            return self._reject(f"missing required scopes {sorted(set(self.required_scopes) - set(scopes))}")
        if self.required_claim and not self.required_claim.matches(claims):
            return self._reject(f"claim {self.required_claim.name!r} does not include the required value")

        client_id = claims.get("client_id") or claims.get("azp") or claims.get("sub")
        return AccessToken(
            token=token,
            client_id=str(client_id),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            subject=claims.get("sub"),
            claims=claims,
        )


# --- Audit ---------------------------------------------------------------------------------------------------------


class AuditMiddleware(Middleware):
    """Log who made each MCP request. The upstream only ever sees the gateway's own identity."""

    def __init__(self, upstream: str):
        self.upstream = upstream

    async def on_request(self, context: MiddlewareContext, call_next: Any) -> Any:
        token = get_access_token()
        entry: dict[str, Any] = {
            "event": "mcp_request",
            "upstream": self.upstream,
            "method": context.method,
            "subject": token.subject if token else None,
            "client_id": token.client_id if token else None,
        }
        if context.method == "tools/call":
            entry["tool"] = getattr(context.message, "name", None)
        started = time.monotonic()
        try:
            result = await call_next(context)
        except Exception as e:
            entry.update(outcome="error", error=type(e).__name__)
            raise
        else:
            entry["outcome"] = "error" if getattr(result, "isError", False) else "ok"
            return result
        finally:
            entry["duration_ms"] = round((time.monotonic() - started) * 1000)
            audit_log.info(json.dumps(entry, sort_keys=True))


# --- Assembly ------------------------------------------------------------------------------------------------------


def advertised_scopes(config: Config, upstream: Upstream) -> list[str]:
    """Scopes clients should request for an upstream: the shared ones plus the upstream's required ones.

    RFC 9728 defines `scopes_supported` as the values used in authorization requests, which for some IdPs differ from
    the values in the token. `advertised_scope_prefix` turns the required (token-form) scopes into the request form.
    """
    prefix = config.advertised_scope_prefix
    return list(dict.fromkeys([*config.scopes_supported, *(prefix + s for s in upstream.required_scopes)]))


def build_server(config: Config, upstream: Upstream, keys: KeySource) -> FastMCP:
    scopes = advertised_scopes(config, upstream)
    auth = RemoteAuthProvider(
        token_verifier=GatewayVerifier(keys=keys, config=config, upstream=upstream),
        # FastMCP types this as list[AnyHttpUrl], but AnyHttpUrl normalises the URL (a bare host gains a trailing "/"),
        # and clients match the advertised issuer exactly against the issuer's metadata. A plain string is passed
        # through unchanged.
        authorization_servers=[config.issuer],  # ty: ignore[invalid-argument-type]
        base_url=config.public_url,
        scopes_supported=scopes,
        # Without this the 401 challenge would ask only for the required scopes, and clients (which prefer the
        # challenge over the metadata) would drop openid / offline_access.
        challenge_scopes=scopes,
        resource_name=upstream.resource_name,
    )
    backend = ProxyClient(
        StreamableHttpTransport(upstream.url, headers={"Authorization": f"Bearer {upstream.token}"}),
        forward_incoming_headers=False,
    )
    server = create_proxy(backend, name=upstream.resource_name, auth=auth)
    server.add_middleware(AuditMiddleware(upstream.name))
    return server


def _combined_lifespan(apps: Sequence[Starlette]):
    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with AsyncExitStack() as stack:
            for app in apps:
                await stack.enter_async_context(app.router.lifespan_context(app))
            yield

    return lifespan


def build_app(config: Config, signing: SigningSettings | None = None) -> Starlette:
    """One ASGI app serving every upstream at its own path. Anything else is 404.

    Each upstream's FastMCP app is built with its full path, so its MCP endpoint, its protected resource metadata
    (/.well-known/oauth-protected-resource/<name>/mcp) and its 401 challenge all use the right URLs; requests are
    dispatched to it unchanged by exact path.
    """
    signing = signing or resolve_signing(config)
    keys = KeySource(signing)
    routes: dict[str, Route] = {}
    apps = []
    for upstream in config.upstreams:
        app = build_server(config, upstream, keys).http_app(path=upstream.path)
        apps.append(app)
        # Route every path the upstream's app serves (its MCP endpoint and metadata document) to it, unchanged.
        for path in sorted({p for r in app.routes if isinstance(p := getattr(r, "path", None), str)}):
            if path in routes:
                raise StartupError(f"path {path} is served by more than one upstream")
            routes[path] = Route(path, app)
    return Starlette(routes=list(routes.values()), lifespan=_combined_lifespan(apps))
