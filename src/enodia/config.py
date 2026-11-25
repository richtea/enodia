"""Gateway configuration: policy from a TOML file, runtime settings from environment variables, secrets from files."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

DEFAULT_CONFIG_FILE = "/etc/enodia/config.toml"
DEFAULT_SCOPES = ("openid", "offline_access")
DEFAULT_TOKEN_TYPES = ("at+jwt",)
DEFAULT_CLOCK_SKEW = 60
MAX_CLOCK_SKEW = 300

#: Asymmetric JWS algorithms the gateway accepts. Symmetric (HS*) and "none" are never accepted.
ASYMMETRIC_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA", "Ed25519", "Ed448",
})

#: Claims a required_claim may not name: they are validated by the gateway itself.
RESERVED_CLAIMS = frozenset({"aud", "iss", "exp", "nbf", "iat", "sub", "scope", "scp"})

#: Token types that identify ID tokens. Listing one in accepted_token_types is almost certainly a mistake.
ID_TOKEN_TYPES = frozenset({"id", "id_token", "id+jwt"})

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

_TOP_LEVEL_KEYS = frozenset({
    "issuer", "public_url", "jwks_uri", "algorithm", "scopes_supported", "advertised_scope_prefix",
    "max_clock_skew_seconds",
    "accepted_token_types", "accept_missing_token_type", "allow_insecure_urls", "upstream",
})
_UPSTREAM_KEYS = frozenset({
    "name", "url", "token_file", "resource_name", "audience", "required_scopes", "required_claim",
})
_CLAIM_KEYS = frozenset({"name", "value"})


class ConfigError(ValueError):
    """The configuration is missing, malformed or unsafe."""


@dataclass(frozen=True)
class RequiredClaim:
    name: str
    value: str

    def matches(self, claims: Mapping[str, Any]) -> bool:
        """True if the claim equals the value, or is an array containing it."""
        actual = claims.get(self.name)
        if isinstance(actual, list):
            return self.value in actual
        return actual == self.value


@dataclass(frozen=True)
class Upstream:
    name: str
    path: str
    url: str
    token: str
    resource_name: str
    audience: tuple[str, ...]
    required_scopes: tuple[str, ...]
    required_claim: RequiredClaim | None


@dataclass(frozen=True)
class Config:
    issuer: str
    public_url: str
    jwks_uri: str | None
    algorithm: str | None
    scopes_supported: tuple[str, ...]
    advertised_scope_prefix: str
    max_clock_skew_seconds: int
    accepted_token_types: tuple[str, ...]
    accept_missing_token_type: bool
    allow_insecure_urls: bool
    host: str
    port: int
    upstreams: tuple[Upstream, ...]

    @property
    def token_type_relaxed(self) -> bool:
        """True if tokens other than RFC 9068 `at+jwt` are accepted, so ID tokens must be screened out by content."""
        return self.accept_missing_token_type or any(t != "at+jwt" for t in self.accepted_token_types)


def upstream_path(name: str) -> str:
    return f"/{name}/mcp"


def normalize_token_type(value: str) -> str:
    """Compare `typ` values case-insensitively, with the optional `application/` prefix removed (RFC 7515 §4.1.9)."""
    value = value.strip().lower()
    return value.removeprefix("application/")


class _Reader:
    """Typed access to one TOML table, with errors that name the file and key."""

    def __init__(self, source: str, where: str, table: Mapping[str, Any], allowed: frozenset[str]):
        self.source = source
        self.where = where
        self.table = table
        unknown = sorted(set(table) - allowed)
        if "token" in unknown:
            raise self.error("token", "inline tokens are not allowed; use token_file")
        if unknown:
            raise self.error(unknown[0], "unknown key")

    def error(self, key: str, message: str) -> ConfigError:
        return ConfigError(f"{self.source}: {self.where}{key}: {message}")

    def get(self, key: str, kind: type, default: Any = None, *, required: bool = False) -> Any:
        if key not in self.table:
            if required:
                raise self.error(key, "is required")
            return default
        value = self.table[key]
        # bool is a subclass of int; never accept one for the other.
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            raise self.error(key, f"must be a {kind.__name__}")
        return value

    def string(self, key: str, default: str | None = None, *, required: bool = False) -> str | None:
        value = self.get(key, str, default, required=required)
        if value is not None and not value.strip():
            raise self.error(key, "must not be empty")
        return value.strip() if value is not None else None

    def required_string(self, key: str) -> str:
        value = self.string(key, required=True)
        assert value is not None  # string() raises for a missing required key
        return value

    def string_list(self, key: str, default: tuple[str, ...] = (), *, tokens: bool = False) -> tuple[str, ...]:
        value = self.get(key, list, None)
        if value is None:
            return default
        result = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise self.error(key, "must be a list of non-empty strings")
            if tokens and any(c.isspace() for c in item.strip()):
                raise self.error(key, f"entry {item!r} must not contain whitespace")
            result.append(item.strip())
        return tuple(result)

    def url(self, key: str, value: str, *, require_https: bool, strip_slash: bool = True) -> str:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise self.error(key, "must be an absolute http(s) URL")
        if require_https and parts.scheme != "https":
            raise self.error(key, "must use https (set allow_insecure_urls = true only for local testing)")
        if parts.query or parts.fragment:
            raise self.error(key, "must not have a query or fragment")
        return value.rstrip("/") if strip_slash else value


def _read_secret_file(where: str, path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            value = f.read().strip()
    except OSError as e:
        raise ConfigError(f"{where}: cannot read {path} ({e.strerror})") from None
    if not value:
        raise ConfigError(f"{where}: {path} is empty")
    if any(c.isspace() for c in value):
        raise ConfigError(f"{where}: {path} must contain a single token without whitespace")
    return value


def _read_toml(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read config file {path} ({e.strerror})") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML ({e})") from None


def _upstream_tables(path: str, data: Mapping[str, Any]) -> list[Any]:
    tables = data.get("upstream")
    if not isinstance(tables, list) or not tables:
        raise ConfigError(f"{path}: at least one [[upstream]] table is required")
    return tables


def upstream_paths(path: str) -> list[str]:
    """The MCP paths a config file defines, without reading secrets or validating anything else (for health checks)."""
    data = _read_toml(path)
    paths = []
    for table in _upstream_tables(path, data):
        name = table.get("name") if isinstance(table, dict) else None
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ConfigError(f"{path}: invalid upstream name {name!r}")
        paths.append(upstream_path(name))
    return paths


def _requirements(upstream: Upstream) -> set[tuple[str, ...]]:
    reqs: set[tuple[str, ...]] = {("scope", s) for s in upstream.required_scopes}
    if upstream.required_claim:
        reqs.add(("claim", upstream.required_claim.name, upstream.required_claim.value))
    return reqs


def _check_distinguishable(source: str, upstreams: tuple[Upstream, ...]) -> None:
    """Refuse configurations where a token accepted by one upstream would also be accepted by another."""
    for i, a in enumerate(upstreams):
        for b in upstreams[i + 1:]:
            if not set(a.audience) & set(b.audience):
                continue
            # A token minted for b satisfies exactly b's requirements; a refuses it only if a requires something more.
            if not (_requirements(a) - _requirements(b)) or not (_requirements(b) - _requirements(a)):
                raise ConfigError(
                    f"{source}: upstreams {a.name!r} and {b.name!r} share an audience, so each must require a scope "
                    "or claim value the other does not; otherwise a token for one is accepted by the other. Give them "
                    "distinct audiences or distinct required_scopes / required_claim"
                )


def _load_upstream(
    source: str, index: int, table: Any, public_url: str, issuer: str, insecure: bool,
) -> Upstream:
    if not isinstance(table, dict):
        raise ConfigError(f"{source}: upstream[{index}] must be a table")
    name_hint = table.get("name") if isinstance(table.get("name"), str) else "?"
    r = _Reader(source, f"upstream[{index}] ({name_hint}).", table, _UPSTREAM_KEYS)

    name = r.required_string("name")
    if not _NAME_RE.match(name):
        raise r.error("name", "must match ^[a-z0-9][a-z0-9-]*$ (lower-case letters, digits and hyphens)")
    url = r.url("url", r.required_string("url"), require_https=False)
    token = _read_secret_file(f"{source}: {r.where}token_file", r.required_string("token_file"))
    resource_name = r.required_string("resource_name")

    path = upstream_path(name)
    audience = r.string_list("audience", (f"{public_url}{path}",))
    if not audience:
        raise r.error("audience", "must not be empty")
    if issuer.rstrip("/") in {a.rstrip("/") for a in audience}:
        # Tokens issued without a resource can carry the issuer as an audience; accepting it would accept them all.
        raise r.error("audience", "must not include the issuer")

    required_scopes = r.string_list("required_scopes", tokens=True)

    required_claim = None
    claim_table = r.get("required_claim", dict)
    if claim_table is not None:
        c = _Reader(source, f"{r.where}required_claim.", claim_table, _CLAIM_KEYS)
        claim_name = c.required_string("name")
        if claim_name in RESERVED_CLAIMS:
            raise c.error("name", f"{claim_name!r} is validated by the gateway and cannot be a required claim")
        required_claim = RequiredClaim(claim_name, c.required_string("value"))

    return Upstream(
        name=name, path=path, url=url, token=token, resource_name=resource_name, audience=audience,
        required_scopes=required_scopes, required_claim=required_claim,
    )


def load_config(path: str, env: Mapping[str, str]) -> Config:
    """Build the configuration from the TOML file at `path` and runtime environment variables.

    Refuses anything unsafe, incomplete or ambiguous. Reads each upstream's token file. Does no network I/O.
    """
    data = _read_toml(path)
    r = _Reader(path, "", data, _TOP_LEVEL_KEYS)

    insecure = r.get("allow_insecure_urls", bool, False)
    # The issuer is compared exactly with the `iss` claim, so it is kept as written (including any trailing slash).
    issuer = r.url("issuer", r.required_string("issuer"), require_https=not insecure, strip_slash=False)
    public_url = r.url("public_url", r.required_string("public_url"), require_https=not insecure)
    jwks_uri = r.string("jwks_uri")
    if jwks_uri is not None:
        jwks_uri = r.url("jwks_uri", jwks_uri, require_https=not insecure, strip_slash=False)

    algorithm = r.string("algorithm")
    if algorithm is not None and algorithm not in ASYMMETRIC_ALGORITHMS:
        raise r.error("algorithm", "must be an asymmetric algorithm such as RS256 or ES256")

    scopes = r.string_list("scopes_supported", DEFAULT_SCOPES, tokens=True)

    # Some IdPs (Entra ID) name a scope by URI in requests but put only the short name in the token. The prefix is
    # added to required_scopes in the metadata and challenge only; tokens are still checked for the short names.
    scope_prefix = r.string("advertised_scope_prefix") or ""
    if any(c.isspace() for c in scope_prefix):
        raise r.error("advertised_scope_prefix", "must not contain whitespace")
    if scope_prefix and not scope_prefix.endswith("/"):
        raise r.error("advertised_scope_prefix", "must end with '/' (for example 'api://<client-id>/')")

    skew = r.get("max_clock_skew_seconds", int, DEFAULT_CLOCK_SKEW)
    if not 0 <= skew <= MAX_CLOCK_SKEW:
        raise r.error("max_clock_skew_seconds", f"must be between 0 and {MAX_CLOCK_SKEW}")

    token_types = tuple(normalize_token_type(t) for t in r.string_list("accepted_token_types", DEFAULT_TOKEN_TYPES))
    if "accepted_token_types" in data and not token_types:
        raise r.error("accepted_token_types", "must not be empty")
    for t in token_types:
        if t in ID_TOKEN_TYPES:
            raise r.error("accepted_token_types", f"{t!r} identifies ID tokens, which must never be accepted "
                                                  "(did you mean 'JWT' or 'at+jwt'?)")
    accept_missing = r.get("accept_missing_token_type", bool, False)

    upstreams = tuple(
        _load_upstream(path, i, table, public_url, issuer, insecure)
        for i, table in enumerate(_upstream_tables(path, data))
    )
    seen: set[str] = set()
    for u in upstreams:
        if u.name in seen:
            raise ConfigError(f"{path}: duplicate upstream name {u.name!r}")
        seen.add(u.name)
    _check_distinguishable(path, upstreams)
    if scope_prefix:
        for u in upstreams:
            if not u.required_scopes:
                raise ConfigError(
                    f"{path}: advertised_scope_prefix is set but upstream {u.name!r} has no required_scopes, so "
                    "clients would request no scope for it and the IdP would not issue a token for this API"
                )

    try:
        port = int(env.get("PORT", "8000"))
    except ValueError:
        raise ConfigError("PORT must be a number") from None

    return Config(
        issuer=issuer,
        public_url=public_url,
        jwks_uri=jwks_uri,
        algorithm=algorithm,
        scopes_supported=scopes,
        advertised_scope_prefix=scope_prefix,
        max_clock_skew_seconds=skew,
        accepted_token_types=token_types,
        accept_missing_token_type=accept_missing,
        allow_insecure_urls=insecure,
        host=env.get("HOST", "0.0.0.0").strip(),
        port=port,
        upstreams=upstreams,
    )
