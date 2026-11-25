"""Command-line entry point: run the gateway, or probe a running one with --healthcheck."""

from __future__ import annotations

import http.client
import logging
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from importlib.metadata import version

import uvicorn

from .config import DEFAULT_CONFIG_FILE, ConfigError, load_config, upstream_paths
from .server import StartupError, advertised_scopes, build_app, resolve_signing

logger = logging.getLogger("enodia")


def _challenged(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=3)
    except urllib.error.HTTPError as e:
        return e.code == 401 and "resource_metadata=" in e.headers.get("WWW-Authenticate", "")
    except (OSError, http.client.HTTPException, ValueError):
        # Connection failures, timeouts (OSError, including URLError), malformed responses, or a bad URL.
        return False
    return False


def healthcheck(env: Mapping[str, str]) -> int:
    """Return 0 if every upstream path refuses an unauthenticated request with an RFC 9728 challenge."""
    try:
        paths = upstream_paths(env.get("CONFIG_FILE", DEFAULT_CONFIG_FILE))
    except ConfigError:
        return 1
    port = env.get("PORT", "8000")
    return 0 if all(_challenged(f"http://127.0.0.1:{port}{path}") for path in paths) else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--healthcheck"]:
        return healthcheck(os.environ)
    if args:
        print("usage: enodia [--healthcheck]", file=sys.stderr)
        return 2

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format="%(levelname)s %(name)s %(message)s")
    config_file = os.environ.get("CONFIG_FILE", DEFAULT_CONFIG_FILE)
    try:
        config = load_config(config_file, os.environ)
        signing = resolve_signing(config)
        app = build_app(config, signing)
    except (ConfigError, StartupError) as e:
        print(f"enodia: {e}", file=sys.stderr)
        return 1

    logger.info("enodia %s: config %s, issuer %s", version("enodia"), config_file, config.issuer)
    logger.info("signing algorithm %s (from %s), keys from %s",
                signing.algorithm, signing.algorithm_source, signing.jwks_uri)
    logger.info("clock skew allowance %ss", config.max_clock_skew_seconds)
    if config.token_type_relaxed:
        logger.warning(
            "accepting token types %s%s; ID tokens are screened out by content instead (RFC 9068 recommends at+jwt)",
            list(config.accepted_token_types), " and tokens without a typ" if config.accept_missing_token_type else "",
        )
    for u in config.upstreams:
        logger.info(
            "upstream %s: %s%s -> %s (audience %s, required scopes %s, required claim %s, advertised scopes %s)",
            u.name, config.public_url, u.path, u.url, list(u.audience), list(u.required_scopes),
            f"{u.required_claim.name}={u.required_claim.value}" if u.required_claim else None,
            advertised_scopes(config, u),
        )

    uvicorn.run(app, host=config.host, port=config.port, log_config=None)
    return 0
