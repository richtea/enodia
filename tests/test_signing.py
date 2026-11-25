"""Finding the issuer's keys (OIDC discovery) and the accepted signing algorithm."""

from __future__ import annotations

from typing import Any

import pytest

from enodia import StartupError, load_config, resolve_signing
from enodia.server import detect_algorithm

from .conftest import free_port, jwk_for, secret_file, write_config


@pytest.fixture
def config_for(tmp_path):
    def _config(issuer: str, **top: Any):
        t = {"issuer": issuer, "public_url": "https://mcp.example", "allow_insecure_urls": True, **top}
        u = {"name": "alpha", "url": "http://a/mcp", "token_file": secret_file(tmp_path, "t", "x"),
             "resource_name": "A"}
        return load_config(write_config(tmp_path, t, [u]), {})

    return _config


def test_keys_and_algorithm_come_from_discovery(config_for, idp):
    signing = resolve_signing(config_for(idp.base))
    assert signing.jwks_uri == f"{idp.base}/keys"
    assert (signing.algorithm, signing.algorithm_source) == ("RS256", "JWKS")


def test_discovery_for_issuer_with_path_and_trailing_slash(config_for, idp):
    issuer = f"{idp.base}/application/o/test/"
    idp.add_issuer("/application/o/test", issuer, f"{idp.base}/keys")
    assert resolve_signing(config_for(issuer)).jwks_uri == f"{idp.base}/keys"


def test_rfc8414_metadata_is_used_when_oidc_discovery_is_absent(config_for, idp):
    issuer = f"{idp.base}/as"
    idp.routes["/.well-known/oauth-authorization-server/as"] = {"issuer": issuer, "jwks_uri": f"{idp.base}/keys"}
    assert resolve_signing(config_for(issuer)).jwks_uri == f"{idp.base}/keys"


def test_discovery_naming_another_issuer_stops_startup(config_for, idp):
    idp.add_issuer("/mismatch", "https://attacker.example", f"{idp.base}/keys")
    with pytest.raises(StartupError, match="names issuer"):
        resolve_signing(config_for(f"{idp.base}/mismatch"))


def test_discovery_without_jwks_uri_stops_startup(config_for, idp):
    idp.routes["/nojwks/.well-known/openid-configuration"] = {"issuer": f"{idp.base}/nojwks"}
    with pytest.raises(StartupError, match="jwks_uri"):
        resolve_signing(config_for(f"{idp.base}/nojwks"))


def test_unreachable_issuer_stops_startup(config_for):
    with pytest.raises(StartupError, match="cannot read issuer metadata"):
        resolve_signing(config_for(f"http://127.0.0.1:{free_port()}"))


def test_configured_jwks_uri_skips_discovery(config_for, idp):
    # The issuer has no metadata at all; the configured jwks_uri is used directly.
    signing = resolve_signing(config_for(f"{idp.base}/no-metadata", jwks_uri=f"{idp.base}/keys"))
    assert (signing.jwks_uri, signing.algorithm) == (f"{idp.base}/keys", "RS256")


def test_configured_algorithm_wins(config_for, idp):
    signing = resolve_signing(config_for(idp.base, algorithm="PS256"))
    assert (signing.algorithm, signing.algorithm_source) == ("PS256", "config file")


def test_configured_jwks_uri_and_algorithm_need_no_network(config_for):
    dead = f"http://127.0.0.1:{free_port()}"
    signing = resolve_signing(config_for(dead, jwks_uri=f"{dead}/keys", algorithm="ES256"))
    assert signing.algorithm == "ES256"


def _key(**fields: Any) -> dict[str, Any]:
    return {"kty": "RSA", "kid": "k", **fields}


@pytest.mark.parametrize(
    ("keys", "result"),
    [
        ([_key(alg="RS256")], "RS256"),
        ([_key(alg="ES256", use="sig"), _key(alg="ES256")], "ES256"),
        ([_key(alg="RS256"), _key(alg="RSA-OAEP", use="enc")], "RS256"),
        ([_key()], StartupError),
        ([_key(alg="RS256"), _key()], StartupError),
        ([_key(alg="RS256"), _key(alg="ES256")], StartupError),
        ([_key(alg="HS256")], StartupError),
        ([_key(alg="none")], StartupError),
        ([_key(alg="RSA-OAEP", use="enc")], StartupError),
        ([], StartupError),
    ],
)
def test_detect_algorithm(keys, result):
    if result is StartupError:
        with pytest.raises(StartupError):
            detect_algorithm({"keys": keys})
    else:
        assert detect_algorithm({"keys": keys}) == result


def test_detection_failure_stops_startup(config_for, idp, signing_key):
    key = jwk_for(signing_key)
    del key["alg"]
    idp.routes["/noalg/keys"] = {"keys": [key]}
    idp.add_issuer("/noalg", f"{idp.base}/noalg", f"{idp.base}/noalg/keys")
    with pytest.raises(StartupError, match="set algorithm"):
        resolve_signing(config_for(f"{idp.base}/noalg"))
