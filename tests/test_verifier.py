"""Access token validation rules (RFC 8725, RFC 9068), tested directly against GatewayVerifier."""

from __future__ import annotations

import time
from typing import Any

import pytest

from enodia import GatewayVerifier, KeySource, SigningSettings, load_config

from .conftest import jwk_for, secret_file, write_config

AUD = "https://mcp.example/alpha/mcp"


@pytest.fixture
def make_verifier(tmp_path, idp, issuer):
    def _make(top: dict[str, Any] | None = None, upstream: dict[str, Any] | None = None,
              jwks_path: str = "/keys") -> GatewayVerifier:
        t = {"issuer": issuer, "public_url": "https://mcp.example", "allow_insecure_urls": True, **(top or {})}
        u = {"name": "alpha", "url": "http://a/mcp", "token_file": secret_file(tmp_path, "t", "x"),
             "resource_name": "A", **(upstream or {})}
        config = load_config(write_config(tmp_path, t, [u]), {})
        keys = KeySource(SigningSettings(f"{idp.base}{jwks_path}", "RS256", "test"))
        return GatewayVerifier(keys=keys, config=config, upstream=config.upstreams[0])

    return _make


@pytest.fixture
def tok(mint):
    def _tok(**kwargs):
        kwargs.setdefault("aud", AUD)
        return mint(**kwargs)

    return _tok


async def accepted(verifier: GatewayVerifier, token: str) -> bool:
    return await verifier.verify_token(token) is not None


async def test_valid_token(make_verifier, tok):
    result = await make_verifier().verify_token(tok(sub="alice", client_id="cc"))
    assert result is not None
    assert result.subject == "alice"
    assert result.client_id == "cc"
    assert result.scopes == ["openid", "offline_access"]


# --- Required claims and issuer ------------------------------------------------------------------------------------


@pytest.mark.parametrize("claim", ["exp", "iss", "aud", "sub"])
async def test_missing_required_claim_is_refused(make_verifier, tok, claim):
    assert not await accepted(make_verifier(), tok(drop=(claim,)))


@pytest.mark.parametrize("variant", ["other", "trailing_slash", "upper_case", "list"])
async def test_issuer_must_match_exactly(make_verifier, tok, issuer, variant):
    iss = {
        "other": "https://attacker.example",
        "trailing_slash": issuer + "/",
        "upper_case": issuer.upper(),
        "list": [issuer],
    }[variant]
    assert not await accepted(make_verifier(), tok(iss=iss))


async def test_issuer_with_trailing_slash_is_kept_exactly(make_verifier, tok, issuer):
    verifier = make_verifier({"issuer": f"{issuer}/application/o/test/"})
    assert await accepted(verifier, tok(iss=f"{issuer}/application/o/test/"))
    assert not await accepted(verifier, tok(iss=f"{issuer}/application/o/test"))


async def test_audience_list_is_accepted_when_it_contains_ours(make_verifier, tok):
    assert await accepted(make_verifier(), tok(aud=["https://other.example", AUD]))
    assert not await accepted(make_verifier(), tok(aud=["https://other.example"]))


# --- Time claims and clock skew ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("skew", "claims", "ok"),
    [
        (None, {"exp_offset": -30}, True),
        (None, {"exp_offset": -120}, False),
        (None, {"nbf": 30}, True),
        (None, {"nbf": 120}, False),
        (None, {"iat": 30}, True),
        (None, {"iat": 120}, False),
        (0, {"exp_offset": -1}, False),
        (0, {"nbf": 5}, False),
        (180, {"exp_offset": -120}, True),
        (180, {"exp_offset": -240}, False),
    ],
)
async def test_time_claims_respect_clock_skew(make_verifier, tok, skew, claims, ok):
    top = {} if skew is None else {"max_clock_skew_seconds": skew}
    now = int(time.time())
    kwargs = dict(claims)
    for name in ("nbf", "iat"):
        if name in kwargs:
            kwargs[name] = now + kwargs[name]
    assert await accepted(make_verifier(top), tok(**kwargs)) is ok


async def test_non_numeric_exp_is_refused(make_verifier, tok):
    assert not await accepted(make_verifier(), tok(exp="tomorrow"))


# --- Token type ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("typ", "ok"), [
    ("at+jwt", True), ("application/at+jwt", True), ("AT+JWT", True), ("JWT", False), (None, False),
    ("id+jwt", False),
])
async def test_default_token_types(make_verifier, tok, typ, ok):
    assert await accepted(make_verifier(), tok(typ=typ)) is ok


@pytest.mark.parametrize(("claims", "ok"), [
    ({}, True),
    ({"nonce": "n"}, False),
    ({"at_hash": "h"}, False),
    ({"c_hash": "h"}, False),
    ({"extra_claims": {"typ": "ID"}}, False),
    ({"scope": None}, False),
    ({"scope": None, "scp": ["openid"]}, True),
])
async def test_extra_token_types_screen_out_id_tokens(make_verifier, tok, claims, ok):
    verifier = make_verifier({"accepted_token_types": ["at+jwt", "JWT"]})
    assert await accepted(verifier, tok(typ="JWT", **claims)) is ok


@pytest.mark.parametrize(("claims", "ok"), [
    ({}, True),
    ({"nonce": "n"}, False),
    ({"scope": None}, False),
])
async def test_missing_token_type_when_allowed_screens_out_id_tokens(make_verifier, tok, claims, ok):
    verifier = make_verifier({"accept_missing_token_type": True})
    assert await accepted(verifier, tok(typ=None, **claims)) is ok
    # at+jwt tokens are still accepted, and other types still refused.
    assert await accepted(verifier, tok(typ="at+jwt"))
    assert not await accepted(verifier, tok(typ="JWT"))


async def test_screening_does_not_apply_to_at_jwt(make_verifier, tok):
    # An at+jwt token is an access token by declaration; a nonce claim is unusual but not disqualifying.
    assert await accepted(make_verifier(), tok(nonce="n"))


# --- Scopes and claims ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("claims", "ok"), [
    ({"scope": "openid mcp:x"}, True),
    ({"scope": None, "scp": ["openid", "mcp:x"]}, True),
    ({"scope": None, "scp": "openid mcp:x"}, True),
    ({"scope": "openid mcp:x", "scp": ["openid", "mcp:x"]}, True),
    ({"scope": "openid"}, False),
    ({"scope": None}, False),
])
async def test_required_scopes(make_verifier, tok, claims, ok):
    verifier = make_verifier(upstream={"required_scopes": ["mcp:x"]})
    assert await accepted(verifier, tok(**claims)) is ok


@pytest.mark.parametrize(("claims", "ok"), [
    ({"scope": None, "scp": "github"}, True),
    ({"scope": None, "scp": "api://11111111-1111-1111-1111-111111111111/github"}, False),
])
async def test_advertised_scope_prefix_does_not_change_the_check(make_verifier, tok, claims, ok):
    # Entra ID: clients request api://<id>/github, the token's scp carries github.
    verifier = make_verifier({"advertised_scope_prefix": "api://11111111-1111-1111-1111-111111111111/"},
                             {"required_scopes": ["github"]})
    assert await accepted(verifier, tok(**claims)) is ok


@pytest.mark.parametrize(("claims", "ok"), [
    ({"groups": "mcp-alpha"}, True),
    ({"groups": ["users", "mcp-alpha"]}, True),
    ({"groups": ["users"]}, False),
    ({"groups": "mcp-alpha-admins"}, False),
    ({}, False),
])
async def test_required_claim(make_verifier, tok, claims, ok):
    verifier = make_verifier(upstream={"required_claim": {"name": "groups", "value": "mcp-alpha"}})
    assert await accepted(verifier, tok(**claims)) is ok


# --- Keys ----------------------------------------------------------------------------------------------------------


async def test_key_declaring_another_algorithm_is_not_used(make_verifier, tok, idp, signing_key):
    idp.routes["/keys-ps256"] = {"keys": [jwk_for(signing_key, alg="PS256")]}
    assert not await accepted(make_verifier(jwks_path="/keys-ps256"), tok())


async def test_key_without_declared_algorithm_is_used(make_verifier, tok, idp, signing_key):
    key = jwk_for(signing_key)
    del key["alg"]
    idp.routes["/keys-noalg"] = {"keys": [key]}
    assert await accepted(make_verifier(jwks_path="/keys-noalg"), tok())


async def test_encryption_key_is_not_used(make_verifier, tok, idp, signing_key):
    idp.routes["/keys-enc"] = {"keys": [jwk_for(signing_key, use="enc")]}
    assert not await accepted(make_verifier(jwks_path="/keys-enc"), tok())


async def test_unsupported_critical_header_is_refused(make_verifier, signing_key, issuer):
    import jwt as pyjwt

    now = int(time.time())
    token = pyjwt.encode(
        {"iss": issuer, "aud": AUD, "sub": "s", "exp": now + 60, "scope": "openid"},
        signing_key, algorithm="RS256",
        headers={"kid": "test-key-1", "typ": "at+jwt", "crit": ["x-custom"], "x-custom": 1},
    )
    assert not await accepted(make_verifier(), token)
