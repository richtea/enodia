"""End-to-end tests against a running gateway with two upstreams: alpha (default audience), beta (requires a scope)."""

from __future__ import annotations

import json
import logging

import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from starlette.testclient import TestClient

import enodia

from .conftest import ALPHA_TOKEN, BETA_SCOPE, BETA_TOKEN, free_port, secret_file, write_config

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}},
}
ACCEPT = {"Accept": "application/json, text/event-stream"}


def post_initialize(gateway: str, token: str | None, upstream: str = "alpha") -> httpx2.Response:
    headers = dict(ACCEPT)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return httpx2.post(f"{gateway}/{upstream}/mcp", json=INITIALIZE, headers=headers, timeout=10)


def client(gateway: str, token: str, upstream: str = "alpha", **extra_headers: str) -> Client:
    headers = {"Authorization": f"Bearer {token}", **extra_headers}
    return Client(StreamableHttpTransport(f"{gateway}/{upstream}/mcp", headers=headers))


@pytest.fixture(scope="session")
def mint_beta(mint, gateway):
    def _mint(**kwargs):
        kwargs.setdefault("aud", f"{gateway}/beta/mcp")
        kwargs.setdefault("scope", f"openid offline_access {BETA_SCOPE}")
        return mint(**kwargs)

    return _mint


# --- Discovery -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("upstream", ["alpha", "beta"])
def test_unauthenticated_request_gets_path_scoped_rfc9728_challenge(gateway, upstream):
    r = post_initialize(gateway, None, upstream)
    assert r.status_code == 401
    expected = f'resource_metadata="{gateway}/.well-known/oauth-protected-resource/{upstream}/mcp"'
    assert expected in r.headers["www-authenticate"]


def test_challenge_scope_includes_shared_and_required_scopes(gateway):
    # Clients prefer the challenge's scope over the metadata; it must keep openid and offline_access.
    challenge = post_initialize(gateway, None, "beta").headers["www-authenticate"]
    assert f'scope="openid offline_access {BETA_SCOPE}"' in challenge


def test_advertised_scope_prefix_changes_request_form_only(tmp_path):
    # Entra ID style: clients request api://<id>/<scope>; the short-name check is covered in test_verifier.

    prefix = "api://11111111-1111-1111-1111-111111111111/"
    path = write_config(
        tmp_path,
        {"issuer": "https://idp.example", "public_url": "https://mcp.example", "advertised_scope_prefix": prefix},
        [{"name": "beta", "url": "http://upstream:3000/mcp", "token_file": secret_file(tmp_path, "t", BETA_TOKEN),
          "resource_name": "Beta resource", "required_scopes": [BETA_SCOPE]}],
    )
    config = enodia.load_config(path, {})
    signing = enodia.SigningSettings("https://idp.example/keys", "RS256", "test")
    expected = ["openid", "offline_access", f"{prefix}{BETA_SCOPE}"]
    with TestClient(enodia.build_app(config, signing)) as http:
        challenge = http.post("/beta/mcp", json=INITIALIZE, headers=ACCEPT).headers["www-authenticate"]
        assert f'scope="{" ".join(expected)}"' in challenge
        doc = http.get("/.well-known/oauth-protected-resource/beta/mcp").json()
        assert doc["scopes_supported"] == expected


@pytest.mark.parametrize("issuer", ["https://id.example.com", "https://idp.example/application/o/mcp/"])
def test_metadata_advertises_issuer_exactly(tmp_path, issuer):
    # Clients compare this with the issuer in the IdP's metadata (RFC 8414 §3.3), so it must not be normalised.
    path = write_config(
        tmp_path,
        {"issuer": issuer, "public_url": "https://mcp.example"},
        [{"name": "alpha", "url": "http://upstream:3000/mcp", "token_file": secret_file(tmp_path, "t", ALPHA_TOKEN),
          "resource_name": "Alpha resource"}],
    )
    config = enodia.load_config(path, {})
    signing = enodia.SigningSettings("https://idp.example/keys", "RS256", "test")
    with TestClient(enodia.build_app(config, signing)) as http:
        doc = http.get("/.well-known/oauth-protected-resource/alpha/mcp").json()
    assert doc["authorization_servers"] == [issuer]


@pytest.mark.parametrize(
    ("upstream", "name", "scopes"),
    [("alpha", "Alpha resource", ["openid", "offline_access"]),
     ("beta", "Beta resource", ["openid", "offline_access", BETA_SCOPE])],
)
def test_protected_resource_metadata(gateway, issuer, upstream, name, scopes):
    r = httpx2.get(f"{gateway}/.well-known/oauth-protected-resource/{upstream}/mcp", timeout=10)
    assert r.status_code == 200
    doc = r.json()
    assert doc["resource"] == f"{gateway}/{upstream}/mcp"
    assert [s.rstrip("/") for s in doc["authorization_servers"]] == [issuer]
    assert doc["scopes_supported"] == scopes
    assert doc["resource_name"] == name


@pytest.mark.parametrize(
    "path", ["/mcp", "/gamma/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
             "/alpha", "/"],
)
def test_unknown_paths_are_not_found(gateway, path):
    assert httpx2.get(f"{gateway}{path}", timeout=10, follow_redirects=False).status_code == 404


# --- Token validation ----------------------------------------------------------------------------------------------


def test_valid_token_is_accepted(gateway, mint):
    assert post_initialize(gateway, mint()).status_code == 200


@pytest.mark.parametrize(
    "case",
    ["expired", "wrong_audience", "issuer_as_audience", "wrong_issuer", "other_key_same_kid", "unknown_kid",
     "malformed", "typ_jwt"],
)
def test_invalid_tokens_are_refused(gateway, mint, issuer, other_key, case):
    token = {
        "expired": lambda: mint(exp_offset=-300),
        "wrong_audience": lambda: mint(aud="https://other.example/mcp"),
        "issuer_as_audience": lambda: mint(aud=issuer),
        "wrong_issuer": lambda: mint(iss="https://attacker.example"),
        "other_key_same_kid": lambda: mint(key=other_key),
        "unknown_kid": lambda: mint(key=other_key, kid="unknown"),
        "malformed": lambda: "not.a.jwt",
        "typ_jwt": lambda: mint(typ="JWT"),
    }[case]()
    assert post_initialize(gateway, token).status_code == 401


def test_hs256_token_signed_with_public_material_is_refused(gateway, mint, signing_key):
    # Algorithm confusion: an HS256 token keyed with the public key must not verify. PyJWT refuses to create one, so
    # forge it by hand as an attacker would.
    import base64
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import serialization

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    public_pem = signing_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    payload = mint().split(".")[1].encode()
    header = b64(json.dumps({"alg": "HS256", "typ": "at+jwt", "kid": "test-key-1"}).encode())
    signing_input = header + b"." + payload
    forged = (signing_input + b"." + b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest())).decode()
    assert post_initialize(gateway, forged).status_code == 401


# --- Upstream isolation --------------------------------------------------------------------------------------------


def test_alpha_token_is_refused_by_beta(gateway, mint):
    assert post_initialize(gateway, mint(), "beta").status_code == 401


def test_beta_token_is_refused_by_alpha(gateway, mint_beta):
    assert post_initialize(gateway, mint_beta(), "alpha").status_code == 401


def test_beta_requires_its_scope(gateway, mint_beta):
    assert post_initialize(gateway, mint_beta(), "beta").status_code == 200
    assert post_initialize(gateway, mint_beta(scope="openid offline_access"), "beta").status_code in {401, 403}


@pytest.mark.parametrize("upstream", ["alpha", "beta"])
async def test_each_path_proxies_only_its_own_upstream(gateway, mint, mint_beta, upstream):
    token = mint() if upstream == "alpha" else mint_beta()
    async with client(gateway, token, upstream) as c:
        names = {t.name for t in await c.list_tools()}
        other = "beta_only" if upstream == "alpha" else "alpha_only"
        assert f"{upstream}_only" in names
        assert other not in names
        result = await c.call_tool(f"{upstream}_only", {})
        assert result.content[0].text == upstream


@pytest.mark.parametrize(("upstream", "upstream_token"), [("alpha", ALPHA_TOKEN), ("beta", BETA_TOKEN)])
async def test_client_headers_are_not_forwarded_upstream(gateway, mint, mint_beta, upstream, upstream_token):
    token = mint() if upstream == "alpha" else mint_beta()
    probe = {"X-Client-Probe": "leak-me", "Cookie": "session=secret"}
    async with client(gateway, token, upstream, **probe) as c:
        result = await c.call_tool("received_headers", {})
    headers = {k.lower(): v for k, v in json.loads(result.content[0].text).items()}
    assert headers.get("authorization") == f"Bearer {upstream_token}"
    assert token not in json.dumps(headers)
    assert "x-client-probe" not in headers
    assert "cookie" not in headers


async def test_audit_log_records_upstream_subject_and_tool(gateway, mint_beta, caplog):
    caplog.set_level(logging.INFO, logger="enodia.audit")
    async with client(gateway, mint_beta(sub="alice", client_id="claude-code"), "beta") as c:
        await c.call_tool("ping", {})
    entries = [json.loads(r.getMessage()) for r in caplog.records if r.name == "enodia.audit"]
    calls = [e for e in entries if e["method"] == "tools/call"]
    assert calls, entries
    assert calls[-1]["upstream"] == "beta"
    assert calls[-1]["subject"] == "alice"
    assert calls[-1]["client_id"] == "claude-code"
    assert calls[-1]["tool"] == "ping"
    assert calls[-1]["outcome"] == "ok"


# --- Health check --------------------------------------------------------------------------------------------------


def test_healthcheck_passes_against_running_gateway(gateway, gateway_config_file, gateway_port):
    env = {"PORT": str(gateway_port), "CONFIG_FILE": gateway_config_file}
    assert enodia.healthcheck(env) == 0


def test_healthcheck_fails_when_one_path_is_not_served(gateway, gateway_port, tmp_path, issuer):
    token = secret_file(tmp_path, "t", "x")
    config = write_config(tmp_path, {"issuer": issuer, "public_url": "https://mcp.example"}, [
        {"name": "alpha", "url": "http://a/mcp", "token_file": token, "resource_name": "A"},
        {"name": "gamma", "url": "http://g/mcp", "token_file": token, "resource_name": "G"},
    ])
    assert enodia.healthcheck({"PORT": str(gateway_port), "CONFIG_FILE": config}) == 1


def test_healthcheck_fails_when_nothing_listens(gateway_config_file):
    assert enodia.healthcheck({"PORT": str(free_port()), "CONFIG_FILE": gateway_config_file}) == 1


def test_healthcheck_fails_without_config(tmp_path):
    assert enodia.healthcheck({"CONFIG_FILE": str(tmp_path / "missing.toml")}) == 1
