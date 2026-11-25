"""Test fixtures: a fake identity provider, two token-protected upstream MCP servers, and the gateway."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.server.dependencies import get_http_headers
from jwt.algorithms import RSAAlgorithm

import enodia

ALPHA_TOKEN = "alpha-static-token-for-tests"
BETA_TOKEN = "beta-static-token-for-tests"
KID = "test-key-1"
BETA_SCOPE = "mcp:beta"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_asgi(app, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("server did not start")
        time.sleep(0.05)
    return server


# --- TOML writing --------------------------------------------------------------------------------------------------


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, str)):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {_toml_value(v)}" for k, v in value.items()) + " }"
    raise TypeError(value)


def toml_config(top: dict[str, Any], upstreams: list[dict[str, Any]]) -> str:
    lines = [f"{k} = {_toml_value(v)}" for k, v in top.items()]
    for u in upstreams:
        lines += ["", "[[upstream]]", *(f"{k} = {_toml_value(v)}" for k, v in u.items())]
    return "\n".join(lines) + "\n"


def write_config(directory: Path, top: dict[str, Any], upstreams: list[dict[str, Any]]) -> str:
    path = directory / "config.toml"
    path.write_text(toml_config(top, upstreams))
    return str(path)


def secret_file(directory: Path, name: str, value: str) -> str:
    path = directory / name
    path.write_text(value + "\n")
    return str(path)


# --- Identity provider ---------------------------------------------------------------------------------------------


def jwk_for(key, **extra: str) -> dict[str, Any]:
    data = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    data.update({"kid": KID, "use": "sig", "alg": "RS256"})
    data.update(extra)
    return data


class FakeIdP:
    """Serves JSON documents at configurable paths; tests add routes for their own scenarios."""

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in routes:
                    body = json.dumps(routes[self.path]).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", free_port()), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def add_issuer(self, path: str, issuer: str, jwks_uri: str) -> None:
        self.routes[f"{path}/.well-known/openid-configuration"] = {"issuer": issuer, "jwks_uri": jwks_uri}


@pytest.fixture(scope="session")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def idp(signing_key) -> Iterator[FakeIdP]:
    idp = FakeIdP()
    # Keys at a non-default path, so the tests prove the gateway uses discovery rather than guessing.
    idp.routes["/keys"] = {"keys": [jwk_for(signing_key)]}
    idp.add_issuer("", idp.base, f"{idp.base}/keys")
    yield idp
    idp.httpd.shutdown()


@pytest.fixture(scope="session")
def issuer(idp) -> str:
    return idp.base


# --- Upstreams -----------------------------------------------------------------------------------------------------


def _upstream(name: str, token: str, tool_name: str) -> FastMCP:
    mcp = FastMCP(name, auth=StaticTokenVerifier({token: {"client_id": "gateway", "scopes": []}}))

    def only_here() -> str:
        return name

    mcp.tool(only_here, name=tool_name, description=f"Only on {name}.")

    @mcp.tool
    def ping() -> str:
        """Reply with pong."""
        return "pong"

    @mcp.tool
    def received_headers() -> dict[str, str]:
        """Return the HTTP headers the upstream received for this call."""
        return get_http_headers(include_all=True)

    return mcp


@pytest.fixture(scope="session")
def upstreams() -> Iterator[dict[str, str]]:
    servers, urls = [], {}
    for name, token in (("alpha", ALPHA_TOKEN), ("beta", BETA_TOKEN)):
        port = free_port()
        servers.append(serve_asgi(_upstream(name, token, f"{name}_only").http_app(path="/mcp"), port))
        urls[name] = f"http://127.0.0.1:{port}/mcp"
    yield urls
    for s in servers:
        s.should_exit = True


# --- Gateway -------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="session")
def gateway_port() -> int:
    return free_port()


@pytest.fixture(scope="session")
def gateway_config_file(tmp_path_factory, issuer, upstreams, gateway_port) -> str:
    d = tmp_path_factory.mktemp("gateway")
    return write_config(
        d,
        {"issuer": issuer, "public_url": f"http://127.0.0.1:{gateway_port}", "allow_insecure_urls": True},
        [
            {"name": "alpha", "url": upstreams["alpha"], "token_file": secret_file(d, "alpha", ALPHA_TOKEN),
             "resource_name": "Alpha resource"},
            {"name": "beta", "url": upstreams["beta"], "token_file": secret_file(d, "beta", BETA_TOKEN),
             "resource_name": "Beta resource", "required_scopes": [BETA_SCOPE]},
        ],
    )


@pytest.fixture(scope="session")
def gateway(gateway_config_file, gateway_port) -> Iterator[str]:
    config = enodia.load_config(gateway_config_file, {"PORT": str(gateway_port)})
    server = serve_asgi(enodia.build_app(config), config.port)
    yield config.public_url
    server.should_exit = True


@pytest.fixture(scope="session")
def mint(signing_key, issuer, gateway_port) -> Callable[..., str]:
    """Mint an access token. Defaults: valid for the alpha upstream, typ at+jwt, scope openid offline_access."""
    default_audience = f"http://127.0.0.1:{gateway_port}/alpha/mcp"

    def _mint(*, iss: Any = None, aud: Any = None, exp_offset: int = 3600, key=None, kid: str = KID,
              sub: str = "user-123", client_id: str = "client-abc", scope: Any = "openid offline_access",
              typ: str | None = "at+jwt", drop: tuple[str, ...] = (), extra_claims: dict[str, Any] | None = None,
              **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": iss or issuer, "aud": aud or default_audience, "sub": sub, "client_id": client_id,
                  "iat": now, "exp": now + exp_offset}
        if scope is not None:
            claims["scope"] = scope
        claims.update(extra)
        claims.update(extra_claims or {})
        for name in drop:
            claims.pop(name, None)
        headers: dict[str, Any] = {"kid": kid, "typ": typ}
        # Sign the raw payload so that tests can forge claims PyJWT would refuse to encode (such as a list `iss`).
        payload = json.dumps(claims).encode()
        return jwt.api_jws.PyJWS().encode(payload, key or signing_key, algorithm="RS256", headers=headers)

    return _mint
