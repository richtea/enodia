"""Configuration file and environment validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from enodia import ConfigError, load_config, upstream_paths

from .conftest import secret_file, toml_config, write_config


@pytest.fixture
def make(tmp_path):
    token = secret_file(tmp_path, "token", "abc123")

    def _make(top: dict[str, Any] | None = None, upstreams: list[dict[str, Any]] | None = None,
              drop_top: tuple[str, ...] = (), env: dict[str, str] | None = None):
        t = {"issuer": "https://idp.example", "public_url": "https://mcp.example", **(top or {})}
        for key in drop_top:
            t.pop(key)
        if upstreams is None:
            upstreams = [{}]
        us = [{"name": f"u{i}", "url": "http://upstream:3000/mcp", "token_file": token, "resource_name": "Example",
               **u} for i, u in enumerate(upstreams)]
        us = [{k: v for k, v in u.items() if v is not None} for u in us]
        return load_config(write_config(tmp_path, t, us), env or {})

    return _make


def test_defaults(make):
    config = make()
    (u,) = config.upstreams
    assert u.name == "u0"
    assert u.path == "/u0/mcp"
    assert u.audience == ("https://mcp.example/u0/mcp",)
    assert u.token == "abc123"
    assert u.required_scopes == ()
    assert u.required_claim is None
    assert config.algorithm is None
    assert config.jwks_uri is None
    assert config.scopes_supported == ("openid", "offline_access")
    assert config.advertised_scope_prefix == ""
    assert config.max_clock_skew_seconds == 60
    assert config.accepted_token_types == ("at+jwt",)
    assert config.accept_missing_token_type is False
    assert config.token_type_relaxed is False
    assert (config.host, config.port) == ("0.0.0.0", 8000)


def test_environment_runtime_settings(make):
    config = make(env={"HOST": "127.0.0.1", "PORT": "9000"})
    assert (config.host, config.port) == ("127.0.0.1", 9000)


def test_issuer_is_kept_exactly(make):
    assert make({"issuer": "https://idp.example/application/o/x/"}).issuer == "https://idp.example/application/o/x/"


def test_token_types_are_normalized(make):
    config = make({"accepted_token_types": ["application/AT+JWT", "JWT"]})
    assert config.accepted_token_types == ("at+jwt", "jwt")
    assert config.token_type_relaxed


def test_missing_token_type_relaxes(make):
    assert make({"accept_missing_token_type": True}).token_type_relaxed


@pytest.mark.parametrize("key", ["issuer", "public_url"])
def test_requires_top_level(make, key):
    with pytest.raises(ConfigError, match=key):
        make(drop_top=(key,))


@pytest.mark.parametrize("key", ["name", "url", "token_file", "resource_name"])
def test_requires_upstream_key(make, key):
    with pytest.raises(ConfigError, match=key):
        make(upstreams=[{key: None}])


def test_requires_an_upstream(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text(toml_config({"issuer": "https://idp.example", "public_url": "https://mcp.example"}, []))
    with pytest.raises(ConfigError, match=r"\[\[upstream\]\]"):
        load_config(str(path), {})


@pytest.mark.parametrize(
    ("top", "upstream", "message"),
    [
        ({"issuer": "http://idp.example"}, {}, "https"),
        ({"public_url": "http://mcp.example"}, {}, "https"),
        ({"jwks_uri": "http://idp.example/keys"}, {}, "https"),
        ({"issuer": "https://idp.example?x=1"}, {}, "query"),
        ({}, {"audience": ["https://idp.example"]}, "issuer"),
        ({}, {"audience": ["https://mcp.example/u0/mcp", "https://idp.example/"]}, "issuer"),
        ({}, {"audience": []}, "audience"),
        ({"algorithm": "HS256"}, {}, "asymmetric"),
        ({"algorithm": "none"}, {}, "asymmetric"),
        ({}, {"url": "ftp://upstream"}, "url"),
        ({}, {"name": "Bad_Name"}, "name"),
        ({}, {"name": "-x"}, "name"),
        ({}, {"required_scopes": ["two words"]}, "whitespace"),
        ({}, {"required_claim": {"name": "aud", "value": "x"}}, "validated by the gateway"),
        ({}, {"required_claim": {"name": "scope", "value": "x"}}, "validated by the gateway"),
        ({}, {"required_claim": {"name": "groups"}}, "value"),
        ({}, {"required_claim": {"name": "groups", "value": "x", "extra": 1}}, "unknown key"),
        ({"max_clock_skew_seconds": -1}, {}, "between 0 and 300"),
        ({"max_clock_skew_seconds": 301}, {}, "between 0 and 300"),
        ({"max_clock_skew_seconds": "60"}, {}, "must be a int"),
        ({"max_clock_skew_seconds": True}, {}, "must be a int"),
        ({"allow_insecure_urls": "yes"}, {}, "must be a bool"),
        ({"accepted_token_types": []}, {}, "must not be empty"),
        ({"accepted_token_types": ["ID"]}, {}, "ID tokens"),
        ({"accepted_token_types": ["at+jwt", "id"]}, {}, "ID tokens"),
        ({"accepted_token_types": ["id_token"]}, {}, "ID tokens"),
        ({"accepted_token_types": ["application/id+jwt"]}, {}, "ID tokens"),
        ({"scopes_supported": "openid"}, {}, "must be a list"),
        ({"advertised_scope_prefix": "api://x"}, {"required_scopes": ["a"]}, "must end with '/'"),
        ({"advertised_scope_prefix": "api://x y/"}, {"required_scopes": ["a"]}, "whitespace"),
        ({"advertised_scope_prefix": ""}, {"required_scopes": ["a"]}, "must not be empty"),
        ({"advertised_scope_prefix": ["api://x/"]}, {"required_scopes": ["a"]}, "must be a str"),
        ({"unknown_setting": 1}, {}, "unknown key"),
        ({}, {"tokne_file": "x"}, "unknown key"),
        ({}, {"token": "secret"}, "use token_file"),
    ],
)
def test_refuses_invalid_or_unsafe_values(make, top, upstream, message):
    with pytest.raises(ConfigError, match=message):
        make(top, [upstream])


def test_advertised_scope_prefix(make):
    config = make({"advertised_scope_prefix": "api://11111111-1111-1111-1111-111111111111/"},
                  [{"required_scopes": ["github"]}])
    assert config.advertised_scope_prefix == "api://11111111-1111-1111-1111-111111111111/"
    # Tokens are still checked for the short name.
    assert config.upstreams[0].required_scopes == ("github",)


def test_advertised_scope_prefix_requires_scopes_on_every_upstream(make):
    with pytest.raises(ConfigError, match="'u1' has no required_scopes"):
        make({"advertised_scope_prefix": "api://x/"},
             [{"required_scopes": ["a"]}, {"required_scopes": [], "audience": ["other"]}])


def test_error_names_file_and_upstream(make, tmp_path):
    with pytest.raises(ConfigError) as e:
        make(upstreams=[{}, {"name": "gitea", "url": "ftp://x"}])
    assert str(tmp_path / "config.toml") in str(e.value)
    assert "upstream[1] (gitea).url" in str(e.value)


def test_refuses_duplicate_names(make):
    with pytest.raises(ConfigError, match="duplicate"):
        make(upstreams=[{"name": "a"}, {"name": "a"}])


def test_insecure_urls_allowed_when_enabled(make):
    config = make({"issuer": "http://idp.local", "public_url": "http://mcp.local", "allow_insecure_urls": True})
    assert config.issuer == "http://idp.local"


@pytest.mark.parametrize("content", ["", "two tokens"])
def test_refuses_empty_or_multi_token_secret(make, tmp_path, content):
    (tmp_path / "token").write_text(content + "\n")
    with pytest.raises(ConfigError, match="token_file"):
        make()


def test_refuses_missing_secret_file(make, tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        make(upstreams=[{"token_file": str(tmp_path / "missing")}])


def test_refuses_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(str(tmp_path / "missing.toml"), {})


def test_refuses_invalid_toml(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text("issuer = \n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(str(path), {})


def test_refuses_bad_port(make):
    with pytest.raises(ConfigError, match="PORT"):
        make(env={"PORT": "abc"})


# --- Distinguishability --------------------------------------------------------------------------------------------

SHARED = ["client-id-123"]


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ({"audience": SHARED}, {"audience": SHARED}),
        ({"audience": SHARED, "required_scopes": ["mcp:a"]}, {"audience": SHARED}),
        ({"audience": SHARED, "required_scopes": ["mcp:a"]}, {"audience": SHARED, "required_scopes": ["mcp:a"]}),
        ({"audience": SHARED, "required_scopes": ["mcp:a", "mcp:b"]},
         {"audience": SHARED, "required_scopes": ["mcp:b"]}),
        ({"audience": ["x", "y"]}, {"audience": ["y", "z"]}),
        ({"audience": SHARED, "required_claim": {"name": "groups", "value": "g"}},
         {"audience": SHARED, "required_claim": {"name": "groups", "value": "g"}}),
    ],
)
def test_refuses_indistinguishable_upstreams(make, a, b):
    with pytest.raises(ConfigError, match="share an audience"):
        make(upstreams=[{"name": "a", **a}, {"name": "b", **b}])


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ({}, {}),  # distinct default audiences
        ({"audience": ["x"]}, {"audience": ["y"]}),
        ({"audience": SHARED, "required_scopes": ["mcp:a"]}, {"audience": SHARED, "required_scopes": ["mcp:b"]}),
        ({"audience": SHARED, "required_claim": {"name": "groups", "value": "a"}},
         {"audience": SHARED, "required_claim": {"name": "groups", "value": "b"}}),
        ({"audience": SHARED, "required_scopes": ["mcp:a"]},
         {"audience": SHARED, "required_claim": {"name": "groups", "value": "b"}}),
    ],
)
def test_accepts_distinguishable_upstreams(make, a, b):
    config = make(upstreams=[{"name": "a", **a}, {"name": "b", **b}])
    assert [u.name for u in config.upstreams] == ["a", "b"]


# --- Health check paths --------------------------------------------------------------------------------------------


def test_upstream_paths_reads_names_only(tmp_path: Path):
    # No secrets are read: the token files do not exist.
    config = write_config(tmp_path, {"issuer": "https://idp.example", "public_url": "https://mcp.example"}, [
        {"name": "github", "token_file": "/nonexistent"},
        {"name": "gitea", "token_file": "/nonexistent"},
    ])
    assert upstream_paths(config) == ["/github/mcp", "/gitea/mcp"]


def test_upstream_paths_refuses_bad_name(tmp_path: Path):
    config = write_config(tmp_path, {}, [{"name": "../etc"}])
    with pytest.raises(ConfigError, match="invalid upstream name"):
        upstream_paths(config)
