"""Release tooling (scripts/release.py): version rules, file checks, and `prepare` with every command faked."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "release.py"
_spec = importlib.util.spec_from_file_location("release_script", SCRIPT)
assert _spec is not None and _spec.loader is not None
release = importlib.util.module_from_spec(_spec)
sys.modules["release_script"] = release  # dataclasses look their module up here
_spec.loader.exec_module(release)

V = release.Version.parse
ReleaseError = release.ReleaseError

UNRELEASED_CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Something new

## [0.1.0] - 2026-11-01

### Added

- First release
"""


# --- versions -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "lower, higher",
    [
        ("1.0.0", "1.0.1"),
        ("1.0.9", "1.1.0"),
        ("1.9.9", "2.0.0"),
        ("1.0.0-rc.1", "1.0.0"),
        ("1.0.0-alpha.1", "1.0.0-beta.0"),
        ("1.0.0-beta.9", "1.0.0-rc.0"),
        ("1.0.0-rc.2", "1.0.0-rc.10"),  # numeric, not lexical
        ("1.0.0-1", "1.0.0-alpha"),  # numeric identifiers sort before alphanumeric ones
        ("1.0.0-alpha", "1.0.0-alpha.1"),  # fewer identifiers sort first
        ("v0.9.0", "0.10.0"),
    ],
)
def test_semver_precedence(lower, higher):
    assert V(lower) < V(higher)
    assert not V(higher) < V(lower)


def test_build_metadata_is_ignored_when_reading():
    assert V("1.2.3+build.5") == V("1.2.3")


@pytest.mark.parametrize("text", ["1.2.3", "0.1.0", "1.2.3-alpha.0", "1.2.3-beta.4", "10.20.30-rc.12"])
def test_release_versions_accepted(text):
    assert str(release.parse_release_version(text)) == text


@pytest.mark.parametrize(
    "text", ["1.2", "v1.2.3", "01.2.3", "1.2.3-0", "1.2.3-rc", "1.2.3-rc.01", "1.2.3-dev.1", "1.2.3+b1", "1.2.3 x", ""]
)
def test_release_versions_rejected(text):
    with pytest.raises(ReleaseError):
        release.parse_release_version(text)


@pytest.mark.parametrize(
    "semver, python",
    [("1.2.0", "1.2.0"), ("1.2.0-alpha.1", "1.2.0a1"), ("1.2.0-beta.0", "1.2.0b0"), ("1.2.0-rc.3", "1.2.0rc3")],
)
def test_pep440(semver, python):
    assert release.pep440(release.parse_release_version(semver)) == python


def test_check_newer_accepts_a_higher_version():
    release.check_newer(V("1.3.0"), ["v1.2.0", "1.2.1-rc.0", "", "not-a-version", "v1.3.0-rc.1"])


def test_check_newer_accepts_the_first_release():
    release.check_newer(V("0.1.0"), [])


@pytest.mark.parametrize("version", ["1.2.0", "1.1.9", "1.2.0-rc.5"])
def test_check_newer_rejects_equal_or_lower(version):
    with pytest.raises(ReleaseError, match="not greater"):
        release.check_newer(V(version), ["v1.0.0", "v1.2.0", "v1.1.0"])


def test_parse_branch():
    assert release.parse_branch("chore/release-1.2.0-rc.1") == V("1.2.0-rc.1")
    for ref in ("chore/release/1.2.0", "autorelease/1.2.0", "chore/release-1.2", "chore/release-1.2.0-0"):
        with pytest.raises(ReleaseError):
            release.parse_branch(ref)


def test_strip_link_definitions():
    notes = (
        "### Added\n\n- See [the docs](https://example.com/docs)\n\n"
        "[Unreleased]: https://github.com/example/enodia/compare/v0.1.0...HEAD\n\n"
        "[0.1.0]: https://github.com/example/enodia/releases/tag/v0.1.0\n"
    )
    assert release.strip_link_definitions(notes) == "### Added\n\n- See [the docs](https://example.com/docs)\n"


# --- input validation ---------------------------------------------------------------------------------------------


def test_manual_requires_version():
    with pytest.raises(ReleaseError, match="need --version"):
        release.validate_input("manual", None, None)
    assert release.validate_input("manual", "2.0.0", None) == V("2.0.0")


def test_version_only_for_manual():
    with pytest.raises(ReleaseError, match="only applies to manual"):
        release.validate_input("minor", "2.0.0", None)


def test_manual_version_must_be_a_release_version():
    with pytest.raises(ReleaseError):
        release.validate_input("manual", "1.0.0-0", None)


def test_preid_rules():
    assert release.validate_input("preminor", None, "rc") is None
    assert release.validate_input("prerelease", None, None) is None
    with pytest.raises(ReleaseError, match="needs --preid"):
        release.validate_input("premajor", None, None)
    with pytest.raises(ReleaseError, match="only applies to"):
        release.validate_input("patch", None, "rc")
    with pytest.raises(ReleaseError, match="must be one of"):
        release.validate_input("prepatch", None, "dev")


# --- verify -------------------------------------------------------------------------------------------------------


def write_project(root: Path, *, version: str, changelog: str, locked: str | None = None) -> None:
    (root / "pyproject.toml").write_text(f'[project]\nname = "enodia"\nversion = "{version}"\n', encoding="utf-8")
    (root / "uv.lock").write_text(
        f'version = 1\n\n[[package]]\nname = "enodia"\nversion = "{locked or version}"\n', encoding="utf-8"
    )
    (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")


RELEASED_CHANGELOG = UNRELEASED_CHANGELOG.replace(
    "## [Unreleased]\n", "## [Unreleased]\n\n## [0.2.0-rc.1] - 2026-11-25\n"
)


def test_verify_passes(tmp_path):
    write_project(tmp_path, version="0.2.0rc1", changelog=RELEASED_CHANGELOG)
    release.verify(V("0.2.0-rc.1"), tmp_path)


@pytest.mark.parametrize(
    "version, locked, changelog, problem",
    [
        ("0.2.0", None, RELEASED_CHANGELOG, "pyproject.toml has version 0.2.0"),
        ("0.2.0rc1", "0.1.0", RELEASED_CHANGELOG, "uv.lock has enodia version 0.1.0"),
        ("0.2.0rc1", None, UNRELEASED_CHANGELOG, "latest release in CHANGELOG.md is 0.1.0"),
        ("0.2.0rc1", None, "# Changelog\n\n## [Unreleased]\n", "no release sections"),
    ],
)
def test_verify_reports_mismatches(tmp_path, version, locked, changelog, problem):
    write_project(tmp_path, version=version, locked=locked, changelog=changelog)
    with pytest.raises(ReleaseError, match=problem):
        release.verify(V("0.2.0-rc.1"), tmp_path)


# --- gh login -----------------------------------------------------------------------------------------------------


class FakeRunner(release.Runner):
    """Answers every command from `respond` and records what ran. Nothing reaches a real process."""

    def __init__(self, respond: Callable[[list[str]], tuple[int, str]], dry_run: bool = False):
        super().__init__(dry_run=dry_run)
        self.respond = respond
        self.queries: list[list[str]] = []
        self.acted: list[list[str]] = []
        self.interactive_calls: list[list[str]] = []

    def query(self, cmd: Sequence[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
        cmd = list(cmd)
        self.queries.append(cmd)
        code, out = self.respond(cmd)
        if check and code != 0:
            raise ReleaseError(f"`{' '.join(cmd)}` failed")
        return subprocess.CompletedProcess(cmd, code, out, "")

    def setup(self, cmd: Sequence[str], *, cwd: Path) -> None:
        self.queries.append(list(cmd))

    def act(self, cmd: Sequence[str], *, cwd: Path) -> None:
        self.planned.append(list(cmd))
        if not self.dry_run:
            self.acted.append(list(cmd))

    def interactive(self, cmd: Sequence[str]) -> int:
        self.interactive_calls.append(list(cmd))
        return 0


def gh_status(results: list[int]) -> Callable[[list[str]], tuple[int, str]]:
    """`gh auth status` returns each of `results` in turn."""

    def respond(cmd: list[str]) -> tuple[int, str]:
        assert cmd[:3] == ["gh", "auth", "status"]
        return results.pop(0), ""

    return respond


def never_ask(prompt: str) -> str:
    raise AssertionError(f"unexpected prompt: {prompt}")


def test_gh_logged_in_continues():
    runner = FakeRunner(gh_status([0]))
    release.ensure_gh_login(runner, interactive=True, yes=False, ask=never_ask)
    assert runner.interactive_calls == []


def test_gh_logged_out_interactive_yes_logs_in():
    runner = FakeRunner(gh_status([1, 0]))
    release.ensure_gh_login(runner, interactive=True, yes=False, ask=lambda _: "y")
    assert runner.interactive_calls == [["gh", "auth", "login", "--hostname", "github.com", "--web"]]


def test_gh_login_that_still_fails_aborts():
    runner = FakeRunner(gh_status([1, 1]))
    with pytest.raises(ReleaseError, match="still not logged in"):
        release.ensure_gh_login(runner, interactive=True, yes=False, ask=lambda _: "yes")


def test_gh_logged_out_interactive_no_aborts():
    runner = FakeRunner(gh_status([1]))
    with pytest.raises(ReleaseError, match="gh auth login"):
        release.ensure_gh_login(runner, interactive=True, yes=False, ask=lambda _: "")
    assert runner.interactive_calls == []


@pytest.mark.parametrize("interactive, yes", [(False, False), (True, True), (False, True)])
def test_gh_logged_out_without_prompting_aborts(interactive, yes):
    runner = FakeRunner(gh_status([1]))
    with pytest.raises(ReleaseError, match="gh auth login"):
        release.ensure_gh_login(runner, interactive=interactive, yes=yes, ask=never_ask)
    assert runner.interactive_calls == []


# --- prepare ------------------------------------------------------------------------------------------------------

BUMPED = UNRELEASED_CHANGELOG.replace("## [Unreleased]\n", "## [Unreleased]\n\n## [{v}] - 2026-11-25\n")


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A release-ready checkout: pyproject at 0.1.0, unreleased changes, kac 'installed'."""
    write_project(tmp_path, version="0.1.0", changelog=UNRELEASED_CHANGELOG)
    kac = tmp_path / "tools" / "kac"
    (kac / "node_modules" / ".bin").mkdir(parents=True)
    (kac / "node_modules" / ".bin" / "kac").write_text("", encoding="utf-8")
    manifest = kac / "node_modules" / "@release-flow" / "keep-a-changelog"
    manifest.mkdir(parents=True)
    (manifest / "package.json").write_text('{"version": "3.1.0"}', encoding="utf-8")
    lock = {"packages": {"node_modules/@release-flow/keep-a-changelog": {"version": "3.1.0"}}}
    (kac / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(release.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    return tmp_path


def github(
    *,
    computed: str = "0.2.0",
    permission: str = "ADMIN",
    dirty: bool = False,
    branch: str = "main",
    tags: str = "v0.1.0\n",
    releases: str = "v0.1.0\n",
    open_prs: str = "[]",
    remote_branch: str = "",
) -> Callable[[list[str]], tuple[int, str]]:
    """Fake answers for every read-only command `prepare` runs."""

    def respond(cmd: list[str]) -> tuple[int, str]:
        tool = Path(cmd[0]).name
        match tool, cmd[1:3]:
            case "node", _:
                return 0, "v24.11.0\n"
            case "gh", ["auth", "status"]:
                return 0, ""
            case "gh", ["repo", "view"]:
                return 0, json.dumps({"nameWithOwner": "example/enodia", "viewerPermission": permission})
            case "gh", ["pr", "list"]:
                return 0, open_prs
            case "gh", ["api", _]:
                return 0, releases
            case "git", ["status", _]:
                return 0, " M README.md\n" if dirty else ""
            case "git", ["fetch", _]:
                return 0, ""
            case "git", ["rev-parse", "--abbrev-ref"]:
                return 0, f"{branch}\n"
            case "git", ["rev-parse", _]:
                return 0, "abc123\n"
            case "git", ["tag", _]:
                return 0, tags
            case "git", ["ls-remote", _]:
                return 0, remote_branch
            case "kac", ["bump", _]:
                changelog = Path(cmd[cmd.index("--changelog") + 1])
                changelog.write_text(BUMPED.format(v=computed), encoding="utf-8")
                return 0, ""
            case "kac", ["query", _]:
                notes = "### Added\n\n- Something new\n"
                return 0, json.dumps({"version": computed, "release-notes": notes})
        raise AssertionError(f"unexpected command: {cmd}")

    return respond


def test_dry_run_changes_nothing(project, capsys):
    runner = FakeRunner(github(), dry_run=True)
    release.prepare(release.Options("minor", dry_run=True), root=project, runner=runner, interactive=False)

    assert runner.acted == []
    assert (project / "CHANGELOG.md").read_text(encoding="utf-8") == UNRELEASED_CHANGELOG
    assert release.project_version(project) == "0.1.0"
    # Every query was read-only.
    for cmd in runner.queries:
        assert cmd[:2] not in (["git", "switch"], ["git", "commit"], ["git", "push"], ["gh", "pr"]) or cmd[2] == "list"
    planned = [" ".join(c) for c in runner.planned]
    assert "git switch --create chore/release-0.2.0 origin/main" in planned
    assert "uv version 0.2.0 --no-sync" in planned
    assert any(
        p.startswith("gh pr create --base main --head chore/release-0.2.0 --title Release 0.2.0") for p in planned
    )
    assert "uv run --locked pytest -q" in planned
    out = capsys.readouterr().out
    assert "+## [0.2.0] - 2026-11-25" in out
    assert "Dry run: nothing was changed" in out


def test_dry_run_skip_checks_omits_checks(project):
    runner = FakeRunner(github(), dry_run=True)
    release.prepare(
        release.Options("minor", dry_run=True, skip_checks=True), root=project, runner=runner, interactive=False
    )
    assert not any(c[:3] == ["uv", "run", "--locked"] for c in runner.planned)


def test_prepare_runs_steps_in_order(project, monkeypatch):
    runner = FakeRunner(github(computed="0.2.0-rc.0"))

    def fake_verify(version, root):
        assert runner.acted[-1] == ["uv", "lock"]  # verify runs once the files are updated

    monkeypatch.setattr(release, "verify", fake_verify)
    release.prepare(release.Options("preminor", preid="rc", yes=True), root=project, runner=runner, interactive=False)
    names = [" ".join(c[:2]) for c in runner.acted]
    assert names == [
        "git switch", "cp " + runner.acted[1][1], "uv version", "uv lock",
        "uv lock", "uv run", "uv run", "uv run",
        "git add", "git commit", "git push", "gh label", "gh pr", "git switch",
    ]  # fmt: skip
    assert ["uv", "version", "0.2.0rc0", "--no-sync"] in runner.acted


def test_prepare_needs_confirmation_outside_a_terminal(project):
    runner = FakeRunner(github())
    with pytest.raises(ReleaseError, match="--yes"):
        release.prepare(release.Options("minor"), root=project, runner=runner, interactive=False)
    assert runner.acted == []


def test_prepare_can_be_cancelled(project):
    runner = FakeRunner(github())
    with pytest.raises(ReleaseError, match="cancelled"):
        release.prepare(release.Options("minor"), root=project, runner=runner, interactive=True, ask=lambda _: "n")
    assert runner.acted == []


@pytest.mark.parametrize(
    "kwargs, problem",
    [
        ({"permission": "WRITE"}, "admin or maintain"),
        ({"dirty": True}, "uncommitted"),
        ({"branch": "feature/x"}, "current branch is feature/x"),
        ({"open_prs": '[{"url": "https://github.com/example/enodia/pull/7"}]'}, "already open"),
        ({"tags": "v0.1.0\nv0.2.0\n"}, "not greater than the current release 0.2.0"),
        ({"releases": "v0.3.0-rc.0\n"}, "not greater than the current release 0.3.0-rc.0"),  # a draft
        ({"remote_branch": "abc\trefs/heads/chore/release-0.2.0\n"}, "already exists on origin"),
        ({"computed": "0.2.0-0"}, "not a valid release version"),
    ],
)
def test_prepare_refuses(project, kwargs, problem):
    runner = FakeRunner(github(**kwargs), dry_run=True)
    with pytest.raises(ReleaseError, match=problem):
        release.prepare(release.Options("minor", dry_run=True), root=project, runner=runner, interactive=False)
    assert runner.acted == []


def test_manual_version_lower_than_current_is_refused(project):
    runner = FakeRunner(github(computed="0.0.9"), dry_run=True)
    with pytest.raises(ReleaseError, match="not greater"):
        release.prepare(
            release.Options("manual", version="0.0.9", dry_run=True), root=project, runner=runner, interactive=False
        )


def test_failure_after_push_explains_cleanup(project, monkeypatch):
    monkeypatch.setattr(release, "verify", lambda version, root: None)  # the faked steps don't edit the files

    class FailingPR(FakeRunner):
        def act(self, cmd: Sequence[str], *, cwd: Path) -> None:
            if list(cmd[:3]) == ["gh", "pr", "create"]:
                raise ReleaseError("`gh pr create` failed")
            super().act(cmd, cwd=cwd)

    runner = FailingPR(github())
    with pytest.raises(ReleaseError, match="was pushed to origin"):
        release.prepare(release.Options("minor", skip_checks=True, yes=True), root=project, runner=runner,
                        interactive=False)  # fmt: skip
