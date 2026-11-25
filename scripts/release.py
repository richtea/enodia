#!/usr/bin/env python3
"""Release tooling for enodia. Standard library only.

Operator command, run from a clean, up-to-date `main` (see docs/releasing.md):

    uv run scripts/release.py prepare <type> [--preid alpha|beta|rc] [--version X.Y.Z[-pre.N]]
                                             [--dry-run] [--skip-checks] [--yes]

It bumps CHANGELOG.md (with the pinned `kac` CLI in tools/kac), the version in pyproject.toml and uv.lock, runs the
checks, commits to a `chore/release-<version>` branch, pushes it and opens the release pull request with `gh`.
`--dry-run` shows what would happen and changes nothing apart from fetching from origin.

Helpers used by the release workflows:

    verify V                     pyproject.toml, uv.lock and CHANGELOG.md all describe release V
    pep440 V                     print the PEP 440 form of V (1.2.0-rc.1 -> 1.2.0rc1)
    is-prerelease V              print true or false
    clean-notes                  read release notes on stdin, print them without Markdown link definitions
    check-newer V --existing F   V is strictly greater than every version listed in F (one per line, '-' = stdin)
    parse-branch REF             print the version from a chore/release-<version> branch name
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import total_ordering
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = "enodia"
BRANCH_PREFIX = "chore/release-"
LABEL = "release"
TAG_PREFIX = "v"
PREIDS = ("alpha", "beta", "rc")
PEP440_PRE = {"alpha": "a", "beta": "b", "rc": "rc"}
RELEASE_TYPES = ("major", "minor", "patch", "premajor", "preminor", "prepatch", "prerelease", "release", "manual")
PRE_TYPES = ("premajor", "preminor", "prepatch", "prerelease")
PREID_REQUIRED = ("premajor", "preminor", "prepatch")
ALLOWED_ROLES = ("ADMIN", "MAINTAIN")
MIN_NODE_MAJOR = 24
GITHUB_HOST = "github.com"

_NUM = r"(?:0|[1-9]\d*)"
# The versions this project releases: X.Y.Z or X.Y.Z-(alpha|beta|rc).N, which map one-to-one onto PEP 440.
RELEASE_VERSION_RE = re.compile(rf"^({_NUM})\.({_NUM})\.({_NUM})(?:-(alpha|beta|rc)\.({_NUM}))?$")
# Any SemVer 2.0 version, optionally with a tag prefix; build metadata is ignored. Used to read existing versions.
_IDENT = r"(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_RE = re.compile(rf"^v?({_NUM})\.({_NUM})\.({_NUM})(?:-({_IDENT}(?:\.{_IDENT})*))?(?:\+[0-9A-Za-z.-]+)?$")
CHANGELOG_HEADING_RE = re.compile(r"^##\s+\[?([^\]\s]+)\]?")
LINK_DEFINITION_RE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*\S+.*$")


class ReleaseError(Exception):
    """A problem the operator or CI has to fix. Reported as a message, without a traceback."""


@total_ordering
@dataclass(frozen=True)
class Version:
    """A semantic version, ordered by SemVer 2.0 precedence."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> Version:
        """Parse any SemVer 2.0 version, with or without a leading `v`."""
        m = SEMVER_RE.match(text.strip())
        if not m:
            raise ReleaseError(f"'{text}' is not a semantic version")
        pre = tuple(m.group(4).split(".")) if m.group(4) else ()
        return cls(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def __str__(self) -> str:
        core = f"{self.major}.{self.minor}.{self.patch}"
        return f"{core}-{'.'.join(self.prerelease)}" if self.prerelease else core

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        core, other_core = (self.major, self.minor, self.patch), (other.major, other.minor, other.patch)
        if core != other_core:
            return core < other_core
        if not self.prerelease or not other.prerelease:
            # A prerelease has lower precedence than the release itself.
            return bool(self.prerelease) and not other.prerelease
        return _prerelease_key(self.prerelease) < _prerelease_key(other.prerelease)


def _prerelease_key(ids: tuple[str, ...]) -> tuple[tuple[int, int, str], ...]:
    # Numeric identifiers compare numerically and sort before alphanumeric ones; a shorter list of otherwise equal
    # identifiers sorts first. Tuple comparison gives exactly that.
    return tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in ids)


def parse_release_version(text: str) -> Version:
    """Parse a version this project may release: X.Y.Z or X.Y.Z-(alpha|beta|rc).N."""
    if not RELEASE_VERSION_RE.match(text.strip()):
        raise ReleaseError(
            f"'{text}' is not a valid release version. Use X.Y.Z or X.Y.Z-<alpha|beta|rc>.N, with no build metadata "
            "(other prerelease forms have no exact PEP 440 equivalent)"
        )
    return Version.parse(text)


def pep440(version: Version) -> str:
    """The PEP 440 form of a release version, as written to pyproject.toml."""
    core = f"{version.major}.{version.minor}.{version.patch}"
    if not version.prerelease:
        return core
    label, number = version.prerelease
    return f"{core}{PEP440_PRE[label]}{number}"


def changelog_versions(text: str) -> list[Version]:
    """The release versions in a changelog, newest first, skipping the Unreleased section."""
    versions = []
    for line in text.splitlines():
        m = CHANGELOG_HEADING_RE.match(line)
        if not m or m.group(1).lower() == "unreleased":
            continue
        versions.append(Version.parse(m.group(1)))
    return versions


def strip_link_definitions(notes: str) -> str:
    """Remove Markdown link definitions from release notes.

    kac 3.1.0's `query` counts the changelog's trailing link definitions as part of the oldest release's notes.
    """
    lines = [line for line in notes.splitlines() if not LINK_DEFINITION_RE.match(line)]
    return "\n".join(lines).strip() + "\n"


def project_version(root: Path) -> str:
    with (root / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def locked_version(root: Path) -> str | None:
    with (root / "uv.lock").open("rb") as f:
        lock = tomllib.load(f)
    for package in lock.get("package", []):
        if package.get("name") == PROJECT:
            return package.get("version")
    return None


def verify(version: Version, root: Path) -> None:
    """Check that pyproject.toml, uv.lock and CHANGELOG.md all describe the release `version`."""
    expected = pep440(version)
    problems = []
    if (found := project_version(root)) != expected:
        problems.append(f"pyproject.toml has version {found}, expected {expected}")
    if (found := locked_version(root)) != expected:
        problems.append(f"uv.lock has {PROJECT} version {found}, expected {expected} (run `uv lock`)")
    releases = changelog_versions((root / "CHANGELOG.md").read_text(encoding="utf-8"))
    if not releases:
        problems.append(f"CHANGELOG.md has no release sections, expected {version} first")
    elif releases[0] != version:
        problems.append(f"the latest release in CHANGELOG.md is {releases[0]}, expected {version}")
    if problems:
        raise ReleaseError("; ".join(problems))


def check_newer(version: Version, existing: Iterable[str]) -> None:
    """Refuse `version` unless it is strictly greater than every existing version. Unparseable entries are skipped."""
    newest: Version | None = None
    for raw in existing:
        text = raw.strip()
        if not text:
            continue
        try:
            v = Version.parse(text)
        except ReleaseError:
            warn(f"ignoring '{text}', which is not a semantic version")
            continue
        if newest is None or v > newest:
            newest = v
    if newest is not None and not version > newest:
        raise ReleaseError(f"version {version} is not greater than the current release {newest}")


def parse_branch(ref: str) -> Version:
    """The release version named by a `chore/release-<version>` branch."""
    if not ref.startswith(BRANCH_PREFIX):
        raise ReleaseError(f"branch '{ref}' is not a release branch ({BRANCH_PREFIX}<version>)")
    return parse_release_version(ref.removeprefix(BRANCH_PREFIX))


def validate_input(release_type: str, version: str | None, preid: str | None) -> Version | None:
    """Check the `prepare` arguments. Returns the explicit version for `manual`, otherwise None."""
    if release_type not in RELEASE_TYPES:
        raise ReleaseError(f"unknown release type '{release_type}'")
    if preid is not None and preid not in PREIDS:
        raise ReleaseError(f"--preid must be one of {', '.join(PREIDS)}")
    if preid is not None and release_type not in PRE_TYPES:
        raise ReleaseError(f"--preid only applies to {', '.join(PRE_TYPES)}")
    if release_type in PREID_REQUIRED and preid is None:
        raise ReleaseError(f"{release_type} needs --preid ({', '.join(PREIDS)})")
    if release_type == "manual":
        if not version:
            raise ReleaseError("manual releases need --version")
        return parse_release_version(version)
    if version:
        raise ReleaseError("--version only applies to manual releases")
    return None


def warn(message: str) -> None:
    prefix = "::warning::" if os.environ.get("GITHUB_ACTIONS") == "true" else "warning: "
    print(f"{prefix}{message}", file=sys.stderr)


# --- prepare ------------------------------------------------------------------------------------------------------


@dataclass
class Runner:
    """Runs commands for `prepare`.

    `query` runs read-only commands, also in a dry run. `act` runs commands that change the repository or GitHub, or
    that only make sense after such a change (the checks); in a dry run it only records them.
    """

    dry_run: bool
    planned: list[list[str]] = field(default_factory=list)

    def query(self, cmd: Sequence[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(list(cmd), cwd=cwd, check=False, text=True, capture_output=True)
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise ReleaseError(f"`{' '.join(cmd)}` failed: {detail}")
        return result

    def setup(self, cmd: Sequence[str], *, cwd: Path) -> None:
        """A command that changes nothing tracked (e.g. installing tools/kac); runs in a dry run too."""
        if subprocess.run(list(cmd), cwd=cwd, check=False).returncode != 0:
            raise ReleaseError(f"`{' '.join(cmd)}` failed")

    def act(self, cmd: Sequence[str], *, cwd: Path) -> None:
        self.planned.append(list(cmd))
        if self.dry_run:
            return
        print(f"$ {' '.join(cmd)}", flush=True)
        if subprocess.run(list(cmd), cwd=cwd, check=False).returncode != 0:
            raise ReleaseError(f"`{' '.join(cmd)}` failed")

    def interactive(self, cmd: Sequence[str]) -> int:
        return subprocess.run(list(cmd), check=False).returncode


@dataclass(frozen=True)
class Options:
    release_type: str
    version: str | None = None
    preid: str | None = None
    dry_run: bool = False
    skip_checks: bool = False
    yes: bool = False


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def ensure_gh_login(runner: Runner, *, interactive: bool, yes: bool, ask: Callable[[str], str] = input) -> None:
    """Make sure `gh` is logged in to GitHub, offering to run `gh auth login` in an interactive terminal.

    The token itself is never read here: `gh` handles the login and stores its own credentials.
    """
    status = ["gh", "auth", "status", "--hostname", GITHUB_HOST]
    if runner.query(status, cwd=Path.cwd(), check=False).returncode == 0:
        return
    hint = f"Run `gh auth login --hostname {GITHUB_HOST}` and try again."
    if not interactive or yes:
        raise ReleaseError(f"the GitHub CLI is not logged in to {GITHUB_HOST}, or its token has expired. {hint}")
    print(f"The GitHub CLI is not logged in to {GITHUB_HOST}, or its token has expired.")
    if ask("Run `gh auth login` now? [y/N] ").strip().lower() not in ("y", "yes"):
        raise ReleaseError(f"not logged in to GitHub. {hint}")
    runner.interactive(["gh", "auth", "login", "--hostname", GITHUB_HOST, "--web"])
    if runner.query(status, cwd=Path.cwd(), check=False).returncode != 0:
        raise ReleaseError(f"still not logged in to GitHub. {hint}")


def check_tools(runner: Runner, root: Path) -> None:
    missing = [tool for tool in ("git", "gh", "uv", "node", "npm") if shutil.which(tool) is None]
    if missing:
        raise ReleaseError(f"missing tools: {', '.join(missing)} (see docs/releasing.md)")
    node = runner.query(["node", "--version"], cwd=root).stdout.strip()
    m = re.match(r"v(\d+)\.", node)
    if not m or int(m.group(1)) < MIN_NODE_MAJOR:
        raise ReleaseError(f"Node.js {MIN_NODE_MAJOR} or later is needed for kac, found {node or 'unknown'}")


def github_repo(runner: Runner, root: Path) -> str:
    """The `owner/repo` of origin, after checking that the operator may prepare releases."""
    out = runner.query(["gh", "repo", "view", "--json", "nameWithOwner,viewerPermission"], cwd=root).stdout
    info = json.loads(out)
    if info.get("viewerPermission") not in ALLOWED_ROLES:
        raise ReleaseError(
            f"preparing a release needs admin or maintain permission on {info.get('nameWithOwner')}; "
            f"you have {info.get('viewerPermission')}"
        )
    return info["nameWithOwner"]


def check_git_state(runner: Runner, root: Path) -> None:
    if runner.query(["git", "status", "--porcelain"], cwd=root).stdout.strip():
        raise ReleaseError("the working tree has uncommitted or untracked changes; commit or stash them first")
    runner.query(["git", "fetch", "--tags", "origin"], cwd=root)
    branch = runner.query(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root).stdout.strip()
    if branch != "main":
        raise ReleaseError(f"releases are prepared from main, but the current branch is {branch}")
    head = runner.query(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    upstream = runner.query(["git", "rev-parse", "origin/main"], cwd=root).stdout.strip()
    if head != upstream:
        raise ReleaseError("main is not the same as origin/main; pull or push first")


def check_no_open_release_pr(runner: Runner, root: Path) -> None:
    out = runner.query(["gh", "pr", "list", "--label", LABEL, "--state", "open", "--json", "url"], cwd=root).stdout
    if prs := json.loads(out or "[]"):
        raise ReleaseError(f"a release pull request is already open: {prs[0]['url']}")


def kac_path(root: Path) -> Path:
    return root / "tools" / "kac" / "node_modules" / ".bin" / "kac"


def ensure_kac(runner: Runner, root: Path) -> Path:
    """Install the hash-pinned kac CLI from tools/kac/package-lock.json, unless the locked version is installed."""
    tools = root / "tools" / "kac"
    lock_file = tools / "package-lock.json"
    if not lock_file.exists():
        raise ReleaseError(f"{lock_file.relative_to(root)} is missing; kac must be pinned by a lockfile")
    lock = json.loads(lock_file.read_text(encoding="utf-8"))
    wanted = lock["packages"]["node_modules/@release-flow/keep-a-changelog"]["version"]
    installed_manifest = tools / "node_modules" / "@release-flow" / "keep-a-changelog" / "package.json"
    installed = None
    if installed_manifest.exists():
        installed = json.loads(installed_manifest.read_text(encoding="utf-8")).get("version")
    if installed != wanted or not kac_path(root).exists():
        # npm ci installs exactly what the lockfile pins and checks every package's integrity hash.
        runner.setup(["npm", "ci", "--prefix", str(tools), "--ignore-scripts", "--no-audit", "--no-fund"], cwd=root)
    return kac_path(root)


def bump_changelog(
    runner: Runner, root: Path, kac: Path, workdir: Path, opts: Options, repo: str
) -> tuple[Path, str, str]:
    """Bump a copy of CHANGELOG.md in `workdir`. Returns the copy's path, the new version and its release notes."""
    copy = workdir / "CHANGELOG.md"
    shutil.copyfile(root / "CHANGELOG.md", copy)
    version_arg = opts.version if opts.release_type == "manual" else opts.release_type
    cmd = [str(kac), "bump", "--changelog", str(copy), "--version", str(version_arg), "--github-repo", repo]
    # Keep an empty [Unreleased] section for the next changes. A release with no notes is refused.
    cmd += ["--tag-prefix", TAG_PREFIX, "--fail-on-empty-release-notes", "--keep-unreleased-section"]
    if opts.preid:
        cmd += ["--preid", opts.preid]
    runner.query(cmd, cwd=workdir)
    out = runner.query([str(kac), "query", "--changelog", str(copy), "--version", "latest"], cwd=workdir).stdout
    info = json.loads(out)
    return copy, info["version"], strip_link_definitions(info.get("release-notes") or "")


def existing_versions(runner: Runner, root: Path, repo: str) -> list[str]:
    """Every version released or drafted so far: v* tags, GitHub releases (drafts too) and the changelog."""
    tags = runner.query(["git", "tag", "--list", f"{TAG_PREFIX}*"], cwd=root).stdout.split()
    releases = runner.query(
        ["gh", "api", f"repos/{repo}/releases", "--paginate", "--jq", ".[].tag_name"], cwd=root
    ).stdout.split()
    changelog = [str(v) for v in changelog_versions((root / "CHANGELOG.md").read_text(encoding="utf-8"))]
    return tags + releases + changelog


def pr_body(version: Version, notes: str) -> str:
    return (
        f"Prepares release {version}.\n\n"
        f"> [!WARNING]\n"
        f"> Merging this pull request creates a **draft** GitHub release `{TAG_PREFIX}{version}`. Publishing that "
        f"draft, then approving the `release` environment, publishes the container image.\n\n"
        f"Created by `scripts/release.py prepare`. Changes: CHANGELOG.md, the version in pyproject.toml and uv.lock.\n\n"
        f"## Release notes\n\n{notes.strip() or '_No release notes._'}\n"
    )


def prepare(
    opts: Options,
    *,
    root: Path = ROOT,
    runner: Runner | None = None,
    interactive: bool | None = None,
    ask: Callable[[str], str] = input,
) -> Runner:
    runner = runner or Runner(dry_run=opts.dry_run)
    interactive = is_interactive() if interactive is None else interactive
    explicit = validate_input(opts.release_type, opts.version, opts.preid)

    # Preflight: fail before changing anything.
    check_tools(runner, root)
    ensure_gh_login(runner, interactive=interactive, yes=opts.yes, ask=ask)
    repo = github_repo(runner, root)
    check_git_state(runner, root)
    check_no_open_release_pr(runner, root)

    with tempfile.TemporaryDirectory(prefix="enodia-release-") as tmp:
        workdir = Path(tmp)
        kac = ensure_kac(runner, root)
        new_changelog, computed, notes = bump_changelog(runner, root, kac, workdir, opts, repo)
        version = parse_release_version(computed)
        if explicit is not None and version != explicit:
            raise ReleaseError(f"kac produced version {version}, expected {explicit}")
        check_newer(version, existing_versions(runner, root, repo))
        branch = f"{BRANCH_PREFIX}{version}"
        if runner.query(["git", "ls-remote", "--heads", "origin", branch], cwd=root).stdout.strip():
            raise ReleaseError(f"branch {branch} already exists on origin")
        python_version = pep440(version)
        body = workdir / "pr-body.md"
        body.write_text(pr_body(version, notes), encoding="utf-8")

        steps: list[list[str]] = [
            ["git", "switch", "--create", branch, "origin/main"],
            ["cp", str(new_changelog), "CHANGELOG.md"],
            ["uv", "version", python_version, "--no-sync"],
            ["uv", "lock"],
        ]
        checks: list[list[str]] = [
            ["uv", "lock", "--check"],
            ["uv", "run", "--locked", "ruff", "check", "."],
            ["uv", "run", "--locked", "ty", "check"],
            ["uv", "run", "--locked", "pytest", "-q"],
        ]
        publish: list[list[str]] = [
            ["git", "add", "CHANGELOG.md", "pyproject.toml", "uv.lock"],
            ["git", "commit", "--message", f"chore: prepare release {version}"],
            ["git", "push", "--set-upstream", "origin", branch],
            ["gh", "label", "create", LABEL, "--color", "0e8a16", "--force",
             "--description", "Release preparation pull request"],
            ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", f"Release {version}",
             "--label", LABEL, "--body-file", str(body)],
            ["git", "switch", "main"],
        ]  # fmt: skip

        print(f"Release:      {version}{' (prerelease)' if version.is_prerelease else ''}")
        print(f"Python:       {python_version} (pyproject.toml was {project_version(root)})")
        print(f"Branch:       {branch}")
        print(f"Repository:   {repo}\n")
        print_diff(root / "CHANGELOG.md", new_changelog)
        print(f"\nRelease notes:\n{notes.strip() or '(none)'}\n")

        if opts.dry_run:
            print("Dry run: nothing was changed. These commands would run:")
            for cmd in steps + ([] if opts.skip_checks else checks) + publish:
                print(f"  {' '.join(cmd)}")
                runner.planned.append(cmd)
            print("  (plus `scripts/release.py verify` after `uv lock`)")
            return runner

        if not opts.yes:
            if not interactive:
                raise ReleaseError("not running in a terminal; pass --yes to confirm, or --dry-run")
            if ask(f"Create {branch} and open the release pull request? [y/N] ").strip().lower() not in ("y", "yes"):
                raise ReleaseError("cancelled; nothing was changed")

        done: list[str] = []
        try:
            for cmd in steps:
                runner.act(cmd, cwd=root)
                done.append(cmd[1])
            verify(version, root)
            if not opts.skip_checks:
                for cmd in checks:
                    runner.act(cmd, cwd=root)
            for cmd in publish:
                runner.act(cmd, cwd=root)
                done.append(cmd[1])
        except ReleaseError as e:
            raise ReleaseError(f"{e}\n{cleanup_hint(branch, done)}") from e
    print(f"\nRelease pull request opened for {version}. Merging it creates the draft release.")
    return runner


def cleanup_hint(branch: str, done: list[str]) -> str:
    if "switch" not in done:
        return "Nothing was changed."
    if "push" in done:
        return (
            f"{branch} was pushed to origin. Finish by hand (see docs/releasing.md), or delete the remote branch on "
            f"GitHub and run `git switch main && git branch -D {branch}`."
        )
    return f"Nothing was pushed. To start again: `git switch --force main && git branch -D {branch}`."


def print_diff(old: Path, new: Path) -> None:
    diff = difflib.unified_diff(
        old.read_text(encoding="utf-8").splitlines(keepends=True),
        new.read_text(encoding="utf-8").splitlines(keepends=True),
        fromfile="CHANGELOG.md",
        tofile="CHANGELOG.md (bumped)",
    )
    sys.stdout.writelines(diff)


# --- command line -------------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("prepare", help="prepare a release branch and open its pull request")
    p.add_argument("release_type", choices=RELEASE_TYPES, metavar="type", help=" | ".join(RELEASE_TYPES))
    p.add_argument("--version", help="the release version, for manual releases")
    p.add_argument("--preid", choices=PREIDS, help="prerelease identifier, for the pre* types")
    p.add_argument("--dry-run", action="store_true", help="show what would happen and change nothing")
    p.add_argument("--skip-checks", action="store_true", help="skip ruff, ty and pytest before pushing")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    for name, text in (("verify", "check the release files"), ("pep440", "print the PEP 440 form")):
        sub.add_parser(name, help=text).add_argument("version")
    sub.add_parser("is-prerelease", help="print true or false").add_argument("version")
    p = sub.add_parser("check-newer", help="check the version is newer than all existing ones")
    p.add_argument("version")
    p.add_argument("--existing", required=True, help="file with one version per line, or - for stdin")
    sub.add_parser("parse-branch", help="print the version in a release branch name").add_argument("ref")
    sub.add_parser("clean-notes", help="strip Markdown link definitions from release notes on stdin")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        match args.command:
            case "prepare":
                opts = Options(args.release_type, args.version, args.preid, args.dry_run, args.skip_checks, args.yes)
                prepare(opts)
            case "verify":
                version = parse_release_version(args.version)
                verify(version, ROOT)
                print(f"pyproject.toml, uv.lock and CHANGELOG.md describe release {version}")
            case "pep440":
                print(pep440(parse_release_version(args.version)))
            case "is-prerelease":
                print("true" if parse_release_version(args.version).is_prerelease else "false")
            case "check-newer":
                source = sys.stdin if args.existing == "-" else open(args.existing, encoding="utf-8")  # noqa: SIM115
                with source:
                    check_newer(parse_release_version(args.version), source.read().splitlines())
            case "parse-branch":
                print(parse_branch(args.ref))
            case "clean-notes":
                sys.stdout.write(strip_link_definitions(sys.stdin.read()))
    except ReleaseError as e:
        prefix = "::error::" if os.environ.get("GITHUB_ACTIONS") == "true" else "error: "
        print(f"{prefix}{e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
