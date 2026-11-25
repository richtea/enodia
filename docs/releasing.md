# Releasing

A release takes three steps. Only the first runs on your machine.

1. **Prepare.** `scripts/release.py prepare` opens a release pull request from a `chore/release-<version>` branch. The
   PR moves the `[Unreleased]` changelog entries into a new release section and sets the version in `pyproject.toml`
   and `uv.lock`.
2. **Merge.** CI checks the pull request. When you merge it, a **draft** GitHub release `v<version>` is created at the
   merge commit.
3. **Publish.** Review the draft and publish it. GitHub Actions then verifies and tests the tagged commit. Once you
   approve the `release` environment, it pushes the multi-arch image to `ghcr.io` with a provenance attestation.

You need admin or maintain permission on the repository to prepare, merge and publish a release.

## Versions

Versions follow [Semantic Versioning](https://semver.org/). Prereleases must take the form `X.Y.Z-alpha.N`,
`X.Y.Z-beta.N` or `X.Y.Z-rc.N`, because `pyproject.toml` needs the matching PEP 440 version (`1.3.0-rc.1` becomes
`1.3.0rc1`). A new version must be greater than every existing tag, release (drafts included) and changelog entry.

| Type | From `1.2.3` | Notes |
| --- | --- | --- |
| `major` / `minor` / `patch` | `2.0.0` / `1.3.0` / `1.2.4` | |
| `premajor` / `preminor` / `prepatch` | `2.0.0-rc.0` / `1.3.0-rc.0` / `1.2.4-rc.0` | Needs `--preid alpha\|beta\|rc` |
| `prerelease` | from `1.3.0-rc.0`: `1.3.0-rc.1` | Increments the current prerelease |
| `release` | from `1.3.0-rc.1`: `1.3.0` | Fails unless the latest release is a prerelease |
| `manual` | whatever `--version` says | e.g. `--version 2.0.0-beta.0` |

## Before you start

- [uv](https://docs.astral.sh/uv/).
- Node.js 24 or later, which runs the `kac` changelog tool.
- The [GitHub CLI](https://cli.github.com/), logged in with `gh auth login`. If you aren't logged in, the script offers
  to run the login for you. It never reads your token.
- A clean checkout of `main` that matches `origin/main`.
- User-facing changes recorded under `## [Unreleased]` in `CHANGELOG.md`. A release with no notes is refused.

The script installs `kac` into `tools/kac/node_modules` with `npm ci --ignore-scripts`, using the exact versions and
integrity hashes in `tools/kac/package-lock.json`.

## 1. Prepare

Run a dry run first. It shows the new version, the changelog diff, the release notes and the commands it would run.
It changes nothing, apart from fetching from `origin`.

```sh
uv run scripts/release.py prepare minor --dry-run
```

Then run the same command without `--dry-run`. The script asks for confirmation before it changes anything.

```sh
uv run scripts/release.py prepare minor
uv run scripts/release.py prepare preminor --preid rc
uv run scripts/release.py prepare manual --version 1.0.0
```

The script:

1. checks the tools, your GitHub login and permission, the working tree, and that no release PR is already open;
2. works out the version on a temporary copy of the changelog and checks it is newer than every existing release;
3. creates `chore/release-<version>` from `origin/main` and updates `CHANGELOG.md`, `pyproject.toml` and `uv.lock`;
4. runs `uv lock --check`, ruff, ty and pytest (`--skip-checks` skips them; CI runs them anyway);
5. commits (with your usual signing settings), pushes, and opens the pull request with the `release` label;
6. switches back to `main`.

Other options: `--yes` skips the confirmation prompt. Without a terminal, `--yes` is required.

If a step fails, the script says how far it got and how to clean up. It never force-pushes or deletes remote branches.

## 2. Merge

The **Release PR check** job checks that the branch name, `pyproject.toml`, `uv.lock` and the changelog all show the
same version, and that the version is still newer than every release. Merge the pull request once CI passes.

The **Release PR merged** workflow then checks that the PR's author and the person who merged it both have the admin
or maintain role, and creates the draft release with the changelog notes.

## 3. Publish

Open the draft release (the workflow run's summary links to it), review it, and choose **Publish release**. This
creates the `v<version>` tag at the merge commit. Don't change the tag or target. The publish workflow refuses tags
that aren't on `main` or that don't match the release files.

The **Release published** workflow verifies the tag, runs the full test suite and smoke test on the tagged commit, then
waits for approval of the `release` environment. Approve it under the run's **Review deployments**. The image is then
pushed as:

- `ghcr.io/<owner>/enodia:<version>` for every release;
- `<major>.<minor>` and `latest` for stable releases only.

Check the result:

```sh
gh attestation verify oci://ghcr.io/<owner>/enodia:<version> --owner <owner>
```

## One-off repository setup

These settings live in GitHub, not in this repository. Set them up before the first release.

- **Rulesets → `main`**:
  - require a pull request (0 approvals is fine for a single maintainer);
  - require the status checks *Build and test / Test*, *Build and test / Smoke test image* and *Release PR check*;
  - block force pushes and deletion.
- **Rulesets → tags `v*`**: two rulesets, both targeting `refs/tags/v*`. They have to be separate because a
  ruleset's bypass list applies to all of its rules.
  - `tags`: *Restrict creations*, with the **Repository admin** and **Maintain** roles as bypass actors (always).
    Publishing a release creates its tag, so the people who publish releases need this bypass.
  - `tags-immutable`: *Restrict updates*, *Restrict deletions* and *Block force pushes*, with **no** bypass actors,
    so nobody can move or delete a release tag once it exists.
- **Settings → General → Releases**: turn on immutable releases.
- **Environments → `release`**:
  - add yourself as a required reviewer (leave "Prevent self-review" off if you are the only maintainer);
  - untick "Allow administrators to bypass configured protection rules", so admins also have to approve;
  - limit deployment to tags matching `v*`;
  - no secrets are needed.
- **Settings → Actions → General**:
  - set the workflow permissions to read-only;
  - leave "Allow GitHub Actions to create and approve pull requests" off.
- **The ghcr.io package**: after the first publish, link the package to this repository and turn on "inherit access".
  Make it public.

No release step uses a stored secret. You prepare with your own `gh` login, and the workflows use the short-lived
`GITHUB_TOKEN` and OIDC.
