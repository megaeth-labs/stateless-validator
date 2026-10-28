# CI credentials

Build, lint, no-std, and coverage jobs check out this repository with the job's `GITHUB_TOKEN` and `persist-credentials: false`.
The Git dependencies in the current lockfile are public; Cargo does not need a PAT or an App token.

| Configuration | Scope | Consumer |
| --- | --- | --- |
| `MEGA_GUTENBERG_CLIENT_ID` variable | Organization | Release App (mega-gutenberg) tokens in `release-candidate.yml` and `release-settle.yml`, the only release identity |
| `MEGA_GUTENBERG_PK` secret | Organization, access granted to this repository | Same release App-token jobs |
| `MEGA_MAXWELL_CLIENT_ID` variable | Organization | PR review App token (CI App, mega-maxwell); never used by a release workflow |
| `MEGA_MAXWELL_PK` secret | Organization | Same PR review job |
| `CLAUDE_CODE_OAUTH_TOKEN` secret | Organization | Claude workflows |
| `CODECOV_TOKEN` secret | Repository | Coverage report upload |
| `GCP_AUTH_KEY` secret | `publish` environment | Release binary upload to Artifact Registry |
| `release` environment | Repository | Gates release-settle's publish job (annotated tag and GitHub Release); required reviewer, deployment policy for `main`, `release-v*` and `v*` tags |

The release flow's dependency token for `cargo update --workspace` is the read-only job token, which is enough while every Git dependency stays public.
`app-token-lint.yml` enforces the App-token rules (which App may mint what, and where) on every workflow change.

Claude jobs rely on the [pinned action's credential replacement](https://github.com/anthropics/claude-code-action/blob/5ef2e550a465a721f4f45e4a7d3c340c873e1dcc/src/github/operations/git-config.ts), which removes checkout's authorization header and configures Git with the action's own token before Claude starts.
In `interactive`, that write token remains in the origin URL in `.git/config` while `Bash(cargo:*)` is allowed, so a build script or proc-macro from a PR branch could read it; `persist-credentials: false` alone would not remove this risk.

The release upload targets the generic Artifact Registry repository `asia-northeast1/megaeth-generic-registry` in project `devops-production-464602`.
It requires upload permission; the dev-image reader credential `GCP_DEV_IMAGES_READER_OAUTH_KEY` cannot replace it.
These workflows do not pull TCR images and do not need TCR configuration.

Secret presence does not prove that an external credential is valid.
Validate build and coverage changes on a PR.
Release delivery needs a separate release rehearsal or an actual approved release; do not create tags or publish a release solely to test credential configuration.
Existing tags retain their workflow files, so changes on `main` do not repair workflows stored in old tags.
