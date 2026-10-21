# CI credentials

Build, lint, no-std, and coverage jobs check out this repository with the job's `GITHUB_TOKEN` and `persist-credentials: false`.
The Git dependencies in the current lockfile are public; Cargo does not need a PAT or an App token.

| Configuration | Scope | Consumer |
| --- | --- | --- |
| `MEGA_MAXWELL_CLIENT_ID` variable | Organization | Release candidate, settle, publish, and PR review App tokens |
| `MEGA_MAXWELL_PK` secret | Organization | Same App-token jobs |
| `CLAUDE_CODE_OAUTH_TOKEN` secret | Organization | Claude workflows |
| `CODECOV_TOKEN` secret | Repository | Coverage report upload |
| `GCP_AUTH_KEY` secret | `publish` environment | Release binary upload to Artifact Registry |

The release upload targets the generic Artifact Registry repository `asia-northeast1/megaeth-generic-registry` in project `devops-production-464602`.
It requires upload permission; the dev-image reader credential `GCP_DEV_IMAGES_READER_OAUTH_KEY` cannot replace it.
These workflows do not pull TCR images and do not need TCR configuration.

Secret presence does not prove that an external credential is valid.
Validate build and coverage changes on a PR.
Release delivery needs a separate release rehearsal or an actual approved release; do not create tags or publish a release solely to test credential configuration.
Existing tags retain their workflow files, so changes on `main` do not repair workflows stored in old tags.
