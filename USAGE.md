# Using cryptoptic

cryptoptic ships as a container image holding Python, the GitHub CLI, a pinned CodeQL CLI, the project's query packs and their resolved dependencies. There is nothing to install beyond Docker.

There are two ways to run it, and they are the same image with the same commands:

- as a **GitHub Action**, from a workflow in any repository
- as a **container**, with `docker run` on your own machine or a build agent

## Prerequisites

- Docker. The image is `linux/amd64` only, because the CodeQL bundle is not published for arm64. On Apple Silicon it runs under emulation, slowly.
- For scans, a GitHub token with read access to list, clone and inspect each target repository. No token is needed for `test`, `python-tests`, `convert` or `aggregate`.

## Commands

| Command | What it does | Needs a token | Output lands in |
| --- | --- | --- | --- |
| `scan` | Scans an organisation or a single repository and writes SARIF. This is the default. | yes | `org-sarif/<language>/` |
| `test` | Builds a CodeQL database from `cbom-test-suite/` and runs the JavaScript query suite against it. | no | `output/cbom-results.sarif` |
| `python-tests` | Runs the project's Python tests with pytest. | no | stdout only |
| `convert` | Converts one SARIF file into CSV. | no | beside the SARIF, or `output-file` |
| `aggregate` | Merges several CSV files into one. | no | `output-file` |

`help` prints the same summary from inside the container.

## Building the image

```bash
make build            # or: docker build --tag cryptoptic .
```

The first build downloads the CodeQL bundle, roughly a gigabyte, and takes a few minutes. After that it is layer-cached and only changes to `requirements.txt`, `scripts/`, `codeql-queries/`, `cbom-test-suite/` or `tests/` cause meaningful rebuild work.

Four build arguments control the pinned tool versions. The CodeQL bundle is checked against `CODEQL_BUNDLE_SHA256`, so bump the two together or the build fails on purpose:

```bash
docker build \
  --build-arg CODEQL_VERSION=2.27.0 \
  --build-arg CODEQL_BUNDLE_SHA256=<digest> \
  --build-arg GH_VERSION=2.63.2 \
  --tag cryptoptic .
```

`GH_SHA256` is optional. Left empty, the GitHub CLI download is verified against the checksums file published alongside it; set it to pin the digest explicitly as well.

## Running the container

Anything that produces files needs a workspace mounted at `/workspace`. That is where the container publishes its results.

**Scan one repository**

```bash
docker run --rm --volume "$PWD:/workspace" \
  --env GH_TOKEN \
  --env REPO=owner/repository \
  --env TARGET_LANG=javascript \
  cryptoptic scan
```

`--env GH_TOKEN` with no `=` passes the variable through from your shell, so the token stays out of your shell history and out of the container's argument list.

**Scan a whole organisation**

```bash
docker run --rm --volume "$PWD:/workspace" \
  --env GH_TOKEN \
  --env ORG=my-org \
  --env TARGET_LANG=python \
  --env MAX_REPOS=25 \
  cryptoptic scan
```

Set `ORG` or `REPO`, not both. `MAX_REPOS`, `START_AT`, `BUDGET_SECONDS` and `REPO_TIMEOUT_SECONDS` bound how much work a single run takes on.

**Run the query suite**

```bash
docker run --rm --volume "$PWD:/workspace" cryptoptic test
```

Writes `output/cbom-results.sarif`. Check it landed with something like:

```bash
jq -r '.runs[].results[].ruleId' output/cbom-results.sarif | sort | uniq -c
```

**Run the Python tests**

```bash
docker run --rm cryptoptic python-tests
```

Nothing is written, so no mount is needed. `PYTEST_TARGET` narrows the run, for example `--env PYTEST_TARGET=tests/unit`.

**Convert and aggregate**

```bash
docker run --rm --volume "$PWD:/workspace" \
  --env SARIF_FILE=org-sarif/python/results.sarif \
  --env OUTPUT_FILE=results.csv \
  cryptoptic convert

docker run --rm --volume "$PWD:/workspace" \
  --env CSV_INPUTS=org-sarif \
  --env RECURSIVE=true \
  --env OUTPUT_FILE=cbom-inventory.csv \
  cryptoptic aggregate
```

`CSV_INPUTS` takes newline-delimited files or directories. Paths are relative to the mounted workspace.

`make help` lists local shortcuts for all of the above.

## Using it as a GitHub Action

```yaml
permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: nationwide-group-oss/cryptoptic@main
        with:
          command: scan
          github-token: ${{ secrets.GITHUB_TOKEN }}
          repository: owner/repository
          target-language: javascript
```

`GITHUB_TOKEN` only reaches the repository running the workflow. Scanning other repositories, or a whole organisation, needs a token with wider read access.

The action exposes one output, `results-directory`, holding the absolute path of the results it copied into the workspace:

```yaml
      - uses: nationwide-group-oss/cryptoptic@main
        id: cryptoptic-test
        with:
          command: test

      - uses: actions/upload-artifact@v7
        with:
          name: cbom-codeql-sarif
          path: ${{ steps.cryptoptic-test.outputs.results-directory }}/cbom-results.sarif
```

`action.yml` points at the `Dockerfile`, so every job that uses the action builds the image first. Publishing the image and pointing `runs.image` at `docker://ghcr.io/<owner>/cryptoptic:<tag>` instead starts jobs in seconds. Consumers need no change.

## Inputs

Each input resolves in this order, highest precedence first:

1. a positional argument to the container
2. `INPUT_<NAME>`, which the Actions runner sets for every declared input
3. an environment variable
4. the built-in default

The action relies on tier 2 and `docker run` on tier 3, so both work without the two interfering.

| Position | Action input | Environment variable | Default |
| --- | --- | --- | --- |
| 1 | `command` | `COMMAND` | `scan` |
| 2 | `github-token` | `GH_TOKEN` | *(empty)* |
| 3 | `target-language` | `TARGET_LANG` | `python` |
| 4 | `organization` | `ORG` | *(empty)* |
| 5 | `repository` | `REPO` | *(empty)* |
| 6 | `repository-list` | `REPO_LIST` | *(empty)* |
| 7 | `start-at` | `START_AT` | `0` |
| 8 | `max-repositories` | `MAX_REPOS` | `0` |
| 9 | `budget-seconds` | `BUDGET_SECONDS` | `19800` |
| 10 | `codeql-ram-mb` | `CODEQL_RAM_MB` | `6144` |
| 11 | `repository-timeout-seconds` | `REPO_TIMEOUT_SECONDS` | `1800` |
| 12 | `output-directory` | `OUTPUT_DIR` | `org-sarif` |
| 13 | `test-output-directory` | `TEST_OUTPUT_DIR` | `output` |
| 14 | `sarif-file` | `SARIF_FILE` | *(empty)* |
| 15 | `output-file` | `OUTPUT_FILE` | *(empty)* |
| 16 | `csv-inputs` | `CSV_INPUTS` | *(empty)* |
| 17 | `recursive` | `RECURSIVE` | `false` |
| 18 | `pytest-target` | `PYTEST_TARGET` | `tests` |

Positions 2 to 11 carry the variables `scripts/org_codeql_sarif_run.py` reads directly, so running that script locally and running the container take the same settings.

The positional form is equivalent and still supported:

```bash
docker run --rm --volume "$PWD:/workspace" --env GH_TOKEN \
  cryptoptic scan '' javascript '' owner/repository
```

## Sharded organisation scans

`.github/workflows/org-codeql-sarif-run.yml` splits an organisation across parallel runners. It builds the image once and hands it to every shard, so all of them run identical bits and the CodeQL bundle is downloaded once per run rather than once per shard.

Two bind mounts matter if you adapt it. The entrypoint only publishes `org-sarif/` out of the container, so mount `work/` over `/opt/cryptoptic/work` to keep CodeQL databases reachable, and mount the compilation cache over `/opt/cryptoptic/.codeql-compilation-cache` to let it survive the run:

```bash
docker run --rm \
  --volume "$PWD:/workspace" \
  --volume "$PWD/work:/opt/cryptoptic/work" \
  --volume "$PWD/.codeql-compilation-cache:/opt/cryptoptic/.codeql-compilation-cache" \
  --env GH_TOKEN --env ORG --env TARGET_LANG --env REPO_LIST \
  cryptoptic scan
```

## Things worth knowing

**Output paths must stay inside the workspace.** `output-directory` and `test-output-directory` are rejected if they are absolute or contain `..`.

**Files come out owned by root.** The container runs as root, which is what GitHub requires for container actions to write to the mounted workspace. Locally, `sudo chown -R "$USER" org-sarif` if you want to edit the results.

**The `test` command asks for 8 GB of RAM.** If Docker Desktop is capped below that the analysis is killed partway through rather than failing clearly. Raise the limit under Settings, Resources, or pass `--memory 10g` on Linux.

**`codeql-ram-mb` applies to `scan` only.** The query suite uses a fixed allocation.

**Query packs are resolved at build time** into the image's CodeQL package cache. GitHub sets `HOME` to `/github/home` for container actions, which would hide that cache, so the entrypoint links it back into place. Nothing is fetched mid-job.

## When something looks wrong

The first line the container logs names the command it resolved and where the value came from:

```
[cryptoptic] command=python-tests (from INPUT_COMMAND), target-language=python (from built-in default)
```

`from built-in default` when you expected otherwise means the input never arrived. In a workflow, check that the value sits under `with:` and that the input name matches `action.yml` exactly, since GitHub reports an unknown input as a warning annotation rather than an error and falls back to the default.
