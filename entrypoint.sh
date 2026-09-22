#!/usr/bin/env bash
#
# cryptoptic container entrypoint.
#
# Every input resolves in this order, highest precedence first:
#
#   1. positional argument  (the order the GitHub Action has always used)
#   2. INPUT_<NAME>         (set by the Actions runner for every declared input)
#   3. environment variable (convenient for local `docker run --env ...`)
#   4. the default below
#
# The INPUT_ tier is what makes the action work. A Docker action's runs.env
# block cannot see the inputs context: ${{ inputs.command }} written there
# dereferences a nonexistent property and silently becomes an empty string,
# so every input arrived blank and the entrypoint fell through to its
# defaults, running `scan` no matter what command was asked for. The runner
# always exports INPUT_COMMAND, INPUT_GITHUB-TOKEN and friends, so read
# those instead. They are not valid shell identifiers (INPUT_GITHUB-TOKEN
# would parse as INPUT_GITHUB with a default of TOKEN), hence printenv.

set -euo pipefail

APP_DIR=/opt/cryptoptic
CALLER_WORKSPACE="${GITHUB_WORKSPACE:-/workspace}"
BUILD_TIME_HOME=/root

resolve() {
    local positional="$1" input_name="$2" env_name="$3" default="$4"
    local value

    if [[ -n "$positional" ]]; then
        printf '%s' "$positional"
        return 0
    fi

    value=$(printenv "INPUT_${input_name}" || true)
    if [[ -n "$value" ]]; then
        printf '%s' "$value"
        return 0
    fi

    value=$(printenv "$env_name" || true)
    if [[ -n "$value" ]]; then
        printf '%s' "$value"
        return 0
    fi

    printf '%s' "$default"
}

COMMAND=$(resolve "${1:-}" COMMAND COMMAND scan)
GH_TOKEN_INPUT=$(resolve "${2:-}" GITHUB-TOKEN GH_TOKEN "")
TARGET_LANGUAGE=$(resolve "${3:-}" TARGET-LANGUAGE TARGET_LANG python)
ORGANIZATION=$(resolve "${4:-}" ORGANIZATION ORG "")
REPOSITORY=$(resolve "${5:-}" REPOSITORY REPO "")
REPOSITORY_LIST=$(resolve "${6:-}" REPOSITORY-LIST REPO_LIST "")
START_AT=$(resolve "${7:-}" START-AT START_AT 0)
MAX_REPOSITORIES=$(resolve "${8:-}" MAX-REPOSITORIES MAX_REPOS 0)
BUDGET_SECONDS=$(resolve "${9:-}" BUDGET-SECONDS BUDGET_SECONDS 19800)
CODEQL_RAM_MB=$(resolve "${10:-}" CODEQL-RAM-MB CODEQL_RAM_MB 6144)
REPOSITORY_TIMEOUT_SECONDS=$(resolve "${11:-}" REPOSITORY-TIMEOUT-SECONDS REPO_TIMEOUT_SECONDS 1800)
OUTPUT_DIRECTORY=$(resolve "${12:-}" OUTPUT-DIRECTORY OUTPUT_DIR org-sarif)
TEST_OUTPUT_DIRECTORY=$(resolve "${13:-}" TEST-OUTPUT-DIRECTORY TEST_OUTPUT_DIR output)
SARIF_FILE=$(resolve "${14:-}" SARIF-FILE SARIF_FILE "")
OUTPUT_FILE=$(resolve "${15:-}" OUTPUT-FILE OUTPUT_FILE "")
CSV_INPUTS=$(resolve "${16:-}" CSV-INPUTS CSV_INPUTS "")
RECURSIVE=$(resolve "${17:-}" RECURSIVE RECURSIVE false)
PYTEST_TARGET=$(resolve "${18:-}" PYTEST-TARGET PYTEST_TARGET tests)

log() {
    printf '[cryptoptic] %s\n' "$*" >&2
}

# Error text is deliberately unprefixed so it stays byte-identical to what
# earlier versions of this script emitted; the prefix is for new log output.
die() {
    printf '%s\n' "$*" >&2
    exit 2
}

usage() {
    cat >&2 <<'USAGE'
Usage: cryptoptic <command> [args...]

Commands:
  scan          Organisation or single-repository CodeQL scan (default).
  test          JavaScript CodeQL query-suite test; writes cbom-results.sarif.
  python-tests  Project Python tests via pytest.
  convert       Convert a SARIF file in the workspace to CSV.
  aggregate     Aggregate newline-delimited CSV paths from the workspace.

Inputs may be given positionally or as environment variables; see
CONTAINER.md for the full table.
USAGE
}

# codeql pack install caches pack dependencies under $HOME/.codeql when the
# image is built (HOME=/root). GitHub Actions runs container actions with
# HOME=/github/home, which hides that cache and makes CodeQL try to re-resolve
# packs over the network mid-job. Link the baked cache into the run-time HOME.
link_codeql_pack_cache() {
    local home="${HOME:-}"

    if [[ -z "$home" || "$home" == "$BUILD_TIME_HOME" ]]; then
        return 0
    fi
    if [[ ! -d "$BUILD_TIME_HOME/.codeql" || -e "$home/.codeql" ]]; then
        return 0
    fi

    if mkdir --parents "$home" 2>/dev/null \
        && ln --symbolic --no-target-directory "$BUILD_TIME_HOME/.codeql" "$home/.codeql" 2>/dev/null; then
        log "Linked the image's CodeQL package cache into $home/.codeql"
    else
        log "Warning: could not link the CodeQL package cache into $home; CodeQL may re-resolve packs"
    fi
}

require_relative_directory() {
    local directory="$1"
    if [[ -z "$directory" || "$directory" = /* || "$directory" =~ (^|/)\.\.(/|$) ]]; then
        echo "Output directory must be a non-empty workspace-relative path: $directory" >&2
        exit 2
    fi
}

publish_directory() {
    local source_directory="$1"
    local destination_directory="$2"

    require_relative_directory "$destination_directory"
    mkdir --parents "$CALLER_WORKSPACE/$destination_directory"
    cp --archive "$source_directory/." "$CALLER_WORKSPACE/$destination_directory/"
    log "Published results to $CALLER_WORKSPACE/$destination_directory"

    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "results-directory=$CALLER_WORKSPACE/$destination_directory" >> "$GITHUB_OUTPUT"
    fi
}

run_scan() {
    if [[ -z "$GH_TOKEN_INPUT" ]]; then
        log "Warning: no github-token/GH_TOKEN supplied; listing and cloning repositories will fail"
    fi
    log "Scanning language=$TARGET_LANGUAGE org=${ORGANIZATION:-<unset>} repo=${REPOSITORY:-<unset>}"

    export GH_TOKEN="$GH_TOKEN_INPUT"
    export TARGET_LANG="$TARGET_LANGUAGE"
    export ORG="$ORGANIZATION"
    export REPO="$REPOSITORY"
    export REPO_LIST="$REPOSITORY_LIST"
    export MAX_REPOS="$MAX_REPOSITORIES"
    export REPO_TIMEOUT_SECONDS="$REPOSITORY_TIMEOUT_SECONDS"
    export START_AT BUDGET_SECONDS CODEQL_RAM_MB
    export GITHUB_WORKSPACE="$APP_DIR"

    link_codeql_pack_cache
    cd "$APP_DIR"
    python scripts/org_codeql_sarif_run.py
    publish_directory "$APP_DIR/org-sarif" "$OUTPUT_DIRECTORY"
}

run_query_suite() {
    link_codeql_pack_cache
    cd "$APP_DIR"
    rm -rf cbom-test-db output
    mkdir --parents output
    codeql database create cbom-test-db \
        --language=javascript \
        --source-root=./cbom-test-suite
    codeql database analyze cbom-test-db codeql-queries/javascript \
        --format=sarifv2.1.0 \
        --output=output/cbom-results.sarif \
        --rerun \
        --ram=8192 \
        --threads=0
    publish_directory "$APP_DIR/output" "$TEST_OUTPUT_DIRECTORY"
}

run_python_tests() {
    cd "$APP_DIR"
    pytest "$PYTEST_TARGET"
}

run_convert() {
    if [[ -z "$SARIF_FILE" ]]; then
        die "sarif-file is required for command=convert"
    fi

    cd "$CALLER_WORKSPACE"
    if [[ -n "$OUTPUT_FILE" ]]; then
        python "$APP_DIR/scripts/sarif_to_csv.py" "$SARIF_FILE" "$OUTPUT_FILE"
    else
        python "$APP_DIR/scripts/sarif_to_csv.py" "$SARIF_FILE"
    fi
}

run_aggregate() {
    if [[ -z "$CSV_INPUTS" ]]; then
        die "csv-inputs is required for command=aggregate"
    fi

    local -a inputs=()
    local input
    while IFS= read -r input; do
        if [[ -n "$input" ]]; then
            inputs+=("$input")
        fi
    done <<< "$CSV_INPUTS"

    if [[ "${#inputs[@]}" -eq 0 ]]; then
        die "csv-inputs contained no usable paths"
    fi

    cd "$CALLER_WORKSPACE"
    local -a arguments=("${inputs[@]}")
    if [[ -n "$OUTPUT_FILE" ]]; then
        arguments+=(--output "$OUTPUT_FILE")
    fi
    if [[ "$RECURSIVE" = "true" ]]; then
        arguments+=(--recursive)
    fi
    python "$APP_DIR/scripts/aggregate_csv.py" "${arguments[@]}"
}

case "$COMMAND" in
    scan)
        run_scan
        ;;
    test)
        run_query_suite
        ;;
    python-tests)
        run_python_tests
        ;;
    convert)
        run_convert
        ;;
    aggregate)
        run_aggregate
        ;;
    help | --help | -h)
        usage
        ;;
    *)
        echo "Unsupported command: $COMMAND. Use scan, test, python-tests, convert, or aggregate." >&2
        usage
        exit 2
        ;;
esac
