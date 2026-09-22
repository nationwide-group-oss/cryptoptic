set -euo pipefail

BUNDLE_URL="${CODEQL_BUNDLE_URL:-https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz}"
DEST_DIR="${RUNNER_TEMP:-/tmp}/codeql-bundle"

mkdir -p "$DEST_DIR"

curl -L -o "$DEST_DIR/codeql-bundle.tar.gz" "$BUNDLE_URL"
tar -xzf "$DEST_DIR/codeql-bundle.tar.gz" -C "$DEST_DIR"

CODEQL_BIN="$(find "$DEST_DIR" -type f -name codeql -perm -111 | head -n 1)"
if [ -z "$CODEQL_BIN" ]; then
  echo "Could not find codeql binary in extracted bundle" >&2
  exit 1
fi

CODEQL_DIR="$(dirname "$CODEQL_BIN")"

# Make it available to later workflow steps.
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$CODEQL_DIR" >> "$GITHUB_PATH"
else
  export PATH="$CODEQL_DIR:$PATH"
fi

"$CODEQL_BIN" version