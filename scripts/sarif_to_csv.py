"""
Parse a CodeQL SARIF file and extract crypto inventory results to CSV.

Usage:
    python sarif_to_csv.py <sarif_file> [output_csv]

If output_csv is not specified, defaults to the SARIF filename with a .csv extension.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


def parse_message(text: str) -> list[dict[str, str]]:
    """Parse one or more 'algo=..., api=...' lines from a SARIF message."""
    results = []
    for line in text.strip().splitlines():
        entry = {}
        # Value allows dots so 'api=Org.BouncyCastle' and 'api=System.Security.Cryptography' parse correctly.
        for match in re.finditer(r"(\w+)=([\w./-]+?)(?:,\s*|$)", line):
            entry[match.group(1)] = match.group(2).strip()
        if entry:
            results.append(entry)
    return results


def repo_name_from_filename(sarif_path: str) -> str:
    """Derive 'owner/repo' from a SARIF filename like 'owner__repo.sarif'."""
    stem = Path(sarif_path).stem
    if "__" in stem:
        owner, repo = stem.split("__", 1)
        return f"{owner}/{repo}"
    return stem


def extract_results(sarif_path: str, repo: str) -> list[dict[str, str]]:
    """Extract crypto inventory rows from a SARIF file."""
    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)

    rows = []
    for run in sarif.get("runs", []):
        run_props = run.get("properties", {})
        portfolio_name = run_props.get("portfolio_name", "")
        value_stream = run_props.get("value_stream", "")

        for result in run.get("results", []):
            message_text = result.get("message", {}).get("text", "")
            parsed_entries = parse_message(message_text)

            for location in result.get("locations", []):
                phys = location.get("physicalLocation", {})
                artifact_uri = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                start_line = region.get("startLine", "")
                # SARIF may omit startColumn even when startLine exists; default to 1.
                start_column = region.get("startColumn", 1 if start_line != "" else "")
                end_column = region.get("endColumn", "")

                for entry in parsed_entries:
                    rows.append(
                        {
                            "repo": repo,
                            "portfolio_name": portfolio_name,
                            "value_stream": value_stream,
                            "algo": entry.get("algo", ""),
                            "api": entry.get("api", ""),
                            "startLine": start_line,
                            "startColumn": start_column,
                            "endColumn": end_column,
                            "artifactUri": artifact_uri,
                        }
                    )

    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Extract crypto inventory results from a CodeQL SARIF file to CSV."
    )
    parser.add_argument("sarif_file", help="Path to the input SARIF file")
    parser.add_argument(
        "output_csv",
        nargs="?",
        default=None,
        help="Path to the output CSV file (default: <sarif_file>.csv)",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="Repository name (owner/repo). Defaults to deriving from the SARIF filename.",
    )
    args = parser.parse_args()

    sarif_path = Path(args.sarif_file)
    if not sarif_path.is_file():
        print(f"Error: SARIF file not found: {sarif_path}", file=sys.stderr)
        sys.exit(1)

    output_path = (
        Path(args.output_csv) if args.output_csv else sarif_path.with_suffix(".csv")
    )
    repo = args.repo if args.repo else repo_name_from_filename(str(sarif_path))

    rows = extract_results(str(sarif_path), repo)

    fieldnames = [
        "repo",
        "portfolio_name",
        "value_stream",
        "algo",
        "api",
        "startLine",
        "startColumn",
        "endColumn",
        "artifactUri",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {output_path}")


if __name__ == "__main__":
    main()
