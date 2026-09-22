"""
Aggregate multiple crypto inventory CSV files into a single output CSV.

Usage:
    python aggregate_csv.py <input_dir_or_files...> [--output OUTPUT] [--recursive]

Examples:
    python aggregate_csv.py results/          # aggregate all CSVs in a directory
    python aggregate_csv.py results/ -r       # search recursively
    python aggregate_csv.py a.csv b.csv       # aggregate specific files
    python aggregate_csv.py results/ --output combined.csv
"""

import argparse
import csv
import sys
from pathlib import Path

FIELDNAMES = [
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


def collect_csv_files(inputs: list[str], recursive: bool) -> list[Path]:
    """Collect CSV file paths from a mix of files and directories."""
    paths: list[Path] = []
    for raw in inputs:
        p = Path(raw)
        if p.is_file():
            if p.suffix.lower() == ".csv":
                paths.append(p)
            else:
                print(f"Warning: skipping non-CSV file: {p}", file=sys.stderr)
        elif p.is_dir():
            pattern = "**/*.csv" if recursive else "*.csv"
            found = sorted(p.glob(pattern))
            if not found:
                print(f"Warning: no CSV files found in: {p}", file=sys.stderr)
            paths.extend(found)
        else:
            print(f"Warning: path not found: {p}", file=sys.stderr)
    return paths


def aggregate(csv_files: list[Path], output_path: Path) -> int:
    """Read all CSV files and write combined rows to output_path. Returns row count."""
    total = 0
    with open(output_path, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()

        for csv_file in csv_files:
            try:
                with open(csv_file, encoding="utf-8", newline="") as in_f:
                    reader = csv.DictReader(in_f)
                    for row in reader:
                        # Fill missing expected columns with empty string
                        normalised = {field: row.get(field, "") for field in FIELDNAMES}
                        writer.writerow(normalised)
                        total += 1
            except Exception as exc:
                print(f"Error reading {csv_file}: {exc}", file=sys.stderr)

    return total


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate crypto inventory CSV files into a single output CSV."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        metavar="INPUT",
        help="One or more CSV files or directories containing CSV files.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="aggregated.csv",
        help="Path for the combined output CSV (default: aggregated.csv).",
    )
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Search directories recursively for CSV files.",
    )
    args = parser.parse_args()

    csv_files = collect_csv_files(args.inputs, args.recursive)
    # Exclude the output file itself if it already exists inside an input directory
    output_path = Path(args.output).resolve()
    csv_files = [f for f in csv_files if f.resolve() != output_path]

    if not csv_files:
        print("Error: no CSV files to aggregate.", file=sys.stderr)
        sys.exit(1)

    print(f"Aggregating {len(csv_files)} file(s)...")
    total = aggregate(csv_files, output_path)
    print(f"Wrote {total} rows to {output_path}")


if __name__ == "__main__":
    main()
