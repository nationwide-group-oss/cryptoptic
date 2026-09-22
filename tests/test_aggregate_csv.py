"""Tests for scripts/aggregate_csv.py"""

import csv
from pathlib import Path

import pytest

from scripts.aggregate_csv import aggregate, collect_csv_files, FIELDNAMES

# ---------------------------------------------------------------------------
# collect_csv_files
# ---------------------------------------------------------------------------


def test_collect_csv_files_single_file(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text("col\nval\n")
    result = collect_csv_files([str(f)], recursive=False)
    assert result == [f]


def test_collect_csv_files_directory(tmp_path):
    (tmp_path / "a.csv").write_text("col\nval\n")
    (tmp_path / "b.csv").write_text("col\nval\n")
    (tmp_path / "ignore.txt").write_text("text")
    result = collect_csv_files([str(tmp_path)], recursive=False)
    assert sorted(result) == sorted([tmp_path / "a.csv", tmp_path / "b.csv"])


def test_collect_csv_files_recursive(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "top.csv").write_text("col\nval\n")
    (sub / "nested.csv").write_text("col\nval\n")
    result = collect_csv_files([str(tmp_path)], recursive=True)
    assert len(result) == 2


def test_collect_csv_files_non_csv_skipped(tmp_path, capsys):
    f = tmp_path / "data.txt"
    f.write_text("not a csv")
    result = collect_csv_files([str(f)], recursive=False)
    assert result == []
    captured = capsys.readouterr()
    assert "skipping non-CSV" in captured.err


def test_collect_csv_files_missing_path(tmp_path, capsys):
    result = collect_csv_files([str(tmp_path / "does_not_exist.csv")], recursive=False)
    assert result == []
    captured = capsys.readouterr()
    assert "path not found" in captured.err


def test_collect_csv_files_empty_dir(tmp_path, capsys):
    result = collect_csv_files([str(tmp_path)], recursive=False)
    assert result == []
    captured = capsys.readouterr()
    assert "no CSV files found" in captured.err


# ---------------------------------------------------------------------------
# aggregate
# ---------------------------------------------------------------------------


def _write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def test_aggregate_combines_rows(tmp_path):
    row1 = {f: f"v1_{f}" for f in FIELDNAMES}
    row2 = {f: f"v2_{f}" for f in FIELDNAMES}
    f1 = tmp_path / "a.csv"
    f2 = tmp_path / "b.csv"
    _write_csv(f1, [row1])
    _write_csv(f2, [row2])

    out = tmp_path / "out.csv"
    total = aggregate([f1, f2], out)

    assert total == 2
    with open(out, newline="", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
    assert len(reader) == 2


def test_aggregate_missing_columns_filled_with_empty(tmp_path):
    partial = tmp_path / "partial.csv"
    with open(partial, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["algo", "api"])
        writer.writeheader()
        writer.writerow({"algo": "AES", "api": "crypto.createCipher"})

    out = tmp_path / "out.csv"
    aggregate([partial], out)

    with open(out, newline="", encoding="utf-8") as f:
        row = list(csv.DictReader(f))[0]
    assert row["algo"] == "AES"
    assert row["repo"] == ""


def test_aggregate_returns_zero_for_empty_csv(tmp_path):
    empty = tmp_path / "empty.csv"
    with open(empty, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=FIELDNAMES).writeheader()

    out = tmp_path / "out.csv"
    total = aggregate([empty], out)
    assert total == 0


def test_aggregate_output_has_header(tmp_path):
    row = {f: "x" for f in FIELDNAMES}
    f1 = tmp_path / "a.csv"
    _write_csv(f1, [row])
    out = tmp_path / "out.csv"
    aggregate([f1], out)

    with open(out, newline="", encoding="utf-8") as f:
        header = f.readline().strip().split(",")
    assert header == FIELDNAMES
