"""Tests for scripts/sarif_to_csv.py"""

import json
from pathlib import Path

import pytest

from scripts.sarif_to_csv import extract_results, parse_message, repo_name_from_filename

# ---------------------------------------------------------------------------
# parse_message
# ---------------------------------------------------------------------------


def test_parse_message_single_entry():
    text = "algo=AES, api=crypto.createCipher"
    result = parse_message(text)
    assert result == [{"algo": "AES", "api": "crypto.createCipher"}]


def test_parse_message_multiple_lines():
    text = "algo=AES, api=encrypt\nalgo=SHA256, api=hash"
    result = parse_message(text)
    assert len(result) == 2
    assert result[0]["algo"] == "AES"
    assert result[1]["algo"] == "SHA256"


def test_parse_message_empty_string():
    assert parse_message("") == []


def test_parse_message_no_key_value_pairs():
    assert parse_message("just some plain text") == []


def test_parse_message_extra_fields():
    text = "algo=RSA, api=sign, keySize=2048"
    result = parse_message(text)
    assert result[0]["algo"] == "RSA"
    assert result[0]["keySize"] == "2048"


# ---------------------------------------------------------------------------
# repo_name_from_filename
# ---------------------------------------------------------------------------


def test_repo_name_with_double_underscore():
    assert repo_name_from_filename("owner__repo.sarif") == "owner/repo"


def test_repo_name_without_double_underscore():
    assert repo_name_from_filename("just-a-name.sarif") == "just-a-name"


def test_repo_name_with_path():
    assert repo_name_from_filename("/some/path/org__myrepo.sarif") == "org/myrepo"


# ---------------------------------------------------------------------------
# extract_results
# ---------------------------------------------------------------------------


def _write_sarif(path: Path, sarif: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f)


def _minimal_sarif(message: str, uri: str = "src/app.js", start_line: int = 10) -> dict:
    return {
        "runs": [
            {
                "properties": {"portfolio_name": "myportfolio", "value_stream": "vs1"},
                "results": [
                    {
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {
                                        "startLine": start_line,
                                        "startColumn": 5,
                                        "endColumn": 30,
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_extract_results_basic(tmp_path):
    sarif_file = tmp_path / "owner__repo.sarif"
    _write_sarif(sarif_file, _minimal_sarif("algo=AES, api=createCipher"))

    rows = extract_results(str(sarif_file), "owner/repo")
    assert len(rows) == 1
    row = rows[0]
    assert row["repo"] == "owner/repo"
    assert row["algo"] == "AES"
    assert row["api"] == "createCipher"
    assert row["artifactUri"] == "src/app.js"
    assert row["startLine"] == 10
    assert row["portfolio_name"] == "myportfolio"
    assert row["value_stream"] == "vs1"


def test_extract_results_multiple_entries_per_message(tmp_path):
    sarif_file = tmp_path / "owner__repo.sarif"
    _write_sarif(
        sarif_file, _minimal_sarif("algo=AES, api=encrypt\nalgo=SHA256, api=hash")
    )

    rows = extract_results(str(sarif_file), "owner/repo")
    assert len(rows) == 2
    algos = {r["algo"] for r in rows}
    assert algos == {"AES", "SHA256"}


def test_extract_results_empty_runs(tmp_path):
    sarif_file = tmp_path / "empty.sarif"
    _write_sarif(sarif_file, {"runs": []})
    rows = extract_results(str(sarif_file), "owner/repo")
    assert rows == []


def test_extract_results_missing_region_fields(tmp_path):
    sarif_file = tmp_path / "owner__repo.sarif"
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "message": {"text": "algo=RSA, api=sign"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "lib/crypto.js"},
                                    "region": {},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }
    _write_sarif(sarif_file, sarif)
    rows = extract_results(str(sarif_file), "owner/repo")
    assert len(rows) == 1
    assert rows[0]["startLine"] == ""
    assert rows[0]["endColumn"] == ""


def test_extract_results_no_properties(tmp_path):
    sarif_file = tmp_path / "owner__repo.sarif"
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "message": {"text": "algo=HMAC, api=createHmac"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "x.js"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }
    _write_sarif(sarif_file, sarif)
    rows = extract_results(str(sarif_file), "r")
    assert rows[0]["portfolio_name"] == ""
    assert rows[0]["value_stream"] == ""
