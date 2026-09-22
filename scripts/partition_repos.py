"""
Partition organisation repos into N balanced buckets for parallel GitHub Actions runners.

This script:
1. Lists all non-archived, non-fork, non-template repos in the org above a minimum size.
2. Filters to repos that contain the target language (concurrently).
3. Fetches each repo's size (KB reported by GitHub API).
4. Uses greedy bin-packing (largest-first) to distribute repos across N runners
   so that the total size per runner is as balanced as possible.
5. Outputs a JSON matrix suitable for GitHub Actions.

Environment variables:
    GH_TOKEN            - GitHub token (used by gh CLI)
    ORG                 - GitHub organisation name
    TARGET_LANG         - python | java | javascript
    NUM_RUNNERS         - Number of runners/buckets (default: 20)
    MAX_REPOS           - Cap on total repos (0 = unlimited, default: 0)
    MIN_REPO_SIZE_KB    - Skip repos smaller than this (default: 50)
"""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_text(cmd):
    print("+", " ".join(cmd))
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            proc.stderr.strip() or proc.stdout.strip() or "command failed"
        )
    return proc.stdout


def list_org_repos(org: str, min_size_kb: int) -> list[dict]:
    """Return list of {name, size} for scannable repos in the org.

    Excludes: archived, forks, template repos, and repos below min_size_kb.
    """
    txt = run_text(
        [
            "gh",
            "api",
            f"orgs/{org}/repos",
            "--paginate",
            "-q",
            ".[] | select(.archived==false and .fork==false and .is_template==false)"
            " | {name: .name, size: .size}",
        ]
    )
    repos = []
    skipped_small = 0
    for line in txt.strip().splitlines():
        if line.strip():
            repo = json.loads(line)
            if repo["size"] < min_size_kb:
                skipped_small += 1
            else:
                repos.append(repo)
    if skipped_small:
        print(f"  Skipped {skipped_small} repos below {min_size_kb} KB")
    return repos


def filter_by_language(org: str, repos: list[dict], target_lang: str) -> list[dict]:
    """Keep only repos whose GitHub-detected languages include the target.

    Language API calls are made concurrently to minimise wall-clock time.
    """
    if target_lang == "python":
        lang_check = 'has("Python")'
    elif target_lang == "java":
        lang_check = 'has("Java") or has("Kotlin")'
    elif target_lang == "csharp":
        lang_check = 'has("C#")'
    else:
        lang_check = 'has("JavaScript") or has("TypeScript")'

    def check_one(repo: dict) -> tuple[dict, bool]:
        name = repo["name"]
        try:
            result = run_text(
                [
                    "gh",
                    "api",
                    f"repos/{org}/{name}/languages",
                    "-q",
                    lang_check,
                ]
            ).strip()
            return repo, result == "true"
        except Exception:
            return repo, False

    included: list[dict] = []
    # Use up to 10 threads — gh CLI is I/O-bound on API calls.
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(check_one, repo): repo for repo in repos}
        for future in as_completed(futures):
            repo, has_lang = future.result()
            name = repo["name"]
            if has_lang:
                included.append(repo)
                print(f"  {name}: size={repo['size']} KB  [included]")
            else:
                print(f"  {name}: [skipped, no {target_lang}]")

    # Re-sort by name so output is deterministic (as_completed order is arbitrary).
    included.sort(key=lambda r: r["name"])
    return included


def greedy_partition(repos: list[dict], num_buckets: int) -> list[list[str]]:
    """Distribute repos across buckets using greedy largest-first bin-packing.

    Each bucket gets the next-largest repo assigned to whichever bucket
    currently has the smallest total size.  This produces a well-balanced
    distribution even when repo sizes vary widely.
    """
    # Sort descending by size so the biggest repos get placed first.
    sorted_repos = sorted(repos, key=lambda r: r["size"], reverse=True)

    buckets: list[list[str]] = [[] for _ in range(num_buckets)]
    bucket_sizes: list[int] = [0] * num_buckets

    for repo in sorted_repos:
        # Find the bucket with the smallest total size.
        min_idx = bucket_sizes.index(min(bucket_sizes))
        buckets[min_idx].append(repo["name"])
        bucket_sizes[min_idx] += repo["size"]

    return buckets


def main():
    org = os.environ.get("ORG", "").strip()
    target_lang = os.environ.get("TARGET_LANG", "").strip().lower()
    num_runners = int(os.environ.get("NUM_RUNNERS", "20"))
    max_repos = int(os.environ.get("MAX_REPOS", "0"))
    min_size_kb = int(os.environ.get("MIN_REPO_SIZE_KB", "50"))

    if not org:
        print("Missing ORG", file=sys.stderr)
        return 2
    if target_lang not in ("python", "java", "javascript", "csharp"):
        print("TARGET_LANG must be python|java|javascript|csharp", file=sys.stderr)
        return 2

    print(
        f"Listing repos for org={org}, lang={target_lang}, runners={num_runners}, min_size={min_size_kb} KB"
    )
    all_repos = list_org_repos(org, min_size_kb)
    print(f"  Total scannable repos: {len(all_repos)}")

    if max_repos > 0:
        all_repos = all_repos[:max_repos]

    print("Filtering by language...")
    lang_repos = filter_by_language(org, all_repos, target_lang)
    print(f"  Repos with {target_lang}: {len(lang_repos)}")

    if not lang_repos:
        print("No repos found. Outputting empty matrix.")
        matrix = {"include": []}
        output_matrix(matrix)
        return 0

    # Don't create more buckets than repos.
    actual_runners = min(num_runners, len(lang_repos))
    buckets = greedy_partition(lang_repos, actual_runners)

    # Build the GitHub Actions matrix.  Each entry is a runner with its repo list.
    include = []
    for i, bucket in enumerate(buckets):
        if bucket:  # skip empty buckets
            include.append(
                {
                    "runner_index": i,
                    "repo_names": json.dumps(bucket),  # JSON array as a string
                }
            )

    matrix = {"include": include}

    # Print summary.
    print(f"\nPartition into {len(include)} runners:")
    size_lookup = {r["name"]: r["size"] for r in lang_repos}
    for entry in include:
        names = json.loads(entry["repo_names"])
        total = sum(size_lookup.get(n, 0) for n in names)
        print(
            f"  Runner {entry['runner_index']}: {len(names)} repos, ~{total} KB total"
        )

    output_matrix(matrix)
    return 0


def output_matrix(matrix: dict):
    """Write the matrix JSON to $GITHUB_OUTPUT or stdout."""
    matrix_json = json.dumps(matrix, separators=(",", ":"))

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"matrix={matrix_json}\n")
        print(
            f"\nWrote matrix to $GITHUB_OUTPUT ({len(matrix.get('include', []))} runners)"
        )
    else:
        print(f"\nmatrix={matrix_json}")


if __name__ == "__main__":
    raise SystemExit(main())
