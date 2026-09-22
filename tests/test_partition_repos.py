"""Tests for scripts/partition_repos.py"""

import pytest

from scripts.partition_repos import greedy_partition

# ---------------------------------------------------------------------------
# greedy_partition
# ---------------------------------------------------------------------------


def test_greedy_partition_single_bucket():
    repos = [{"name": "a", "size": 100}, {"name": "b", "size": 200}]
    result = greedy_partition(repos, num_buckets=1)
    assert len(result) == 1
    assert set(result[0]) == {"a", "b"}


def test_greedy_partition_equal_repos_and_buckets():
    repos = [
        {"name": "a", "size": 10},
        {"name": "b", "size": 20},
        {"name": "c", "size": 30},
    ]
    result = greedy_partition(repos, num_buckets=3)
    assert len(result) == 3
    # Each bucket should have exactly one repo
    all_repos = [r for bucket in result for r in bucket]
    assert sorted(all_repos) == ["a", "b", "c"]


def test_greedy_partition_more_buckets_than_repos():
    repos = [{"name": "a", "size": 50}]
    result = greedy_partition(repos, num_buckets=5)
    assert len(result) == 5
    all_repos = [r for bucket in result for r in bucket]
    assert all_repos == ["a"]


def test_greedy_partition_empty_repos():
    result = greedy_partition([], num_buckets=3)
    assert result == [[], [], []]


def test_greedy_partition_balances_load():
    # Two repos of size 100 across 2 buckets → one each
    repos = [{"name": "a", "size": 100}, {"name": "b", "size": 100}]
    result = greedy_partition(repos, num_buckets=2)
    assert len(result) == 2
    assert len(result[0]) == 1
    assert len(result[1]) == 1


def test_greedy_partition_largest_first_placement():
    # Large repo (300) goes to one bucket; two small repos (100 each) should
    # end up in the other buckets so total sizes are 300, 100, 100 — not 300+100, 100.
    repos = [
        {"name": "big", "size": 300},
        {"name": "mid", "size": 100},
        {"name": "small", "size": 100},
    ]
    result = greedy_partition(repos, num_buckets=3)
    all_repos = [r for bucket in result for r in bucket]
    assert sorted(all_repos) == ["big", "mid", "small"]


def test_greedy_partition_all_repos_present():
    repos = [{"name": str(i), "size": i * 10} for i in range(1, 11)]
    result = greedy_partition(repos, num_buckets=4)
    all_repos = [r for bucket in result for r in bucket]
    assert sorted(all_repos) == sorted(r["name"] for r in repos)
