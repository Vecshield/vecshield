"""Tests for config store concurrency & multi-worker safety (improvement plan
1.8): advisory file locking around read-modify-write so concurrent writers do
not lose updates, plus round-trip and in-memory behaviour."""

from __future__ import annotations

import threading

from vecshield_platform.api.config_store import ConfigStore


def _store(path):
    return ConfigStore(path=str(path))


# --------------------------------------------------------------------------- #
# Round-trip / persistence                                                    #
# --------------------------------------------------------------------------- #

def test_save_load_round_trip(tmp_path):
    cfg = _store(tmp_path / "cfg.json")
    cfg.add_store("s1", "chroma", conn={"path": "/tmp/a"})
    cfg.add_policy(name="p", description="", when="always", action="alert",
                   severity="high")
    cfg.set_alerting(enabled=True, min_severity="high")

    reloaded = _store(tmp_path / "cfg.json")
    assert set(reloaded.stores) == {"s1"}
    assert len(reloaded.policies) == 1
    assert reloaded.alerting.enabled is True
    assert reloaded.alerting.min_severity == "high"


def test_in_memory_store_has_no_file(tmp_path):
    cfg = ConfigStore(path=None)
    cfg.add_store("s1", "chroma", conn={"path": "/tmp/a"})
    assert "s1" in cfg.stores
    # No path => nothing written anywhere.
    assert list(tmp_path.iterdir()) == []


def test_separate_instance_sees_prior_writes(tmp_path):
    a = _store(tmp_path / "cfg.json")
    a.add_store("s1", "chroma", conn={"path": "/tmp/a"})

    b = _store(tmp_path / "cfg.json")
    b.add_store("s2", "chroma", conn={"path": "/tmp/b"})

    # A mutating again must not clobber s2 written by B: the locked
    # read-modify-write reloads fresh on-disk state first.
    a.add_store("s3", "chroma", conn={"path": "/tmp/c"})

    final = _store(tmp_path / "cfg.json")
    assert set(final.stores) == {"s1", "s2", "s3"}


# --------------------------------------------------------------------------- #
# Concurrency                                                                 #
# --------------------------------------------------------------------------- #

def test_concurrent_add_store_no_lost_updates(tmp_path):
    path = tmp_path / "cfg.json"
    # Seed the file so every instance loads a real store list.
    _store(path).add_store("seed", "chroma", conn={"path": "/tmp/seed"})

    n = 12
    errors: list[Exception] = []
    barrier = threading.Barrier(n)

    def worker(i: int) -> None:
        try:
            cfg = _store(path)
            barrier.wait()  # maximize contention
            cfg.add_store(f"s{i}", "chroma", conn={"path": f"/tmp/{i}"})
        except Exception as e:  # pragma: no cover - surfaced via assert
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    final = _store(path)
    expected = {"seed"} | {f"s{i}" for i in range(n)}
    assert set(final.stores) == expected


def test_concurrent_writers_same_instance(tmp_path):
    cfg = _store(tmp_path / "cfg.json")
    n = 20
    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            cfg.add_policy(name=f"p{i}", description="", when="always",
                           action="alert", severity="high")
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(cfg.policies) == n
    assert len(_store(tmp_path / "cfg.json").policies) == n
