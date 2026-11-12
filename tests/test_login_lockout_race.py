"""Lockout holds under concurrent guesses (bug hunt authz F7).

``UserStore.authenticate`` used to check the lock, verify the password, and
only then count the failure. A burst of concurrent wrong guesses all passed the
lock check and each ran a full password verification, so the threshold did not
bound the number of guesses. The attempt is now reserved in the same locked
transaction as the lock check.
"""
from __future__ import annotations

import threading
import time

import pytest

from vecshield_platform.api import users as users_mod
from vecshield_platform.api.users import (
    AccountLockedError,
    InvalidCredentialsError,
    UserStore,
)

PW = "alice-initial-pw-1"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("VECSHIELD_LOGIN_MAX_ATTEMPTS", "VECSHIELD_LOGIN_LOCKOUT_MINUTES",
                 "VECSHIELD_INITIAL_ADMIN_PASSWORD"):
        monkeypatch.delenv(name, raising=False)


def _store_with_alice(max_attempts=5):
    store = UserStore(max_attempts=max_attempts, lockout_minutes=15)
    store.create_user("alice", PW, ["viewer"], created_by="admin")
    return store


def test_concurrent_wrong_guesses_are_bounded_by_max_attempts(monkeypatch):
    store = _store_with_alice(max_attempts=5)
    real = users_mod.verify_password
    checks = []
    lock = threading.Lock()

    def slow_verify(password, encoded):
        with lock:
            checks.append(password)
        time.sleep(0.05)  # keep every guess in flight together
        return real(password, encoded)

    monkeypatch.setattr(users_mod, "verify_password", slow_verify)
    barrier = threading.Barrier(40)
    outcomes = []

    def guess(i):
        barrier.wait()
        try:
            store.authenticate("alice", f"wrong-{i}")
        except (InvalidCredentialsError, AccountLockedError) as e:
            outcomes.append(type(e).__name__)

    threads = [threading.Thread(target=guess, args=(i,)) for i in range(40)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert len(outcomes) == 40
    assert len(checks) <= 5, f"{len(checks)} password checks ran for 5 allowed attempts"
    assert store.is_locked("alice")
    # The right password after the lock is refused, not accepted.
    with pytest.raises(AccountLockedError):
        store.authenticate("alice", PW)


def test_correct_guess_does_not_clear_a_lock_set_while_it_was_checked(monkeypatch):
    store = _store_with_alice(max_attempts=2)
    real = users_mod.verify_password
    started = threading.Event()
    release = threading.Event()

    def gated_verify(password, encoded):
        if password == PW:
            started.set()
            release.wait(5)
        return real(password, encoded)

    monkeypatch.setattr(users_mod, "verify_password", gated_verify)
    result = {}

    def right():
        try:
            store.authenticate("alice", PW)
            result["ok"] = True
        except AccountLockedError:
            result["ok"] = False

    t = threading.Thread(target=right)
    t.start()
    assert started.wait(5)
    # One more wrong guess reaches the threshold while the right one is checked.
    with pytest.raises(InvalidCredentialsError):
        store.authenticate("alice", "wrong")
    assert store.is_locked("alice")
    release.set()
    t.join()
    assert result["ok"] is False
    assert store.is_locked("alice")


def test_sequential_behaviour_is_unchanged():
    store = _store_with_alice(max_attempts=5)
    for _ in range(4):
        with pytest.raises(InvalidCredentialsError):
            store.authenticate("alice", "nope")
    # The fifth attempt, if right, still signs in and clears the count.
    assert store.authenticate("alice", PW).username == "alice"
    for _ in range(4):
        with pytest.raises(InvalidCredentialsError):
            store.authenticate("alice", "nope")
    assert not store.is_locked("alice")
    with pytest.raises(InvalidCredentialsError):
        store.authenticate("alice", "nope")
    assert store.is_locked("alice")


def test_disabled_account_right_password_does_not_consume_attempts():
    store = _store_with_alice(max_attempts=2)
    store.update_user("alice", disabled=True, actor=None)
    for _ in range(5):
        with pytest.raises(InvalidCredentialsError):
            store.authenticate("alice", PW)
    assert not store.is_locked("alice")
