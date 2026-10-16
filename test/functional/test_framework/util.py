"""Assertions, waiting, ports and small helpers for the functional tests."""

from __future__ import annotations

import errno
import os
import socket
import time

from .authproxy import JSONRPCException

# Multiplies every timeout; set from --timeout-factor (slow or busy machines).
TIMEOUT_FACTOR = 1.0


class AssertionFailure(AssertionError):
    pass


def assert_equal(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionFailure(f"not equal: {a!r} != {b!r}{(' (' + msg + ')') if msg else ''}")


def assert_not_equal(a, b, msg: str = "") -> None:
    if a == b:
        raise AssertionFailure(f"unexpectedly equal: {a!r}{(' (' + msg + ')') if msg else ''}")


def assert_greater_than(a, b, msg: str = "") -> None:
    if not a > b:
        raise AssertionFailure(f"{a!r} is not > {b!r}{(' (' + msg + ')') if msg else ''}")


def assert_greater_than_or_equal(a, b, msg: str = "") -> None:
    if not a >= b:
        raise AssertionFailure(f"{a!r} is not >= {b!r}{(' (' + msg + ')') if msg else ''}")


def assert_true(cond, msg: str = "") -> None:
    if not cond:
        raise AssertionFailure(msg or "condition is false")


def assert_in(item, container, msg: str = "") -> None:
    if item not in container:
        raise AssertionFailure(f"{item!r} not in {container!r}{(' (' + msg + ')') if msg else ''}")


def assert_not_in(item, container, msg: str = "") -> None:
    if item in container:
        raise AssertionFailure(f"{item!r} unexpectedly in {container!r}{(' (' + msg + ')') if msg else ''}")


def assert_raises_rpc_error(message_substr: str | None, fun, *args, http_status: int | None = None,
                            code: int | None = None, **kwds) -> JSONRPCException:
    """Call `fun(*args)`; it must raise JSONRPCException whose message contains
    `message_substr` (case-insensitive) and, if given, has `http_status` /
    `code`. Returns the exception for further checks."""
    try:
        fun(*args, **kwds)
    except JSONRPCException as e:
        if message_substr is not None and message_substr.lower() not in e.message.lower():
            raise AssertionFailure(f"expected error containing {message_substr!r}, got {e.message!r}")
        if http_status is not None and e.http_status != http_status:
            raise AssertionFailure(f"expected HTTP {http_status}, got {e.http_status} ({e.message!r})")
        if code is not None and e.code != code:
            raise AssertionFailure(f"expected error code {code}, got {e.code} ({e.message!r})")
        return e
    raise AssertionFailure(f"no RPC error raised (expected {message_substr!r})")


def wait_until(predicate, *, timeout: float = 60, interval: float = 0.25, desc: str = "",
               deadline: float | None = None) -> None:
    """Poll `predicate()` until it returns a truthy value or `timeout` seconds
    (scaled by TIMEOUT_FACTOR) elapse. Exceptions from the predicate count as
    "not yet" until the deadline, then the last one is re-raised in the
    failure message. An optional absolute monotonic deadline caps the scaled
    timeout and is never scaled again. A late predicate result cannot pass;
    this synchronous helper cannot interrupt a predicate blocked in I/O."""
    started = time.monotonic()
    relative_deadline = started + timeout * TIMEOUT_FACTOR
    deadline = relative_deadline if deadline is None else min(deadline, relative_deadline)
    last_exc = None
    while time.monotonic() < deadline:
        ready = False
        try:
            ready = predicate()
            last_exc = None
        except AssertionError:
            raise
        except Exception as e:  # noqa: BLE001 - reported below
            last_exc = e
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if ready:
            return
        time.sleep(min(interval, remaining))
    what = desc or getattr(predicate, "__name__", "predicate")
    extra = f"; last error: {last_exc!r}" if last_exc else ""
    raise AssertionFailure(f"wait_until deadline reached after {time.monotonic() - started:.3f}s: {what}{extra}")


# ── Ports ────────────────────────────────────────────────────────────────────
#
# Every test process gets a port seed (test_runner passes --portseed; a
# standalone run uses its pid). Ports are taken from a per-seed window so
# parallel tests do not race for the same ports, and each candidate is bind-
# checked on loopback so a port held by an unrelated process is skipped.

PORT_MIN = 20000
PORT_WINDOW = 40
PORT_SLOTS = 600     # PORT_MIN + PORT_SLOTS * PORT_WINDOW < 45000 (below the ephemeral range)


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError as e:
            if e.errno in (errno.EADDRINUSE, errno.EACCES):
                return False
            raise
    return True


class PortAllocator:
    def __init__(self, seed: int):
        self.base = PORT_MIN + (seed % PORT_SLOTS) * PORT_WINDOW
        self.next = self.base
        self.taken: set[int] = set()

    def get(self) -> int:
        while self.next < self.base + PORT_WINDOW:
            p = self.next
            self.next += 1
            if p not in self.taken and _port_free(p):
                self.taken.add(p)
                return p
        raise RuntimeError(f"no free port left in window [{self.base}, {self.base + PORT_WINDOW})")


# ── Misc ─────────────────────────────────────────────────────────────────────

def satoshis(value) -> int:
    """RPC amounts are decimal strings of satoshis (R3); accept int too."""
    return int(value)


def tail(path: str, lines: int = 60) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 2 * 1024 * 1024))
            data = f.read().decode("utf-8", "replace")
    except OSError as e:
        return f"<cannot read {path}: {e}>"
    return "\n".join(data.splitlines()[-lines:])
