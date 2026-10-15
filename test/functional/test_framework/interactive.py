"""Run a program on a pseudo-terminal and answer its prompts.

`gnb-cli` reads passwords with rpassword, which opens /dev/tty, so piping
stdin is not enough: the child needs a controlling terminal. `pty.fork()`
gives it one (the child is a session leader whose controlling terminal is the
pty), exactly what a user at a terminal provides.
"""

from __future__ import annotations

import os
import pty
import select
import time


class InteractiveError(RuntimeError):
    pass


def run_with_answers(argv: list, answers: list, *, env: dict | None = None, timeout: float = 120,
                     cwd: str | None = None) -> tuple[int, str]:
    """Run `argv` on a pty. `answers` is a list of (prompt_substring, reply):
    each reply (plus newline) is written once its prompt has appeared in the
    output, in order. Returns (exit_code, full output). Raises
    InteractiveError on timeout (the child is killed)."""
    pid, fd = pty.fork()
    if pid == 0:  # child
        try:
            if cwd:
                os.chdir(cwd)
            os.execvpe(argv[0], argv, env if env is not None else os.environ)
        finally:
            os._exit(127)

    output = b""
    pending = list(answers)
    scanned = 0  # output offset after the last matched prompt
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InteractiveError(f"timeout after {timeout}s running {argv[:2]}; output so far:\n"
                                       + output.decode("utf-8", "replace")[-4000:])
            r, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if fd in r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:  # EIO: the child closed the terminal
                    chunk = b""
                if not chunk:
                    break
                output += chunk
            while pending:
                prompt, reply = pending[0]
                idx = output.find(prompt.encode(), scanned)
                if idx < 0:
                    break
                scanned = idx + len(prompt)
                os.write(fd, reply.encode() + b"\n")
                pending.pop(0)
        _, status = os.waitpid(pid, 0)
        pid = 0
    finally:
        if pid:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except OSError:
                pass
        os.close(fd)
    code = os.waitstatus_to_exitcode(status)
    return code, output.decode("utf-8", "replace").replace("\r\n", "\n")
