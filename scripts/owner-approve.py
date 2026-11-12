#!/usr/bin/env python3
"""Drive `zbrain claim approve` through the real owner ceremony.

The owner ceremony needs an interactive terminal: the binary checks that stdin
is a TTY, prints the action digest on stderr, and reads the last 16 hex
characters of that digest from the terminal without echo. A script has no
terminal, so this driver allocates one (a pty), attaches it to the child's
stdin and stdout, answers the prompt with the digest suffix, and forwards the
child's output and exit code.

Nothing is bypassed. A binary that refuses without a TTY still refuses; a
binary that does not prompt at all (an older build) is passed through
unchanged, so the same driver works before and after the ceremony gate.

Usage:
    scripts/owner-approve.py [--bin PATH] <claim-id> [--workspace <name>]

`--bin` defaults to $ZBRAIN_BIN, then `zbrain` on PATH.
"""

import argparse
import os
import pty
import select
import subprocess
import sys
import time

PROMPT = b"confirm the last 16 hex characters of the action digest:"
DIGEST_PREFIX = b"action digest:"
TIMEOUT_SECONDS = 120


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Approve a zbrain claim through the real owner ceremony."
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("ZBRAIN_BIN", "zbrain"),
        help="zbrain binary to drive (default: $ZBRAIN_BIN or zbrain)",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="arguments passed to `zbrain claim approve`",
    )
    parsed = parser.parse_args(argv)
    args = parsed.args
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        parser.error("a claim id is required")
    return parsed.bin, args


def digest_suffix(stderr):
    """Last `action digest:` line on stderr, or None before it is printed.

    The prompt text also contains "action digest: ", so the digest is the last
    line that starts with the label, never the text after the label's last
    occurrence anywhere in the stream.
    """
    lines = [line for line in stderr.splitlines() if line.startswith(DIGEST_PREFIX)]
    if not lines:
        return None
    digest = lines[-1][len(DIGEST_PREFIX) :].strip().decode("utf-8", "replace")
    return digest[-16:]


def drive(binary, args):
    master, slave = pty.openpty()
    child = subprocess.Popen(
        [binary, "claim", "approve", *args],
        stdin=slave,
        stdout=slave,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    os.close(slave)

    stdout = b""
    stderr = b""
    answered = False
    deadline = time.monotonic() + TIMEOUT_SECONDS
    streams = {master: False, child.stderr.fileno(): True}
    while streams and time.monotonic() < deadline:
        ready, _, _ = select.select(list(streams), [], [], 1.0)
        for fd in ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                streams.pop(fd, None)
                continue
            if not streams[fd]:
                stdout += chunk
                continue
            stderr += chunk
            if answered or PROMPT not in stderr:
                continue
            suffix = digest_suffix(stderr)
            if suffix is None:
                continue
            os.write(master, (suffix + "\n").encode())
            answered = True

    if streams:
        child.kill()
        child.wait()
        os.close(master)
        sys.stderr.write("owner-approve: timed out waiting for the ceremony\n")
        return 1

    code = child.wait()
    try:
        os.close(master)
    except OSError:
        pass
    sys.stdout.buffer.write(stdout.replace(b"\r\n", b"\n"))
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()
    return code


def main(argv):
    binary, args = parse_args(argv)
    return drive(binary, args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
