"""The kit's witness on your host (D709; mark's docs/platform/STOP-TEST-ANY-HOST-DESIGN.md, section 3 (c)): a small
program of the kit's, on the same host as your test copy and outside it, that sends the observer one beat a second, so
that a stop of your agent can be told from a host or a network that went down. While the witness keeps reaching the
observer through the window and your copy's paths fall silent, the host and its network stayed up and the stop acted on
the agent, as a process kill does. A stop that contains the host cuts the witness off too; then the evidence that the
host stayed up is your stop product's own record of the host's state (KH3).

You run it, as an ordinary user, with the file the kit wrote for it:

    python -m arvaken_stop_test_probe.witness stop-test-<run>-witness.json

**What it does, and leaves.** It refuses to run as root or as an administrator, and says so (the design's section 4).
It makes a folder of its own for the run, `arvaken-stop-test-<run>-witness`, where you start it, and runs from it; it
writes nothing in it or anywhere else, installs nothing and keeps no log. Each beat is one HTTPS POST to the observer's
`/witness`, with the run's witness key, which only the witness's file holds, and the beat's number; nothing else. It
stops when the observer answers 410 (the run is over), at the settings' `until`, or at Ctrl-C; then it removes its
folder, checks that it is gone, and names it if it could not.

It uses the probe's host module (host.py) for its settings, its pinned TLS and its POST, and the standard library alone.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from arvaken_stop_test_probe import core, host
from arvaken_stop_test_probe.core import NotTheKits

# What the witness says: each line approved by the founder, word for word (D709), as marked.
# CUSTOMER TEXT: approved by the founder, word for word, 00:32:06 UTC on 15 November 2026 (D709's words, batch 10,
# record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b)
NOT_AS_ROOT = "The kit's witness doesn't run as root or as an administrator. Run it as an ordinary user."
# CUSTOMER TEXT: approved by the founder, word for word, 00:32:06 UTC on 15 November 2026 (D709's words, batch 10,
# record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b)
NOT_ITS_FILE = "That isn't the witness's file for a run ({field}). Give the file the kit wrote for the witness."
# CUSTOMER TEXT: approved by the founder, word for word, 00:32:06 UTC on 15 November 2026 (D709's words, batch 10,
# record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b)
STARTED = ("The kit's witness for run {run} sends {observer} one beat a second. Leave it running until it says the run "
           "is over.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:32:06 UTC on 15 November 2026 (D709's words, batch 10,
# record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b)
FOLDER_IN_USE = "The folder {folder} is already here, so the witness didn't start. Remove it, then start again."
# CUSTOMER TEXT: approved by the founder, word for word, 00:32:06 UTC on 15 November 2026 (D709's words, batch 10,
# record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b)
ENDED = "The run is over. The witness has stopped and removed its folder, {folder}."
# CUSTOMER TEXT: approved by the founder, word for word, 00:32:06 UTC on 15 November 2026 (D709's words, batch 10,
# record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b)
LEFT = "The witness has stopped. Left for you to delete: {folder}"


def is_administrator() -> bool:
    """Whether this process runs as root, or on Windows as an administrator."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - where it can't be asked, the process is taken as not an administrator
        return False


def folder_for(run: str, where: Path) -> Path:
    return where / f"arvaken-stop-test-{run}-witness"


def beats(s: dict, post, clock=time, stopping=None) -> int:
    """One beat a second to the observer until it says the run is over, `until` passes, or `stopping` is set: the beats
    sent."""
    n, due = 0, clock.time()
    headers = {"User-Agent": core.AGENT, "Authorization": "Bearer " + s["key"], "Content-Type": "application/json"}
    while clock.time() < s["until"] and not (stopping is not None and stopping()):
        try:
            answer = post(f"{s['observer']}/witness", headers, json.dumps({"n": n}).encode(), core.TIMEOUT)
        except Exception:  # noqa: BLE001 - a beat that could not be sent is one the observer never hears
            answer = 0
        n, due = n + 1, due + host.EVERY
        if answer == host.OVER:
            break
        clock.sleep(max(0.0, due - clock.time()))
    return n


def remove(folder: Path) -> bool:
    """The witness's folder removed, and checked gone: whether it is."""
    shutil.rmtree(folder, ignore_errors=True)
    return not folder.exists()


def main(argv=None, post=None, clock=time, say=print, where=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if is_administrator():
        say(NOT_AS_ROOT)
        return 1
    try:
        s = host.witness_settings(args[0] if args else "")
    except NotTheKits as e:
        say(NOT_ITS_FILE.format(field=e.args[0]))
        return 1
    except (OSError, ValueError):
        say(NOT_ITS_FILE.format(field="file"))
        return 1
    start = Path.cwd() if where is None else where
    folder = folder_for(s["run"], start)
    try:
        folder.mkdir()
    except FileExistsError:
        say(FOLDER_IN_USE.format(folder=folder))
        return 1
    try:
        os.chdir(folder)
        say(STARTED.format(run=s["run"], observer=s["observer"]))
        beats(s, post or host.runtime_post(host.pinned(s["certificate"])), clock)
    except KeyboardInterrupt:
        pass
    finally:
        os.chdir(start)
        gone = remove(folder)
    say(ENDED.format(folder=folder) if gone else LEFT.format(folder=folder))
    return 0 if gone else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
