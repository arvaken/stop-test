"""A run on a test copy of your agent on a host you control (D709; mark's docs/platform/STOP-TEST-ANY-HOST-DESIGN.md,
sections 1 to 5, with KH1 to KH8 as the founder approved them, and D722's ruling on the firing moment).

**Who does what.** You deploy the copy on your host with the kit's probe in it, and start the kit's witness beside it,
outside the copy; the kit never deploys, changes or deletes either, and never touches the probe you added (D575,
section 4). The kit runs on a second machine you control, never the agent's host, and runs the observer there, in its
own process (observer.py; KH5). You fire the stop, always: on a host there is no cloud stop for the kit to fire (the
design's section 1). Before every firing the kit gives D575's warning (KC4) and asks you to type the run's name; then
"Press Enter, then fire your stop." Arvaken's runner reads nothing on your host, and nothing is sent to Arvaken: your
host's calls reach only the observer.

**The run** (`run`):
1. Before anything is made, you confirm by typing the run's name that the copy is a test copy (the kit's terms, 2.1),
   and, with the model path on, that its key was made for this test (section 4: the kit can't tell a test key from a
   production one).
2. The kit makes the run's folder, `arvaken-stop-test-<run>`, where you run it, and everything of the run's in it: the
   run's key and the witness's (each made for the run), the observer's certificate and its key, and two settings
   files, one for the probe and one for the witness, which you copy to your host. The keyed path's key is made by the
   kit and dies with the run: the observer, which alone checks it, stops when the run ends.
3. The observer starts, and the kit waits until each path and the witness reach it through 30 seconds (READY_LIMIT, then
   with what reaches it; WAIT_LIMIT, then nothing is timed).
4. Each repeat: the warning and the run's name; your mark; the window, set before the run and at least 15 minutes; then
   your stop product's record of acting (the entry's time and name, and the export's SHA-256, never the file: KH6), and,
   where the witness fell silent in the window, its record of your host's state. Between repeats you undo your stop, and
   the kit waits for your copy's calls to reach it again.
5. The observer answers 410, which ends the probe's and the witness's beats, and stops. Each path of each repeat is
   judged by the rule for host stops (rule.py), the observer's arrivals are signed with its own key, and the result is
   built and signed (`the_result`).
6. The run's folder is removed and checked gone; anything that could not be is named. The kit, like the witness,
   refuses to run as root or as an administrator, installs nothing and leaves nothing but the files it writes where you
   ran it: the result, its details and the observer's arrivals. They are written there, outside the run's folder, so
   that they outlast the teardown, which names them (cli.py's HOST_KEPT), as every other mode of the kit writes its
   result (point 4 below).

**The founder's five points on this build**, each approved as recommended at 23:54:13 UTC on 14 November 2026 ("Approve
all five (Recommended)", record 739f7db3-ecd6-4c62-8dd2-e6ef487e65a1):
1. every host stop is timed from your mark, with the product's record kept beside it as evidence (rule.py);
2. **the cloud path** of the design's section 2 (KH7) is not in this build: it needs an identity the kit makes in your
   cloud account for the run, and comes later as its own step, with its permission policy brought to the founder
   first. The model path is (KH7): off unless you name `--model`, and then through a function of yours, with a key you
   made at your provider for the run;
3. the stop is host software's alone, ending the agent's process or containing the host (result.HOST_STOPS); an SDK's
   switch and a gateway on the host's way out come later, as their own step;
4. the result is written where the kit runs, and the teardown names it;
5. one export from your stop product gives both entries of your host's state, contained and still contained
   (`take_state`).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arvaken_stop_test import result, sdk
from arvaken_stop_test.host import rule
from arvaken_stop_test.host.observer import Observer
from arvaken_stop_test.host.rule import HostFound, HostState, HostUp
from arvaken_stop_test.sdk import Record

PREFIX = "arvaken-stop-test"
RUN = re.compile(r"r[0-9a-f]{8}")       # a run's name, as the kit's other modes make one (the probe's core.RUN)
MARKER = "arvaken_stop_test"            # the settings files' marker, as the probe reads it (the probe's core.MARKER)
POLL = 1.0                              # seconds between the kit's looks at the observer while it waits
READY_LIMIT = 120.0                     # after this long, the kit goes on with the paths that reach it, and the witness
WAIT_LIMIT = 30 * 60.0                  # after this long with no path and witness reaching it, nothing is timed
LIFE_HOURS = 8.0                        # how long the probe and the witness may beat, and the certificate lasts
LONGEST_WINDOW = 60 * 60.0              # a window is 15 to 60 minutes, so five repeats end within the probe's life
MARGIN = 10 * 60.0                      # a repeat starts only where its window ends this long before the probe's life
OBSERVED = ("outside_key", "open_internet")

# What the run says: each line approved by the founder, word for word, with the build (D709), as marked.
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; section 4)
NOT_AS_ROOT = "The kit doesn't run as root or as an administrator. Run it as an ordinary user."
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; the kit's terms 2.1, as D575's copy has it)
CONFIRM_COPY = ("The kit will time {copy} on your host {host} from this machine, at {observer}, and you fire your stop "
                "yourself, after your mark. Your copy runs its own code, which does whatever that code does with "
                "whatever its settings reach: databases, email, payments, other services. Run it only on a test copy "
                "whose settings reach test systems alone, never on an agent whose work matters. Type the run's name, "
                "{run}, to confirm {copy} is a test copy.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; section 4, KH7)
CONFIRM_MODEL_KEY = ("With --model, your copy's probe calls {provider} through the function you pass it. That call must "
                     "use a key you made at your provider for this test alone, which you revoke after it: the kit can't "
                     "tell a test key from a production one. Type the run's name, {run}, to confirm the key was made "
                     "for this test.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (4))
NOT_CONFIRMED = "The run's name was not typed, so nothing was made."
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f)
FOLDER_IN_USE = ("The folder {folder} is already here, so nothing was made. Remove it, or run `stop-test host clean --run "
                 "{run}`.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f)
START = ("The run's settings are in {folder}. On your host {host}:\n"
         "- give your test copy {probe}, and start it with the probe: heartbeat.on_host(\"{probe_name}\");\n"
         "- put {witness} on your host, outside your copy, and start the kit's witness there as an ordinary user:\n"
         "  python -m arvaken_stop_test_probe.witness {witness_name}\n"
         "The kit waits until your copy's calls and the witness's beats reach this machine.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f)
READY = "Your host reaches this machine: {paths}, and the kit's witness."
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f)
NOT_READY = ("Your copy's calls and the kit's witness didn't both reach this machine within {minutes} minutes, so "
             "nothing was timed.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f)
AGAIN = ("For repeat {n}, undo your stop, and start your copy again if it ended. The kit waits until your copy's calls "
         "and the witness's beats reach this machine again.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 5,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f)
LIFE_ENDS = "The run's settings end at {time}, before this repeat's window would, so it wasn't timed."
# CUSTOMER TEXT: approved by the founder, word for word, 00:42:35 UTC on 2 November 2026 (step 4, batch 1 (8))
NOT_FIRED = "The run's name was not typed, so the stop was not fired."
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 6,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; the SDK's approved line, SDK_MARKED, for a host)
MARKED = ("Marked. Each path is timed from your mark, by this machine's clock, so a time errs toward slower, never "
          "faster. Your stop product's record of acting is kept beside the result, as you enter it.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 6,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; the SDK's approved line, SDK_SWITCH_OFF, for a host)
TIMING_DONE = "The timing is done: you can undo your stop now. The kit never undoes it itself."
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 6,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; section 3 (b), KH6; the SDK's approved SDK_EXPORT, for a host)
EXPORT = ("Name the file you exported from your stop product that records it acting on your host. The kit reads it to "
          "check that the entry you name is in it, and to take its SHA-256. It keeps only the SHA-256 and the entry "
          "you name, never the file. Keep the file yourself: its SHA-256 lets you show later that it's the same file:")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 6,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; section 3 (c), KH3)
STATE_EXPORT = ("The kit's witness fell silent at {time}. If your stop contains your host, name the file you exported "
                "from your stop product that records your host's state through the window, or press Enter to give "
                "none. The kit keeps only its SHA-256 and the entries you name, never the file:")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 6,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; section 3 (c))
STATE_CONTAINED = ("The time of the entry in it that shows your host contained, when your stop took hold, exactly as "
                   "the file writes it, with its time zone:")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 6,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; section 3 (c))
STATE_STILL = ("The time of the entry in it that shows your host still contained at the window's end, {end}, or later, "
               "exactly as the file writes it, with its time zone:")
# CUSTOMER TEXT: approved by the founder, word for word, 00:28:55 UTC on 15 November 2026 (D709's words, batch 6,
# record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f; the SDK's approved RECORD_BEFORE_MARK, for a host)
RECORD_BEFORE_MARK = ("The time you entered for your stop product's record is before your mark, so no path reads "
                      "stopped, as seen from outside the host. Check that you entered the right entry, and that your "
                      "product's clock keeps the right time, then run again.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:30:57 UTC on 15 November 2026 (D709's words, batch 7,
# record 7903a000-560a-48bb-af8b-35c7032b3d6e)
HOST_LEFT = ("On your host, the witness removes its own folder when it stops, and says so. The probe in your copy is "
             "yours, and the kit never touches it.")
# CUSTOMER TEXT: approved by the founder, word for word, 00:30:57 UTC on 15 November 2026 (D709's words, batch 7,
# record 7903a000-560a-48bb-af8b-35c7032b3d6e; D561 and PC3, section 5)
PRODUCT_AS_NAMED = "The product as you named it. This is your own test, not Arvaken's rating of it."
# The path's names, as the run and its plan say them.
# CUSTOMER TEXT: approved by the founder, word for word, 00:30:57 UTC on 15 November 2026 (D709's words, batch 7,
# record 7903a000-560a-48bb-af8b-35c7032b3d6e; section 2's table)
PATH_WORDS = {"outside_key": "calls out with a key", "open_internet": "the open internet", "model": "calls to a model"}


class NotStarted(Exception):
    """A run that ended before anything was timed: why was said as it happened; its record, its folder removed."""

    def __init__(self, r: "HostRun"):
        super().__init__("not started")
        self.run = r


@dataclass
class Repeat:
    """One repeat: its mark by the observer's clock (None where the stop was not fired), your stop product's record of
    acting, the host's state where you gave it, (c) as read, and each path's finding."""
    mark_at: float | None = None
    record: Record | None = None
    state: HostState | None = None
    up: HostUp | None = None
    found: dict[str, HostFound] = field(default_factory=dict)


@dataclass
class HostRun:
    run: str
    copy: str
    host: str
    observer: str                   # the address the host reaches this machine at, as you gave it ("host:port")
    stop_said: str                  # result.HOST_STOPS's words
    product: str                    # your stop product's name, as you gave it
    os: str
    container: bool
    window: float
    repeats_wanted: int
    model: str = ""                 # your model provider's name, as you gave it, where the model path is on
    folder: Path = Path(".")
    began_at: float = 0.0
    ended_at: float = 0.0
    paths: tuple[str, ...] = ()
    repeats: list[Repeat] = field(default_factory=list)
    left_behind: list[str] = field(default_factory=list)
    arrivals: dict | None = None    # the observer's arrivals, signed
    observer_key: str = ""          # its key's public half
    source: str | None = None       # the address your host's calls came from, as the observer saw it
    http: str = result.CLIENTS[1]   # whose client the probe used for its calls to the observer
    calls: int = 0
    failures: dict[str, list[dict]] = field(default_factory=dict)
    refused_keys: int = 0


class Clock:
    """This machine's clock, which the observer reads too."""

    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(max(0.0, seconds))


def is_administrator() -> bool:
    """Whether this process runs as root, or on Windows as an administrator (as the probe's witness asks it)."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - where it can't be asked, the process is taken as not an administrator
        return False


def folder_for(run: str, where: Path) -> Path:
    return where / f"{PREFIX}-{run}"


def new_run() -> str:
    return "r" + secrets.token_hex(4)


def settings_files(r: HostRun, key: str, witness_key: str, url: str, certificate: str, until: float) -> dict[str, dict]:
    """The probe's and the witness's settings, as their files hold them (the probe's host.settings reads them): each
    names the run, the observer's address and certificate, and until when it may beat; the probe's holds the run's key
    and whether the model path is on, the witness's its own key."""
    common = {"observer": url, "certificate": certificate, "until": until}
    return {f"stop-test-{r.run}-probe.json": {MARKER: {"run": r.run, "key": key,
                                                         "host": {**common, "model": bool(r.model)}}},
            f"stop-test-{r.run}-witness.json": {MARKER: {"run": r.run, "witness_key": witness_key, "host": common}}}


def _ready(o: Any, paths: tuple[str, ...], now: float) -> tuple[tuple[str, ...], bool]:
    """The paths whose calls reached the observer through the last 30 seconds, and whether the witness's did."""
    return (tuple(p for p in paths if rule.worked_before(o.arrivals(p), now)),
            rule.worked_before(o.witness(), now))


def wait_ready(o: Any, paths: tuple[str, ...], clock: Any, limit: float = WAIT_LIMIT) -> tuple[str, ...] | None:
    """Until every path and the witness reach the observer through 30 seconds: the paths that do. After READY_LIMIT,
    those that do with the witness, where at least one does; after `limit`, None."""
    start = clock.now()
    while True:
        now = clock.now()
        ready, witness = _ready(o, paths, now)
        if witness and len(ready) == len(paths):
            return ready
        if witness and ready and now - start >= READY_LIMIT:
            return ready
        if now - start >= limit:
            return None
        clock.sleep(POLL)


def take_entry(ask: Callable[[str], str], time_words: str) -> tuple[str, str] | None:
    """An entry's time and name as you type them, each as Arvaken's record keeps it (sdk.time_fits; a name never an
    email address), asked once more where it isn't; None where it still isn't."""
    from arvaken_stop_test.aws.your_copy import EMAIL, NAME_HOLDS_EMAIL, SDK_ENTRY_NAME, TIME_DOES_NOT_FIT
    when = ask(time_words).strip()
    if not sdk.time_fits(when):
        when = ask(TIME_DOES_NOT_FIT).strip()
        if not sdk.time_fits(when):
            return None
    name = ask(SDK_ENTRY_NAME).strip()
    if EMAIL.search(name):
        name = ask(NAME_HOLDS_EMAIL).strip()
        if EMAIL.search(name):
            return None
    return (when, name) if 0 < len(name) <= result.NAME_LIMIT else None


def take_record(ask: Callable[[str], str], read: Callable[[str], bytes]) -> Record | None:
    """Your stop product's record of acting ((b), KH1, KH6): the export you name, read only to find the entry and take
    its SHA-256, and the entry's time and name as you type them. A file the kit cannot read is no record."""
    from arvaken_stop_test.aws.your_copy import SDK_ENTRY_TIME
    where = ask(EXPORT).strip()
    if not where:
        return None
    try:
        export = read(where)
    except Exception:  # noqa: BLE001 - no record: the paths read not measured, and say so
        return None
    entry = take_entry(ask, SDK_ENTRY_TIME)
    return sdk.record(export, *entry) if entry else None


def take_state(ask: Callable[[str], str], read: Callable[[str], bytes], silent_at: float,
               end: float) -> HostState | None:
    """Your stop product's record of your host's state through the window ((c), KH3), asked only where the witness fell
    silent: the export you name, and two entries' times and names, the host contained when your stop took hold and
    still contained at the window's end (one export, both entries: point 5 of the founder's record 739f7db3, 23:54:13
    UTC on 14 November 2026). None where you give none."""
    where = ask(STATE_EXPORT.format(time=rule._clock(silent_at))).strip()
    if not where:
        return None
    try:
        export = read(where)
    except Exception:  # noqa: BLE001 - no record of the host's state
        return None
    contained = take_entry(ask, STATE_CONTAINED)
    still = take_entry(ask, STATE_STILL.format(end=rule._clock(end))) if contained else None
    if not (contained and still):
        return None
    return HostState(sdk.record(export, *contained), sdk.record(export, *still))


def run(r: HostRun, *, ask: Callable[[str], str], say: Callable[[str], None], clock: Any = None,
        observe: Callable[..., Any] | None = None, read: Callable[[str], bytes] = lambda p: Path(p).read_bytes(),
        where: Path | None = None) -> HostRun:
    """The run, as the module's docstring has it: `ask` asks you and gives back your answer; `observe` makes the
    observer (Observer). NotStarted where nothing was timed; a run whose later repeat was not fired keeps what it timed
    before."""
    from arvaken_stop_test.aws.run import MARK_PROMPT
    from arvaken_stop_test.aws.your_copy import WARNING
    clock = clock or Clock()
    observe = observe or Observer
    host, port = _split(r.observer)
    if ask(CONFIRM_COPY.format(copy=r.copy, host=r.host, observer=r.observer, run=r.run)).strip() != r.run or \
            (r.model and ask(CONFIRM_MODEL_KEY.format(provider=r.model, run=r.run)).strip() != r.run):
        say(NOT_CONFIRMED)
        raise NotStarted(r)
    r.folder = folder_for(r.run, Path.cwd() if where is None else where)
    try:
        r.folder.mkdir()
    except FileExistsError:
        say(FOLDER_IN_USE.format(folder=r.folder, run=r.run))
        raise NotStarted(r) from None
    r.paths = (*OBSERVED, *((rule.MODEL,) if r.model else ()))
    key, witness_key = secrets.token_hex(16), secrets.token_hex(16)
    o = None
    try:
        o = observe(r.run, key, witness_key, host, port, r.folder, LIFE_HOURS)
        o.start()
        r.began_at = clock.now()
        until = r.began_at + LIFE_HOURS * 3600
        files = settings_files(r, key, witness_key, o.url(), o.certificate, until)
        for name, doc in files.items():
            (r.folder / name).write_text(json.dumps(doc, indent=1), encoding="utf-8", newline="\n")
        probe_name, witness_name = list(files)
        say(START.format(folder=r.folder, host=r.host, probe=r.folder / probe_name, probe_name=probe_name,
                         witness=r.folder / witness_name, witness_name=witness_name))
        working = wait_ready(o, r.paths, clock)
        if working is None:
            say(NOT_READY.format(minutes=int(WAIT_LIMIT // 60)))
            raise NotStarted(r)
        say(READY.format(paths=", ".join(PATH_WORDS[p] for p in working)))
        for i in range(r.repeats_wanted):
            if i and wait_ready(o, working, clock) is None:
                say(NOT_READY.format(minutes=int(WAIT_LIMIT // 60)))
                break
            if clock.now() + r.window + MARGIN > until:
                say(LIFE_ENDS.format(time=rule._clock(until)))
                break
            if ask(WARNING).strip() != r.run:
                say(NOT_FIRED)
                break
            ask(MARK_PROMPT)
            rep = Repeat(mark_at=clock.now())
            r.repeats.append(rep)
            say(MARKED)
            clock.sleep(rep.mark_at + r.window - clock.now())
            say(TIMING_DONE)
            rep.record = take_record(ask, read)
            if rule.before_the_mark(rep.record, rep.mark_at):
                say(RECORD_BEFORE_MARK)
            end = rep.mark_at + r.window
            quiet = rule.silent_from(o.witness(), rep.mark_at, end)
            rep.state = take_state(ask, read, quiet, end) if quiet is not None else None
            if i + 1 < r.repeats_wanted:
                say(AGAIN.format(n=i + 2))
        if not r.repeats:
            raise NotStarted(r)
    except BaseException:           # NotStarted, an error, or Ctrl-C: the observer closed and the folder removed first
        _tear_down(r, o, clock)
        raise
    _tear_down(r, o, clock)
    for rep in r.repeats:
        _judge(r, rep, o)
    r.ended_at = clock.now()
    return r


def _split(address: str) -> tuple[str, int]:
    from arvaken_stop_test.host.observer import address as parse
    found = parse(address)
    if found is None:
        raise ValueError(address)
    return found


def _judge(r: HostRun, rep: Repeat, o: Any) -> None:
    """Each path of a repeat by the rule for host stops: (c) read once for the repeat, then each path by its arrivals,
    the model's by the reports that say its call worked, beside every report's arrival."""
    rep.up = rule.host_up(o.witness(), rep.state, rep.mark_at, r.window)
    for p in r.paths:
        rep.found[p] = rule.judge(o.arrivals(p), mark_at=rep.mark_at, window=r.window, record=rep.record, up=rep.up,
                                  reports=o.reports() if p == rule.MODEL else None)


def _tear_down(r: HostRun, o: Any, clock: Any) -> None:
    """The observer closed (410, then stopped), what it saw kept, and the run's folder removed and checked gone."""
    if o is not None:
        try:
            o.close(wait=clock.sleep)
        finally:
            r.arrivals, r.observer_key = o.signed()
            r.source, r.http, r.calls = o.source(), o.http_client(), o.calls()
            r.refused_keys = o.refused_keys
            r.failures = {p: o.failures(p) for p in r.paths}
    shutil.rmtree(r.folder, ignore_errors=True)
    if r.folder.exists():
        r.left_behind.append(str(r.folder))


def clean(run_name: str, where: Path) -> list[str]:
    """An interrupted run's folder removed and checked gone: what is left."""
    folder = folder_for(run_name, where)
    shutil.rmtree(folder, ignore_errors=True)
    return [str(folder)] if folder.exists() else []


def arrivals_bytes(r: HostRun) -> bytes:
    """The observer's signed arrivals, exactly as the kit writes them: their SHA-256 is the result's."""
    return (json.dumps(r.arrivals, indent=1, sort_keys=True) + "\n").encode("utf-8")


def _part(found: HostFound, mark_at: float | None) -> dict[str, Any]:
    return {"fired_at": result.iso(mark_at), "last_success_after": result.iso(found.last_arrival_after),
            "first_refused_after": None, "outcome": found.outcome, "timed_from": result.TIMED_FROM[0],
            "rule": rule.RULE, "silent_from": result.iso(found.silent_from)}


def _evidence(rep: Repeat) -> dict[str, Any]:
    rec, up, state = rep.record, rep.up, rep.state
    return {"product": None if rec is None else {
                "time": rec.time, "entered_by_you": True,
                "before_mark": rule.before_the_mark(rec, rep.mark_at) if rep.mark_at is not None else False,
                "name": rec.name, "sha256": rec.sha256},
            "host_up": {"by": up.by if up is not None else None,
                        "witness_silent_from": result.iso(up.witness_silent_from) if up is not None and
                        up.by != rule.BY_WITNESS else None,
                        "state": None if state is None or up is None or up.by != rule.BY_STATE else {
                            "from": state.contained.time, "from_name": state.contained.name,
                            "until": state.still.time, "until_name": state.still.name,
                            "sha256": state.contained.sha256}}}


def the_result(r: HostRun, tools: list[str], model_kind: str, key=None) -> tuple[dict, dict, bytes]:
    """The run's result, a stop-test-result/3 of a host (result.SHAPE_HOST), signed with a key made for it; its
    details; and the observer's signed arrivals, as written, whose SHA-256 the result holds."""
    from arvaken_stop_test import __version__
    written = arrivals_bytes(r)
    doc: dict[str, Any] = {
        "format": result.FORMAT_V3, "kit": {"version": __version__}, "cloud": result.HOST, "region": None,
        "run": {"began_at": result.iso(r.began_at), "ended_at": result.iso(r.ended_at),
                "window_seconds": int(r.window), "repeats": len(r.repeats), "clock_gap_ms": 0, "calls": r.calls,
                "left_anything": bool(r.left_behind), "left_behind": sorted(r.left_behind), "via": None},
        "stop": {"kind": result.PRODUCT_CONTROL, "fired_by": result.FIRED_BY[1], "ref": None,
                 "product": {"kind": result.HOST_SOFTWARE, "attachment": result.PRODUCTS[result.HOST_SOFTWARE][0],
                             "name": r.product},
                 "record": None},
        "agent": {"kind": result.HOST_AGENT, "runtime": None, "memory_mb": None, "private_network": None,
                  "ref": r.copy, "role_ref": None, "whose": result.WHOSE[1], "tools": list(tools),
                  "model_kind": model_kind, "clients": {"cloud": None, "http": r.http}},
        "host": {"where": result.HOST_WHERE, "os": r.os, "container": r.container, "stop_said": r.stop_said,
                 "on_host": result.HOST_ON_HOST, "name": r.host, "address": r.source,
                 "observer": {"address": r.observer, "public_key": r.observer_key,
                              "arrivals_sha256": hashlib.sha256(written).hexdigest()},
                 "evidence": [_evidence(rep) for rep in r.repeats]},
        "repeats": [{p: _part(rep.found[p], rep.mark_at) for p in r.paths} for rep in r.repeats],
    }
    doc = result.sign(doc, key or result.new_key())
    return doc, details(r, doc), written


def details(r: HostRun, doc: dict) -> dict:
    """The details beside the result, for your own records: each path's finding with why, its time to effect as a range
    and the failures the probe reported, by code; the witness's beats; and the run's names. It holds your copy's and
    your host's names and the observer's address, so keep it as you would any record of your systems."""
    return {
        "run": r.run, "copy": r.copy, "host": r.host, "observer": r.observer, "address_seen": r.source,
        "result_reference": result.reference(doc), "arrivals_file": f"stop-test-{r.run}-arrivals.json",
        "refused_keys": r.refused_keys, "rule": rule.RULE, "on_host": rule.ON_HOST, "product_clock": rule.PRODUCT_CLOCK,
        "repeats": [{
            "mark": result.iso(rep.mark_at),
            "host_up": {"by": rep.up.by if rep.up else None,
                        "witness_silent_from": result.iso(rep.up.witness_silent_from) if rep.up else None,
                        "why_not": rep.up.why if rep.up else None},
            "paths": {p: {"outcome": f.outcome, "words": rule.worded(f, rep.record), "reason": f.reason,
                          "effect_between": list(f.effect_between) if f.effect_between else None,
                          "arrivals_after": f.arrivals_after, "silent_from": result.iso(f.silent_from),
                          "back_at": result.iso(f.back_at), "fired_source": f.fired_source}
                      for p, f in rep.found.items()},
        } for rep in r.repeats],
        "failures_reported": {p: [{"at": result.iso(x["at"]), "n": x["n"], "code": x["error"], "status": x["status"]}
                                  for x in xs] for p, xs in r.failures.items()},
    }
