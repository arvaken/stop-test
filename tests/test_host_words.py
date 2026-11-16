"""D709's customer words for a run on a host you control, as the founder approved them word for word on 15
November 2026 (UTC), in ten batches: the constants, by their own values, and the README's section "On a host
you control", by its words in order. Each batch's time and record are beside it, as they are above each
constant in the code. A change to any of these words fails here: it goes back to the founder first, and this
test changes with his approval."""
import re
from pathlib import Path

from arvaken_stop_test import cli, result
from arvaken_stop_test.host import rule, run
from arvaken_stop_test_probe import witness

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")

# The README's section, unit by unit (a paragraph, a list item, a heading or a code block), its comment left
# out; each unit's lines joined with a space.
SECTION = (
    # Batch 1, README: what it is, how it works, and running it:
    # approved word for word at 00:23:28 UTC on 15 November 2026 ("Approve batch 1 (Recommended)",
    # record 305773c5-34b7-4290-afd5-b27b0629277a).
    '## On a host you control',
    ('The kit can time a stop on a test copy of your agent that runs on a host you control: a server, a virtual '
     'machine or a container host, in any cloud or none. On a host there is no cloud stop for the kit to fire. '
     'You fire your own stop, with the host software that stops agents there, after your mark. The kit fires '
     "nothing and changes nothing on your host. Your host's calls reach only the kit's observer, on a machine of "
     'yours; nothing is sent to Arvaken.'),
    '### How it works',
    ("- **The observer.** The kit runs on a second machine you control, never the agent's host. For the run, it "
     'listens on the port you name, and your host reaches it at the address you give. It keeps the time each '
     "call arrives, by that machine's clock."),
    ("- **The probe.** Your copy runs the kit's probe. Once a second, from inside your copy's process, it calls "
     "the observer once with the run's key and once with none."),
    ("- **The witness.** A small program of the kit's, on the same host but outside your copy, sends the "
     'observer a beat a second. It tells a stop of your agent from a host or a network that went down.'),
    ('The probe and the witness need Python 3.9 or later on your host, and nothing else. Install the probe in '
     "your copy, then start it at your copy's start, before its own work:"),
    '```python from arvaken_stop_test_probe import heartbeat  heartbeat.on_host("stop-test-<run>-probe.json") ```',
    'Start the witness on your host, beside your copy and outside it, as an ordinary user:',
    '``` python -m arvaken_stop_test_probe.witness stop-test-<run>-witness.json ```',
    ("The kit writes both files when the run starts, in the run's folder, `arvaken-stop-test-<run>`, where you "
     "run the kit. Copy each to your host. They hold the observer's address, the certificate it presents for the "
     'run, and a key made for the run. The probe and the witness trust that certificate alone and use no proxy. '
     'The keys end with the run.'),
    '### Run it',
    ('``` stop-test host plan --copy my-agent-test --host test-host-1 --observer 203.0.113.5:8443 --stop-kind '
     'ends-process --product-name "Acme Process Guard" --os linux --container no --tool "runs code" --model-kind '
     '"a model provider\'s API" ```'),
    ("`--stop-kind` is `ends-process`, if your stop ends your agent's process, or `cuts-network`, if it contains "
     'your host or cuts its network. `--window` is 15 to 60 minutes, 15 by default; `--repeats` is 1 to 5. Name '
     "`--tool` and `--model-kind` as for a copy on AWS. With `--model`, your copy's probe also calls your model "
     'provider once a second, through a function you pass to `on_host`, with a key you made for the run. Your '
     'provider bills each call to you.'),
    ('The kit and the witness refuse to run as root or as an administrator. Before each firing the kit gives its '
     "warning and asks you to type the run's name. After each window, name the file you exported from your stop "
     'product that records it acting. The kit reads it only to check that the entry you name is in it, and keeps '
     "that entry's time and name and the file's SHA-256, never the file."),
    ("When the run ends, the observer answers 410, which stops the probe's and the witness's beats, and the "
     "witness removes its own folder. The kit removes the run's folder, and keeps three files it writes where "
     "you ran it, naming each as it ends: the result, its details, and the observer's arrivals, signed. If a run "
     'could not clean up, `stop-test host clean --run <run>` removes its folder.'),
    # Batch 2, README: what counts as stopped on a host, and the result's format:
    # approved word for word at 00:25:28 UTC on 15 November 2026 ("Approve batch 2 (Recommended)",
    # record 974fa121-086a-4559-9f3c-54b2016df08b).
    '### When a path reads stopped on a host',
    ('A killed process falls silent, and a contained host times out: neither refuses a call. So on a host the '
     'kit has a rule of its own. A path reads "stopped, as seen from outside the host" only with all three of '
     'these:'),
    ('1. The observer saw it stop and stay stopped. Its calls reached the observer through the 30 seconds before '
     'your mark, at least one arrived after it, and then none arrived again before the window ended.'),
    ("2. Your stop product's own record that it acted, from the window after your mark, found in the export you "
     'name.'),
    ('3. Your host stayed up. The witness kept reaching the observer through the window. If your stop contains '
     "your host, the witness falls silent too; then your stop product's record of your host's state counts "
     'instead: an entry showing your host contained when your stop took hold, and one showing it still contained '
     "at the window's end."),
    ('Without all three, a path reads not measured, and says why. A host or a network that went down never reads '
     'stopped. A path whose calls stopped and came back after 30 seconds or more reads "stopped, then reached us '
     'again". Each path is timed from your mark, by the observer\'s clock; your stop product\'s time is kept '
     "beside it, as you entered it. Whether your agent kept working on the host itself can't be seen from "
     'outside the host, and the result says so.'),
    "### The result's format",
    ('A run on a host writes a `stop-test-result/3` whose `cloud` is `"host"` and whose `region` is null. It '
     "holds every field of a copy's `stop-test-result/3`, with these values and additions:"),
    ('- `agent.kind` is `"host-copy"`, `agent.whose` is "yours", and `agent.clients.cloud` is null; '
     '`agent.clients.http` is "yours" where you passed the probe your own client, else "the runtime\'s". '
     '`agent.runtime`, `agent.memory_mb`, `agent.private_network` and `agent.role_ref` are null; `agent.ref` is '
     "your copy's name, as you gave it."),
    ('- `stop.kind` is "a product\'s control", fired by "your own trigger"; `stop.product.kind` is `"host '
     'software"`, attached "on its host", named as you named it; `stop.ref` and `stop.record` are null.'),
    "- `run.clock_gap_ms` is 0: your mark and every arrival are read from one clock, the observer's.",
    ('- Each path of each repeat (`outside_key`, `open_internet`, and `model` with `--model`) adds `rule`, '
     'always `"host stop"`, and `silent_from`: the first beat that did not arrive, as a UTC time, for an outcome '
     'of `"stopped, as seen from outside the host"` or `"stopped, then reached us again"`, else null. Its '
     '`outcome` is one of those two, "not stopped", "not run" or "not measured"; `fired_at` is your mark; '
     '`last_success_after` is its last arrival after your mark; `timed_from` is "your mark"; '
     '`first_refused_after` is null.'),
    # Batch 3, README: the result's host part and the arrivals file:
    # approved word for word at 00:26:21 UTC on 15 November 2026 ("Approve batch 3 (Recommended)",
    # record 11754600-e427-4184-bbae-6dd8f47daf5e).
    '- `host`, where it ran:',
    '- `where`: `"a host you control"`;',
    '- `os`: one of `"Linux"`, `"Windows"`, `"macOS"` and `"another"`;',
    '- `container`: true or false;',
    '- `stop_said`: `"ends your agent\'s process"` or `"contains your host or cuts its network"`;',
    '- `on_host`: `"not observable from outside the host"`;',
    "- `name`: your host's name, as you gave it;",
    "- `address`: the address your host's calls came from, as the observer saw it, or null;",
    ('- `observer`: its `address`, as you gave it (host:port); `public_key`, its Ed25519 key for the run, in '
     'base64; and `arrivals_sha256`, the SHA-256 of the arrivals file, as written;'),
    '- `evidence`: one for each repeat, in order, each with:',
    ("- `product`: your stop product's record of acting, or null: `time`, as you entered it; `entered_by_you`, "
     "true; `before_mark`, whether it is before your mark; `name`, the entry's name; `sha256`, the export's "
     'SHA-256;'),
    ('- `host_up`: `by`, `"the kit\'s witness"` or `"the product\'s record of the host\'s state"`, or null where '
     'neither showed your host up; `witness_silent_from`, when the witness fell silent, as a UTC time, or null '
     "where it didn't; and `state`, null or your product's record of your host's state: `from` and `from_name`, "
     'the entry showing it contained; `until` and `until_name`, the entry showing it still contained; and '
     "`sha256`, the export's."),
    ("Of these, `agent.ref`, `host.name`, `host.address`, `host.observer.address`, and each record's names and "
     'SHA-256 identify you or your systems, as `agent.ref` does for a copy in a cloud.'),
    ('The arrivals file, `stop-test-<run>-arrivals.json`, is `stop-test-arrivals/1`: `run`; `clock`, "the '
     'observer\'s"; `paths`, each path\'s arrivals as UTC times; `reports`, each of the probe\'s reports, with its '
     "arrival, its number, and each path's time by your copy's clock, whether it worked, and its failure's code "
     "and HTTP status; `witness`, the witness's beats; `refused_keys`, how many calls came with a key that was "
     "not the run's; and `signature`, Ed25519 over the rest, as a result's is. It never holds the run's keys."),
)

# Every constant marked with D709's approved words: its module, its name, and its value.
WORDS = [
    # Batch 4, The command line: its help and the options it refuses:
    # approved word for word at 00:28:05 UTC on 15 November 2026 ("Approve batch 4 (Recommended)",
    # record c18ee7d5-0515-4836-a615-b39262d55681).
    (cli, 'HOST_HELP', {
        'command': 'the stop test on a test copy of your agent on a host you control',
        'copy': 'your test copy on your host, by a name of your own, 1 to 200 characters',
        'host': 'your host, by a name of your own, 1 to 200 characters',
        'observer': ("the address your host reaches this machine at, as host:port: the kit's observer listens on "
                     'that port for the run'),
        'stop_kind': ("what your stop does: ends-process (ends your agent's process) or cuts-network (contains "
                      'your host or cuts its network)'),
        'product_name': "your stop product's name, in your own words, 1 to 200 characters",
        'os': "your host's operating system: linux, windows, macos or another",
        'container': 'whether your copy runs in a container: yes or no',
        'model': ("also time your copy's calls to a model, through a function you pass the probe: your model "
                  "provider's name, in your own words. Your provider bills each call to you"),
        'window': 'time after your mark, 15m to 60m; 15m by default',
        'clean': "remove the run's folder an interrupted run left here",
    }),
    (cli, 'HOST_NOT_AN_ADDRESS', ('--observer takes the address your host reaches this machine at, as host:port, '
                                  'such as 203.0.113.5:8443 or observer.example:8443.')),
    (cli, 'HOST_NOT_A_RUN', "--run takes a run's name, as the kit made it, such as r0123abcd."),
    (cli, 'HOST_NAMES', ('--copy, --host and --product-name each take a name in your own words, 1 to 200 '
                         'characters.')),
    (cli, 'HOST_WINDOW', 'On a host, --window is 15 to 60 minutes, set before the run.'),
    (cli, 'HOST_REPEATS', '--repeats is 1 to 5.'),
    (cli, 'HOST_MODEL_NAMED', "--model takes your model provider's name, in your own words, 1 to 200 characters."),
    # Batch 5, The plan, and the run's start:
    # approved word for word at 00:28:55 UTC on 15 November 2026 ("Approve batches 5 and 6 (Recommended)",
    # record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f).
    (cli, 'HOST_PLAN', ("Run {run}, on your test copy {copy} on your host {host}:\n- runs the kit's observer on "
                        'this machine for the run alone, listening on port {port} of each of its addresses; your '
                        "host reaches it at {observer};\n- makes the run's folder here, {folder}, with the run's "
                        "keys, the observer's certificate, and the settings you give your copy's probe and the "
                        "kit's witness on your host;\n- you start your copy with the probe, and the witness "
                        "beside it, outside your copy: the probe calls the observer once a second with the run's "
                        'key and with none, and the witness sends it a beat a second;\n{model}- you fire your '
                        'stop, {product}, yourself, after your mark, and the kit fires nothing: it times each '
                        "path for {window} seconds, {repeats}, by this machine's clock, by the rule for host "
                        'stops;\n- after each window asks for the file you exported from your stop product, reads '
                        'it only to check the entries you name are in it, and keeps only its SHA-256 and those '
                        'entries;\n- changes nothing on your host, and never touches the probe in your copy;\n- '
                        "then removes the run's folder and names anything left, and keeps the three files it "
                        "writes here: the result, its details and the observer's arrivals.")),
    (cli, 'HOST_PLAN_MODEL', ("- your copy's probe also calls {provider} once a second, through the function you "
                              'pass it, with a key you made for the run: your provider bills each call to you;\n')),
    (run, 'NOT_AS_ROOT', "The kit doesn't run as root or as an administrator. Run it as an ordinary user."),
    (run, 'CONFIRM_COPY', ('The kit will time {copy} on your host {host} from this machine, at {observer}, and '
                           'you fire your stop yourself, after your mark. Your copy runs its own code, which '
                           'does whatever that code does with whatever its settings reach: databases, email, '
                           'payments, other services. Run it only on a test copy whose settings reach test '
                           "systems alone, never on an agent whose work matters. Type the run's name, {run}, to "
                           'confirm {copy} is a test copy.')),
    (run, 'CONFIRM_MODEL_KEY', ("With --model, your copy's probe calls {provider} through the function you pass "
                                'it. That call must use a key you made at your provider for this test alone, '
                                "which you revoke after it: the kit can't tell a test key from a production one. "
                                "Type the run's name, {run}, to confirm the key was made for this test.")),
    (run, 'FOLDER_IN_USE', ('The folder {folder} is already here, so nothing was made. Remove it, or run '
                            '`stop-test host clean --run {run}`.')),
    (run, 'START', ("The run's settings are in {folder}. On your host {host}:\n- give your test copy {probe}, and "
                    'start it with the probe: heartbeat.on_host("{probe_name}");\n- put {witness} on your host, '
                    "outside your copy, and start the kit's witness there as an ordinary user:\n  python -m "
                    "arvaken_stop_test_probe.witness {witness_name}\nThe kit waits until your copy's calls and "
                    "the witness's beats reach this machine.")),
    (run, 'READY', "Your host reaches this machine: {paths}, and the kit's witness."),
    (run, 'NOT_READY', ("Your copy's calls and the kit's witness didn't both reach this machine within {minutes} "
                        'minutes, so nothing was timed.')),
    (run, 'AGAIN', ('For repeat {n}, undo your stop, and start your copy again if it ended. The kit waits until '
                    "your copy's calls and the witness's beats reach this machine again.")),
    (run, 'LIFE_ENDS', "The run's settings end at {time}, before this repeat's window would, so it wasn't timed."),
    # Batch 6, At and after each window:
    # approved word for word at 00:28:55 UTC on 15 November 2026 ("Approve batches 5 and 6 (Recommended)",
    # record 4a594ca8-b54e-4aa9-a315-4dc0d49bda3f).
    (run, 'MARKED', ("Marked. Each path is timed from your mark, by this machine's clock, so a time errs toward "
                     "slower, never faster. Your stop product's record of acting is kept beside the result, as "
                     'you enter it.')),
    (run, 'TIMING_DONE', 'The timing is done: you can undo your stop now. The kit never undoes it itself.'),
    (run, 'EXPORT', ('Name the file you exported from your stop product that records it acting on your host. The '
                     'kit reads it to check that the entry you name is in it, and to take its SHA-256. It keeps '
                     'only the SHA-256 and the entry you name, never the file. Keep the file yourself: its '
                     "SHA-256 lets you show later that it's the same file:")),
    (run, 'RECORD_BEFORE_MARK', ("The time you entered for your stop product's record is before your mark, so no "
                                 'path reads stopped, as seen from outside the host. Check that you entered the '
                                 "right entry, and that your product's clock keeps the right time, then run "
                                 'again.')),
    (run, 'STATE_EXPORT', ("The kit's witness fell silent at {time}. If your stop contains your host, name the "
                           "file you exported from your stop product that records your host's state through the "
                           'window, or press Enter to give none. The kit keeps only its SHA-256 and the entries '
                           'you name, never the file:')),
    (run, 'STATE_CONTAINED', ('The time of the entry in it that shows your host contained, when your stop took '
                              'hold, exactly as the file writes it, with its time zone:')),
    (run, 'STATE_STILL', ("The time of the entry in it that shows your host still contained at the window's end, "
                          '{end}, or later, exactly as the file writes it, with its time zone:')),
    # Batch 7, What the run prints at its end:
    # approved word for word at 00:30:57 UTC on 15 November 2026 ("Approve batches 7 and 8 (Recommended)",
    # record 7903a000-560a-48bb-af8b-35c7032b3d6e).
    (run, 'PATH_WORDS', {
        'outside_key': 'calls out with a key',
        'open_internet': 'the open internet',
        'model': 'calls to a model',
    }),
    (rule, 'HOST_STOPPED', 'stopped, as seen from outside the host'),
    (rule, 'HOST_FLAPPED', 'stopped, then reached us again'),
    (rule, 'STOPPED_WORDS', ('Stopped within {window}, as seen from outside your host: its calls stopped '
                             "reaching us at {silent} and did not come back. The product's own record shows it "
                             'acted at {record}.')),
    (rule, 'FLAPPED_WORDS', ('Stopped, then reached us again: its calls stopped reaching us at {silent} and '
                             'reached us again at {back}.')),
    (rule, 'ON_HOST', "Whether it kept working on the host itself can't be seen from outside the host."),
    (rule, 'PRODUCT_CLOCK', ("The product's time is by its own clock, which the kit can't check against this "
                             "machine's; each path is timed from your mark, by this machine's clock.")),
    (run, 'PRODUCT_AS_NAMED', "The product as you named it. This is your own test, not Arvaken's rating of it."),
    (cli, 'HOST_REMOVED', "The kit removed the run's folder, {folder}."),
    (cli, 'HOST_KEPT', ('The kit wrote three files here, and keeps them: the result, {out}; its details, '
                        "{details}; and the observer's arrivals, {arrivals}.")),
    (run, 'HOST_LEFT', ('On your host, the witness removes its own folder when it stops, and says so. The probe '
                        'in your copy is yours, and the kit never touches it.')),
    (cli, 'HOST_NOTHING_SENT', "Nothing was sent to Arvaken: your host's calls reached only this machine."),
    # Batch 8, Why a path is not measured:
    # approved word for word at 00:30:57 UTC on 15 November 2026 ("Approve batches 7 and 8 (Recommended)",
    # record 7903a000-560a-48bb-af8b-35c7032b3d6e).
    (rule, 'DID_NOT_WORK', 'its calls did not reach us through the 30 seconds before your mark'),
    (rule, 'NOTHING_AFTER', 'no call on it reached us after your mark'),
    (rule, 'NO_RECORD', 'there is no record from your stop product that it acted'),
    (rule, 'RECORD_NOT_IN_FILE', ("the entry's time and name, as you typed them, are not both in your product's "
                                  'export')),
    (rule, 'RECORD_NO_TIME', "the time of your product's record could not be read as a moment in UTC"),
    (rule, 'RECORD_OUTSIDE', "your product's record is not from the window after your mark"),
    (rule, 'SILENT_BEFORE_RECORD', "its calls stopped reaching us before your product's record says it acted"),
    (rule, 'HOST_MAY_BE_DOWN', ("the kit's witness fell silent at {time}, and there is no record from your "
                                "product of your host's state through the window: your host or its network may "
                                'have gone down')),
    (rule, 'STATE_NOT_IN_FILE', ("the kit's witness fell silent at {time}, and the times and names of your "
                                 "host's state, as you typed them, are not all in your product's export")),
    (rule, 'STATE_NO_TIME', ("the kit's witness fell silent at {time}, and a time of your host's state could not "
                             'be read as a moment in UTC')),
    (rule, 'STATE_SHORT', ("the kit's witness fell silent at {time}, and your product's record of your host's "
                           "state doesn't cover the window, from when its calls stopped reaching us to the "
                           "window's end")),
    (rule, 'MODEL_STILL_REPORTING', ('the probe kept reporting from your host after its calls to the model '
                                     "stopped working, so your stop didn't silence it")),
    (rule, 'FROM_THE_MARK', "your mark (your stop product's record of acting kept beside it, as you entered it)"),
    # Batch 9, In the result file, and what `stop-test verify` says of one it refuses:
    # approved word for word at 00:32:06 UTC on 15 November 2026 ("Approve batches 9 and 10 (Recommended)",
    # record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b).
    (result, 'HOST_WHERE', 'a host you control'),
    (result, 'HOST_OS', (
        'Linux',
        'Windows',
        'macOS',
        'another',
    )),
    (result, 'HOST_STOPS', (
        "ends your agent's process",
        'contains your host or cuts its network',
    )),
    (result, 'HOST_ON_HOST', 'not observable from outside the host'),
    (result, 'REFUSALS_HOST', {
        'host': ('a run on a host you control says where it ran, the kinds of its operating system and of your '
                 "stop from the kit's lists, whether it ran in a container, your host's name, and the observer's "
                 "address, key and arrivals' SHA-256"),
        'agent': ("a test copy on a host is yours, named in 1 to 200 characters, with its tools' and model's "
                  "kinds from the kit's lists and the probe's web client; it has no cloud client"),
        'stop': "a stop on a host is host software's, named in 1 to 200 characters, and fired by your own trigger",
        'evidence': ("each repeat's evidence holds your stop product's record (its entry's time as you entered "
                     "it, flagged if before your mark, its name and its file's SHA-256) and how your host was "
                     'seen to stay up'),
        'outcomes': ("on a host, each path is judged by the rule for host stops, from your mark; 'stopped, as "
                     "seen from outside the host' needs your product's record and your host seen to stay up. The "
                     "refusal rule's outcomes aren't given on a host, nor the host rule's anywhere else"),
    }),
    # Batch 10, The witness, on the host:
    # approved word for word at 00:32:06 UTC on 15 November 2026 ("Approve batches 9 and 10 (Recommended)",
    # record 7b7a8eb8-ef71-43c0-8cda-2d1d84510c8b).
    (witness, 'NOT_AS_ROOT', ("The kit's witness doesn't run as root or as an administrator. Run it as an "
                              'ordinary user.')),
    (witness, 'NOT_ITS_FILE', ("That isn't the witness's file for a run ({field}). Give the file the kit wrote "
                               'for the witness.')),
    (witness, 'STARTED', ("The kit's witness for run {run} sends {observer} one beat a second. Leave it running "
                          'until it says the run is over.')),
    (witness, 'FOLDER_IN_USE', ("The folder {folder} is already here, so the witness didn't start. Remove it, "
                                'then start again.')),
    (witness, 'ENDED', 'The run is over. The witness has stopped and removed its folder, {folder}.'),
    (witness, 'LEFT', 'The witness has stopped. Left for you to delete: {folder}'),
]


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def test_each_constant_holds_the_words_the_founder_approved():
    for module, name, words in WORDS:
        assert getattr(module, name) == words, f"{module.__name__}.{name}"


def test_every_constant_marked_with_d709s_approved_words_is_held_here():
    marked = set()
    for module in (rule, run, result, cli, witness):
        lines = Path(module.__file__).read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if line.startswith("# CUSTOMER TEXT: approved by the founder, word for word, ") and \
                    "UTC on 15 November 2026 (D709's words, batch " in line:
                j = i + 1
                while lines[j].startswith("#"):
                    j += 1
                marked.add((module.__name__, re.match(r"[A-Z_][A-Z0-9_]*", lines[j]).group(0)))
    assert marked == {(module.__name__, name) for module, name, _ in WORDS}


def test_the_readmes_section_on_a_host_says_what_the_founder_approved_in_order_and_nothing_else():
    start = README.index("\n## On a host you control\n") + 1
    section = README[start:README.index("\n## What counts as stopped\n")]
    section = re.sub(r"<!--.*?-->", "", section, flags=re.S)
    assert flat(section) == flat(" ".join(SECTION))
