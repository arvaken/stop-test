"""Two stop-test-result/3 fixtures of a run on a test copy on Google Cloud, for the customer app's tests: each written
and signed by the kit's own code on google-test-copy (your_copy.run, then the_result), against test_google_copy's fake
project with the real probe in the copy. Run from the kit's root:
    .venv/Scripts/python tests/data/make_google_copy_results.py tests/data/google-copy-results.json
Each run signs with a new key, so its bytes differ each time; test_google_copy checks the file is the kit's own."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path[:0] = [str(Path("tests").resolve()), str(Path("probe/src").resolve())]
import pytest  # noqa: E402

import test_google_copy as t  # noqa: E402
from arvaken_stop_test import result  # noqa: E402
from arvaken_stop_test.google import fire as firing  # noqa: E402
from arvaken_stop_test.google import your_copy  # noqa: E402
from test_google_run import Clock  # noqa: E402


def one(start: str, tools: list, model_kind: str, **over) -> dict:
    clock = Clock()
    clock.t = datetime.fromisoformat(start).replace(tzinfo=timezone.utc).timestamp()
    g = t.CopyGoogle(clock)
    with pytest.MonkeyPatch.context() as mp:
        r, _, _ = t.a_copy_run(g, mp, window=900.0, **over)
    doc, _ = your_copy.the_result(r, tools, model_kind)
    return result.check(json.loads(json.dumps(doc)))


out = {
    "a copy of your Cloud Run service, the kit's deny policy on the run's account, the account it still runs as left":
        one("2026-11-03T21:00:00", ["runs code", "calls other services' APIs"], "a model service of its cloud",
            points=("at",)),
    "a copy of your Cloud Run service, the run's account disabled, two repeats":
        one("2026-11-03T22:00:00", ["no tools"], "no model", stop=firing.DISABLE, repeats=2),
}
Path(sys.argv[1]).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
for name, doc in out.items():
    print(name, "|", doc["stop"], "|", doc["run"]["left_behind"], "|", result.reference(doc))
