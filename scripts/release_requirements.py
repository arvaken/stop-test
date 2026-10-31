"""A release's hash-pinned requirements file (the founder's README changes, 24 October 2026, item 7): "Publish a
hash-pinned lockfile; the main install path installs from the verified wheel with --require-hashes."

It names the release's own wheel by its address and its SHA-256, then every package the kit and its AWS module need,
exactly as uv.lock pins them, each with the SHA-256 of every file the lock knows for it (`uv export`). pip, given it
with `--require-hashes`, installs those bytes or nothing. The release workflow signs it with Sigstore beside the other
files, so checking that one signature checks everything installed.

    uv export --format requirements-txt --frozen --extra aws --no-dev --no-emit-project > deps.txt
    python scripts/release_requirements.py 0.3.1 dist/arvaken_stop_test-0.3.1-py3-none-any.whl deps.txt > dist/requirements-0.3.1.txt
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

RELEASES = "https://github.com/arvaken/stop-test/releases/download"


def requirements(version: str, wheel_name: str, wheel_sha256: str, exported: str, base: str = RELEASES) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", wheel_sha256):
        raise ValueError("the wheel's SHA-256 is 64 hexadecimal characters")
    if not wheel_name.startswith(f"arvaken_stop_test-{version}-") or not wheel_name.endswith(".whl"):
        raise ValueError(f"{wheel_name} is not version {version}'s wheel")
    deps = [line for line in exported.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not deps or not any("--hash=sha256:" in line for line in deps):
        raise ValueError("the exported requirements hold no hashes: export them from uv.lock with uv export")
    head = [f"# The stop test kit, version {version}: every file it installs, by its SHA-256.",
            f"# python -m pip install --require-hashes -r requirements-{version}.txt",
            f"arvaken-stop-test[aws] @ {base}/v{version}/{wheel_name} \\",
            f"    --hash=sha256:{wheel_sha256}"]
    return "\n".join(head + deps) + "\n"


def main(argv: list[str]) -> int:
    version, wheel, exported = argv
    path = Path(wheel)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    sys.stdout.write(requirements(version, path.name, digest, Path(exported).read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
