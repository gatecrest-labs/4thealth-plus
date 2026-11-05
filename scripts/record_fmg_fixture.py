"""Capture a scrubbed FortiManager fixture for the replay tests.

Runs the read-only API self-test against the FortiManager configured in
``.env`` (FMG_PRIMARY_HOST / FMG_API_TOKEN) while recording every JSON-RPC
exchange, then writes ``tests/fixtures/fmg_<version>/exchanges.json``.

    uv run python scripts/record_fmg_fixture.py
    uv run python scripts/record_fmg_fixture.py --literal "Acme Corp=ORG"
    # also capture the install-preview chain (STAGES a package on the FMG,
    # then cancels it -- same as the Config-Delta tab does):
    uv run python scripts/record_fmg_fixture.py --preview "MyADOM/my-device"

ADOM and device names found on the FMG are replaced with ADOM1/FGT-LAB-1/...
automatically; pass --literal OLD=NEW for anything else (company names,
domains, hostnames inside object names). The scrubber also replaces secrets,
IPv4 addresses, serial numbers and e-mail addresses, but it is best-effort:
READ the output before committing it -- this repository is public.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# FortiManager's own ADOMs: not identifying, and replacing words like "root" or
# "others" as substrings would mangle unrelated values (e.g. the root VDOM).
_BUILTIN_ADOMS = {"root", "rootp", "others", "syslog", "unmanaged_devices", "global"}


def _discover_literals(client) -> dict[str, str]:
    """Map real ADOM / device names to neutral ones (before recording starts)."""
    lit: dict[str, str] = {}
    adoms = [a.get("name", "") for a in client.get_adoms() if isinstance(a, dict)]
    adoms = [a for a in adoms if a and not a.lower().startswith("forti")]
    n_adom = n_dev = 0
    for adom in adoms:
        if adom.lower() not in _BUILTIN_ADOMS:
            n_adom += 1
            lit[adom] = f"ADOM{n_adom}"
        for d in client.get_devices(adom):
            name = d.get("name") if isinstance(d, dict) else None
            # A model name (e.g. FortiWiFi-71G on a device named after its
            # model) is not identifying and consumers bucket on it.
            if name and name not in lit and name != d.get("platform_str"):
                n_dev += 1
                lit[name] = f"FGT-LAB-{n_dev}"
    host = (client.get_system_status() or {}).get("Hostname")
    if host:
        lit[host] = "FMG-LAB"
    return lit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", help="output directory (default tests/fixtures/fmg_<ver>)")
    ap.add_argument("--literal", action="append", default=[], metavar="OLD=NEW")
    ap.add_argument(
        "--preview",
        metavar="ADOM/DEVICE",
        help="also record the install-preview chain for this device (stages a package)",
    )
    args = ap.parse_args(argv)

    from app.fmg_helpers import make_client
    from app.fmg_recorder import Recorder, Scrubber
    from app.fmg_selftest import run_selftest

    with make_client() as client:
        literals = _discover_literals(client)
        for pair in args.literal:
            old, _, new = pair.partition("=")
            if not old or not new:
                ap.error(f"--literal expects OLD=NEW, got {pair!r}")
            literals[old] = new

        version = client.version
        if version is None:
            print(
                "Could not read the FMG version; refusing to record.", file=sys.stderr
            )
            return 2
        out_dir = (
            Path(args.out)
            if args.out
            else ROOT
            / "tests"
            / "fixtures"
            / f"fmg_{version.major}.{version.minor}.{version.patch}"
        )
        out_file = out_dir / "exchanges.json"
        if out_file.exists():
            out_file.unlink()  # one capture == one process == one mapping

        client._recorder = Recorder(out_file, scrubber=Scrubber(literals))
        report = run_selftest(client)
        print(f"self-test: {report['summary']}")

        if args.preview:
            adom, _, device = args.preview.partition("/")
            if not adom or not device:
                ap.error("--preview expects ADOM/DEVICE")
            print(f"recording install preview for {adom}/{device} ...")
            raw = client.get_install_preview(adom, device)
            print(f"preview returned {len(raw)} characters")

    print(f"wrote {out_file}")
    print("Review it for anything identifying before you commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
