"""Record and replay FortiManager JSON-RPC traffic.

Purpose: catch FMG-version-specific breakage in CI without needing a lab on
every release. A fixture is a scrubbed capture of real exchanges; tests plug
:class:`ReplayTransport` into an :class:`~app.fmg_client.FMGClient` so the
real client methods run offline against what a given FMG release answered.

Recording is opt-in: set ``FMG_RECORD_FILE=/path/to/exchanges.json`` and every
``FMGClient._post`` exchange is scrubbed and appended to that file. Record one
fixture per process run (identifier mapping is per-process, so the same
address maps to the same stand-in throughout one capture).

Scrubbing is best-effort, not a guarantee: always read a capture before
committing it.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import threading
from pathlib import Path

REDACTED = "<redacted>"

# Dict keys whose values are always replaced, at any depth.
_SECRET_KEYS = frozenset(
    {
        "session",
        "passwd",
        "password",
        "token",
        "access_token",
        "api_key",
        "apikey",
        "psksecret",
        "secret",
        "passphrase",
        "private-key",
        "privatekey",
        "cloud-authentication-access-key",
        "auth-key",
        "authkey",
        "priv-key",
        "privkey",
    }
)

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})(?:\.\d{1,3}){3}(?![\d.])")
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# FortiGate / FortiManager style serials: FGT60FTK21091234, FMG-VM0A17001234
_SERIAL = re.compile(
    r"\b(?=[A-Z0-9-]*\d)(?:F[A-Z0-9]{2,5}|FMG-VM|FAZ-VM)[0-9A-Z]{8,}\b"
)


_ADMIN_BLOCK = re.compile(r"config system admin\n(.*?)\nend\b", re.DOTALL)
_EDIT_NAME = re.compile(r'^\s*edit "([^"]+)"', re.MULTILINE)
_STOCK_ADMINS = frozenset({"admin"})


class Scrubber:
    """Replaces secrets and identifying values with stable stand-ins."""

    def __init__(self, literals: dict[str, str] | None = None):
        # Longest first so "Corp West HQ" wins over "Corp West".
        self._literals = sorted((literals or {}).items(), key=lambda kv: -len(kv[0]))
        self._ips: dict[str, str] = {}
        self._serials: dict[str, str] = {}
        self._emails: dict[str, str] = {}
        self._uuids: dict[str, str] = {}
        self._admins: dict[str, str] = {}

    def scrub(self, obj):
        return self._walk(copy.deepcopy(obj))

    # -- internals --------------------------------------------------------

    def _walk(self, obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                key = self._text(k) if isinstance(k, str) else k
                if isinstance(k, str) and k.lower() in _SECRET_KEYS:
                    out[key] = REDACTED if isinstance(v, str) and v else v
                else:
                    out[key] = self._walk(v)
            return out
        if isinstance(obj, list):
            return [self._walk(v) for v in obj]
        if isinstance(obj, str):
            return self._text(obj)
        return obj

    def _text(self, s: str) -> str:
        if s.startswith("ENC "):  # FMG's masked secret values
            return REDACTED
        for src, dst in self._literals:
            s = s.replace(src, dst)
        # Admin account names appear inside CLI diff text; learn them from the
        # `config system admin` block, then replace them wherever quoted.
        for block in _ADMIN_BLOCK.findall(s):
            for name in _EDIT_NAME.findall(block):
                if name not in _STOCK_ADMINS:
                    self._map(self._admins, name, "admin-user-{n}")
        for name, repl in self._admins.items():
            s = s.replace(f'"{name}"', f'"{repl}"')
        s = _UUID.sub(
            lambda m: self._map(
                self._uuids, m.group(0).lower(), "00000000-0000-4000-8000-{n:012d}"
            ),
            s,
        )
        s = _EMAIL.sub(
            lambda m: self._map(self._emails, m.group(0), "user{n}@example.com"), s
        )
        s = _SERIAL.sub(
            lambda m: self._map(self._serials, m.group(0), "FGT{n:013d}"), s
        )
        return _IPV4.sub(self._ip, s)

    @staticmethod
    def _map(table: dict, value: str, template: str) -> str:
        if value not in table:
            table[value] = template.format(n=len(table) + 1)
        return table[value]

    def _ip(self, m: re.Match) -> str:
        ip = m.group(0)
        first = int(m.group(1))
        # Netmasks (255.x), wildcard masks (0.x) and 0.0.0.0 carry no identity.
        if first in (0, 255):
            return ip
        if ip not in self._ips:
            n = len(self._ips) + 1
            self._ips[ip] = f"10.250.{n // 256}.{n % 256}"
        return self._ips[ip]


def _request_key(body: dict) -> str:
    """Identity of a request: method + params, ignoring per-call id/session."""
    return json.dumps(
        {"method": body.get("method"), "params": body.get("params")},
        sort_keys=True,
        separators=(",", ":"),
    )


def _url_key(body: dict) -> tuple:
    first = (body.get("params") or [{}])[0]
    url = first.get("url") if isinstance(first, dict) else None
    return (body.get("method"), url)


class Recorder:
    """Appends scrubbed request/response pairs to a JSON file."""

    def __init__(self, path, scrubber: Scrubber | None = None):
        self.path = Path(path)
        self._scrubber = scrubber or Scrubber()
        self._lock = threading.Lock()
        self._exchanges: list[dict] = []
        if self.path.exists():
            self._exchanges = json.loads(self.path.read_text()).get("exchanges", [])
        else:
            self._flush()

    def record(self, body: dict, response: dict) -> None:
        request = {k: body[k] for k in ("method", "params") if k in body}
        entry = self._scrubber.scrub({"request": request, "response": response})
        with self._lock:
            self._exchanges.append(entry)
            self._flush()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump({"exchanges": self._exchanges}, fh, indent=1, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


class ReplayMiss(LookupError):
    """The code under test made a request that was not in the fixture."""


class ReplayTransport:
    """Drop-in for ``FMGClient._post`` that answers from a recorded fixture.

    Identical requests are answered in recorded order and the last answer
    repeats, which models task polling (``percent`` 0 -> 50 -> 100).
    """

    def __init__(self, path, loose_urls: tuple[str, ...] = ()):
        """``loose_urls``: URLs whose params hold a value that changes per run
        (e.g. the audit-log time window). They match on method + url alone
        when no exact match exists; every other URL must match exactly.
        """
        data = json.loads(Path(path).read_text())
        self._loose = set(loose_urls)
        self._by_url: dict[tuple, list[dict]] = {}
        self._answers: dict[str, list[dict]] = {}
        self._used: dict[str, int] = {}
        for ex in data.get("exchanges", []):
            self._answers.setdefault(_request_key(ex["request"]), []).append(
                ex["response"]
            )
            self._by_url.setdefault(_url_key(ex["request"]), []).append(ex["response"])

    def post(self, body: dict) -> dict:
        key = _request_key(body)
        answers = self._answers.get(key)
        if not answers and _url_key(body)[1] in self._loose:
            key = "url:" + "|".join(_url_key(body))
            answers = self._by_url.get(_url_key(body))
        if not answers:
            first = (body.get("params") or [{}])[0]
            raise ReplayMiss(
                f"no recorded response for {body.get('method')} "
                f"{first.get('url') if isinstance(first, dict) else first}: {key}"
            )
        i = self._used.get(key, 0)
        self._used[key] = i + 1
        resp = copy.deepcopy(answers[min(i, len(answers) - 1)])
        if "id" in body:
            resp["id"] = body["id"]
        return resp
