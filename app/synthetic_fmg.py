"""A deterministic in-process stand-in for FortiManager, for load testing.

``SyntheticFMG.post`` is a drop-in for ``FMGClient._post`` (same shape as
``fmg_recorder.ReplayTransport.post``): plug it into a client with
``client._post = SyntheticFMG(...).post`` or patch it onto the class. It
generates ADOMs, devices (with VDOMs and HA members), policy packages with
scope members, policies, firewall objects and the few FortiGate monitor
resources the sweeps proxy, all derived from one seed so runs are repeatable.

It exists so call counts, payload sizes and collector run time can be
measured at 1,000-device scale without a 1,000-device FortiManager. It can NOT
prove real FMG behaviour (task queue, workspace locks, proxy throttling,
permission failures, version differences) -- see the scale design doc.

Every request is counted in ``calls`` under ``"<method> <normalized url>"``
(``app.fmg_metrics.normalize_url``); requests it cannot answer also land in
``unsupported`` and get FMG's "object does not exist" (-3) error object.
"""

from __future__ import annotations

import copy
import random
import threading
import time
import zlib
from collections import Counter
from datetime import UTC, datetime, timedelta

import requests

from app.fmg_metrics import normalize_url

_VERSION = "v7.6.7-build3737 260101 (GA.M)"
_SYSTEM_ADOM = "FortiManager_Managed_Devices"
_PLATFORMS = ("FortiGate-60F", "FortiGate-100F", "FortiGate-200F", "FortiGate-VM64-KVM")


def _ok(body: dict, url: str, data) -> dict:
    return {
        "id": body.get("id"),
        "result": [{"status": {"code": 0, "message": "OK"}, "url": url, "data": data}],
    }


def _err(body: dict, url: str, code: int, message: str) -> dict:
    return {
        "id": body.get("id"),
        "result": [{"status": {"code": code, "message": message}, "url": url}],
    }


class SyntheticFMG:
    def __init__(
        self,
        adoms: int = 5,
        devices: int = 1000,
        multi_vdom_fraction: float = 0.4,
        packages_per_adom: int = 80,
        rules_per_package: int = 300,
        latency_ms: tuple[float, float] = (0.0, 0.0),
        error_rate: float = 0.0,
        seed: int = 1,
        address_objects: int = 2000,
        address_groups: int = 300,
        service_objects: int = 150,
        vip_objects: int = 100,
    ):
        self.adom_count = adoms
        self.device_count = devices
        self.multi_vdom_fraction = multi_vdom_fraction
        self.packages_per_adom = packages_per_adom
        self.rules_per_package = rules_per_package
        self.latency_ms = latency_ms
        self.error_rate = error_rate
        self.seed = seed
        self.address_objects = address_objects
        self.address_groups = address_groups
        self.service_objects = service_objects
        self.vip_objects = vip_objects

        self.calls: Counter[str] = Counter()
        self.unsupported: Counter[str] = Counter()
        self.proxy_calls: Counter[str] = Counter()
        self._lock = threading.Lock()
        self._rng = random.Random(f"{seed}:noise")
        self._adoms: dict[str, list[dict]] = {}
        self._build_inventory()

    @property
    def total_calls(self) -> int:
        return sum(self.calls.values())

    # ---- inventory ---------------------------------------------------------

    def _build_inventory(self) -> None:
        rng = random.Random(f"{self.seed}:inventory")
        names = [f"Ent-{i + 1}" for i in range(self.adom_count)]
        per, extra = divmod(self.device_count, max(self.adom_count, 1))
        n = 0
        for ai, adom in enumerate(names):
            count = per + (1 if ai < extra else 0)
            devs = []
            for _ in range(count):
                n += 1
                devs.append(self._make_device(rng, adom, n))
            self._adoms[adom] = devs
        self._adoms[_SYSTEM_ADOM] = []

    def _make_device(self, rng: random.Random, adom: str, n: int) -> dict:
        name = f"FW-{adom}-{n:04d}"
        multi = rng.random() < self.multi_vdom_fraction
        vdoms = [{"name": "root", "status": "enable"}]
        if multi:
            vdoms += [
                {"name": f"vd{k}", "status": "enable"} for k in range(rng.randint(1, 3))
            ]
        ha = rng.random() < 0.1
        dev = {
            "name": name,
            "ip": f"10.{(n >> 8) & 255}.{n & 255}.1",
            "sn": f"FGT{self.seed:02d}{n:010d}",
            "platform_str": rng.choice(_PLATFORMS),
            "os_ver": 7,
            "mr": 6,
            "patch": rng.choice((3, 4, 6, 7)),
            "conn_status": 1 if rng.random() < 0.97 else 0,
            "conf_status": 1 if rng.random() < 0.9 else 2,
            # FMG encoding: 0 unknown, 1 nomod, 2 modified (confirmed on a lab FMG 8.0.2)
            "db_status": 1 if rng.random() < 0.9 else 2,
            "ha_mode": 1 if ha else 0,
            "mgt_vdom": "root",
            "vdom": vdoms,
            "latitude": f"{30 + rng.random() * 15:.4f}",
            "longitude": f"{-120 + rng.random() * 40:.4f}",
            "desc": "",
        }
        if ha:
            dev["ha_slave"] = [
                {
                    "name": f"{name}-m{k}",
                    "sn": f"FGT{self.seed:02d}{n:08d}{k:02d}",
                    "role": "master" if k == 0 else "slave",
                    "prio": 200 - k * 100,
                    "status": 1,
                }
                for k in range(2)
            ]
        return dev

    def _pkg_names(self, adom: str) -> list[str]:
        idx = list(self._adoms).index(adom)
        return [f"Pkg-{idx}-{i:03d}" for i in range(self.packages_per_adom)]

    def _pkg_scope(self, adom: str, pkg: str) -> list[dict]:
        names = self._pkg_names(adom)
        if pkg not in names:
            return []
        slot = names.index(pkg)
        return [
            {"name": d["name"], "vdom": v["name"]}
            for i, d in enumerate(self._adoms[adom])
            if i % self.packages_per_adom == slot
            for v in d["vdom"]
        ]

    def _pkg_for_device(self, adom: str, device: str) -> str:
        for i, d in enumerate(self._adoms.get(adom, [])):
            if d["name"] == device:
                return self._pkg_names(adom)[i % self.packages_per_adom]
        return ""

    # ---- generators --------------------------------------------------------

    def _policies(self, adom: str, pkg: str) -> list[dict]:
        rng = random.Random(f"{self.seed}:{adom}:{pkg}")
        return [
            {
                "policyid": i + 1,
                "name": f"rule-{i + 1}",
                "srcintf": ["port1"],
                "dstintf": ["port2"],
                "srcaddr": [f"addr-{rng.randrange(self.address_objects or 1)}"],
                "dstaddr": [f"addr-{rng.randrange(self.address_objects or 1)}"],
                "service": [f"svc-{rng.randrange(self.service_objects or 1)}"],
                "action": 1,
                "status": 1,
                "schedule": ["always"],
                "logtraffic": 2,
                "comments": "",
            }
            for i in range(self.rules_per_package)
        ]

    def _objects(self, kind: str, adom_key: str) -> list[dict]:
        if adom_key == "global":
            return [{"name": f"g-{kind}-{i}"} for i in range(min(100, 10))]
        if kind == "address":
            return [
                {
                    "name": f"addr-{i}",
                    "type": 0,
                    "subnet": [f"10.{i >> 8 & 255}.{i & 255}.0", "255.255.255.0"],
                }
                for i in range(self.address_objects)
            ]
        if kind == "addrgrp":
            return [
                {"name": f"grp-{i}", "member": [f"addr-{i}", f"addr-{i + 1}"]}
                for i in range(self.address_groups)
            ]
        if kind == "service/custom":
            return [
                {"name": f"svc-{i}", "tcp-portrange": [str(1000 + i)]}
                for i in range(self.service_objects)
            ]
        if kind == "service/group":
            return [{"name": f"svcgrp-{i}", "member": [f"svc-{i}"]} for i in range(10)]
        if kind == "vip":
            return [
                {
                    "name": f"vip-{i}",
                    "extip": [f"203.0.113.{i % 250}"],
                    "mappedip": [f"10.9.{i % 250}.1"],
                }
                for i in range(self.vip_objects)
            ]
        if kind == "ippool":
            return [
                {
                    "name": f"pool-{i}",
                    "startip": f"198.51.100.{i}",
                    "endip": f"198.51.100.{i}",
                }
                for i in range(20)
            ]
        return []

    def _proxy_payload(self, adom: str, device: str, resource: str):
        path = resource.split("?")[0]
        dev = next((d for d in self._adoms.get(adom, []) if d["name"] == device), None)
        if dev is None:
            return None
        if path == "/api/v2/monitor/license/status":
            rng = random.Random(f"{self.seed}:lic:{device}")
            days = rng.choice((-30, 20, 75, 200, 400))
            ts = int((datetime.now(UTC) + timedelta(days=days)).timestamp())
            sub = {"status": "licensed", "expires": ts}
            results = {
                "forticare": {
                    "support": {"enhanced": {"status": "licensed", "expires": ts}}
                }
            }
            for key in ("antivirus", "ips", "web_filtering", "appctrl", "antispam"):
                results[key] = dict(sub)
            return results
        if path == "/api/v2/monitor/system/status":
            return {
                "version": f"v7.6.{dev['patch']}",
                "serial": dev["sn"],
                "hostname": device,
            }
        if path == "/api/v2/cmdb/system/interface":
            return [
                {
                    "vdom": v["name"],
                    "results": [
                        {
                            "name": f"port{k}",
                            "ip": f"10.0.{k}.1 255.255.255.0",
                            "allowaccess": "ping https ssh",
                            "status": "up",
                            "type": "physical",
                        }
                        for k in range(1, 4)
                    ],
                }
                for v in dev["vdom"]
            ]
        return None

    # ---- transport ---------------------------------------------------------

    def post(self, body: dict, timeout: int | None = None) -> dict:
        """Answer one JSON-RPC request. Thread-safe; may raise ConnectionError."""
        first = (body.get("params") or [{}])[0]
        url = first.get("url", "") if isinstance(first, dict) else ""
        method = str(body.get("method", ""))
        key = f"{method} {normalize_url(url)}"

        with self._lock:
            self.calls[key] += 1
            lo, hi = self.latency_ms
            delay = self._rng.uniform(lo, hi) if hi > 0 else 0.0
            fail = self.error_rate > 0 and self._rng.random() < self.error_rate
        if delay:
            time.sleep(delay / 1000.0)
        if fail:
            raise requests.ConnectionError("synthetic FMG: injected failure")

        resp = self._dispatch(
            body, method, url, first if isinstance(first, dict) else {}
        )
        if resp is None:
            with self._lock:
                self.unsupported[key] += 1
            return _err(body, url, -3, "Object does not exist")
        return copy.deepcopy(resp)

    def _pkg_status_entry(self, adom: str, dev: dict, vdom: str) -> dict | None:
        pkg = self._pkg_for_device(adom, dev["name"])
        if not pkg:
            return None
        if dev["db_status"] == 2:
            status = "modified"
        elif zlib.crc32(f"{dev['name']}/{vdom}".encode()) % 23 == 0:
            status = "conflict"
        else:
            status = "installed"
        return {
            "dev": dev["name"],
            "vdom": vdom,
            "pkg": pkg,
            "status": status,
            "flags": 0,
            "stype": 0,
            "type": 1,
        }

    def _package_status(self, body: dict, url: str, adom: str, parts: list):
        """ADOM-wide, per-device or per-device/VDOM ``_package/status``."""
        devs = self._adoms[adom]
        if len(parts) >= 7:
            devs = [d for d in devs if d["name"] == parts[6]]
            if not devs:
                return None
        rows = []
        for dev in devs:
            for v in dev["vdom"]:
                if len(parts) == 8 and v["name"] != parts[7]:
                    continue
                entry = self._pkg_status_entry(adom, dev, v["name"])
                if entry is not None:
                    rows.append(entry)
        if len(parts) == 8:
            return _ok(body, url, rows[0] if rows else {"status": "unassigned"})
        return _ok(body, url, rows)

    def _page(self, first: dict, items: list):
        rng = first.get("range")
        if isinstance(rng, list) and len(rng) == 2:
            offset, size = rng
            return items[offset : offset + size]
        return items

    def _dispatch(self, body: dict, method: str, url: str, first: dict) -> dict | None:
        parts = [p for p in url.split("/") if p]
        if method == "exec" and url == "/sys/proxy/json":
            return self._proxy(body, first.get("data", {}))
        if method != "get":
            return None
        if url == "/sys/status":
            return _ok(body, url, {"Version": _VERSION, "Hostname": "synthetic-fmg"})
        if url == "/dvmdb/adom":
            return _ok(
                body,
                url,
                [
                    {"name": a, "oid": 100 + i, "desc": ""}
                    for i, a in enumerate(self._adoms)
                ],
            )
        if (
            parts[:2] == ["dvmdb", "adom"]
            and len(parts) >= 4
            and parts[2] in self._adoms
        ):
            adom = parts[2]
            if parts[3] == "device":
                devs = self._adoms[adom]
                if len(parts) == 4:
                    return _ok(body, url, devs)
                dev = next((d for d in devs if d["name"] == parts[4]), None)
                if dev is None:
                    return None
                if len(parts) == 5:
                    return _ok(body, url, dev)
                if parts[5] == "vdom" and len(parts) == 6:
                    return _ok(body, url, dev["vdom"])
            if parts[3] == "revision" and len(parts) == 4:
                return _ok(
                    body,
                    url,
                    [
                        {
                            "oid": 1000 + i,
                            "version": 1,
                            "name": f"{d['name']}_2026-11-01-02-00-00-UTC",
                            "created_time": 1793000000 + i,
                        }
                        for i, d in enumerate(self._adoms[adom])
                    ],
                )
            return None
        if (
            parts[:3] == ["pm", "pkg", "adom"]
            and len(parts) >= 4
            and parts[3] in self._adoms
        ):
            adom = parts[3]
            if len(parts) == 4:
                return _ok(
                    body,
                    url,
                    [
                        {"name": p, "type": "pkg", "oid": 5000 + i}
                        for i, p in enumerate(self._pkg_names(adom))
                    ],
                )
            pkg = "/".join(parts[4:])
            if pkg in self._pkg_names(adom):
                return _ok(
                    body,
                    url,
                    {
                        "name": pkg,
                        "type": "pkg",
                        "scope member": self._pkg_scope(adom, pkg),
                        "package settings": {},
                    },
                )
            return None
        if (
            parts[:3] == ["pm", "config", "adom"]
            and len(parts) >= 5
            and parts[3] in self._adoms
        ):
            adom = parts[3]
            if parts[4] == "pkg" and parts[-2:] == ["firewall", "policy"]:
                pkg = "/".join(parts[5:-2])
                if pkg not in self._pkg_names(adom):
                    return None
                return _ok(body, url, self._page(first, self._policies(adom, pkg)))
            if parts[4:6] == ["_package", "status"] and len(parts) in (6, 7, 8):
                return self._package_status(body, url, adom, parts)
            if parts[4:7] == ["obj", "firewall", "address"] and len(parts) == 7:
                return _ok(body, url, self._page(first, self._objects("address", adom)))
            if parts[4:6] == ["obj", "firewall"] and len(parts) >= 7:
                kind = "/".join(parts[6:])
                if kind in (
                    "addrgrp",
                    "service/custom",
                    "service/group",
                    "vip",
                    "ippool",
                ):
                    return _ok(body, url, self._page(first, self._objects(kind, adom)))
            return None
        if (
            parts[:3] == ["pm", "config", "global"]
            and parts[3:5] == ["obj", "firewall"]
            and len(parts) >= 6
        ):
            kind = "/".join(parts[5:])
            if kind in ("address", "addrgrp", "vip", "ippool"):
                return _ok(body, url, self._page(first, self._objects(kind, "global")))
        return None

    def _proxy(self, body: dict, data: dict) -> dict | None:
        resource = data.get("resource", "")
        targets = data.get("target") or []
        with self._lock:
            self.proxy_calls[resource.split("?")[0]] += 1
        out = []
        for target in targets:
            segs = target.split("/")  # adom/<adom>/device/<device>
            adom, device = (segs[1], segs[3]) if len(segs) >= 4 else ("", "")
            payload = self._proxy_payload(adom, device, resource)
            if payload is None:
                return None
            out.append(
                {
                    "target": target,
                    "status": {"code": 0, "message": "OK"},
                    "response": {"http_status": 200, "results": payload},
                }
            )
        return _ok(body, "/sys/proxy/json", out)
