"""FortiManager JSON-RPC client — read-only, no device changes."""

import json
import os
import re
import time
import warnings

import requests
import urllib3

if os.environ.get("FMG_SUPPRESS_INSECURE_WARNING", "true").lower() == "true":
    warnings.filterwarnings(
        "ignore", category=urllib3.exceptions.InsecureRequestWarning
    )

PROXY_ENDPOINTS = [
    {
        "key": "system_status",
        "label": "System status",
        "resource": "/api/v2/monitor/system/status?vdom=root",
        "required": True,
    },
    {
        "key": "cpu",
        "label": "CPU usage",
        "resource": "/api/v2/monitor/system/resource/usage?resource=cpu&interval=1-min&vdom=root",
        "required": True,
    },
    {
        "key": "mem",
        "label": "Memory usage",
        "resource": "/api/v2/monitor/system/resource/usage?resource=mem&interval=1-min&vdom=root",
        "required": True,
    },
    {
        "key": "interfaces",
        "label": "Interfaces",
        "resource": "/api/v2/monitor/system/interface?vdom=*",
        "required": False,
    },
    {
        "key": "interfaces_cfg",
        "label": "Interface config",
        "resource": "/api/v2/cmdb/system/interface?vdom=root",
        "required": False,
    },
    {
        "key": "performance",
        "label": "Performance",
        "resource": "/api/v2/monitor/system/performance/status?vdom=root",
        "required": False,
    },
    {
        "key": "ha_status",
        "label": "HA status",
        "resource": "/api/v2/monitor/system/ha-status?vdom=root",
        "required": False,
    },
    {
        "key": "ipv4_routes",
        "label": "IPv4 routes",
        "resource": "/api/v2/monitor/router/ipv4?vdom=*",
        "required": False,
    },
    {
        "key": "ipv6_routes",
        "label": "IPv6 routes",
        "resource": "/api/v2/monitor/router/ipv6?vdom=*",
        "required": False,
    },
    {
        "key": "bgp_neighbors",
        "label": "BGP neighbors",
        "resource": "/api/v2/monitor/router/bgp/neighbors?vdom=*",
        "required": False,
    },
    {
        "key": "bgp_paths",
        "label": "BGP paths",
        "resource": "/api/v2/monitor/router/bgp/paths?vdom=*",
        "required": False,
    },
    {
        "key": "ospf_neighbors",
        "label": "OSPF neighbors",
        "resource": "/api/v2/monitor/router/ospf/neighbors?vdom=*",
        "required": False,
    },
    {
        "key": "ipsec",
        "label": "IPsec tunnels",
        "resource": "/api/v2/monitor/vpn/ipsec?vdom=root",
        "required": False,
    },
]

PREVIEW_TIMEOUT_SECS = 120
_CONF_STATUS_MAP = {0: "unknown", 1: "insync", 2: "outofsync"}
# db_status: whether FMG DB has been modified since the last install
_DB_STATUS_MAP = {0: "unknown", 1: "nomod", 2: "modified"}

_SUMMARY_KEYWORDS = [
    (["firewall policy", "firewall policy6"], "firewall_policy"),
    (
        ["router static", "router policy", "router ospf", "router bgp", "router rip"],
        "routing",
    ),
    (["firewall address", "firewall addrgrp", "firewall wildcard-fqdn"], "address"),
    (["firewall service"], "service"),
    (
        [
            "system global",
            "system interface",
            "system settings",
            "system admin",
            "system dns",
        ],
        "system",
    ),
]


def _classify_lines(content: str) -> list:
    """Classify each line in a FortiOS CLI diff block as add/remove/modify."""
    changes = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("==="):
            continue
        if stripped.startswith(("delete ", "unset ")):
            changes.append({"type": "remove", "line": line})
        elif stripped.startswith(("config ", "end", "edit ", "next")):
            changes.append({"type": "modify", "line": line})
        elif stripped.startswith("set "):
            changes.append({"type": "add", "line": line})
        else:
            changes.append({"type": "modify", "line": line})
    return changes


def _split_vdom_blocks(raw: str) -> list[tuple[str, str]]:
    """Split raw FMG diff text into (vdom_name, content) blocks.

    FMG uses two formats depending on version/mode:
      Format A (standalone marker):  a bare line "vdom <name>" separates sections.
      Format B (nested config block): "config vdom\\n    edit <name>\\n...\\n    next\\nend"
        wraps each vdom's diff inside a config vdom block.

    Returns list of (name, content) tuples, or [("root", raw)] if no markers found.
    """
    # Format A: standalone "vdom <name>" line
    split_a = re.split(r"^\s*vdom\s+(\S+)\s*$", raw, flags=re.MULTILINE)
    if len(split_a) > 1:
        blocks = []
        for i in range(1, len(split_a), 2):
            vname = split_a[i].strip()
            content = split_a[i + 1] if i + 1 < len(split_a) else ""
            blocks.append((vname, content))
        return blocks

    # Format B: "config vdom\n    edit <name>\n    ...\n    next\nend" sections.
    # Split on "config vdom" markers, then take only the FIRST "edit" line in
    # each block as the vdom name. All subsequent "edit" lines are diff content
    # (address objects, policy IDs, etc.) and must not be used as vdom names.
    config_vdom_blocks = re.split(
        r"^config\s+vdom\s*$", raw, flags=re.MULTILINE | re.IGNORECASE
    )
    if len(config_vdom_blocks) > 1:
        blocks = []
        for block in config_vdom_blocks[1:]:
            # The first "edit" line at any leading whitespace is the vdom name.
            m = re.search(r"^\s+edit\s+(\S+)\s*$", block, flags=re.MULTILINE)
            if not m:
                continue
            vname = m.group(1).strip('"')
            # Everything after "edit <vdom>" is the diff content for this vdom.
            content = block[m.end() :]
            # Strip the outer wrapper lines (next / end) that belong to
            # "config vdom", not to the diff content itself.
            content = re.sub(r"^\s*next\s*$", "", content, flags=re.MULTILINE)
            content = re.sub(r"^\s*end\s*$", "", content, count=1, flags=re.MULTILINE)
            blocks.append((vname, content))
        if blocks:
            return blocks

    return [("root", raw)]


def parse_preview_diff(raw: str) -> dict:
    """Parse raw FMG install-preview CLI text into structured diff.

    Returns:
        {
          "summary": {"firewall_policy": int, "routing": int, ...},
          "vdoms": [{"name": str, "changes": [{"type": str, "line": str}]}],
          "raw": str,
        }
    """
    empty_summary = {
        "firewall_policy": 0,
        "routing": 0,
        "address": 0,
        "service": 0,
        "system": 0,
        "other": 0,
    }
    if not raw or not raw.strip() or raw.strip() == "=== No preview result ===":
        return {
            "summary": empty_summary,
            "vdoms": [{"name": "root", "changes": []}],
            "raw": raw,
        }

    vdom_blocks = _split_vdom_blocks(raw)

    summary = dict(empty_summary)
    vdoms_out = []

    for vname, content in vdom_blocks:
        changes = _classify_lines(content)
        # Count config blocks per category
        for line_obj in changes:
            line = line_obj["line"].strip().lower()
            if line.startswith("config "):
                block = line[len("config ") :]
                cat = "other"
                for keywords, key in _SUMMARY_KEYWORDS:
                    if any(block.startswith(k) for k in keywords):
                        cat = key
                        break
                summary[cat] += 1
        vdoms_out.append({"name": vname, "changes": changes})

    return {"summary": summary, "vdoms": vdoms_out, "raw": raw}


class FMGError(Exception):
    pass


class FMGClient:
    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        token: str = "",
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self.base_url = f"https://{host}/jsonrpc"
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = None
        self._req_id = 0
        self._http = requests.Session()

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _post(self, body: dict) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = self._http.post(
            self.base_url,
            json=body,
            verify=self.verify_ssl,
            timeout=self.timeout,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    def login(self):
        # Bearer token auth — no login call needed
        if self.token:
            return
        body = {
            "id": self._next_id(),
            "method": "exec",
            "params": [
                {
                    "url": "/sys/login/user",
                    "data": {"user": self.username, "passwd": self.password},
                }
            ],
        }
        data = self._post(body)
        result = data.get("result", [{}])[0]
        if result.get("status", {}).get("code", -1) != 0:
            raise FMGError("Authentication failed")
        self.session = data["session"]

    def logout(self):
        # Bearer token auth — no logout call needed
        if self.token:
            return
        if not self.session:
            return
        try:
            self._post(
                {
                    "id": self._next_id(),
                    "method": "exec",
                    "session": self.session,
                    "params": [{"url": "/sys/logout"}],
                }
            )
        except Exception:
            pass
        self.session = None

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *_):
        self.logout()
        self._http.close()

    def _get(self, url: str) -> dict:
        body = {
            "id": self._next_id(),
            "method": "get",
            "params": [{"url": url}],
        }
        if self.session:
            body["session"] = self.session
        data = self._post(body)
        result = data.get("result", [{}])[0]
        if result.get("status", {}).get("code", -1) != 0:
            raise FMGError(f"FMG error on {url}: {result.get('status')}")
        return result.get("data", {})

    def get_system_status(self) -> dict:
        """Return FortiManager /sys/status."""
        return self._get("/sys/status")

    def get_performance(self) -> dict:
        """Return FortiManager /sys/resource/performance (CPU, memory)."""
        try:
            return self._get("/sys/resource/performance")
        except Exception:
            return {}

    def get_resource_usage(self) -> dict:
        """Alternative CPU/mem endpoint used on some FMG versions."""
        try:
            return self._get("/sys/resource/usage")
        except Exception:
            return {}

    def get_adoms(self) -> list:
        return self._get("/dvmdb/adom") or []

    def get_devices(self, adom: str) -> list:
        return self._get(f"/dvmdb/adom/{adom}/device") or []

    def get_devices_with_sync_status(self, adom: str) -> list:
        """Return devices in an ADOM with normalized conf_status and db_status strings."""
        raw = self._get(f"/dvmdb/adom/{adom}/device") or []
        result = []
        for d in raw:
            if not isinstance(d, dict):
                continue
            cs_int = d.get("conf_status", 0)
            try:
                cs_int = int(cs_int)
            except (TypeError, ValueError):
                cs_int = 0
            d["conf_status"] = _CONF_STATUS_MAP.get(cs_int, "unknown")
            db_int = d.get("db_status", 0)
            try:
                db_int = int(db_int)
            except (TypeError, ValueError):
                db_int = 0
            d["db_status"] = _DB_STATUS_MAP.get(db_int, "unknown")
            result.append(d)
        return result

    def get_install_preview(self, adom: str, device: str) -> str:
        """Trigger FMG install preview for device, poll until done, return raw CLI diff text.

        Implements the 4-step chained workflow required for FMG 7.4.4+:
          1. securityconsole/install/package  flags=["preview"] — stage the package
          2. securityconsole/install/preview  flags=["none"]    — generate combined diff
          3. securityconsole/preview/result                     — fetch CLI text
          4. securityconsole/package/cancel/install             — cleanup (best-effort)

        Scope uses name-based {"name": device, "vdom": vdom_name} format — OID-based scope
        was silently broken by FMG 7.4.4.

        Raises FMGError on task failure or timeout.
        Returns empty string if device has no pending changes.
        """
        vdoms = self.get_device_vdoms(adom, device)
        vdom_names = (
            [
                v.get("name", "root")
                for v in vdoms
                if isinstance(v, dict) and v.get("name")
            ]
            if vdoms
            else ["root"]
        )
        scope = [{"name": device, "vdom": v} for v in vdom_names]

        # Resolve per-vdom package assignments. Only stage packages that are
        # "modified" — staging an already-installed package overwrites the preview
        # state and causes preview/result to return empty for the modified package.
        pkg_names: list[str] = []
        for vname in vdom_names:
            info = self.get_package_info(adom, device, vname)
            pname = info.get("pkg_name", "")
            if (
                pname
                and pname not in pkg_names
                and info.get("pkg_status") == "modified"
            ):
                pkg_names.append(pname)

        def _exec(url: str, data: dict) -> dict:
            body = {
                "id": self._next_id(),
                "method": "exec",
                "params": [{"url": url, "data": data}],
            }
            if self.session:
                body["session"] = self.session
            resp = self._post(body)
            result = resp.get("result", [{}])[0]
            if result.get("status", {}).get("code", -1) != 0:
                raise FMGError(f"FMG error on {url}: {result.get('status')}")
            return result.get("data", {})

        def _poll(taskid: int, label: str) -> None:
            deadline = time.time() + PREVIEW_TIMEOUT_SECS
            while time.time() < deadline:
                poll_body = {
                    "id": self._next_id(),
                    "method": "get",
                    "params": [{"url": f"/task/task/{taskid}"}],
                }
                if self.session:
                    poll_body["session"] = self.session
                poll_resp = self._post(poll_body)
                poll_result = poll_resp.get("result", [{}])[0]
                task_data = poll_result.get("data", [])
                if isinstance(task_data, list) and task_data:
                    task_data = task_data[0]
                if isinstance(task_data, dict):
                    percent = task_data.get("percent", 0)
                    num_err = task_data.get("num_err", 0)
                    if percent >= 100:
                        if num_err:
                            lines = task_data.get("line") or []
                            detail = ""
                            if isinstance(lines, list) and lines:
                                failed = next(
                                    (
                                        ln
                                        for ln in lines
                                        if isinstance(ln, dict) and ln.get("err")
                                    ),
                                    lines[0] if isinstance(lines[0], dict) else {},
                                )
                                detail = failed.get("detail", "")
                            # FMG reports num_err > 0 with "Copy to device done" on
                            # certain firmware combinations when the preview was
                            # successfully applied to the device — not a real failure.
                            if detail.strip().lower() == "copy to device done":
                                return
                            raise FMGError(
                                f"{label} task {taskid} for {device} failed"
                                f"{f': {detail}' if detail else ''}"
                            )
                        return
                time.sleep(2)
            raise FMGError(
                f"{label} task {taskid} for {device} timed out after {PREVIEW_TIMEOUT_SECS}s"
            )

        # Step 1: stage each assigned policy package so policy changes appear in
        # the diff. Multi-vdom devices can have a different package per vdom, so
        # we stage each unique pkg_name. Skip entirely if none are assigned.
        # Failure modes:
        #   - RPC rejected (no task): fall through silently, try next pkg.
        #   - Task accepted but fails mid-run (num_err > 0): propagate.
        #
        # FMG's own web GUI links preview/result back to the STAGE task's ID via
        # a "preview_taskid" field passed into both the install/preview call and
        # the final preview/result call — not the install/preview call's own task
        # ID. Confirmed by capturing the GUI's own JSON-RPC traffic on FMG 7.6.7;
        # without this, install/preview reports status=OK but preview/result
        # always returns "No preview result" even though a real diff exists.
        stage_ok = False
        last_stage_taskid = None
        for pkg_name in pkg_names:
            try:
                stage_data = _exec(
                    "/securityconsole/install/package",
                    {
                        "adom": adom,
                        "flags": ["preview"],
                        "scope": scope,
                        "pkg": pkg_name,
                    },
                )
                stage_taskid = stage_data.get("task")
                if stage_taskid:
                    _poll(stage_taskid, "Stage")
                    stage_ok = True
                    last_stage_taskid = stage_taskid
            except FMGError as exc:
                if "Stage task" in str(exc):
                    raise
                # RPC rejection for this pkg — try the next one

        # Step 2: generate preview diff report, linked to the stage task above
        preview_request: dict = {"adom": adom, "flags": ["none"], "scope": scope}
        if last_stage_taskid:
            preview_request["preview_taskid"] = last_stage_taskid
        try:
            preview_data = _exec("/securityconsole/install/preview", preview_request)
        except FMGError:
            # Both stage and preview calls rejected — device has no pending changes
            if not stage_ok:
                return ""
            raise
        preview_taskid = preview_data.get("task")
        if not preview_taskid:
            if not stage_ok:
                return ""
            raise FMGError(f"No task ID returned for install/preview of {device}")
        _poll(preview_taskid, "Preview")

        def _fetch_result(taskid: int) -> str:
            """Call preview/result with the given key and return this device's
            CLI diff text, or "" if absent / no diff / lookup failed."""
            try:
                result_data = _exec(
                    "/securityconsole/preview/result",
                    {"adom": adom, "scope": scope, "preview_taskid": taskid},
                )
            except FMGError:
                return ""
            message = result_data.get("message", "")
            if not message:
                return ""
            try:
                entries = json.loads(message)
            except (ValueError, TypeError):
                return message
            if not isinstance(entries, list):
                return ""
            for entry in entries:
                if (
                    isinstance(entry, dict)
                    and entry.get("name", "").lower() == device.lower()
                ):
                    result = entry.get("result", "")
                    if result.strip() == "=== No preview result ===":
                        return ""
                    return result
            return ""

        # Step 3: fetch result. Try the install/preview task's own ID first —
        # this is the exact key confirmed working against FMG 7.4.10 in
        # production. On FMG 7.6.7 this call succeeds (status=OK) but returns
        # "=== No preview result ===" for this device; in that case retry
        # keyed by the STAGE task's ID instead, which FMG 7.6.7's own GUI uses
        # for this same lookup (confirmed by capturing its JSON-RPC traffic).
        # Trying the proven key first means 7.4.x behavior is unchanged.
        result = _fetch_result(preview_taskid)
        if not result and last_stage_taskid and last_stage_taskid != preview_taskid:
            result = _fetch_result(last_stage_taskid)

        # Step 4: cleanup — FMG holds a pending-install lock until cancelled
        try:
            _exec(
                "/securityconsole/package/cancel/install",
                {"adom": adom, "scope": scope},
            )
        except Exception:
            pass

        return result

    def _proxy(self, adom: str, device: str, resource: str) -> dict:
        body = {
            "id": self._next_id(),
            "method": "exec",
            "params": [
                {
                    "url": "/sys/proxy/json",
                    "data": {
                        "action": "get",
                        "resource": resource,
                        "target": [f"adom/{adom}/device/{device}"],
                    },
                }
            ],
        }
        if self.session:
            body["session"] = self.session
        data = self._post(body)
        result = data.get("result", [{}])[0]
        rpc_code = result.get("status", {}).get("code", -1)
        raw = result.get("data", {})

        # FMG proxy envelope:
        #   result[0].data → list of per-device dicts
        #   each dict has: { "response": { "http_status": 200, "results": <actual data> }, ... }
        # We need to unwrap two layers: data[0] → .response → .results
        http_status = 200
        payload = {}

        # Step 1: get the per-device dict (first element of the list, or the dict itself)
        if isinstance(raw, list) and raw:
            device_wrapper = raw[0] if isinstance(raw[0], dict) else {}
        elif isinstance(raw, dict):
            device_wrapper = raw
        else:
            device_wrapper = {}

        # Step 2: pull http_status from the wrapper (before diving into response)
        http_status = int(
            device_wrapper.get(
                "http_status", device_wrapper.get("http_status_code", 200)
            )
        )

        # Step 3: unwrap .response — may be a dict or a JSON-encoded string
        response = device_wrapper.get("response", device_wrapper)
        if isinstance(response, str):
            try:
                import json as _json

                response = _json.loads(response)
            except Exception:
                response = {}
        if isinstance(response, dict):
            http_status = int(response.get("http_status", http_status))
            payload = response.get("results", response)
        else:
            payload = response

        return {"rpc_code": rpc_code, "http_status": http_status, "payload": payload}

    def get_device(self, adom: str, device_name: str) -> dict:
        """Fetch a single device record from FMG's dvmdb — authoritative for inventory fields."""
        data = self._get(f"/dvmdb/adom/{adom}/device/{device_name}")
        if isinstance(data, list) and data:
            return data[0]
        if isinstance(data, dict):
            return data
        return {}

    def get_device_vdoms(self, adom: str, device_name: str) -> list:
        """Return the list of VDOMs for a device from dvmdb (empty list when not in VDOM mode)."""
        try:
            data = self._get(f"/dvmdb/adom/{adom}/device/{device_name}/vdom")
            if isinstance(data, list):
                return data
            return []
        except Exception:
            return []

    def get_package_info(self, adom: str, device: str, vdom: str = "root") -> dict:
        """Return policy package info for a device/vdom.

        Calls /pm/config/adom/{adom}/_package/status/{device}/{vdom}.
        Response fields (confirmed against FMG 7.4.x, extended for 7.6.x):
          "pkg"    — package path string, e.g. "PROD/LMR/Device_Policy" (absent if unassigned)
          "status" — plain string: "installed" | "modified" | "conflict" | "unassigned"
                     "conflict" is a 7.6.x value meaning the assigned package differs from
                     what's installed on the device — same install-preview handling as
                     "modified", it just isn't surfaced on 7.4.x.
        Returns {"pkg_name": str, "pkg_status": str} where pkg_status is one of
        "modified", "nomod", or "" (unassigned / error).
        """
        try:
            data = self._get(f"/pm/config/adom/{adom}/_package/status/{device}/{vdom}")
            if not isinstance(data, dict):
                return {"pkg_name": "", "pkg_status": ""}
            pkg_name = data.get("pkg", "")
            raw_status = data.get("status", "")
            if raw_status in ("modified", "conflict"):
                pkg_status = "modified"
            elif raw_status == "installed":
                pkg_status = "nomod"
            else:
                pkg_status = ""  # unassigned or unknown
            return {"pkg_name": pkg_name, "pkg_status": pkg_status}
        except Exception:
            return {"pkg_name": "", "pkg_status": ""}

    def get_package_status(self, adom: str, device: str, vdom: str = "root") -> str:
        """Return the policy package install status string for a device/vdom.

        Returns "modified" if any vdom's package is modified, "nomod" if all
        are installed, or "" if all are unassigned/error.
        """
        return self.get_package_info(adom, device, vdom)["pkg_status"]

    def get_device_pkg_status(self, adom: str, device: str, vdom_names: list) -> str:
        """Check package status across all vdoms — returns "modified" if any are modified.

        Short-circuits on the first "modified" vdom so multi-vdom devices with many
        vdoms don't make unnecessary extra calls once a modified package is found.
        """
        found_nomod = False
        for vname in vdom_names:
            status = self.get_package_info(adom, device, vname)["pkg_status"]
            if status == "modified":
                return "modified"
            if status == "nomod":
                found_nomod = True
        return "nomod" if found_nomod else ""

    def get_policy_packages(self, adom: str) -> list:
        """Return all policy packages in an ADOM, recursing into folder subobj lists.

        Each returned dict has 'name' (display name) and 'path' (the slash-joined
        folder/package string needed for API calls, e.g. 'MyFolder/MyPackage').
        """
        try:
            data = self._get(f"/pm/pkg/adom/{adom}")
            if not isinstance(data, list):
                return []
            return self._flatten_packages(data, prefix="")
        except Exception:
            return []

    @staticmethod
    def _flatten_packages(items: list, prefix: str) -> list:
        """Recursively collect pkg-type entries, tracking the folder path."""
        result = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            pkg_type = (item.get("type") or "").lower()
            if pkg_type == "folder":
                sub = item.get("subobj") or []
                if isinstance(sub, list):
                    folder_prefix = f"{prefix}{name}/" if name else prefix
                    result.extend(FMGClient._flatten_packages(sub, folder_prefix))
            else:
                result.append({**item, "path": f"{prefix}{name}"})
        return result

    def get_pkg_settings(self, adom: str, pkg_path: str) -> dict:
        """Return the 'package settings' dict for a policy package.

        The last component of pkg_path is the package name; the leading parts
        are folder names.  The API path for the package object itself is:
          /pm/pkg/adom/<adom>/<folder1>/<folder2>/.../<pkg_name>
        Returns {} on any error.
        """
        try:
            data = self._get(f"/pm/pkg/adom/{adom}/{pkg_path}")
            if isinstance(data, dict):
                return data.get("package settings") or {}
            if isinstance(data, list) and data:
                return data[0].get("package settings") or {}
        except Exception:
            pass
        return {}

    def get_policies(self, adom: str, pkg_path: str) -> list:
        """Return all firewall policies in a package.

        pkg_path is the slash-joined folder/package path as returned by
        get_policy_packages(), e.g. 'MyFolder/MyPackage' or just 'MyPackage'.

        FMG JSON-RPC caps un-ranged results at 500. We paginate with 1000-row
        windows until we get a short page, guaranteeing all rules are returned
        regardless of package size.
        """
        url = f"/pm/config/adom/{adom}/pkg/{pkg_path}/firewall/policy"
        all_policies: list = []
        page_size = 1000
        offset = 0
        while True:
            body = {
                "id": self._next_id(),
                "method": "get",
                "params": [{"url": url, "range": [offset, page_size]}],
            }
            if self.session:
                body["session"] = self.session
            data = self._post(body)
            result = data.get("result", [{}])[0]
            if result.get("status", {}).get("code", -1) != 0:
                raise FMGError(f"FMG error on {url}: {result.get('status')}")
            page = result.get("data", [])
            if not isinstance(page, list):
                break
            all_policies.extend(page)
            if len(page) < page_size:
                break
            offset += page_size
        return all_policies

    def get_pblock_policies(self, adom: str, block_name: str) -> list:
        """Return firewall policies from a policy block (pblock) in an ADOM.

        FMG 7.2+ stores policy blocks under:
          /pm/config/adom/<adom>/pblock/<block_name>/firewall/policy

        Returns [] if the block doesn't exist or is inaccessible.
        """
        url = f"/pm/config/adom/{adom}/pblock/{block_name}/firewall/policy"
        all_policies: list = []
        page_size = 1000
        offset = 0
        while True:
            body = {
                "id": self._next_id(),
                "method": "get",
                "params": [{"url": url, "range": [offset, page_size]}],
            }
            if self.session:
                body["session"] = self.session
            data = self._post(body)
            result = data.get("result", [{}])[0]
            if result.get("status", {}).get("code", -1) != 0:
                return []
            page = result.get("data", [])
            if not isinstance(page, list):
                break
            all_policies.extend(page)
            if len(page) < page_size:
                break
            offset += page_size
        return all_policies

    def get_live_policy_hits(
        self, adom: str, device_name: str, vdom: str = "root"
    ) -> dict:
        """Return live per-policy hit counts from the device via FMG proxy.

        FMG's stored _hitcount is updated only when FMG syncs stats from the
        device (which may be infrequent or never).  This method queries the
        FortiGate's monitor API directly through FMG's proxy so hit counts are
        always current regardless of FMG sync state.

        Returns {policyid (int): hit_count (int)}.  Returns {} on any error so
        callers can fall back to FMG-cached values gracefully.
        """
        try:
            r = self._proxy(
                adom, device_name, f"/api/v2/monitor/firewall/policy?vdom={vdom}"
            )
            payload = r.get("payload", [])
            if not isinstance(payload, list):
                return {}
            result: dict = {}
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                pid = entry.get("policyid") or entry.get("id")
                if pid is None:
                    continue
                # FortiOS REST API uses "hit_count" on the monitor endpoint
                hit = entry.get("hit_count")
                if hit is None:
                    hit = entry.get("hitcount", 0)
                result[int(pid)] = int(hit) if hit is not None else 0
            return result
        except Exception:
            return {}

    def get_policy_count(self, adom: str, pkg_path: str) -> int:
        """Return the number of firewall policies in a package without fetching full objects."""
        try:
            # Use fields param to minimise payload — we only need the count
            body = {
                "id": self._next_id(),
                "method": "get",
                "params": [
                    {
                        "url": f"/pm/config/adom/{adom}/pkg/{pkg_path}/firewall/policy",
                        "fields": ["policyid"],
                    }
                ],
            }
            if self.session:
                body["session"] = self.session
            data = self._post(body)
            result = data.get("result", [{}])[0]
            if result.get("status", {}).get("code", -1) != 0:
                return 0
            policies = result.get("data", [])
            return len(policies) if isinstance(policies, list) else 0
        except Exception:
            return 0

    def get_pkg_scope_members(self, adom: str, pkg_path: str) -> list:
        """Return the list of devices/groups this policy package is installed on.

        Each entry is typically {"name": "FW01", "vdom": "root"}.
        Returns [] on error or when the package has no explicit scope.
        """
        try:
            data = self._get(f"/pm/pkg/adom/{adom}/{pkg_path}")
            if isinstance(data, list) and data:
                data = data[0]
            if not isinstance(data, dict):
                return []
            scope = data.get("scope member") or data.get("scope_member") or []
            if isinstance(scope, list):
                return scope
            return []
        except Exception:
            return []

    def get_device_group_names(self, adom: str) -> set[str]:
        """Return the set of device group names in an ADOM.

        Single API call — does not fetch member lists.
        Returns empty set on error.
        """
        try:
            data = self._get(f"/dvmdb/adom/{adom}/group")
            if not isinstance(data, list):
                return set()
            return {g["name"] for g in data if isinstance(g, dict) and g.get("name")}
        except Exception:
            return set()

    def get_device_group_members(self, adom: str, group_name: str) -> list[str]:
        """Return device names that belong to a FMG device group.

        FMG requires option=['object member'] to include the sub-table inline;
        the /object member path suffix does not work for dvmdb device groups.
        Returns [] on error or when the name is not a group.
        """
        try:
            url = f"/dvmdb/adom/{adom}/group/{group_name}"
            body = {
                "id": self._next_id(),
                "method": "get",
                "params": [{"url": url, "option": ["object member"]}],
            }
            if self.session:
                body["session"] = self.session
            resp = self._post(body)
            data = resp.get("result", [{}])[0].get("data") or {}
            if isinstance(data, list) and data:
                data = data[0]
            members = data.get("object member") or [] if isinstance(data, dict) else []
            return [
                m.get("name", "")
                for m in members
                if isinstance(m, dict) and m.get("name")
            ]
        except Exception:
            return []

    def get_device_policy_package(self, adom: str, device_name: str) -> list[dict]:
        """Return policy packages installed on a device.

        Uses the scope member list already embedded in each package dict returned by
        get_policy_packages(). Scope members may be individual devices OR device groups.

        Strategy (avoids O(N) per-scope-member API calls):
        1. Collect unmatched scope member names — no API calls.
        2. Fetch all group names in one call and intersect — isolates names that are
           actual groups AND appear in scope members (typically 0-2).
        3. Fetch member lists only for that small intersection.
        Returns a list of {"name": pkg_name, "vdom": vdom} dicts; [] if none found.
        """
        try:
            packages = self.get_policy_packages(adom)
            device_lower = device_name.lower()

            # Pass 1 — collect scope member names that don't match the device directly.
            unmatched: set[str] = set()
            for pkg in packages:
                scope = pkg.get("scope member") or pkg.get("scope_member") or []
                for m in scope:
                    if isinstance(m, dict):
                        n = m.get("name", "")
                        if n and n.lower() != device_lower:
                            unmatched.add(n)

            # Pass 2 — resolve members only for unmatched names that are real groups.
            group_members: dict[str, list[str]] = {}
            if unmatched:
                known_groups = self.get_device_group_names(adom)  # 1 API call
                for grp in unmatched & known_groups:  # typically 0-2 names
                    group_members[grp] = self.get_device_group_members(adom, grp)

            # Pass 3 — match packages.
            matched = []
            for pkg in packages:
                scope = pkg.get("scope member") or pkg.get("scope_member") or []
                if not isinstance(scope, list):
                    continue
                for m in scope:
                    if not isinstance(m, dict):
                        continue
                    name = m.get("name", "")
                    if name.lower() == device_lower:
                        matched.append({"name": pkg["name"], "vdom": m.get("vdom", "")})
                        break
                    if any(
                        gm.lower() == device_lower for gm in group_members.get(name, [])
                    ):
                        matched.append({"name": pkg["name"], "vdom": m.get("vdom", "")})
                        break
            return matched
        except Exception:
            return []

    def get_device_interfaces(self, adom: str, device_name: str) -> list:
        """Return interface list from live device via FMG proxy (root VDOM only)."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/monitor/system/interface?vdom=root"
            )
            payload = r.get("payload", {})
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict):
                return list(payload.values())
            return []
        except Exception:
            return []

    def get_device_interfaces_all_vdoms(self, adom: str, device_name: str) -> list:
        """Return all interfaces across every VDOM using the CMDB endpoint (vdom=*).

        CMDB returns a flat list; each entry has 'vdom', 'name', 'ip', 'type',
        'allowaccess' (space-separated string), and 'status'.  VLAN and
        sub-interfaces are included because the CMDB covers all interface types.
        """
        try:
            r = self._proxy(adom, device_name, "/api/v2/cmdb/system/interface?vdom=*")
            payload = r.get("payload", {})
            # vdom=* wraps each vdom's results in [{vdom: ..., results: [...]}, ...]
            if isinstance(payload, list):
                # Could be either the flat list or the vdom-envelope list
                if payload and isinstance(payload[0], dict) and "results" in payload[0]:
                    flat = []
                    seen: set[tuple[str, str]] = set()
                    for item in payload:
                        vname = item.get("vdom", "root")
                        results = item.get("results", [])
                        if isinstance(results, list):
                            for iface in results:
                                if isinstance(iface, dict):
                                    iface.setdefault("vdom", vname)
                                    # Deduplicate by (name, vdom) so the same
                                    # physical interface can appear in multiple
                                    # VDOMs but each (name, vdom) pair is listed
                                    # only once.
                                    iname = iface.get("name", "")
                                    ivdom = iface.get("vdom", vname)
                                    key = (iname, ivdom)
                                    if iname and key not in seen:
                                        seen.add(key)
                                        flat.append(iface)
                    return flat
                return [i for i in payload if isinstance(i, dict)]
            if isinstance(payload, dict):
                return list(payload.values())
            return []
        except Exception:
            return []

    def get_device_routes(self, adom: str, device_name: str) -> list:
        """Return IPv4 routing table from live device via FMG proxy."""
        try:
            r = self._proxy(adom, device_name, "/api/v2/monitor/router/ipv4?vdom=root")
            payload = r.get("payload", [])
            return payload if isinstance(payload, list) else []
        except Exception:
            return []

    def get_device_routes_all_vdoms(self, adom: str, device_name: str) -> list:
        """Return IPv4 routing table across all VDOMs via FMG proxy.

        The vdom=* envelope returns [{vdom: ..., results: [...]}, ...]; we
        flatten it so callers get a single list of route dicts identical to
        what get_device_routes() returns for the root VDOM.
        """
        try:
            r = self._proxy(adom, device_name, "/api/v2/monitor/router/ipv4?vdom=*")
            payload = r.get("payload", [])
            if isinstance(payload, list):
                if payload and isinstance(payload[0], dict) and "results" in payload[0]:
                    flat = []
                    for item in payload:
                        results = item.get("results", [])
                        if isinstance(results, list):
                            flat.extend(r for r in results if isinstance(r, dict))
                    return flat
                return [r for r in payload if isinstance(r, dict)]
            return []
        except Exception:
            return []

    def get_device_ntp(self, adom: str, device_name: str) -> dict:
        """Return NTP configuration from the device via FMG proxy.

        Returns the raw CMDB dict for system/ntp (keys: ntpsync, type,
        ntpserver list, etc.), or an empty dict on failure.
        """
        try:
            r = self._proxy(adom, device_name, "/api/v2/cmdb/system/ntp?vdom=root")
            payload = r.get("payload", {})
            if isinstance(payload, list) and payload:
                return payload[0] if isinstance(payload[0], dict) else {}
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception:
            return {}

    def get_device_syslog(self, adom: str, device_name: str) -> list:
        """Return all enabled remote syslog servers configured on the device.

        FortiOS supports up to 4 syslog profiles (syslogd … syslogd4).  Each
        enabled profile is returned as a dict with at least ``server`` and
        ``status`` keys.  Disabled or unreachable profiles are omitted.
        """
        profiles = [
            "/api/v2/cmdb/log.syslogd/setting?vdom=root",
            "/api/v2/cmdb/log.syslogd2/setting?vdom=root",
            "/api/v2/cmdb/log.syslogd3/setting?vdom=root",
            "/api/v2/cmdb/log.syslogd4/setting?vdom=root",
        ]
        servers: list[dict] = []
        for resource in profiles:
            try:
                r = self._proxy(adom, device_name, resource)
                payload = r.get("payload", {})
                if isinstance(payload, list) and payload:
                    cfg = payload[0] if isinstance(payload[0], dict) else {}
                elif isinstance(payload, dict):
                    cfg = payload
                else:
                    continue
                if cfg.get("status") == "enable" and cfg.get("server"):
                    servers.append(cfg)
            except Exception:
                continue
        return servers

    def _get_paged(self, url: str, page_size: int = 1000) -> list:
        """Paginated GET for endpoints that may return large lists.

        Sends range=[offset, page_size] until a short page is returned.
        Uses a per-request timeout of 120 s to handle large ADOM object lists
        that exceed the default 30 s window.
        """
        all_items: list = []
        offset = 0
        while True:
            body = {
                "id": self._next_id(),
                "method": "get",
                "params": [{"url": url, "range": [offset, page_size]}],
            }
            if self.session:
                body["session"] = self.session
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            resp = self._http.post(
                self.base_url,
                json=body,
                verify=self.verify_ssl,
                timeout=120,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            result = data.get("result", [{}])[0]
            if result.get("status", {}).get("code", -1) != 0:
                raise FMGError(f"FMG error on {url}: {result.get('status')}")
            page = result.get("data", [])
            if not isinstance(page, list):
                break
            all_items.extend(page)
            if len(page) < page_size:
                break
            offset += page_size
        return all_items

    def get_address_objects(self, adom: str, scope: str = "all") -> list:
        """Return firewall address objects filtered by scope: 'local', 'global', or 'all'."""
        urls = []
        if scope in ("all", "local"):
            urls.append(f"/pm/config/adom/{adom}/obj/firewall/address")
        if scope in ("all", "global"):
            urls.append("/pm/config/global/obj/firewall/address")
        results: list = []
        for url in urls:
            try:
                results.extend(self._get_paged(url))
            except Exception:
                pass
        return results

    def get_address_groups(self, adom: str, scope: str = "all") -> list:
        """Return firewall address groups filtered by scope: 'local', 'global', or 'all'."""
        urls = []
        if scope in ("all", "local"):
            urls.append(f"/pm/config/adom/{adom}/obj/firewall/addrgrp")
        if scope in ("all", "global"):
            urls.append("/pm/config/global/obj/firewall/addrgrp")
        results: list = []
        for url in urls:
            try:
                results.extend(self._get_paged(url))
            except Exception:
                pass
        return results

    def get_service_objects(self, adom: str, scope: str = "all") -> list:
        """Return all custom service objects in an ADOM (services have no global pool)."""
        if scope == "global":
            return []
        try:
            data = self._get(f"/pm/config/adom/{adom}/obj/firewall/service/custom")
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def get_service_groups(self, adom: str, scope: str = "all") -> list:
        """Return all service groups in an ADOM (service groups have no global pool)."""
        if scope == "global":
            return []
        try:
            data = self._get(f"/pm/config/adom/{adom}/obj/firewall/service/group")
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def get_vip_objects(self, adom: str) -> list:
        """Return all firewall VIP objects in an ADOM plus the global database."""
        results: list = []
        for url in (
            f"/pm/config/adom/{adom}/obj/firewall/vip",
            "/pm/config/global/obj/firewall/vip",
        ):
            try:
                results.extend(self._get_paged(url))
            except Exception:
                pass
        return results

    def get_ippool_objects(self, adom: str) -> list:
        """Return all firewall IP pool objects in an ADOM plus the global database."""
        results: list = []
        for url in (
            f"/pm/config/adom/{adom}/obj/firewall/ippool",
            "/pm/config/global/obj/firewall/ippool",
        ):
            try:
                results.extend(self._get_paged(url))
            except Exception:
                pass
        return results

    def get_device_vip_objects(self, device: str, vdom: str = "root") -> list:
        """Return VIP objects from a specific device/vdom via the per-device DB path.

        Used by NAT lookup to find VIPs that are installed on a device but are
        not present in the ADOM shared-object database.
        """
        try:
            return self._get_paged(
                f"/pm/config/device/{device}/vdom/{vdom}/firewall/vip"
            )
        except Exception:
            return []

    def get_audit_log(self, hours: int = 24) -> list:
        """Return FortiManager audit log entries from the last ``hours`` hours.

        Returns a list of log entry dicts.  Returns an empty list on any error
        so callers can degrade gracefully if the FMG version doesn't support
        this endpoint.
        """
        since = int(time.time()) - (hours * 3600)
        try:
            body = {
                "id": self._next_id(),
                "method": "get",
                "params": [
                    {
                        "url": "/sys/audit-log",
                        "filter": [["timestamp", ">=", since]],
                        "sortings": [{"timestamp": -1}],
                        "range": [0, 5000],
                    }
                ],
            }
            if self.session:
                body["session"] = self.session
            data = self._post(body)
            result = data.get("result", [{}])[0]
            if result.get("status", {}).get("code", -1) != 0:
                return []
            entries = result.get("data", [])
            return entries if isinstance(entries, list) else []
        except Exception:
            return []

    def get_device_health(self, adom: str, device_name: str) -> dict:
        results = {}
        for ep in PROXY_ENDPOINTS:
            key = ep["key"]
            try:
                r = self._proxy(adom, device_name, ep["resource"])
                results[key] = r
            except Exception as exc:
                results[key] = {
                    "rpc_code": -1,
                    "http_status": 500,
                    "payload": {},
                    "error": str(exc),
                }
        return results

    def stream_device_health(self, adom: str, device_name: str):
        """Yield (index, total, label, key, result) for each proxy endpoint as it completes."""
        total = len(PROXY_ENDPOINTS)
        for i, ep in enumerate(PROXY_ENDPOINTS):
            key = ep["key"]
            label = ep.get("label", key)
            try:
                r = self._proxy(adom, device_name, ep["resource"])
            except Exception as exc:
                r = {
                    "rpc_code": -1,
                    "http_status": 500,
                    "payload": {},
                    "error": str(exc),
                }
            yield i + 1, total, label, key, r

    # ── CIS hardening data fetchers ───────────────────────────────────────────

    def get_device_admins(self, adom: str, device_name: str) -> list:
        """Return admin account list from the device via FMG proxy."""
        try:
            r = self._proxy(adom, device_name, "/api/v2/cmdb/system/admin?vdom=root")
            payload = r.get("payload", [])
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict):
                return list(payload.values())
            return []
        except Exception:
            return []

    def get_device_system_global(self, adom: str, device_name: str) -> dict:
        """Return system/global config from the device via FMG proxy."""
        try:
            r = self._proxy(adom, device_name, "/api/v2/cmdb/system/global?vdom=root")
            payload = r.get("payload", {})
            if isinstance(payload, list) and payload:
                return payload[0] if isinstance(payload[0], dict) else {}
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception:
            return {}

    def get_device_password_policy(self, adom: str, device_name: str) -> dict:
        """Return system/password-policy config from the device via FMG proxy."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/cmdb/system/password-policy?vdom=root"
            )
            payload = r.get("payload", {})
            if isinstance(payload, list) and payload:
                return payload[0] if isinstance(payload[0], dict) else {}
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception:
            return {}

    def get_device_log_disk(self, adom: str, device_name: str) -> dict:
        """Return log.disk/setting config from the device via FMG proxy."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/cmdb/log.disk/setting?vdom=root"
            )
            payload = r.get("payload", {})
            if isinstance(payload, list) and payload:
                return payload[0] if isinstance(payload[0], dict) else {}
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception:
            return {}

    def get_device_log_faz(self, adom: str, device_name: str) -> list[dict]:
        """Return all enabled log.fortianalyzer/setting slots (1, 2, 3) from the device."""
        slots = []
        endpoints = [
            "/api/v2/cmdb/log.fortianalyzer/setting?vdom=root",
            "/api/v2/cmdb/log.fortianalyzer2/setting?vdom=root",
            "/api/v2/cmdb/log.fortianalyzer3/setting?vdom=root",
        ]
        for endpoint in endpoints:
            try:
                r = self._proxy(adom, device_name, endpoint)
                payload = r.get("payload", {})
                if isinstance(payload, list) and payload:
                    entry = payload[0] if isinstance(payload[0], dict) else {}
                elif isinstance(payload, dict):
                    entry = payload
                else:
                    entry = {}
                if entry:
                    slots.append(entry)
            except Exception:
                pass
        return slots

    def get_device_dns(self, adom: str, device_name: str) -> dict:
        """Return system/dns config from the device via FMG proxy."""
        try:
            r = self._proxy(adom, device_name, "/api/v2/cmdb/system/dns?vdom=root")
            payload = r.get("payload", {})
            if isinstance(payload, list) and payload:
                return payload[0] if isinstance(payload[0], dict) else {}
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception:
            return {}

    def get_device_snmp_community(self, adom: str, device_name: str) -> list:
        """Return SNMP community list (v1/v2c) from the device via FMG proxy."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/cmdb/system/snmp/community?vdom=root"
            )
            payload = r.get("payload", [])
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict):
                return list(payload.values())
            return []
        except Exception:
            return []

    def get_device_snmp_sysinfo(self, adom: str, device_name: str) -> dict:
        """Return SNMP system info (enabled flag) from the device via FMG proxy."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/cmdb/system/snmp/sysinfo?vdom=root"
            )
            payload = r.get("payload", {})
            if isinstance(payload, list) and payload:
                return payload[0] if isinstance(payload[0], dict) else {}
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception:
            return {}

    def get_device_snmp_users(self, adom: str, device_name: str) -> list:
        """Return SNMPv3 user list from the device via FMG proxy."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/cmdb/system/snmp/user?vdom=root"
            )
            payload = r.get("payload", [])
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict):
                return list(payload.values())
            return []
        except Exception:
            return []

    def get_device_ha_status(self, adom: str, device_name: str) -> dict:
        """Return HA status from the device via FMG proxy (monitor endpoint)."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/monitor/system/ha-status?vdom=root"
            )
            payload = r.get("payload", {})
            if isinstance(payload, list) and payload:
                return payload[0] if isinstance(payload[0], dict) else {}
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception:
            return {}

    def get_device_ipsec_phase1(self, adom: str, device_name: str) -> list:
        """Return vpn.ipsec/phase1-interface config from all VDOMs via FMG proxy."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/cmdb/vpn.ipsec/phase1-interface?vdom=*"
            )
            payload = r.get("payload", [])
            if isinstance(payload, list):
                if payload and isinstance(payload[0], dict) and "results" in payload[0]:
                    flat = []
                    for item in payload:
                        vname = item.get("vdom", "root")
                        for entry in item.get("results", []):
                            if isinstance(entry, dict):
                                entry.setdefault("vdom", vname)
                                flat.append(entry)
                    return flat
                return [i for i in payload if isinstance(i, dict)]
            if isinstance(payload, dict):
                return list(payload.values())
            return []
        except Exception:
            return []

    def get_device_ipsec_phase2(self, adom: str, device_name: str) -> list:
        """Return vpn.ipsec/phase2-interface config from all VDOMs via FMG proxy."""
        try:
            r = self._proxy(
                adom, device_name, "/api/v2/cmdb/vpn.ipsec/phase2-interface?vdom=*"
            )
            payload = r.get("payload", [])
            if isinstance(payload, list):
                if payload and isinstance(payload[0], dict) and "results" in payload[0]:
                    flat = []
                    for item in payload:
                        vname = item.get("vdom", "root")
                        for entry in item.get("results", []):
                            if isinstance(entry, dict):
                                entry.setdefault("vdom", vname)
                                flat.append(entry)
                    return flat
                return [i for i in payload if isinstance(i, dict)]
            if isinstance(payload, dict):
                return list(payload.values())
            return []
        except Exception:
            return []
