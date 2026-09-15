#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import time
from pathlib import Path

SOCK = Path(os.environ.get("NVP_SERVER_SOCK", "/run/nexvary-panel/server.sock"))
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 512 * 1024
BASE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "DEBIAN_FRONTEND": "noninteractive",
}
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?=.+\..+)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
FINGERPRINT_RE = re.compile(r"^[a-f0-9]{64}$")
ACTIONS = {
    "server-overview",
    "server-network",
    "server-processes",
    "server-updates-preview",
    "server-updates-apply",
    "server-time-enable-ntp",
    "server-hostname-set",
}


def _run(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=BASE_ENV, check=False)
    if proc.returncode:
        raise RuntimeError(f"server-command-failed:{Path(args[0]).name}:{proc.returncode}")
    return proc


def _os_release() -> str:
    values: dict[str, str] = {}
    try:
        for raw in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            values[key] = value.strip().strip('"')
    except OSError:
        return platform.system()
    return str(values.get("PRETTY_NAME") or values.get("NAME") or platform.system())[:160]


def _time_state() -> dict:
    state = {"timezone": "", "ntp": False, "synchronized": False, "epoch": int(time.time())}
    try:
        proc = _run(["timedatectl", "show", "--property=Timezone", "--property=NTP", "--property=NTPSynchronized"], 10)
        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key == "Timezone":
                state["timezone"] = value[:96]
            elif key == "NTP":
                state["ntp"] = value.lower() == "yes"
            elif key == "NTPSynchronized":
                state["synchronized"] = value.lower() == "yes"
    except Exception:
        pass
    return state


def _overview() -> dict:
    try:
        uptime = int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        uptime = 0
    try:
        load = [round(float(x), 2) for x in os.getloadavg()]
    except OSError:
        load = []
    return {
        "ok": True,
        "hostname": socket.gethostname()[:253],
        "os": _os_release(),
        "kernel": platform.release()[:160],
        "architecture": platform.machine()[:64],
        "uptime_seconds": uptime,
        "load": load,
        "reboot_required": Path("/var/run/reboot-required").exists(),
        "time": _time_state(),
    }


def _network() -> dict:
    addresses: list[dict] = []
    routes: list[dict] = []
    nameservers: list[str] = []
    try:
        raw = json.loads(_run(["ip", "-j", "address", "show"], 12).stdout or "[]")
        for item in raw[:64] if isinstance(raw, list) else []:
            ifname = str(item.get("ifname", ""))[:64]
            for info in (item.get("addr_info") or [])[:32]:
                family = str(info.get("family", ""))
                local = str(info.get("local", ""))[:128]
                scope = str(info.get("scope", ""))[:32]
                if local and family in {"inet", "inet6"}:
                    addresses.append({"interface": ifname, "family": family, "address": local, "prefixlen": int(info.get("prefixlen", 0)), "scope": scope})
    except Exception:
        pass
    try:
        raw = json.loads(_run(["ip", "-j", "route", "show", "default"], 12).stdout or "[]")
        for item in raw[:16] if isinstance(raw, list) else []:
            routes.append({"dev": str(item.get("dev", ""))[:64], "gateway": str(item.get("gateway", ""))[:128], "protocol": str(item.get("protocol", ""))[:32]})
    except Exception:
        pass
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")[:16384]
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and len(nameservers) < 8:
                nameservers.append(parts[1][:128])
    except OSError:
        pass
    return {"ok": True, "addresses": addresses[:128], "default_routes": routes, "nameservers": nameservers}


def _processes() -> dict:
    rows: list[dict] = []
    try:
        proc = _run(["ps", "--no-headers", "-eo", "pid=,user=,comm=,%cpu=,%mem=,etimes=", "--sort=-%cpu"], 12)
        for line in proc.stdout.splitlines()[:30]:
            parts = line.split(None, 5)
            if len(parts) != 6:
                continue
            pid, user, command, cpu, mem, elapsed = parts
            if not pid.isdigit() or not elapsed.isdigit():
                continue
            try:
                cpu_value = float(cpu); mem_value = float(mem)
            except ValueError:
                continue
            rows.append({"pid": int(pid), "user": user[:64], "command": command[:96], "cpu": cpu_value, "memory": mem_value, "elapsed_seconds": int(elapsed)})
    except Exception:
        return {"ok": False, "error": "process-inventory-unavailable"}
    return {"ok": True, "processes": rows}


_INST_RE = re.compile(r"^Inst\s+(?P<name>[A-Za-z0-9][A-Za-z0-9+_.:-]{0,127})(?:\s+\[[^\]]*\])?\s+\((?P<version>[^ )]+)")


def _updates_preview() -> dict:
    try:
        proc = _run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], 90)
    except Exception:
        return {"ok": False, "error": "system-update-preview-unavailable"}
    packages: list[dict] = []
    normalized: list[str] = []
    for line in proc.stdout.splitlines():
        match = _INST_RE.match(line)
        if not match:
            continue
        name = match.group("name")[:128]
        version = match.group("version")[:160]
        packages.append({"name": name, "version": version})
        normalized.append(f"{name}={version}")
        if len(packages) >= 200:
            break
    fingerprint = hashlib.sha256("\n".join(normalized).encode()).hexdigest()
    return {
        "ok": True,
        "count": len(packages),
        "packages": packages,
        "fingerprint": fingerprint,
        "reboot_required": Path("/var/run/reboot-required").exists(),
        "generated_at": int(time.time()),
        "apply_supported": True,
    }


def _updates_apply(expected_fingerprint: object) -> dict:
    expected = str(expected_fingerprint or "").strip().lower()
    if not FINGERPRINT_RE.fullmatch(expected):
        return {"ok": False, "error": "invalid-system-update-fingerprint"}
    before = _updates_preview()
    if not before.get("ok"):
        return before
    actual = str(before.get("fingerprint", ""))
    if actual != expected:
        return {
            "ok": False,
            "error": "system-update-preview-stale",
            "expected_fingerprint": expected,
            "actual_fingerprint": actual,
        }
    planned = int(before.get("count", 0) or 0)
    if planned == 0:
        return {
            "ok": True,
            "changed": False,
            "applied_count": 0,
            "fingerprint": actual,
            "reboot_required": Path("/var/run/reboot-required").exists(),
        }
    try:
        _run([
            "apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "--with-new-pkgs", "upgrade"
        ], 1800)
    except Exception:
        return {"ok": False, "error": "system-update-apply-failed"}
    after = _updates_preview()
    if not after.get("ok"):
        after = {"count": 0, "fingerprint": "", "reboot_required": Path("/var/run/reboot-required").exists()}
    return {
        "ok": True,
        "changed": True,
        "applied_count": planned,
        "remaining_count": int(after.get("count", 0) or 0),
        "previous_fingerprint": actual,
        "fingerprint": str(after.get("fingerprint", "")),
        "reboot_required": bool(after.get("reboot_required")),
    }


def _enable_ntp() -> dict:
    _run(["timedatectl", "set-ntp", "true"], 20)
    return {"ok": True, "time": _time_state()}


def _set_hostname(value: object) -> dict:
    hostname = str(value or "").strip().lower().rstrip(".")
    if not HOSTNAME_RE.fullmatch(hostname):
        return {"ok": False, "error": "invalid-server-hostname"}
    previous = socket.gethostname()[:253]
    if previous.lower().rstrip(".") == hostname:
        state = _overview()
        state.update(changed=False, previous_hostname=previous)
        return state
    try:
        _run(["hostnamectl", "set-hostname", hostname], 30)
    except Exception:
        return {"ok": False, "error": "server-hostname-change-failed"}
    state = _overview()
    state.update(changed=True, previous_hostname=previous)
    return state


def dispatch(req: dict) -> dict:
    action = str(req.get("action", ""))
    if action not in ACTIONS:
        return {"ok": False, "error": "server-action-not-allowed"}
    if action == "server-overview":
        return _overview()
    if action == "server-network":
        return _network()
    if action == "server-processes":
        return _processes()
    if action == "server-updates-preview":
        return _updates_preview()
    if action == "server-updates-apply":
        return _updates_apply(req.get("fingerprint", ""))
    if action == "server-hostname-set":
        return _set_hostname(req.get("hostname", ""))
    return _enable_ntp()


def _reply(conn: socket.socket, body: dict) -> None:
    raw = (json.dumps(body, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAX_RESPONSE:
        raw = b'{"ok":false,"error":"server-response-too-large"}\n'
    conn.sendall(raw)


def main() -> None:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCK))
    gid = grp.getgrnam("nexvary-panel").gr_gid
    os.chown(SOCK, 0, gid)
    os.chmod(SOCK, 0o660)
    server.listen(16)
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                data = b""
                while not data.endswith(b"\n") and len(data) < MAX_REQUEST:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if len(data) >= MAX_REQUEST:
                    raise ValueError("request-too-large")
                req = json.loads(data.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("object-required")
                _reply(conn, dispatch(req))
            except Exception:
                _reply(conn, {"ok": False, "error": "server-request-failed"})


if __name__ == "__main__":
    main()
