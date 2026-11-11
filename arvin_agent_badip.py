#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
arvin-agent-badip: find out whether the IPv4 addresses ArvanCloud hands out
are reachable from Iran ("good") or blocked ("bad").

It runs on your Mac, not on the server. It uses two separate credentials:

  * ArvanCloud API key   -> panel access: add and remove public IPs.
  * SSH user "hani" with the key in your macOS ssh-agent (or any key file / key
    value) -> access to the VM itself, through the saved MANAGEMENT IP, to bring
    each test IP up on the NIC. Several servers: comma-separated management IPs.

One test run does ROUNDS rounds (default 5). Each round:

  1. ALLOCATE  one extra public IPv4 on the server (add-public-ip).
  2. CONFIGURE it inside the VM over SSH: address + source-policy routing on
     the hot-plugged NIC. The management IP and its routing are never touched.
  3. TEST      it from Iranian check-host.net nodes, CHECKS_PER_IP times,
               with control nodes outside Iran to rule out "server down".
  4. RELEASE   it: remove it from the OS, detach its port with the API, and
               wait until the panel no longer lists it.
  5. SAVE      the result to results.jsonl and results.csv.

Safety rules:
  * The management IP/port is never released, and no port that existed
    before a round is ever released. Only the port the round created is.
  * The pending allocation is written to state.json before the billable
    POST, so a crash or Ctrl-C can be cleaned up with `cleanup --yes`.
  * Before the first allocation, a policy route pins the management IP's
    replies to its own NIC (with a 90 s auto-revert watchdog in the VM), so a
    hot-plugged NIC with its own default route cannot cut off your SSH session.

Single file, Python 3.8+ standard library only. Needs the system `ssh`
client (macOS ships one) and a loaded ssh-agent.

!!! Not yet run against the real ArvanCloud API. Run `preflight`, then
    `test --dry-run`, then `test --rounds 1 --yes` before a full run.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import csv
import datetime as _dt
import getpass
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid as _uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

__version__ = "1.0.0"
PROJECT = "arvin-agent-badip"

# =============================================================================
# CONFIG defaults. `init` writes the per-server values to <HOME>/config.json,
# which overrides these. CLI flags override both for one run.
# =============================================================================
DEFAULTS: Dict[str, Any] = {
    # ---- ArvanCloud panel (API key) ---------------------------------------
    "ARVAN_API_BASE": "https://napi.arvancloud.ir/ecc/v1",
    "API_KEY_PREFIX": "Apikey ",
    "API_KEY": "",                    # the key itself OR the path of a file holding it
    "API_KEY_FILE": "",               # old name of API_KEY (value or path accepted)
    "REGION": "ir-thr-ba1",
    "SERVER_ID": "",                  # found by `init` from the management IP
    "SERVER_NAME": "",
    "IP_TYPE": "ipv4",

    # ---- Management access (never released) -------------------------------
    "MANAGEMENT_IP": "",              # one IP, or several servers: "1.2.3.4, 5.6.7.8"
    "MANAGEMENT_PORT_ID": "",         # filled by `init`
    "MANAGEMENT_IFACE": "",           # filled by `init` (from the VM)
    "MANAGEMENT_GATEWAY": "",         # filled by `init` (from the VM)
    "MANAGEMENT_CIDR": "",            # filled by `init` (from the VM)
    "PROTECT_MGMT_ROUTE": True,       # pin replies from the mgmt IP to its NIC
    "MGMT_TABLE": 2099,
    "MGMT_PRIORITY": 20999,
    "MGMT_WATCHDOG_SEC": 90,

    # ---- SSH into the VM ----------------------------------------------------
    "SSH_USER": "hani",
    "SSH_PORT": 22,
    # Path to the PUBLIC key (.pub) of the ssh-agent key to use. ssh then asks
    # the agent for exactly that key (IdentitiesOnly). "" = any agent key.
    "SSH_PUBKEY": "",
    # SSH_KEY: a path (private key, or .pub of an agent key) OR the key itself
    # (a one-line public key, or a private key with \n for line breaks).
    "SSH_KEY": "",
    "SSH_BIN": "ssh",
    "SSH_CONNECT_TIMEOUT": 10,
    # macOS/Linux: one interactive login per server (ssh may ask for a passphrase,
    # a PIN or a touch); every later command reuses that connection for this long.
    "SSH_MASTER_PERSIST_SEC": 1800,
    "SSH_LOGIN_TIMEOUT_SEC": 180,
    "SSH_EXTRA_OPTS": [],             # e.g. ["-o", "ProxyJump=bastion"]
    "SUDO": "sudo -n",                # "" if SSH_USER is root

    # ---- Test run -----------------------------------------------------------
    "ROUNDS": 5,                      # how many test IPs per run
    "CHECKS_PER_IP": 2,               # check-host cycles per test IP
    "ROUND_SPACING_SEC": 60,          # pause between rounds
    "BASELINE_CHECK": True,           # also probe the management IP once per run
    "MAX_PUBLIC_IPS_PER_SERVER": 4,   # Arvan per-server cap

    # ---- Policy routing for the test IP inside the VM ------------------------
    "POLICY_TABLE": 2100,
    "POLICY_PRIORITY": 21000,
    "NIC_APPEAR_TIMEOUT_SEC": 120,
    "PORT_ACTIVE_TIMEOUT_SEC": 180,
    "RELEASE_TIMEOUT_SEC": 180,
    "ALLOCATION_SETTLE_SEC": 60,
    "EGRESS_ECHO_URLS": ["https://api.ipify.org", "https://ifconfig.me/ip",
                         "https://icanhazip.com"],

    # ---- Iran reachability (check-host.net) ----------------------------------
    "CHECKHOST_BASE": "https://check-host.net",
    "CHECK_TYPE": "tcp",              # tcp | ping | http
    "CHECK_PORT": 22,                 # sshd listens on every address already
    "CHECK_HTTP_PATH": "/",
    "PROBE_NODES": [],
    "PROBE_NODES_FALLBACK": ["ir1.node.check-host.net", "ir2.node.check-host.net",
                             "ir3.node.check-host.net", "ir4.node.check-host.net",
                             "ir5.node.check-host.net", "ir6.node.check-host.net",
                             "ir7.node.check-host.net"],
    "PROBE_COUNTRY": "ir",
    "PROBE_MAX_NODES": 10,
    "MIN_CONCLUSIVE_NODES": 3,
    "FAIL_RATIO_THRESHOLD": 0.5,
    "CONTROL_NODES": [],
    "CONTROL_NODES_FALLBACK": ["de4.node.check-host.net", "fr2.node.check-host.net",
                               "nl1.node.check-host.net"],
    "CONTROL_MIN_SUCCESS": 1,
    "IRAN_CONTROL_TARGET": "1.1.1.1:443",
    "CHECKHOST_MIN_SPACING_SEC": 60,
    "CHECKHOST_RESULT_WAIT_SEC": 30,
    "CHECKHOST_RESULT_POLL_SEC": 3,
    "CHECKHOST_LIMIT_BACKOFF_SEC": 120,

    # ---- HTTP -------------------------------------------------------------------
    "HTTP_TIMEOUT_SEC": 30,
    "HTTP_RETRIES": 3,
    "HTTP_RETRY_BACKOFF_SEC": 2.0,
    "HTTP_USER_AGENT": "%s/%s" % (PROJECT, __version__),
    "LOG_LEVEL": "info",
}

IS_WINDOWS = os.name == "nt"
HOME_DIR = os.path.expanduser(os.environ.get("ABIP_HOME", "~/" + PROJECT))
KEYCHAIN_SERVICE = PROJECT

_SECRET_HINTS = ("key", "token", "secret", "password", "apikey", "authorization")


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def iso(ts: Optional[_dt.datetime] = None) -> str:
    return (ts or utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***REDACTED***" if isinstance(k, str) and k.lower() != "ssh_pubkey"
                    and any(h in k.lower() for h in _SECRET_HINTS) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return re.sub(r"(?i)(apikey|bearer)\s+[A-Za-z0-9\-\._~\+/=]+", r"\1 ***REDACTED***", obj)
    return obj


class AgentError(Exception):
    """A controlled, explained failure."""


class AbortRun(AgentError):
    """Stop the whole run (no more allocations)."""


class TransientError(AgentError):
    pass


class InconclusiveError(TransientError):
    pass


# =============================================================================
# Files: config.json, state.json, events.jsonl, checks.jsonl, results.*
# =============================================================================
def _write_json_atomic(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def server_dir(ip: str) -> str:
    return os.path.join(HOME_DIR, "servers", ip)


def config_path(ip: str) -> str:
    """What `init` found for one server (server id, mgmt port, NIC, gateway)."""
    return os.path.join(server_dir(ip), "config.json")


def parse_ip_list(value: Any) -> List[str]:
    items = value if isinstance(value, list) else re.split(r"[,\s;]+", str(value or ""))
    out: List[str] = []
    for x in items:
        x = str(x).strip()
        if not x:
            continue
        if not _is_ipv4(x):
            raise AgentError("management_ip: %r is not an IPv4 address" % x)
        if x not in out:
            out.append(x)
    return out


def _migrate_legacy() -> None:
    """Move a single-server config.json/state.json from v1.0 into servers/<ip>/."""
    old = os.path.join(HOME_DIR, "config.json")
    if not os.path.isfile(old):
        return
    with contextlib.suppress(OSError, ValueError):
        with open(old, encoding="utf-8") as fh:
            ip = json.load(fh).get("MANAGEMENT_IP")
        if ip and not os.path.exists(config_path(ip)):
            os.makedirs(server_dir(ip), exist_ok=True)
            os.replace(old, config_path(ip))
            st = os.path.join(HOME_DIR, "state.json")
            if os.path.isfile(st):
                os.replace(st, os.path.join(server_dir(ip), "state.json"))


# ---- YAML input file ---------------------------------------------------------
# A small parser for the flat YAML used by arvin-agent-badip.yaml (stdlib only):
#   key: value        scalars: "quoted", 'quoted', bare strings, ints, floats,
#                     true/false/yes/no, null/~ or empty
#   key: [a, b]       inline list
#   key:              block list
#     - a
# Comments (#) and blank lines are ignored. Nested mappings are rejected.
YAML_SEARCH = ["arvin-agent-badip.yaml", os.path.join(HOME_DIR, "config.yaml")]


def _yaml_strip_comment(line: str) -> str:
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _yaml_scalar(v: str, where: str) -> Any:
    v = v.strip()
    if v == "" or v in ("~", "null", "Null", "NULL"):
        return None
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [_yaml_scalar(x, where) for x in _yaml_split(inner)] if inner else []
    if v.startswith(("{", "&", "*", "|", ">")):
        raise AgentError("%s: unsupported YAML value %r (keep the file flat)" % (where, v))
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if re.fullmatch(r"[-+]?\d+", v):
        return int(v)
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?", v):
        return float(v)
    return v


def _yaml_split(s: str) -> List[str]:
    out, cur, q = [], "", None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            cur += ch
        elif ch == ",":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out]


def parse_simple_yaml(text: str, src: str = "yaml") -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    list_key: Optional[str] = None
    for n, raw in enumerate(text.splitlines(), 1):
        where = "%s line %d" % (src, n)
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise AgentError("%s: use spaces, not tabs, for indentation" % where)
        line = _yaml_strip_comment(raw)
        if not line.strip() or line.strip() in ("---", "..."):
            continue
        if line.lstrip().startswith("- "):
            if list_key is None or not raw.startswith((" ", "-")):
                raise AgentError("%s: list item without a key above it" % where)
            data[list_key].append(_yaml_scalar(line.lstrip()[2:], where))
            continue
        if line[0] == " ":
            raise AgentError("%s: nested values are not supported (keep the file flat)" % where)
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:(\s+(.*))?$", line)
        if not m:
            raise AgentError("%s: expected 'key: value', got %r" % (where, line))
        key, val = m.group(1), (m.group(3) or "")
        if key in data:
            raise AgentError("%s: duplicate key %r" % (where, key))
        if val.strip() == "":
            data[key], list_key = [], key       # may become a block list; fixed below
            continue
        data[key], list_key = _yaml_scalar(val, where), None
    # an empty "key:" that never got list items means null
    for k, v in list(data.items()):
        if v == [] and not re.search(r"^%s\s*:\s*\[\s*\]" % re.escape(k), text, re.M):
            data[k] = None
    return data


def find_yaml(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        p = os.path.expanduser(explicit)
        if not os.path.isfile(p):
            raise AgentError("config file %s not found" % p)
        return p
    for p in YAML_SEARCH:
        if os.path.isfile(p):
            return p
    return None


def load_yaml_inputs(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        raw = parse_simple_yaml(fh.read(), path)
    out: Dict[str, Any] = {}
    unknown = []
    for k, v in raw.items():
        K = k.upper()
        if K not in DEFAULTS:
            unknown.append(k)
            continue
        if v is None or (v == "" and K != "SUDO"):
            continue                              # empty -> keep the default / init value
        if isinstance(v, list) and K in ("MANAGEMENT_IP", "SERVER_ID"):
            v = ",".join(str(x) for x in v)       # [ip1, ip2] works as well as "ip1, ip2"
        d = DEFAULTS[K]
        if isinstance(d, bool):
            ok = isinstance(v, bool)
        elif isinstance(d, (int, float)):
            ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        elif isinstance(d, list):
            ok = isinstance(v, list)
        else:
            ok = True
            v = str(v)
        if not ok:
            raise AgentError("%s: %s should be %s, got %r" % (path, k, type(d).__name__, v))
        out[K] = v
    if unknown:
        raise AgentError("%s: unknown key(s): %s" % (path, ", ".join(unknown)))
    return out


def load_config(overrides: Optional[Dict[str, Any]] = None,
                yaml_path: Optional[str] = None) -> Dict[str, Any]:
    """Global inputs: DEFAULTS < YAML inputs < CLI flags (MANAGEMENT_IP may list several)."""
    _migrate_legacy()
    cfg = copy.deepcopy(DEFAULTS)
    ypath = find_yaml(yaml_path)
    if ypath:
        cfg.update(load_yaml_inputs(ypath))
    for k, v in (overrides or {}).items():
        if v is not None:
            cfg[k] = v
    cfg["_YAML_PATH"] = ypath or ""
    return cfg


def server_config(base: Dict[str, Any], ip: str, index: int, count: int) -> Dict[str, Any]:
    """Per-server config: DEFAULTS < saved by `init` < YAML < CLI, with MANAGEMENT_IP = ip."""
    cfg = copy.deepcopy(DEFAULTS)
    p = config_path(ip)
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as fh:
            saved = json.load(fh)
        unknown = [k for k in saved if k not in DEFAULTS]
        if unknown:
            raise AgentError("unknown key(s) in %s: %s" % (p, ", ".join(unknown)))
        cfg.update(saved)
    saved_sid = cfg.get("SERVER_ID") or ""
    for k, v in base.items():
        if k == "SERVER_ID" or v == DEFAULTS.get(k, object()):
            continue
        cfg[k] = v
    cfg["MANAGEMENT_IP"] = ip
    cfg["_YAML_PATH"] = base.get("_YAML_PATH", "")
    # server_id may be one UUID (single server) or a comma list in the same order as the IPs
    sids = [x.strip() for x in str(base.get("SERVER_ID") or "").split(",") if x.strip()]
    if sids:
        if len(sids) == count:
            cfg["SERVER_ID"] = sids[index]
        elif len(sids) == 1 and count == 1:
            cfg["SERVER_ID"] = sids[0]
        else:
            raise AgentError("server_id lists %d id(s) for %d management IP(s); give one per IP, "
                             "in the same order, or leave it empty" % (len(sids), count))
    else:
        cfg["SERVER_ID"] = saved_sid
    return cfg


class EventLog:
    LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}

    def __init__(self, cfg: Dict[str, Any], quiet: bool = False):
        self.min = self.LEVELS.get(str(cfg.get("LOG_LEVEL", "info")).lower(), 20)
        self.quiet = quiet
        os.makedirs(HOME_DIR, exist_ok=True)

    def _append(self, fname: str, rec: Dict[str, Any]) -> None:
        with contextlib.suppress(OSError):
            with open(os.path.join(HOME_DIR, fname), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(redact(rec), ensure_ascii=False, sort_keys=True) + "\n")

    def event(self, level: str, event: str, **fields: Any) -> None:
        if self.LEVELS.get(level, 20) < self.min:
            return
        rec = {"ts": iso(), "level": level, "event": event}
        rec.update(fields)
        self._append("events.jsonl", rec)
        if not self.quiet:
            tag = {"debug": "·", "info": "•", "warning": "!", "error": "✗"}.get(level, "•")
            extra = " ".join("%s=%s" % (k, json.dumps(redact(v), ensure_ascii=False))
                             for k, v in fields.items())
            sys.stdout.write("%s %s %-24s %s\n" % (time.strftime("%H:%M:%S"), tag, event, extra))
            sys.stdout.flush()

    def check(self, rec: Dict[str, Any]) -> None:
        r = {"ts": iso()}
        r.update(rec)
        self._append("checks.jsonl", r)

    def debug(self, e: str, **f: Any) -> None: self.event("debug", e, **f)
    def info(self, e: str, **f: Any) -> None: self.event("info", e, **f)
    def warning(self, e: str, **f: Any) -> None: self.event("warning", e, **f)
    def error(self, e: str, **f: Any) -> None: self.event("error", e, **f)


class State:
    """servers/<ip>/state.json: the allocation that is in flight on that server (if any)."""

    def __init__(self, ip: str) -> None:
        self.path = os.path.join(server_dir(ip), "state.json")
        self.data: Dict[str, Any] = {"pending": None, "runs": 0}
        if os.path.isfile(self.path):
            with open(self.path, encoding="utf-8") as fh:
                self.data.update(json.load(fh))

    def save(self) -> None:
        _write_json_atomic(self.path, self.data)

    @property
    def pending(self) -> Optional[Dict[str, Any]]:
        return self.data.get("pending")


RESULT_FIELDS = ["finished_at", "server", "run_id", "round", "ip", "port_id", "verdict",
                 "reachable_cycles", "blocked_cycles", "down_cycles", "inconclusive_cycles",
                 "best_ok_ratio", "egress_ok", "from_mac_tcp", "seen_before",
                 "released", "error", "links"]


def append_result(rec: Dict[str, Any]) -> None:
    os.makedirs(HOME_DIR, exist_ok=True)
    with open(os.path.join(HOME_DIR, "results.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    cpath = os.path.join(HOME_DIR, "results.csv")
    new = not os.path.exists(cpath)
    with open(cpath, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=RESULT_FIELDS, extrasaction="ignore")
        if new:
            w.writeheader()
        row = dict(rec)
        row["links"] = " ".join(rec.get("links") or [])
        w.writerow(row)


def load_results() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    p = os.path.join(HOME_DIR, "results.jsonl")
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                with contextlib.suppress(ValueError):
                    out.append(json.loads(line))
    return out


# =============================================================================
# Secrets: the ArvanCloud API key
# =============================================================================
def _looks_like_path(v: str) -> bool:
    return v.startswith(("~", ".", "/")) or "\\" in v or "/" in v or bool(re.match(r"^[A-Za-z]:", v)) \
        or v.lower().endswith((".txt", ".key", ".pub", ".pem"))


def _clean_api_key(v: str, src: str) -> str:
    v = v.strip()
    if v.lower().startswith("apikey "):
        v = v[7:].strip()
    if not v or not re.fullmatch(r"[\x21-\x7e]+", v):
        raise AgentError("the ArvanCloud API key from %s is empty or contains spaces/odd characters" % src)
    return v


def load_api_key(value: str = "") -> Tuple[Optional[str], str]:
    """api_key from the YAML (the key itself or a file path) -> $ARVAN_API_KEY
    -> <HOME>/api_key -> macOS Keychain."""
    value = (value or "").strip()
    if value:
        p = os.path.expanduser(value)
        if os.path.isfile(p) or _looks_like_path(value):
            if not os.path.isfile(p):
                raise AgentError("api_key looks like a file path but %s does not exist" % p)
            if not IS_WINDOWS and os.stat(p).st_mode & 0o077:
                raise AgentError("refusing %s: permissions are too open (chmod 600)" % p)
            with open(p, encoding="utf-8") as fh:
                return _clean_api_key(fh.read(), p), "file:%s" % p
        return _clean_api_key(value, "the YAML file"), "yaml (value)"
    v = os.environ.get("ARVAN_API_KEY", "").strip()
    if v:
        return _clean_api_key(v, "$ARVAN_API_KEY"), "env:$ARVAN_API_KEY"
    strip = lambda x: _clean_api_key(x, "file")  # noqa: E731
    p = os.path.join(HOME_DIR, "api_key")
    if os.path.isfile(p):
        mode = os.stat(p).st_mode
        if not IS_WINDOWS and mode & 0o077:
            raise AgentError("refusing %s: permissions %o are too open (chmod 600)" % (p, mode & 0o777))
        with open(p, encoding="utf-8") as fh:
            v = fh.read().strip()
        if v:
            return strip(v), "file:%s" % p
    if sys.platform == "darwin":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            r = subprocess.run(["security", "find-generic-password", "-a", getpass.getuser(),
                                "-s", KEYCHAIN_SERVICE, "-w"],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and r.stdout.strip():
                return strip(r.stdout), "keychain:%s" % KEYCHAIN_SERVICE
    if IS_WINDOWS:
        return None, ("missing: in PowerShell run  $env:ARVAN_API_KEY = Read-Host -MaskInput 'API key'  "
                      "or set api_key in the YAML file (the key itself or a file path)")
    return None, ("missing: set $ARVAN_API_KEY, write %s (chmod 600), or store it in the "
                  "macOS Keychain (see README)" % p)


# =============================================================================
# HTTP client
# =============================================================================
class HttpResponse:
    def __init__(self, status: int, headers: Dict[str, str], body: bytes, url: str):
        self.status, self.headers, self.body, self.url = status, headers, body, url

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8")) if self.body else None
        except (ValueError, UnicodeDecodeError):
            return None


class AmbiguousRequestError(TransientError):
    """A non-idempotent request failed in a way where it MAY have been applied."""


def _short_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return "%s://%s%s" % (p.scheme, p.netloc, p.path)


CA_FALLBACKS = ["/etc/ssl/cert.pem",                       # macOS, FreeBSD, Alpine
                "/etc/ssl/certs/ca-certificates.crt",      # Debian/Ubuntu
                "/etc/pki/tls/certs/ca-bundle.crt"]        # RHEL/Fedora


def make_ssl_context() -> ssl.SSLContext:
    """Verifying TLS context. Python from python.org on macOS ships without root
    certificates ("CERTIFICATE_VERIFY_FAILED ... unable to get local issuer
    certificate"), so when the default store is empty, load the system bundle
    (or certifi if it is installed). Verification is never turned off."""
    ctx = ssl.create_default_context()
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
        return ctx                                 # the user chose a bundle explicitly
    with contextlib.suppress(Exception):
        if ctx.cert_store_stats().get("x509_ca", 0) > 0:
            return ctx
    candidates = list(CA_FALLBACKS)
    with contextlib.suppress(Exception):
        import certifi  # type: ignore
        candidates.insert(0, certifi.where())
    for path in candidates:
        if os.path.isfile(path):
            with contextlib.suppress(ssl.SSLError, OSError):
                ctx.load_verify_locations(cafile=path)
                return ctx
    return ctx


class Http:
    def __init__(self, cfg: Dict[str, Any], log: EventLog, read_only: bool = False):
        self.cfg, self.log, self.read_only = cfg, log, read_only
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=make_ssl_context()))
        self.mutations: List[str] = []
        self._sunset_warned: set = set()

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                json_body: Any = None, idempotent: Optional[bool] = None,
                retries: Optional[int] = None, timeout: Optional[float] = None,
                raw_body: Optional[bytes] = None) -> HttpResponse:
        method = method.upper()
        mutating = method not in ("GET", "HEAD")
        if mutating and self.read_only:
            raise AgentError("SAFETY: refusing %s %s in dry-run mode" % (method, _short_url(url)))
        if idempotent is None:
            idempotent = not mutating
        hdrs = {"User-Agent": self.cfg["HTTP_USER_AGENT"], "Accept": "application/json"}
        hdrs.update(headers or {})
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif raw_body is not None:
            data = raw_body
            hdrs["Content-Type"] = "application/json"
        n = int(self.cfg["HTTP_RETRIES"] if retries is None else retries)
        attempts = 1 + (n if idempotent else 0)
        backoff = float(self.cfg["HTTP_RETRY_BACKOFF_SEC"])
        if mutating:
            self.mutations.append("%s %s" % (method, _short_url(url)))
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
                with self._opener.open(req, timeout=float(timeout or self.cfg["HTTP_TIMEOUT_SEC"])) as r:
                    status, rh, body = r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
            except urllib.error.HTTPError as exc:
                status = exc.code
                rh = {k.lower(): v for k, v in (exc.headers or {}).items()}
                try:
                    body = exc.read()
                except Exception:  # noqa: BLE001
                    body = b""
            except (urllib.error.URLError, socket.timeout, ConnectionError, ssl.SSLError, OSError) as exc:
                if attempt < attempts - 1:
                    time.sleep(backoff * (2 ** attempt))
                    continue
                if mutating and not idempotent:
                    raise AmbiguousRequestError("%s %s failed at network level (%s); it MAY have "
                                                "been applied" % (method, _short_url(url), exc))
                hint = ""
                if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                    hint = (" | fix: run '/Applications/Python 3.x/Install Certificates.command' "
                            "(python.org Python on macOS), or  export SSL_CERT_FILE=/etc/ssl/cert.pem")
                raise TransientError("%s %s network error: %s%s" % (method, _short_url(url), exc, hint))
            for h in ("sunset", "deprecation"):
                if h in rh and h not in self._sunset_warned:
                    self._sunset_warned.add(h)
                    self.log.warning("api_deprecation_header", header=h, value=rh[h])
            if (status >= 500 or status == 429) and attempt < attempts - 1:
                wait = backoff * (2 ** attempt)
                ra = rh.get("retry-after")
                if ra and ra.isdigit():
                    wait = max(wait, min(float(ra), 120.0))
                time.sleep(wait)
                continue
            return HttpResponse(status, rh, body, url)
        raise TransientError("request failed")  # pragma: no cover


# =============================================================================
# ArvanCloud IaaS v1 API (same endpoints as the official CLI / Terraform provider)
# =============================================================================
class ApiError(AgentError):
    def __init__(self, method: str, url: str, status: int, message: str, rid: Optional[str]):
        self.status = status
        self.kind = {401: "unauthenticated", 403: "forbidden", 404: "not_found",
                     420: "quota_exceeded", 429: "rate_limited"}.get(
            status, "server_error" if status >= 500 else "client_error")
        super().__init__("%s %s -> HTTP %d (%s): %s%s" % (
            method, _short_url(url), status, self.kind, message,
            " [X-AR-Request-Id=%s]" % rid if rid else ""))

    @property
    def transient(self) -> bool:
        return self.kind in ("rate_limited", "server_error")


def _api_message(resp: HttpResponse) -> str:
    j = resp.json
    if isinstance(j, dict):
        for k in ("message", "error", "errors", "detail"):
            if j.get(k):
                v = j[k]
                return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)[:500]
    return resp.text[:300]


def _is_ipv4(s: Any) -> bool:
    try:
        return isinstance(ipaddress.ip_address(str(s)), ipaddress.IPv4Address)
    except ValueError:
        return False


def _is_public_ipv4(s: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(s))
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except ValueError:
        return False


class ArvanAPI:
    def __init__(self, cfg: Dict[str, Any], http: Http, api_key: Optional[str]):
        self.cfg, self.http, self._key = cfg, http, api_key
        self.base = cfg["ARVAN_API_BASE"].rstrip("/")
        self.server_id = cfg.get("SERVER_ID") or ""

    def _headers(self) -> Dict[str, str]:
        if not self._key:
            raise AbortRun("no ArvanCloud API key available")
        return {"Authorization": self.cfg["API_KEY_PREFIX"] + self._key}

    def call(self, method: str, url: str, body: Any = None, idempotent: Optional[bool] = None,
             allow_404: bool = False, empty_body: bool = False) -> Any:
        resp = self.http.request(method, url, headers=self._headers(), json_body=body,
                                 idempotent=idempotent, raw_body=b"" if empty_body else None)
        if 200 <= resp.status < 300:
            j = resp.json
            return j["data"] if isinstance(j, dict) and "data" in j else j
        if resp.status == 404 and allow_404:
            return None
        raise ApiError(method, url, resp.status, _api_message(resp), resp.headers.get("x-ar-request-id"))

    def _r(self, path: str) -> str:
        return "%s/regions/%s%s" % (self.base, self.cfg["REGION"], path)

    def list_servers(self) -> List[Dict[str, Any]]:
        return self.call("GET", self._r("/servers")) or []

    def get_server(self) -> Dict[str, Any]:
        return self.call("GET", self._r("/servers/%s" % self.server_id)) or {}

    def list_networks(self) -> List[Dict[str, Any]]:
        return self.call("GET", self._r("/networks")) or []

    def get_quotas(self) -> Any:
        return self.call("GET", self._r("/quotas"))

    # Endpoints below are the ones ArvanCloud's own Terraform provider uses
    # (github.com/arvancloud/terraform-provider-arvan, internal/api/iaas):
    #   POST  /servers/{id}/add-public-ip          empty body, reply not used
    #   PATCH /networks/{port_id}/detach           {"server_id": ...}
    #   GET   /networks                            subnets[].servers[].ips[] = the ports
    def add_public_ip_preview(self) -> Dict[str, Any]:
        return {"method": "POST", "url": self._r("/servers/%s/add-public-ip" % self.server_id),
                "body": None}

    def add_public_ip(self, body: Optional[Dict[str, Any]] = None) -> Any:
        """BILLABLE and NOT idempotent: one request per call. body=None sends an empty body
        (as the Terraform provider does); otherwise the given JSON body is sent."""
        url = self.add_public_ip_preview()["url"]
        resp = self.http.request("POST", url, headers=self._headers(), json_body=body,
                                 idempotent=False, raw_body=None if body is not None else b"")
        if 200 <= resp.status < 300:
            return resp.json
        raise ApiError("POST", url, resp.status,
                       "%s | raw response: %s" % (_api_message(resp), resp.text[:400]),
                       resp.headers.get("x-ar-request-id"))

    def server_security_group_ids(self) -> List[str]:
        out = []
        for g in self.get_server().get("security_groups") or []:
            gid = g.get("id") if isinstance(g, dict) else g
            if gid:
                out.append(str(gid))
        return out

    def detach_preview(self, port_id: str) -> Dict[str, Any]:
        return {"method": "PATCH", "url": self._r("/networks/%s/detach" % port_id),
                "body": {"server_id": self.server_id}}

    def detach_port(self, port_id: str) -> Any:
        p = self.detach_preview(port_id)
        return self.call("PATCH", p["url"], body=p["body"], idempotent=False)

    @staticmethod
    def server_ipv4s(server: Dict[str, Any]) -> List[str]:
        out = []
        for _net, addrs in (server.get("addresses") or {}).items():
            for a in addrs or []:
                if _is_ipv4(a.get("addr")):
                    out.append(a["addr"])
        return out

    def ports(self, networks: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Every port of THIS server, from the networks listing:
        [{ip, port_id, mac, public, float_ip, version, network_id, network_name, cidr, gateway}]."""
        out: List[Dict[str, Any]] = []
        for n in (networks if networks is not None else self.list_networks()):
            for sn in n.get("subnets") or []:
                for srv in sn.get("servers") or []:
                    if srv.get("id") != self.server_id:
                        continue
                    for x in srv.get("ips") or []:
                        ip = x.get("ip") or x.get("ip_address") or x.get("addr")
                        if not ip:
                            continue
                        out.append({"ip": ip,
                                    "port_id": x.get("port_id") or x.get("id"),
                                    "mac": str(x.get("mac_address") or x.get("mac_addr") or "").lower(),
                                    "public": x.get("public") if "public" in x else x.get("is_public"),
                                    "float_ip": bool(x.get("float_ip")),
                                    "version": str(x.get("version") or ""),
                                    "network_id": n.get("id"), "network_name": n.get("name"),
                                    "cidr": sn.get("cidr"), "gateway": sn.get("gateway_ip")})
        return out

    def public_inventory(self) -> List[Dict[str, Any]]:
        """The server's public IPv4 ports (floating IPs are not ports, so they are left out)."""
        inv = []
        for x in self.ports():
            if not _is_ipv4(x["ip"]) or x["float_ip"] or not x["port_id"]:
                continue
            if x["public"] is True or (x["public"] is None and _is_public_ipv4(x["ip"])):
                inv.append(x)
        return inv


# =============================================================================
# check-host.net reachability from Iran (with control nodes outside Iran)
# =============================================================================
REACHABLE, BLOCKED, INCONCLUSIVE, DOWN = "REACHABLE", "BLOCKED", "INCONCLUSIVE", "DOWN"


class CheckHostLimit(TransientError):
    pass


def classify_node_result(ctype: str, value: Any) -> Tuple[str, str]:
    """One node's raw check-host result -> ('ok'|'fail'|'unknown', detail)."""
    if value is None:
        return "unknown", "pending/no result"
    try:
        if ctype == "tcp":
            if not isinstance(value, list) or not value or value[0] is None:
                return "unknown", "no data"
            first = value[0]
            if isinstance(first, dict) and "error" in first:
                return "fail", str(first.get("error"))
            if isinstance(first, dict) and ("time" in first or "address" in first):
                return "ok", "connected in %ss" % first.get("time")
            return "unknown", "unparsed"
        if ctype == "ping":
            if not isinstance(value, list) or not value:
                return "unknown", "no data"
            pings = value[0]
            if not isinstance(pings, list) or not pings or pings[0] is None:
                return "unknown", "no data"
            oks = [p for p in pings if isinstance(p, list) and p and p[0] == "OK"]
            return ("ok", "%d/%d replies" % (len(oks), len(pings))) if oks else \
                   ("fail", "0/%d replies" % len(pings))
        if ctype == "http":
            if not isinstance(value, list) or not value or not isinstance(value[0], list):
                return "unknown", "no data"
            r = value[0]
            code = r[3] if len(r) > 3 else None
            if code not in (None, "", 0):
                return "ok", "HTTP %s" % code
            return ("ok" if (r[0] if r else 0) == 1 else "fail"), str(r[2] if len(r) > 2 else "")
    except (TypeError, IndexError, KeyError) as exc:
        return "unknown", "parse error: %s" % exc
    return "unknown", "unsupported check type"


class CheckHost:
    last_submit = 0.0          # shared by all servers in one run (check-host rate limit)
    PREFERRED_CONTROL_COUNTRIES = ("de", "nl", "fi", "fr", "se", "gb", "pl", "ch", "at", "cz")

    def __init__(self, cfg: Dict[str, Any], http: Http, log: EventLog):
        self.cfg, self.http, self.log = cfg, http, log
        self.base = cfg["CHECKHOST_BASE"].rstrip("/")
        self._nodes: Optional[Dict[str, Any]] = None

    def nodes(self) -> Dict[str, Any]:
        if self._nodes is None:
            resp = self.http.request("GET", self.base + "/nodes/hosts", retries=1)
            j = resp.json if resp.status == 200 else None
            if not isinstance(j, dict) or not isinstance(j.get("nodes"), dict):
                raise TransientError("check-host /nodes/hosts unavailable (HTTP %s)" % resp.status)
            self._nodes = j["nodes"]
        return self._nodes

    def probe_nodes(self) -> List[str]:
        if self.cfg["PROBE_NODES"]:
            return list(self.cfg["PROBE_NODES"])
        try:
            cc = str(self.cfg["PROBE_COUNTRY"]).lower()
            found = sorted(n for n, m in self.nodes().items()
                           if str((m.get("location") or [""])[0]).lower() == cc)
            if found:
                return found[: int(self.cfg["PROBE_MAX_NODES"])]
        except TransientError as exc:
            self.log.warning("checkhost_nodes_unavailable", error=str(exc))
        return list(self.cfg["PROBE_NODES_FALLBACK"])

    def control_nodes(self) -> List[str]:
        if self.cfg["CONTROL_NODES"]:
            return list(self.cfg["CONTROL_NODES"])
        with contextlib.suppress(TransientError):
            nodes, picked = self.nodes(), []
            for cc in self.PREFERRED_CONTROL_COUNTRIES:
                for n in sorted(nodes):
                    if str((nodes[n].get("location") or [""])[0]).lower() == cc:
                        picked.append(n)
                        break
                if len(picked) >= 3:
                    break
            if picked:
                return picked
        return list(self.cfg["CONTROL_NODES_FALLBACK"])

    def submit(self, ctype: str, host: str, nodes: List[str]) -> Tuple[str, Dict[str, Any], str]:
        wait = CheckHost.last_submit + float(self.cfg["CHECKHOST_MIN_SPACING_SEC"]) - time.time()
        if wait > 0:
            self.log.debug("checkhost_pacing", sleep_sec=int(wait))
            time.sleep(wait)
        q = [("host", host)] + [("node", n) for n in nodes]
        url = "%s/check-%s?%s" % (self.base, ctype, urllib.parse.urlencode(q))
        CheckHost.last_submit = time.time()
        resp = self.http.request("GET", url, retries=0)
        j = resp.json
        if resp.status == 429 or (isinstance(j, dict) and j.get("error") == "limit_exceeded"):
            raise CheckHostLimit("check-host.net rate limit")
        if resp.status != 200 or not isinstance(j, dict) or not j.get("ok"):
            raise InconclusiveError("check-host submit failed: HTTP %s %s" % (resp.status, resp.text[:200]))
        return str(j["request_id"]), dict(j.get("nodes") or {}), str(j.get("permanent_link") or "")

    def results(self, rid: str, nodes: List[str]) -> Dict[str, Any]:
        deadline = time.time() + float(self.cfg["CHECKHOST_RESULT_WAIT_SEC"])
        last: Dict[str, Any] = {}
        while True:
            time.sleep(float(self.cfg["CHECKHOST_RESULT_POLL_SEC"]))
            resp = self.http.request("GET", "%s/check-result/%s" % (self.base, rid), retries=1)
            if resp.status == 200 and isinstance(resp.json, dict):
                last = resp.json
                if all(last.get(n) is not None for n in nodes):
                    return last
            if time.time() >= deadline:
                return last

    def run(self, ctype: str, host: str, nodes: List[str]) -> Tuple[Dict[str, Any], List[str], str]:
        for attempt in range(2):
            try:
                rid, accepted, link = self.submit(ctype, host, nodes)
                acc = [n for n in nodes if n in accepted] or list(accepted.keys())
                return self.results(rid, acc), acc, link
            except CheckHostLimit:
                if attempt == 0:
                    self.log.warning("checkhost_limit_backoff", sleep_sec=self.cfg["CHECKHOST_LIMIT_BACKOFF_SEC"])
                    time.sleep(float(self.cfg["CHECKHOST_LIMIT_BACKOFF_SEC"]))
        raise InconclusiveError("check-host.net rate limit persisted")


class Reachability:
    """One cycle = one check-host request from Iranian + control nodes."""

    def __init__(self, cfg: Dict[str, Any], ch: CheckHost, log: EventLog):
        self.cfg, self.ch, self.log = cfg, ch, log

    def target(self, ip: str) -> str:
        t, port = self.cfg["CHECK_TYPE"], int(self.cfg["CHECK_PORT"])
        if t == "tcp":
            return "%s:%d" % (ip, port)
        if t == "http":
            return "%s://%s:%d%s" % ("https" if port == 443 else "http", ip, port, self.cfg["CHECK_HTTP_PATH"])
        return ip

    def cycle(self, ip: str, purpose: str) -> Dict[str, Any]:
        ctype = self.cfg["CHECK_TYPE"]
        if ctype not in ("tcp", "ping", "http"):
            raise AbortRun("CHECK_TYPE must be tcp, ping or http")
        probes = self.ch.probe_nodes()
        controls = [n for n in self.ch.control_nodes() if n not in probes]
        raw, accepted, link = self.ch.run(ctype, self.target(ip), probes + controls)
        per_node = {}
        for n in accepted:
            v, d = classify_node_result(ctype, raw.get(n))
            per_node[n] = {"v": v, "d": d, "probe": n in probes}
        ir = {k: x for k, x in per_node.items() if x["probe"]}
        ctl = {k: x for k, x in per_node.items() if not x["probe"]}
        ok = [n for n, x in ir.items() if x["v"] == "ok"]
        fail = [n for n, x in ir.items() if x["v"] == "fail"]
        unknown = [n for n in probes if n not in ok and n not in fail]
        ctl_ok = sum(1 for x in ctl.values() if x["v"] == "ok")
        ctl_concl = sum(1 for x in ctl.values() if x["v"] in ("ok", "fail"))
        res: Dict[str, Any] = {"purpose": purpose, "ip": ip, "type": ctype, "target": self.target(ip),
                               "link": link, "ok": len(ok), "fail": len(fail), "unknown": len(unknown),
                               "control_ok": ctl_ok, "nodes": per_node}
        min_c, thr = int(self.cfg["MIN_CONCLUSIVE_NODES"]), float(self.cfg["FAIL_RATIO_THRESHOLD"])

        def finish(verdict: str, why: str) -> Dict[str, Any]:
            concl = res["ok"] + res["fail"]
            res.update(verdict=verdict, why=why, ok_ratio=round(res["ok"] / concl, 3) if concl else None)
            self.log.check(res)
            self.log.event("info" if verdict == REACHABLE else "warning", "reachability_cycle",
                           purpose=purpose, ip=ip, verdict=verdict, ok=res["ok"], fail=res["fail"],
                           unknown=res["unknown"], control_ok=ctl_ok, why=why, link=link)
            return res

        if len(ok) + len(fail) < min_c:
            return finish(INCONCLUSIVE, "only %d conclusive Iranian nodes (< %d)" % (len(ok) + len(fail), min_c))
        if len(fail) / float(len(ok) + len(fail)) <= thr:
            return finish(REACHABLE, "%d/%d Iranian nodes reached it" % (len(ok), len(ok) + len(fail)))
        if ctl_ok < int(self.cfg["CONTROL_MIN_SUCCESS"]):
            if ctl_concl == 0:
                return finish(INCONCLUSIVE, "Iran failed but no control node answered")
            return finish(DOWN, "unreachable from outside Iran too (OS config, firewall or "
                                "security group problem, not an Iran block)")
        guard = str(self.cfg.get("IRAN_CONTROL_TARGET") or "").strip()
        if guard:
            graw, _gacc, glink = self.ch.run("tcp", guard, fail)
            healthy = [n for n in fail if classify_node_result("tcp", graw.get(n))[0] == "ok"]
            res["probe_guard"] = {"target": guard, "link": glink, "healthy_failing_nodes": healthy}
            dropped = [n for n in fail if n not in healthy]
            for n in dropped:
                per_node[n]["d"] += " (ignored: node cannot reach control target)"
            fail = healthy
            res["fail"], res["unknown"] = len(fail), len(unknown) + len(dropped)
            if len(ok) + len(fail) < min_c:
                return finish(INCONCLUSIVE, "Iranian probe nodes look unhealthy (cannot reach %s)" % guard)
            if len(fail) / float(len(ok) + len(fail)) <= thr:
                return finish(REACHABLE, "after probe-health filtering %d/%d reached" % (len(ok), len(ok) + len(fail)))
        return finish(BLOCKED, "%d/%d Iranian nodes failed while %d control node(s) outside Iran succeeded"
                      % (len(fail), len(ok) + len(fail), ctl_ok))


def aggregate_verdict(verdicts: List[str]) -> str:
    """Per-IP verdict from its cycles: GOOD, BAD, MIXED, UNTESTABLE or INCONCLUSIVE."""
    r, b, d = verdicts.count(REACHABLE), verdicts.count(BLOCKED), verdicts.count(DOWN)
    if b > r:
        return "BAD"
    if r > b:
        return "GOOD"
    if r and r == b:
        return "MIXED"
    if d:
        return "UNTESTABLE"
    return "INCONCLUSIVE"


# =============================================================================
# SSH into the VM (system ssh client + macOS ssh-agent)
# =============================================================================
class SshError(AgentError):
    pass


class Ssh:
    def __init__(self, cfg: Dict[str, Any], log: EventLog):
        self.cfg, self.log = cfg, log
        self.host = cfg["MANAGEMENT_IP"]
        self.identity, self.pub_id, self.key_kind = resolve_ssh_identity(cfg)

    def base_cmd(self, multiplex: bool = True) -> List[str]:
        c = self.cfg
        cmd = [c["SSH_BIN"], "-p", str(c["SSH_PORT"]),
               "-o", "BatchMode=yes",
               "-o", "ConnectTimeout=%d" % int(c["SSH_CONNECT_TIMEOUT"]),
               "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
               "-o", "StrictHostKeyChecking=accept-new"]
        if multiplex and not IS_WINDOWS:     # Windows OpenSSH has no ControlMaster support
            cmd += ["-o", "ControlMaster=no", "-o", "ControlPath=/tmp/abip-%C"]   # reuse the master only
        elif not IS_WINDOWS:
            cmd += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
        if self.identity:
            cmd += ["-o", "IdentityFile=%s" % self.identity, "-o", "IdentitiesOnly=yes"]
        cmd += list(c.get("SSH_EXTRA_OPTS") or [])
        cmd += ["%s@%s" % (c["SSH_USER"], self.host)]
        return cmd

    # ---- one interactive login, then a shared connection (macOS/Linux) ---------------
    def master_alive(self) -> bool:
        p = subprocess.run(self.base_cmd() + ["-O", "check"], capture_output=True, timeout=15)
        return p.returncode == 0

    def ensure_master(self) -> None:
        """Log in ONCE with the terminal attached, so ssh can ask for a key passphrase,
        a security-key PIN or a touch. All later commands reuse this connection and
        never authenticate again. Not available on Windows (no ControlMaster there)."""
        if IS_WINDOWS or self.master_alive():
            return
        c = self.cfg
        target = "%s@%s" % (c["SSH_USER"], self.host)

        def login(with_identity: bool) -> bool:
            cmd = [c["SSH_BIN"], "-p", str(c["SSH_PORT"]),
                   "-o", "ConnectTimeout=%d" % int(c["SSH_CONNECT_TIMEOUT"]),
                   "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
                   "-o", "StrictHostKeyChecking=accept-new",
                   "-o", "ControlMaster=yes", "-o", "ControlPath=/tmp/abip-%C",
                   "-o", "ControlPersist=%d" % int(c["SSH_MASTER_PERSIST_SEC"])]
            if with_identity and self.identity:
                cmd += ["-o", "IdentityFile=%s" % self.identity, "-o", "IdentitiesOnly=yes"]
            cmd += list(c.get("SSH_EXTRA_OPTS") or []) + ["-f", "-N", target]
            try:
                p = subprocess.run(cmd, timeout=float(c["SSH_LOGIN_TIMEOUT_SEC"]))   # terminal attached
            except subprocess.TimeoutExpired:
                raise SshError("ssh login to %s was not completed within %ss"
                               % (target, c["SSH_LOGIN_TIMEOUT_SEC"]))
            return p.returncode == 0 and self.master_alive()

        print("ssh login to %s (ssh may ask for a passphrase, a PIN or a touch) ..." % target, flush=True)
        if login(True):
            return
        if self.identity:
            print("login with ssh_key failed; trying again the way plain `ssh %s` does ..." % target,
                  flush=True)
            if login(False):
                self.log.warning("ssh_key_not_used", detail="logged in with ssh's default keys instead; "
                                                            "set ssh_key to \"\" in the YAML file")
                return
        raise SshError("ssh login to %s failed (see the ssh messages above). Check that "
                       "`ssh %s` works by hand" % (target, target))

    def fresh_ok(self) -> bool:
        """Can a NEW connection reach sshd on the management IP? macOS/Linux: a plain TCP
        connect that reads the SSH banner (no login, so no PIN prompt). Windows: a new ssh."""
        if IS_WINDOWS:
            try:
                self.run("true", multiplex=False, timeout=30)
                return True
            except SshError:
                return False
        try:
            with socket.create_connection((self.host, int(self.cfg["SSH_PORT"])), timeout=10) as sk:
                sk.settimeout(10)
                return sk.recv(64).startswith(b"SSH-")
        except OSError:
            return False

    def run(self, remote: str, stdin: Optional[str] = None, check: bool = True,
            timeout: float = 60, multiplex: bool = True) -> subprocess.CompletedProcess:
        if multiplex:
            self.ensure_master()
        cmd = self.base_cmd(multiplex) + ["--", remote]
        self.log.debug("ssh", remote=remote)
        try:
            p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout,
                               encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            raise SshError("ssh %s@%s timed out after %ss running: %s"
                           % (self.cfg["SSH_USER"], self.host, timeout, remote))
        if p.returncode == 255:
            raise SshError("ssh %s@%s failed: %s" % (self.cfg["SSH_USER"], self.host,
                                                    (p.stderr or "").strip()[:300]))
        if check and p.returncode != 0:
            raise SshError("remote command failed (rc=%d): %s\n%s"
                           % (p.returncode, remote, (p.stderr or p.stdout).strip()[:500]))
        return p

    def sudo_sh(self, script: str, check: bool = True, timeout: float = 60) -> subprocess.CompletedProcess:
        """Run a POSIX sh script as root (script sent on stdin, so no quoting issues)."""
        sudo = self.sudo_prefix()
        return self.run(("%s sh -s" % sudo).strip(), stdin="set -e\n" + script, check=check,
                        timeout=timeout)

    def ip_json(self, args: str) -> List[Dict[str, Any]]:
        out = self.run("ip -j %s" % args, check=False).stdout.strip()
        try:
            return json.loads(out) if out else []
        except ValueError:
            return []

    def sudo_prefix(self) -> str:
        if str(self.cfg.get("SSH_USER")) == "root":
            return ""                          # already root: no sudo needed
        return (self.cfg.get("SUDO") or "").strip()

    def close_master(self) -> None:
        if IS_WINDOWS:
            return
        with contextlib.suppress(Exception):
            subprocess.run(self.base_cmd() + ["-O", "exit"], capture_output=True, timeout=10)

    # ---- inspection helpers ----------------------------------------------------
    def iface_for_mac(self, mac: str) -> Optional[str]:
        for link in self.ip_json("link show"):
            if str(link.get("address", "")).lower() == mac.lower():
                return link.get("ifname")
        return None

    def addr_info(self, ip: str) -> Optional[Tuple[str, int]]:
        for a in self.ip_json("-4 addr show"):
            for ai in a.get("addr_info", []):
                if ai.get("local") == ip:
                    return a.get("ifname"), int(ai.get("prefixlen"))
        return None

    def gateway_on(self, ifname: str) -> Optional[str]:
        for r in self.ip_json("-4 route show default"):
            if r.get("dev") == ifname and r.get("gateway"):
                return r["gateway"]
        return None

    def egress_from(self, src_ip: str) -> Optional[str]:
        """Public IP seen by echo services for traffic sourced from src_ip."""
        seen: Dict[str, int] = {}
        for url in self.cfg["EGRESS_ECHO_URLS"]:
            p = self.run("curl -4 -s --noproxy '*' --max-time 8 --interface %s %s || "
                         "wget -4 -q --no-proxy -T 8 --bind-address=%s -O - %s"
                         % (shlex.quote(src_ip), shlex.quote(url), shlex.quote(src_ip), shlex.quote(url)),
                         check=False, timeout=40)
            words = p.stdout.split()
            if words and _is_ipv4(words[0]):
                seen[words[0]] = seen.get(words[0], 0) + 1
                if seen[words[0]] >= 2:
                    return words[0]
        return max(seen, key=lambda k: seen[k]) if seen else None


PUBKEY_PREFIXES = ("ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")


def _write_private(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.chmod(path, 0o600)
    if IS_WINDOWS:   # Windows OpenSSH refuses private keys other users can read
        user = os.environ.get("USERNAME") or getpass.getuser()
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", "%s:F" % user],
                       capture_output=True, text=True)


def resolve_ssh_identity(cfg: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], str]:
    """(IdentityFile path or None, "<type> <base64>" of the public key or None, kind).
    kind: none | agent-pub (agent must hold it) | private (ssh reads the file)."""
    v = str(cfg.get("SSH_KEY") or cfg.get("SSH_PUBKEY") or "").strip()
    if not v:
        return None, None, "none"
    import hashlib
    tag = hashlib.sha256(v.encode("utf-8")).hexdigest()[:10]
    kdir = os.path.join(HOME_DIR, "keys")
    if v.startswith(PUBKEY_PREFIXES) and len(v.split()) >= 2:          # public key text
        path = os.path.join(kdir, "inline-%s.pub" % tag)
        os.makedirs(kdir, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(v + "\n")
        return path, " ".join(v.split()[:2]), "agent-pub"
    if "PRIVATE KEY" in v:                                             # private key text
        text = v.replace("\\n", "\n").strip() + "\n"
        if not text.startswith("-----BEGIN"):
            raise AgentError("ssh_key looks like a private key but does not start with -----BEGIN")
        path = os.path.join(kdir, "inline-%s" % tag)
        _write_private(path, text)
        return path, None, "private"
    path = os.path.expanduser(v)                                       # a file path
    if not os.path.isfile(path):
        raise AgentError("ssh_key %s: no such file (give a key file path, a public key line "
                         "'ssh-ed25519 AAAA...', or a private key)" % path)
    if path.endswith(".pub"):
        return path, pubkey_id(path), "agent-pub"
    return path, pubkey_id(path + ".pub") if os.path.isfile(path + ".pub") else None, "private"


def agent_keys() -> Tuple[bool, List[str], str]:
    """(ok, ["<type> <base64>"...], message) from the local ssh-agent."""
    if IS_WINDOWS:
        hint = ("start the agent and load the key in an ADMIN PowerShell:  "
                "Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent; "
                "then (normal PowerShell):  ssh-add $HOME\\.ssh\\id_ed25519")
    else:
        hint = "ssh-add --apple-use-keychain ~/.ssh/id_ed25519" if sys.platform == "darwin" \
            else "ssh-add ~/.ssh/id_ed25519"
        if not os.environ.get("SSH_AUTH_SOCK"):
            return False, [], "SSH_AUTH_SOCK is not set: no ssh-agent in this shell (%s)" % hint
    try:
        p = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True, timeout=10,
                           encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError) as exc:
        return False, [], "ssh-add failed: %s" % exc
    if p.returncode != 0:
        return False, [], "ssh-agent has no keys or is not running (%s). Fix: %s" \
            % ((p.stdout or p.stderr).strip()[:150], hint)
    keys = [" ".join(l.split()[:2]) for l in p.stdout.splitlines() if l.strip()]
    return True, keys, "%d key(s) in agent" % len(keys)


def pubkey_id(path: str) -> Optional[str]:
    with contextlib.suppress(OSError):
        with open(os.path.expanduser(path), encoding="utf-8") as fh:
            parts = fh.read().split()
            return " ".join(parts[:2]) if len(parts) >= 2 else None
    return None


# =============================================================================
# Remote shell snippets (run as root inside the VM)
# =============================================================================
def sh_vars(**kv: Any) -> str:
    return "".join("%s=%s\n" % (k, shlex.quote(str(v))) for k, v in kv.items())


MGMT_PROTECT_SH = r"""
OK=/run/arvin-agent-badip.mgmt-ok
rm -f "$OK"
ip route replace "$MNET" dev "$MIF" src "$MIP" table "$MT"
ip route replace default via "$MGW" dev "$MIF" table "$MT"
ip rule show | grep -q "from $MIP lookup $MT" || ip rule add from "$MIP/32" lookup "$MT" priority "$MPR"
# watchdog: undo unless a NEW ssh session confirms within $WD seconds
nohup setsid sh -c "sleep $WD; [ -f $OK ] || { ip rule del from $MIP/32 lookup $MT; ip route flush table $MT; }" \
  >/dev/null 2>&1 </dev/null &
echo armed
"""

MGMT_UNPROTECT_SH = r"""
while ip rule show | grep -q "from $MIP lookup $MT"; do ip rule del from "$MIP/32" lookup "$MT" || break; done
ip route flush table "$MT" 2>/dev/null || true
rm -f /run/arvin-agent-badip.mgmt-ok
"""

TESTIP_UP_SH = r"""
ip link set dev "$IF" up
ip -4 addr show dev "$IF" | grep -q " $IP/" || ip addr add "$IP/$PLEN" dev "$IF"
ip route replace "$NET" dev "$IF" src "$IP" table "$T"
ip route replace default via "$GW" dev "$IF" table "$T"
ip rule show | grep -q "from $IP lookup $T" || ip rule add from "$IP/32" lookup "$T" priority "$PR"
sysctl -qw net.ipv4.conf.all.rp_filter=2 || true
sysctl -qw "net.ipv4.conf.$IF.rp_filter=2" || true
# a hot-plugged NIC may get a DHCP default route in main: remove it so that
# normal egress keeps using the management NIC
ip -4 route show default dev "$IF" table main | while read -r r; do
  ip route del $r dev "$IF" table main || true
done
echo up
"""

TESTIP_DOWN_SH = r"""
while ip rule show | grep -q "from $IP lookup"; do ip rule del from "$IP/32" || break; done
ip route flush table "$T" 2>/dev/null || true
if [ -n "$IF" ]; then ip addr del "$IP/$PLEN" dev "$IF" 2>/dev/null || true; fi
echo down
"""


# =============================================================================
# The agent
# =============================================================================
class Agent:
    def __init__(self, cfg: Dict[str, Any], log: EventLog, dry_run: bool = False,
                 need_key: bool = True):
        self.cfg, self.log, self.dry_run = cfg, log, dry_run
        self.http = Http(cfg, log, read_only=dry_run)
        key, src = load_api_key(cfg.get("API_KEY") or cfg.get("API_KEY_FILE") or "")
        if need_key and not key:
            raise AgentError("ArvanCloud API key " + src)
        self.key_source = src
        self.api = ArvanAPI(cfg, self.http, key)
        self.ssh = Ssh(cfg, log)
        self.ch = CheckHost(cfg, self.http, log)
        self.reach = Reachability(cfg, self.ch, log)
        self.state = State(cfg["MANAGEMENT_IP"])

    # ---------------------------------------------------------------- helpers --
    @staticmethod
    def _wait_for(fn: Callable[[], Any], timeout: float, interval: float = 3.0) -> Any:
        deadline = time.time() + float(timeout)
        while True:
            v = fn()
            if v:
                return v
            if time.time() >= deadline:
                return None
            time.sleep(interval)

    def _require_init(self) -> None:
        missing = [k for k in ("MANAGEMENT_IP", "SERVER_ID", "MANAGEMENT_PORT_ID") if not self.cfg.get(k)]
        if missing:
            raise AgentError("server %s is not initialised (%s missing): run `%s init`"
                             % (self.cfg.get("MANAGEMENT_IP"), ", ".join(missing), PROJECT))

    def _protected(self) -> Tuple[set, set]:
        return ({self.cfg["MANAGEMENT_PORT_ID"]}, {self.cfg["MANAGEMENT_IP"]})

    def _mgmt_vars(self) -> str:
        c = self.cfg
        return sh_vars(MIP=c["MANAGEMENT_IP"], MIF=c["MANAGEMENT_IFACE"], MGW=c["MANAGEMENT_GATEWAY"],
                       MNET=c["MANAGEMENT_CIDR"], MT=c["MGMT_TABLE"], MPR=c["MGMT_PRIORITY"],
                       WD=c["MGMT_WATCHDOG_SEC"])

    # ------------------------------------------------------------------- init --
    def _find_server(self, mgmt_ip: str) -> None:
        cfg = self.cfg
        if not cfg.get("SERVER_ID"):
            matches = [s for s in self.api.list_servers() if mgmt_ip in ArvanAPI.server_ipv4s(s)]
            if len(matches) != 1:
                raise AgentError("found %d servers in region %s with IP %s; pass --server-id"
                                 % (len(matches), cfg["REGION"], mgmt_ip))
            cfg["SERVER_ID"] = matches[0].get("id")
            cfg["SERVER_NAME"] = matches[0].get("name") or ""
        self.api.server_id = cfg["SERVER_ID"]

    def inspect(self) -> int:
        """Read-only: save what the API returns for this server, to debug field names."""
        ip = self.cfg["MANAGEMENT_IP"]
        self._find_server(ip)
        srv, nets = self.api.get_server(), self.api.list_networks()
        mine = []
        for n in nets:                      # keep only this server's entries (others are not needed)
            n2 = {k: v for k, v in n.items() if k != "subnets"}
            n2["subnets"] = []
            for sn in n.get("subnets") or []:
                sv = [x for x in (sn.get("servers") or []) if x.get("id") == self.api.server_id]
                if sv:
                    sn2 = dict(sn)
                    sn2["servers"] = sv
                    n2["subnets"].append(sn2)
            if n2["subnets"]:
                mine.append(n2)
        for k in ("password",):
            srv.pop(k, None)
        path = os.path.join(server_dir(ip), "inspect.json")
        _write_json_atomic(path, {"server": srv, "networks_for_this_server": mine,
                                  "network_count": len(nets),
                                  "network_keys": sorted({k for n in nets for k in n}),
                                  "subnet_keys": sorted({k for n in nets for sn in (n.get("subnets") or [])
                                                         for k in sn})})
        ports = self.api.ports(nets)
        print("server %s (%s): %d network(s) listed, %d port(s) found for this server"
              % (srv.get("name"), self.api.server_id, len(nets), len(ports)))
        for x in ports:
            print("  %-16s port=%s mac=%s public=%s float=%s subnet=%s gw=%s net=%s"
                  % (x["ip"], x["port_id"], x["mac"] or "?", x["public"], x["float_ip"], x["cidr"],
                     x["gateway"], x["network_name"]))
        print("raw API data saved to %s" % path)
        return 0

    def init(self, mgmt_ip: str) -> int:
        if not _is_ipv4(mgmt_ip):
            raise AgentError("management IP %r is not an IPv4 address" % mgmt_ip)
        cfg = self.cfg
        cfg["MANAGEMENT_IP"] = mgmt_ip
        self.ssh.host = mgmt_ip
        # 1) panel side: which server and which port carries the management IP
        self._find_server(mgmt_ip)
        srv = self.api.get_server()
        cfg["SERVER_NAME"] = srv.get("name") or cfg.get("SERVER_NAME") or ""
        allp = self.api.ports()
        inv = self.api.public_inventory()
        mine = [x for x in inv if x["ip"] == mgmt_ip]
        if not mine:
            if not allp:
                raise AgentError("the networks listing shows no ports for server %s (%s). Run `%s inspect` "
                                 "and send the saved file so the field names can be matched"
                                 % (cfg["SERVER_ID"], cfg["SERVER_NAME"], PROJECT))
            raise AgentError("IP %s is not a public IPv4 port of server %s (%s); the API lists: %s. "
                             "If it is a floating IP, use the server's own public IP instead"
                             % (mgmt_ip, cfg["SERVER_ID"], cfg["SERVER_NAME"],
                                ", ".join("%s%s" % (x["ip"], " (float)" if x["float_ip"] else "")
                                          for x in allp)))
        cfg["MANAGEMENT_PORT_ID"] = mine[0]["port_id"]
        print("server   : %s (%s) in %s" % (cfg["SERVER_NAME"], cfg["SERVER_ID"], cfg["REGION"]))
        print("mgmt IP  : %s on port %s" % (mgmt_ip, cfg["MANAGEMENT_PORT_ID"]))
        # 2) VM side over SSH
        self.ssh.run("true")
        ai = self.ssh.addr_info(mgmt_ip)
        if ai:
            cfg["MANAGEMENT_IFACE"], plen = ai
            cfg["MANAGEMENT_CIDR"] = str(ipaddress.ip_network("%s/%d" % (mgmt_ip, plen), strict=False))
            cfg["MANAGEMENT_GATEWAY"] = self.ssh.gateway_on(cfg["MANAGEMENT_IFACE"]) or ""
        if not (ai and cfg["MANAGEMENT_GATEWAY"]):
            cfg["PROTECT_MGMT_ROUTE"] = False
            print("WARNING: %s is not on a VM interface with a default route (NAT?). Management-route "
                  "protection is OFF." % mgmt_ip)
        print("VM side  : iface=%s cidr=%s gw=%s  (ssh %s@%s ok)"
              % (cfg["MANAGEMENT_IFACE"] or "?", cfg["MANAGEMENT_CIDR"] or "?",
                 cfg["MANAGEMENT_GATEWAY"] or "?", cfg["SSH_USER"], mgmt_ip))
        keep = {k: cfg[k] for k in ("REGION", "SERVER_ID", "SERVER_NAME", "MANAGEMENT_IP",
                                    "MANAGEMENT_PORT_ID", "MANAGEMENT_IFACE", "MANAGEMENT_GATEWAY",
                                    "MANAGEMENT_CIDR", "PROTECT_MGMT_ROUTE")}
        _write_json_atomic(config_path(mgmt_ip), keep)
        print("saved    : %s" % config_path(mgmt_ip))
        return 0

    # -------------------------------------------------------------- preflight --
    def preflight(self) -> int:
        self._require_init()
        cfg, bad = self.cfg, 0
        self.api.server_id = cfg["SERVER_ID"]

        def row(ok: Optional[bool], name: str, detail: str) -> None:
            nonlocal bad
            tag = {True: "PASS", False: "FAIL", None: "WARN"}[ok]
            bad += 1 if ok is False else 0
            print("[%s] %-26s %s" % (tag, name, detail))

        row(True, "api key", self.key_source)
        try:
            srv = self.api.get_server()
            row(True, "server", "%s (%s) status=%s" % (srv.get("name"), cfg["SERVER_ID"], srv.get("status")))
            inv = self.api.public_inventory()
            ips = ", ".join("%s%s" % (x["ip"], " [mgmt]" if x["port_id"] == cfg["MANAGEMENT_PORT_ID"] else "")
                            for x in inv)
            m = [x for x in inv if x["port_id"] == cfg["MANAGEMENT_PORT_ID"] and x["ip"] == cfg["MANAGEMENT_IP"]]
            row(bool(m), "management ip on port", cfg["MANAGEMENT_IP"] + " / " + cfg["MANAGEMENT_PORT_ID"])
            room = int(cfg["MAX_PUBLIC_IPS_PER_SERVER"]) - len(inv)
            row(room >= 1, "ip headroom", "%d public IPv4 now (%s); room for %d more" % (len(inv), ips, max(room, 0)))
            if m:
                row(bool(m[0]["mac"] and m[0]["cidr"] and m[0]["gateway"]), "port details from api",
                    "mac=%s subnet=%s gw=%s" % (m[0]["mac"] or "?", m[0]["cidr"] or "?", m[0]["gateway"] or "?"))
            with contextlib.suppress(Exception):
                self.api.get_quotas()
                row(True, "quotas read", "ok")
        except AgentError as exc:
            row(False, "arvan api", str(exc))
        ssh_ok = False
        try:
            self.ssh.run("true")
            ssh_ok = True
        except SshError:
            pass
        # the ssh login itself is the real test; the agent only matters when it fails
        ok, keys, msg = agent_keys()
        if ssh_ok or self.ssh.key_kind == "private":
            if not ok:
                row(None, "ssh-agent", "not running or empty; not needed, the ssh login works without it")
        else:
            row(ok, "ssh-agent", msg)
            if ok and self.ssh.key_kind == "agent-pub":
                row(bool(self.ssh.pub_id and self.ssh.pub_id in keys), "agent has ssh_key",
                    "%s %s" % ((self.ssh.pub_id or "?")[:40] + "...", "" if self.ssh.pub_id else
                                "(cannot read the public key)"))
        try:
            self.ssh.run("true")
            row(True, "ssh", "%s@%s:%s" % (cfg["SSH_USER"], cfg["MANAGEMENT_IP"], cfg["SSH_PORT"]))
            p = self.ssh.sudo_sh("id -u", check=False)
            sudo_ok = p.returncode == 0 and p.stdout.strip() == "0"
            if not sudo_ok:
                print("       fix, on the server:  echo '%s ALL=(ALL) NOPASSWD:ALL' | sudo tee "
                      "/etc/sudoers.d/90-%s-nopasswd && sudo chmod 440 /etc/sudoers.d/90-%s-nopasswd"
                      % ((cfg["SSH_USER"],) * 3))
            row(sudo_ok, "passwordless sudo",
                (p.stderr or p.stdout).strip()[:120] or "ok")
            p = self.ssh.run("command -v ip; command -v curl || command -v wget", check=False)
            tools = p.stdout.split()
            row(len(tools) >= 2, "remote tools (ip, curl)", " ".join(tools) or "missing")
            if cfg["CHECK_TYPE"] in ("tcp", "http"):
                p = self.ssh.run("ss -ltnH 2>/dev/null || netstat -ltn", check=False)
                port = int(cfg["CHECK_PORT"])
                wild = any(re.search(r"(^|\s)(0\.0\.0\.0|\*|\[::\]|::):%d\s" % port, l + " ")
                           for l in p.stdout.splitlines())
                row(True if wild else None, "listener on CHECK_PORT",
                    "port %d %s" % (port, "listens on all addresses" if wild else
                                    "NOT seen on 0.0.0.0/:: (test IPs would look DOWN)"))
            eg = self.ssh.egress_from(cfg["MANAGEMENT_IP"])
            if eg == cfg["MANAGEMENT_IP"]:
                row(True, "mgmt egress ip", str(eg))
            else:
                # not fatal: the test measures INBOUND reachability of each test IP
                row(None, "mgmt egress ip", "%s (outbound traffic leaves through another address: a VPN, "
                                            "tunnel or provider NAT; inbound tests still work)" % eg)
            if cfg["PROTECT_MGMT_ROUTE"]:
                row(bool(cfg["MANAGEMENT_GATEWAY"] and cfg["MANAGEMENT_IFACE"]), "mgmt route data",
                    "%s via %s" % (cfg["MANAGEMENT_IFACE"], cfg["MANAGEMENT_GATEWAY"]))
            else:
                row(None, "mgmt route protection", "OFF")
        except SshError as exc:
            row(False, "ssh", str(exc))
        try:
            probes = self.ch.probe_nodes()
            row(len(probes) >= int(cfg["MIN_CONCLUSIVE_NODES"]), "check-host iran nodes",
                "%d: %s" % (len(probes), ", ".join(p.split(".")[0] for p in probes)))
        except AgentError as exc:
            row(False, "check-host", str(exc))
        print("\n%s" % ("all required checks passed" if not bad else "%d check(s) FAILED" % bad))
        return 0 if not bad else 1

    # ------------------------------------------------------------ mgmt route --
    def protect_mgmt(self) -> None:
        if not self.cfg["PROTECT_MGMT_ROUTE"]:
            return
        self.ssh.sudo_sh(self._mgmt_vars() + MGMT_PROTECT_SH)
        # confirm that a FRESH connection still reaches sshd and that the existing session
        # still works; otherwise the watchdog in the VM undoes the pin
        try:
            if not self.ssh.fresh_ok():
                raise SshError("a new connection to port %s got no SSH banner" % self.cfg["SSH_PORT"])
            self.ssh.run(("%s touch /run/arvin-agent-badip.mgmt-ok" % self.ssh.sudo_prefix()).strip(),
                         timeout=30)
        except SshError as exc:
            raise AbortRun("management SSH failed after pinning the management route (%s); the VM "
                           "watchdog reverts it within %ss" % (exc, self.cfg["MGMT_WATCHDOG_SEC"]))
        self.log.info("mgmt_route_pinned", ip=self.cfg["MANAGEMENT_IP"], table=self.cfg["MGMT_TABLE"])

    def unprotect_mgmt(self) -> None:
        if self.cfg["PROTECT_MGMT_ROUTE"]:
            with contextlib.suppress(AgentError):
                self.ssh.sudo_sh(self._mgmt_vars() + MGMT_UNPROTECT_SH)
                self.log.info("mgmt_route_unpinned")

    # --------------------------------------------------------------- release --
    def release(self, pend: Dict[str, Any]) -> bool:
        """Remove the test IP from the OS and detach its port. Guarded: never mgmt/pre-existing."""
        port_id, ip = pend.get("port_id"), pend.get("ip")
        prot_ports, prot_ips = self._protected()
        if not port_id:
            return False
        if port_id in prot_ports or ip in prot_ips or port_id in set(pend.get("ports_before") or []):
            raise AbortRun("SAFETY: refusing to release %s/%s: it is the management port or existed "
                           "before this round" % (ip, port_id))
        # OS side first (best effort; detaching the port removes the NIC anyway)
        with contextlib.suppress(AgentError):
            self.ssh.sudo_sh(sh_vars(IP=ip, IF=pend.get("iface") or "", PLEN=pend.get("plen") or 32,
                                     T=pend.get("table") or self.cfg["POLICY_TABLE"]) + TESTIP_DOWN_SH)
        if any(x["port_id"] == port_id for x in self.api.public_inventory()):
            self.log.info("release_request", ip=ip, port_id=port_id)
            try:
                self.api.detach_port(port_id)
            except AmbiguousRequestError as exc:
                self.log.warning("release_ambiguous", error=str(exc))
            except ApiError as exc:
                if exc.kind != "not_found":
                    raise
        gone = self._wait_for(lambda: not any(x["port_id"] == port_id for x in self.api.public_inventory()),
                              self.cfg["RELEASE_TIMEOUT_SEC"], 5)
        if not gone:
            return False
        self.log.info("released", ip=ip, port_id=port_id)
        return True

    def _find_new_port(self, ports_before: List[str]) -> Optional[Dict[str, Any]]:
        new = [x for x in self.api.public_inventory() if x["port_id"] not in set(ports_before)]
        if len(new) > 1:
            raise AbortRun("%d new public ports appeared during the round (%s); refusing to guess"
                           % (len(new), ", ".join("%s/%s" % (x["ip"], x["port_id"]) for x in new)))
        return new[0] if new else None

    # ------------------------------------------------------------------ round --
    def one_round(self, run_id: str, n: int, seen: set) -> Dict[str, Any]:
        cfg = self.cfg
        rec: Dict[str, Any] = {"server": cfg["MANAGEMENT_IP"], "run_id": run_id, "round": n, "started_at": iso(), "ip": None,
                               "port_id": None, "verdict": "ERROR", "cycles": [], "links": [],
                               "released": None, "error": None}
        inv = self.api.public_inventory()
        mg = [x for x in inv if x["port_id"] == cfg["MANAGEMENT_PORT_ID"] and x["ip"] == cfg["MANAGEMENT_IP"]]
        if not mg:
            raise AbortRun("management IP %s is no longer on port %s; stopping"
                           % (cfg["MANAGEMENT_IP"], cfg["MANAGEMENT_PORT_ID"]))
        if len(inv) >= int(cfg["MAX_PUBLIC_IPS_PER_SERVER"]):
            raise AbortRun("server already has %d public IPv4 (cap %s); release extras in the panel"
                           % (len(inv), cfg["MAX_PUBLIC_IPS_PER_SERVER"]))
        ports_before = sorted({p["port_id"] for p in self.api.ports() if p["port_id"]})
        pend: Dict[str, Any] = {"run_id": run_id, "round": n, "ports_before": ports_before,
                                "add_sent_at": iso(), "table": int(cfg["POLICY_TABLE"])}
        self.state.data["pending"] = pend
        self.state.save()                                   # write-ahead before the billable POST
        # ---- 1) allocate --------------------------------------------------------
        self.log.info("allocate_request", round=n)
        data: Any = None
        try:
            data = self._allocate_call()
        except AmbiguousRequestError as exc:
            self.log.warning("allocate_ambiguous", error=str(exc))
        except ApiError as exc:
            if not exc.transient:
                self.state.data["pending"] = None
                self.state.save()
                raise AbortRun("add-public-ip refused: %s" % exc)
            self.log.warning("allocate_ambiguous", error=str(exc))
        new = None
        if isinstance(data, dict):
            fixed = [f for f in (data.get("fixed_ips") or []) if isinstance(f, dict)]
            ip4 = next((f.get("ip_address") for f in fixed if _is_ipv4(f.get("ip_address"))), None)
            pid = data.get("port_id") or data.get("id")
            if pid and ip4:
                new = {"ip": ip4, "port_id": pid,
                       "mac": str(data.get("mac_addr") or data.get("mac_address") or "").lower()}
        if not new:   # reply lost or unparsed: find it by diffing the port list
            new = self._wait_for(lambda: self._find_new_port(ports_before), cfg["ALLOCATION_SETTLE_SEC"], 5)
        if not new:
            # keep 'pending' (with ports_before): the IP may still show up later, and
            # `cleanup` will find and release it by diffing the port list again
            raise AbortRun("add-public-ip sent but no new port appeared within %ss; check the "
                           "panel, then run `%s cleanup --yes`" % (cfg["ALLOCATION_SETTLE_SEC"], PROJECT))
        if new["port_id"] in set(ports_before) or new["ip"] == cfg["MANAGEMENT_IP"]:
            raise AbortRun("allocation result points at a pre-existing port/IP (%s)" % new)
        pend.update(ip=new["ip"], port_id=new["port_id"], mac=new.get("mac") or "")
        self.state.save()
        rec.update(ip=new["ip"], port_id=new["port_id"], seen_before=new["ip"] in seen)
        self.log.info("allocated", round=n, ip=new["ip"], port_id=new["port_id"], mac=new.get("mac"),
                      seen_before=rec["seen_before"])
        try:
            self._configure_and_test(pend, rec)
        except (AgentError, TransientError) as exc:
            rec["error"] = str(exc)
            self.log.error("round_error", round=n, ip=new["ip"], error=str(exc))
            if isinstance(exc, AbortRun):
                rec["abort"] = True
        finally:
            # ---- 4) release (always) ---------------------------------------------
            try:
                rec["released"] = self.release(pend)
            except (AgentError, TransientError) as exc:
                rec["released"] = False
                rec["error"] = ((rec["error"] or "") + "; release: %s" % exc).lstrip("; ")
            if rec["released"]:
                self.state.data["pending"] = None
                self.state.save()
        rec["finished_at"] = iso()
        vs = [c["verdict"] for c in rec["cycles"]]
        rec.update(reachable_cycles=vs.count(REACHABLE), blocked_cycles=vs.count(BLOCKED),
                   down_cycles=vs.count(DOWN), inconclusive_cycles=vs.count(INCONCLUSIVE),
                   best_ok_ratio=max([c.get("ok_ratio") or 0 for c in rec["cycles"]] or [None]))
        if vs:
            rec["verdict"] = aggregate_verdict(vs)
        append_result(rec)
        self.log.info("round_result", round=n, ip=rec["ip"], verdict=rec["verdict"],
                      released=rec["released"])
        if not rec["released"]:
            raise AbortRun("test IP %s (port %s) could NOT be confirmed released; stopping. Run "
                           "`%s cleanup --yes` or detach it in the panel" % (rec["ip"], rec["port_id"], PROJECT))
        if rec.get("abort"):
            raise AbortRun(rec["error"])
        return rec

    def _allocate_call(self) -> Any:
        """Send add-public-ip. If ArvanCloud refuses it (not a transient error), a refusal
        creates nothing, so try once more in the format the older API notes used:
        {"type": "ipv4", "security_groups": [...]}. A transient error is not retried here."""
        try:
            return self.api.add_public_ip()
        except ApiError as first:
            if first.transient:
                raise
            sg = self.api.server_security_group_ids()
            self.log.warning("allocate_refused_retrying_with_body", error=str(first),
                             body={"type": self.cfg["IP_TYPE"], "security_groups": sg})
            return self.api.add_public_ip({"type": self.cfg["IP_TYPE"], "security_groups": sg})

    def _configure_and_test(self, pend: Dict[str, Any], rec: Dict[str, Any]) -> None:
        cfg, ip = self.cfg, pend["ip"]
        # ---- 2) wait for the port and the NIC; configure it inside the VM ------
        port: Dict[str, Any] = {}

        def listed() -> bool:
            nonlocal port
            port = next((x for x in self.api.ports() if x["port_id"] == pend["port_id"]), {})
            return bool(port and port.get("mac"))

        if not self._wait_for(listed, cfg["PORT_ACTIVE_TIMEOUT_SEC"], 5):
            raise AgentError("port %s is not listed with a MAC address after %ss"
                             % (pend["port_id"], cfg["PORT_ACTIVE_TIMEOUT_SEC"]))
        pend["mac"] = pend.get("mac") or port["mac"]
        if not pend["mac"]:
            raise AgentError("unknown MAC for port %s" % pend["port_id"])
        ifname = self._wait_for(lambda: self.ssh.iface_for_mac(pend["mac"]), cfg["NIC_APPEAR_TIMEOUT_SEC"])
        if not ifname:
            raise AgentError("no NIC with MAC %s appeared in the VM within %ss (no NIC hot-plug?)"
                             % (pend["mac"], cfg["NIC_APPEAR_TIMEOUT_SEC"]))
        if ifname == cfg["MANAGEMENT_IFACE"]:
            raise AbortRun("new port's MAC maps to the management interface %s; refusing" % ifname)
        pend["iface"] = ifname
        cidr, gw = port.get("cidr"), port.get("gateway")
        with contextlib.suppress(ValueError, TypeError):
            if cidr and ipaddress.ip_address(ip) not in ipaddress.ip_network(cidr, strict=False):
                cidr = gw = None                    # listing does not match this IP: use the NIC
        if not (cidr and gw):           # fallback: what DHCP put on the NIC
            ai = self.ssh.addr_info(ip)
            gw = gw or self.ssh.gateway_on(ifname)
            if ai and not cidr:
                cidr = str(ipaddress.ip_network("%s/%d" % (ip, ai[1]), strict=False))
        if not (cidr and gw):
            raise AgentError("cannot determine subnet/gateway for %s" % ip)
        pend.update(plen=ipaddress.ip_network(cidr, strict=False).prefixlen, cidr=cidr, gateway=gw)
        self.state.save()
        self.ssh.sudo_sh(sh_vars(IF=ifname, IP=ip, PLEN=pend["plen"], NET=str(ipaddress.ip_network(cidr, strict=False)),
                                 GW=gw, T=pend["table"], PR=cfg["POLICY_PRIORITY"]) + TESTIP_UP_SH)
        self.log.info("configured", ip=ip, iface=ifname, cidr=cidr, gateway=gw)
        # management must still be fine
        if not self.ssh.fresh_ok():
            raise AgentError("the management IP stopped accepting new SSH connections after the "
                             "test IP was configured")
        self.ssh.run("true", timeout=30)
        # ---- outbound from the test IP -------------------------------------------
        eg = self.ssh.egress_from(ip)
        rec["egress_ok"] = (eg == ip)
        if eg != ip:
            self.log.warning("egress_mismatch", ip=ip, seen=eg)
        # ---- informational: TCP from this Mac ----------------------------------------
        if cfg["CHECK_TYPE"] in ("tcp", "http"):
            try:
                with socket.create_connection((ip, int(cfg["CHECK_PORT"])), timeout=5):
                    rec["from_mac_tcp"] = True
            except OSError:
                rec["from_mac_tcp"] = False
        # ---- 3) test from Iran ---------------------------------------------------------
        for i in range(int(cfg["CHECKS_PER_IP"])):
            try:
                res = self.reach.cycle(ip, "test-ip")
            except InconclusiveError as exc:
                res = {"verdict": INCONCLUSIVE, "why": str(exc)}
            rec["cycles"].append({k: res.get(k) for k in ("verdict", "why", "ok", "fail", "unknown",
                                                         "control_ok", "ok_ratio", "link")})
            if res.get("link"):
                rec["links"].append(res["link"])

    # -------------------------------------------------------------------- run --
    def test(self, rounds: int) -> int:
        self._require_init()
        self.api.server_id = self.cfg["SERVER_ID"]
        if self.state.pending:
            raise AgentError("a previous allocation is still pending (%s); run `%s cleanup --yes` first"
                             % (self.state.pending.get("ip") or "unknown IP", PROJECT))
        run_id = time.strftime("%Y%m%d-%H%M%S-") + _uuid.uuid4().hex[:4]
        self.state.data["runs"] = int(self.state.data.get("runs") or 0) + 1
        self.state.save()
        seen = {r.get("ip") for r in load_results() if r.get("ip")}
        self.log.info("run_start", run_id=run_id, rounds=rounds, server=self.cfg["SERVER_ID"],
                      mgmt_ip=self.cfg["MANAGEMENT_IP"])
        self.ssh.run("true")
        if self.cfg["BASELINE_CHECK"]:
            with contextlib.suppress(InconclusiveError):
                b = self.reach.cycle(self.cfg["MANAGEMENT_IP"], "baseline-mgmt")
                append_result({"server": self.cfg["MANAGEMENT_IP"], "run_id": run_id, "round": 0, "ip": self.cfg["MANAGEMENT_IP"],
                               "port_id": self.cfg["MANAGEMENT_PORT_ID"], "finished_at": iso(),
                               "verdict": "MGMT-" + aggregate_verdict([b["verdict"]]),
                               "links": [b.get("link")] if b.get("link") else [], "released": "n/a"})
        out: List[Dict[str, Any]] = []
        rc = 0
        try:
            self.protect_mgmt()
            for n in range(1, rounds + 1):
                if n > 1:
                    time.sleep(float(self.cfg["ROUND_SPACING_SEC"]))
                print("\n===== round %d/%d =====" % (n, rounds))
                rec = self.one_round(run_id, n, seen)
                seen.add(rec["ip"])
                out.append(rec)
        except AbortRun as exc:
            self.log.error("run_aborted", reason=str(exc))
            rc = 2
        except KeyboardInterrupt:
            self.log.warning("interrupted")
            pend = self.state.pending
            if pend and pend.get("port_id"):
                print("\nCtrl-C: releasing the in-flight test IP %s ..." % pend.get("ip"))
                if self.release(pend):
                    self.state.data["pending"] = None
                    self.state.save()
            rc = 4
        finally:
            self.unprotect_mgmt()
        print("\n" + summary_table(out))
        if self.state.pending:
            print("\n!! an allocation is still pending: run `%s cleanup --yes`" % PROJECT)
            rc = rc or 2
        print("results: %s" % os.path.join(HOME_DIR, "results.csv"))
        return rc

    def dry_run_report(self, rounds: int) -> int:
        self._require_init()
        self.api.server_id = self.cfg["SERVER_ID"]
        inv = self.api.public_inventory()
        print("DRY RUN: nothing is allocated, configured or released.\n")
        print("server %s, public IPv4 now: %s" % (self.cfg["SERVER_ID"], ", ".join(x["ip"] for x in inv)))
        if self.cfg["PROTECT_MGMT_ROUTE"]:
            print("\nonce per run, in the VM as root (pins mgmt replies; %ss watchdog):\n%s"
                  % (self.cfg["MGMT_WATCHDOG_SEC"], self._mgmt_vars() + MGMT_PROTECT_SH))
        a, d = self.api.add_public_ip_preview(), self.api.detach_preview("<NEW_PORT_ID>")
        print("each of %d rounds:" % rounds)
        print("  1. %s %s (empty body)" % (a["method"], a["url"]))
        print("  2. wait for the new port in GET /networks + its NIC (MAC) in the VM, then as root:")
        print("     " + TESTIP_UP_SH.strip().replace("\n", "\n     "))
        print("  3. %d check-host %s cycle(s) to <NEW_IP>%s from: %s"
              % (int(self.cfg["CHECKS_PER_IP"]), self.cfg["CHECK_TYPE"],
                 "" if self.cfg["CHECK_TYPE"] == "ping" else ":%s" % self.cfg["CHECK_PORT"],
                 ", ".join(n.split(".")[0] for n in self.ch.probe_nodes())))
        print("  4. %s %s %s, then wait until the port is gone" % (d["method"], d["url"], json.dumps(d["body"])))
        print("  5. append to %s" % os.path.join(HOME_DIR, "results.csv"))
        print("\nmutating HTTP requests made during this dry run: %d" % len(self.http.mutations))
        return 0

    # ---------------------------------------------------------------- cleanup --
    def cleanup(self) -> int:
        self._require_init()
        self.api.server_id = self.cfg["SERVER_ID"]
        pend = self.state.pending
        if not pend:
            print("nothing pending")
            return 0
        if not pend.get("port_id"):
            found = self._find_new_port(pend.get("ports_before") or [])
            if not found:
                print("no port was created by the pending allocation; clearing it")
                self.state.data["pending"] = None
                self.state.save()
                return 0
            pend.update(ip=found["ip"], port_id=found["port_id"], mac=found["mac"])
            self.state.save()
        print("releasing %s (port %s) ..." % (pend["ip"], pend["port_id"]))
        if self.release(pend):
            append_result({"server": self.cfg["MANAGEMENT_IP"], "run_id": pend.get("run_id"), "round": pend.get("round"), "ip": pend["ip"],
                           "port_id": pend["port_id"], "finished_at": iso(), "verdict": "ERROR",
                           "released": True, "error": "released by cleanup"})
            self.state.data["pending"] = None
            self.state.save()
            self.unprotect_mgmt()
            print("released")
            return 0
        print("NOT released yet; check the panel and re-run cleanup")
        return 2


def summary_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "(no results)"
    lines = ["%-20s %-16s %-5s %-16s %-12s %-5s %-6s %-8s %s" % (
        "finished", "server", "round", "ip", "verdict", "r/b/d", "egress", "released", "first link")]
    for r in rows:
        lines.append("%-20s %-16s %-5s %-16s %-12s %-5s %-6s %-8s %s" % (
            r.get("finished_at") or "", r.get("server") or "-", r.get("round"), r.get("ip") or "-", r.get("verdict"),
            "%s/%s/%s" % (r.get("reachable_cycles", "-"), r.get("blocked_cycles", "-"), r.get("down_cycles", "-")),
            {True: "ok", False: "BAD", None: "-"}.get(r.get("egress_ok"), "-"),
            r.get("released"), (r.get("links") or [""])[0]))
        if r.get("error"):
            lines.append("      error: %s" % r["error"])
    return "\n".join(lines)


# =============================================================================
# CLI
# =============================================================================
EPILOG = """\
typical first use on Windows (PowerShell):
  ssh-add $HOME/.ssh/id_ed25519                # ssh-agent service must be running
  $env:ARVAN_API_KEY = Read-Host -MaskInput "API key"
  python arvin_agent_badip.py init             # reads arvin-agent-badip.yaml
  python arvin_agent_badip.py preflight
  python arvin_agent_badip.py test --dry-run
  python arvin_agent_badip.py test --rounds 1 --yes

typical first use (on your Mac):
  ssh-add --apple-use-keychain ~/.ssh/id_ed25519
  security add-generic-password -U -a "$USER" -s %(p)s -w      # paste the API key
  ./arvin_agent_badip.py init        # reads management_ip (one or "ip1, ip2") from the YAML
  ./arvin_agent_badip.py preflight
  ./arvin_agent_badip.py test --dry-run
  ./arvin_agent_badip.py test --rounds 1 --yes        # one billable round first
  ./arvin_agent_badip.py test --yes                   # 5 rounds
  ./arvin_agent_badip.py results --bad

exit codes: 0 ok, 1 error, 2 aborted / something left pending, 4 interrupted
""" % {"p": PROJECT}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog=PROJECT, description=__doc__.split("\n\n")[0].strip(),
                                 epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--region")
    ap.add_argument("--ssh-user")
    ap.add_argument("--ssh-key", "--ssh-pubkey", dest="ssh_key",
                    help="SSH key: a file path or the key itself (public key line or private key)")
    ap.add_argument("--server", help="only these management IP(s) from the YAML file (comma list)")
    ap.add_argument("--ssh-port", type=int)
    ap.add_argument("-c", "--config", help="YAML inputs file (default: ./arvin-agent-badip.yaml, "
                                           "then ~/arvin-agent-badip/config.yaml)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("init", help="save the management IP and find the server")
    p.add_argument("--management-ip", help="default: management_ip from the YAML file (comma list ok)")
    p.add_argument("--server-id", help="only with a single management IP")
    sub.add_parser("preflight", help="read-only checks: API key, server, SSH, sudo, check-host")
    p = sub.add_parser("test", help="allocate, test and release test IPs (billable)")
    p.add_argument("--rounds", type=int)
    p.add_argument("--checks-per-ip", type=int)
    p.add_argument("--check-type", choices=["tcp", "ping", "http"])
    p.add_argument("--check-port", type=int)
    p.add_argument("--no-baseline", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p = sub.add_parser("cleanup", help="release a test IP left behind by a crash")
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("results", help="show saved results")
    p.add_argument("--bad", action="store_true", help="only BAD IPs")
    p.add_argument("--good", action="store_true", help="only GOOD IPs")
    p.add_argument("--last", type=int, default=0)
    sub.add_parser("status", help="show config and anything pending")
    sub.add_parser("inspect", help="read-only: save what the API returns for the server(s)")
    a = ap.parse_args(argv)
    a.server_id_check = bool(getattr(a, "server_id", None))
    for name in ("server_id", "management_ip", "rounds", "checks_per_ip", "check_type", "check_port",
                 "no_baseline", "dry_run", "yes", "bad", "good", "last"):
        if not hasattr(a, name):
            setattr(a, name, None)
    if not a.cmd:
        ap.print_help()
        print("\nno command given. Start with:\n  python arvin_agent_badip.py init\n"
              "  python arvin_agent_badip.py preflight")
        return 1

    ov: Dict[str, Any] = {"REGION": a.region, "SSH_USER": a.ssh_user, "SSH_KEY": a.ssh_key,
                          "SSH_PORT": a.ssh_port, "LOG_LEVEL": "debug" if a.verbose else None}
    if a.cmd == "test":
        ov.update(ROUNDS=a.rounds, CHECKS_PER_IP=a.checks_per_ip, CHECK_TYPE=a.check_type,
                  CHECK_PORT=a.check_port, BASELINE_CHECK=False if a.no_baseline else None)
    if a.cmd == "init":
        ov["SERVER_ID"] = a.server_id
        ov["MANAGEMENT_IP"] = a.management_ip
    try:
        base = load_config(ov, a.config)
        log = EventLog(base, quiet=a.cmd in ("results", "status"))
        if a.cmd == "results":
            rows = load_results()
            if a.bad:
                rows = [r for r in rows if r.get("verdict") == "BAD"]
            if a.good:
                rows = [r for r in rows if r.get("verdict") == "GOOD"]
            if a.server:
                rows = [r for r in rows if r.get("server") in parse_ip_list(a.server)]
            if a.last:
                rows = rows[-a.last:]
            print(summary_table(rows))
            return 0
        ips = parse_ip_list(base.get("MANAGEMENT_IP"))
        if a.server:
            only = parse_ip_list(a.server)
            unknown = [x for x in only if x not in ips]
            if unknown:
                raise AgentError("--server %s is not in management_ip (%s)"
                                 % (", ".join(unknown), ", ".join(ips) or "empty"))
            sel = only
        else:
            sel = ips
        if not sel:
            raise AgentError("no management IP: set management_ip in the YAML file "
                             "(one IP, or several separated by commas) or use --management-ip")
        if a.server_id_check and len(ips) > 1:
            raise AgentError("--server-id only works with one management IP; with several, put a "
                             "comma list in server_id (same order) or leave it empty")
        cfgs = [server_config(base, ip, ips.index(ip), len(ips)) for ip in sel]
        if a.cmd == "status":
            print("inputs :", base.get("_YAML_PATH") or "(no YAML file found)")
            print("home   :", HOME_DIR)
            for c in cfgs:
                st = State(c["MANAGEMENT_IP"])
                print("\n== %s ==" % c["MANAGEMENT_IP"])
                print(json.dumps(redact({k: c[k] for k in (
                    "REGION", "SERVER_ID", "SERVER_NAME", "MANAGEMENT_PORT_ID", "MANAGEMENT_IFACE",
                    "MANAGEMENT_GATEWAY", "SSH_USER", "ROUNDS", "CHECKS_PER_IP", "CHECK_TYPE",
                    "CHECK_PORT")}), indent=2))
                print("pending:", json.dumps(st.pending) if st.pending else "none")
            return 0
        if a.cmd == "cleanup" and not a.yes:
            print("cleanup changes the server(s): re-run with --yes")
            return 1
        if a.cmd == "test" and not a.dry_run and not a.yes:
            rounds = sum(int(c["ROUNDS"]) for c in cfgs)
            ans = input("This allocates and releases %d billable public IPv4(s) on %d server(s) (%s). "
                        "Continue? [y/N] " % (rounds, len(cfgs), ", ".join(sel)))
            if ans.strip().lower() not in ("y", "yes"):
                return 1
        rc = 0
        for c in cfgs:
            if len(cfgs) > 1:
                print("\n################ server %s ################" % c["MANAGEMENT_IP"])
            try:
                agent = Agent(c, log, dry_run=(a.cmd == "test" and a.dry_run))
                if a.cmd == "init":
                    r = agent.init(c["MANAGEMENT_IP"])
                elif a.cmd == "inspect":
                    r = agent.inspect()
                elif a.cmd == "preflight":
                    r = agent.preflight()
                elif a.cmd == "cleanup":
                    r = agent.cleanup()
                elif a.dry_run:
                    r = agent.dry_run_report(int(c["ROUNDS"]))
                else:
                    r = agent.test(int(c["ROUNDS"]))
                    if r == 4 or State(c["MANAGEMENT_IP"]).pending:
                        rc = max(rc, r or 2)
                        print("stopping: not continuing with the other servers")
                        break
            except AgentError as exc:
                print("error [%s]: %s" % (c["MANAGEMENT_IP"], exc), file=sys.stderr)
                r = 1
            rc = max(rc, r)
        return rc
    except AgentError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 4


if __name__ == "__main__":
    for _stream in (sys.stdout, sys.stderr):     # Windows consoles may not be UTF-8
        with contextlib.suppress(AttributeError, ValueError):
            _stream.reconfigure(errors="replace")
    sys.exit(main())
