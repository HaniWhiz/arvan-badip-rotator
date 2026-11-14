"""End-to-end test of arvin_agent_badip against a fake ArvanCloud API, fake VMs over a
fake ssh, and a fake check-host. Run:  python3 tests/test_mock.py"""
import itertools
import types
import json
import os
import subprocess
import sys
import tempfile

home = tempfile.mkdtemp()
os.chdir(home)
os.environ["ABIP_HOME"] = home
os.environ["ARVAN_API_KEY"] = "Apikey xyz"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import arvin_agent_badip as m  # noqa: E402

m.time.sleep = lambda s: None
m.DEFAULTS["VM_CONFIG_MODE"] = "ssh"          # the ssh-mode tests come first; panel mode is last


def _no_conn(*a, **k):
    raise OSError("mock")


m.socket.create_connection = _no_conn


class FakeServer:
    def __init__(s, sid, net):                      # net: "185.1.1" / "185.2.2"
        s.sid, s.net = sid, net
        s.mgmt = net + ".10"
        s.ports = [{"id": "p-mgmt-" + sid, "ips": [s.mgmt], "mac_address": "aa:%s" % sid[-1],
                    "network_id": "n-" + sid, "security_group_ids": ["sg1"], "status": "ACTIVE"}]
        s.n = itertools.count(20)
        s.detached = []
        s.fail_add = None

    def server(s):
        return {"id": s.sid, "name": "vm-" + s.sid, "security_groups": [{"id": "sg1"}],
                "addresses": {"pub": [{"addr": ip, "is_public": True} for p in s.ports for ip in p["ips"]]}}


cloud = {"srv1": FakeServer("srv1", "185.1.1"), "srv2": FakeServer("srv2", "185.2.2")}
by_ip = {c.mgmt: c for c in cloud.values()}
keys_seen = []


def fake_networks():
    """Same shape as the Terraform provider's NetworkDetails: subnets[].servers[].ips[]."""
    nets = []
    for c in cloud.values():
        nets.append({"id": "n-" + c.sid, "name": "public-" + c.sid, "subnets": [{
            "id": "sub-" + c.sid, "cidr": c.net + ".0/24", "gateway_ip": c.net + ".1",
            "servers": [{"id": c.sid, "name": "vm-" + c.sid,
                         "ips": [{"ip": p["ips"][0], "mac_address": p["mac_address"], "port_id": p["id"],
                                  "public": True, "float_ip": False, "version": "4",
                                  "subnet_id": "sub-" + c.sid} for p in c.ports]},
                        {"id": "someone-else", "ips": [{"ip": c.net + ".99", "port_id": "p-other",
                                                        "mac_address": "ff:ff", "public": True}]}]}]})
    return nets


def fake_call(self, method, url, body=None, idempotent=None, allow_404=False, empty_body=False):
    keys_seen.append(self._key)
    path = url.split("/regions/ir-thr-ba1")[1]
    parts = path.strip("/").split("/")
    if method == "GET" and path == "/servers":
        return [c.server() for c in cloud.values()]
    if method == "GET" and path == "/networks":
        return fake_networks()
    if method == "GET" and path == "/quotas":
        return {}
    if method == "GET" and path == "/securities":
        return [{"id": "sg1", "name": "Default"}, {"id": "sg2", "name": "allow-any"}]
    if parts[0] == "servers":
        c = cloud[parts[1]]
        if method == "GET" and len(parts) == 2:
            return c.server()
        if method == "POST" and parts[2] == "add-public-ip":
            if body is None or not body.get("security_groups"):   # no firewall: refused, like the API
                raise m.ApiError("POST", url, 422, "Bad Request", None)
            assert body == {"type": "ipv4", "security_groups": ["sg1"]}, body
            k = next(c.n)
            c.ports.append({"id": "p-%s-%d" % (c.sid, k), "ips": ["%s.%d" % (c.net, k)],
                            "mac_address": "bb:%02d" % k})
            if c.fail_add == "lost":
                raise m.AmbiguousRequestError("lost")
            return None                              # the real reply carries no port details
    if method == "PATCH" and parts[0] == "networks" and parts[2] == "detach":
        pid = parts[1]
        assert not pid.startswith("p-mgmt"), "tried to release the management port!"
        assert pid != "p-other", "tried to release another server's port!"
        for c in cloud.values():
            if any(p["id"] == pid for p in c.ports):
                assert body["server_id"] == c.sid
                c.detached.append(pid)
                c.ports = [p for p in c.ports if p["id"] != pid]
        return {}
    raise AssertionError((method, path))


m.ArvanAPI.call = fake_call


def _fake_http_request(self, method, url, headers=None, json_body=None, idempotent=None,
                       retries=None, timeout=None, raw_body=None):
    """add-public-ip goes straight through Http.request: route it to the same fake API."""
    if method == "POST" and "/add-public-ip" in url:
        body = json_body
        try:
            data = fake_call(types.SimpleNamespace(_key="k"), method, url, body=body, idempotent=False,
                             empty_body=raw_body == b"")
            return m.HttpResponse(200, {}, json.dumps({"data": data}).encode(), url)
        except m.ApiError as exc:
            return m.HttpResponse(exc.status, {}, b'{"message":"Bad Request"}', url)
    return _orig_request(self, method, url, headers, json_body, idempotent, retries, timeout, raw_body)


_orig_request = m.Http.request
m.Http.request = _fake_http_request

scripts = []
ssh_cmds = []


def fake_run(self, remote, stdin=None, check=True, timeout=60, multiplex=True):
    ssh_cmds.append(self.base_cmd(multiplex))
    scripts.append((self.host, remote, stdin))
    c = by_ip[self.host]
    out = ""
    if remote.startswith("ip -j link"):
        out = json.dumps([{"ifname": "eth%d" % i, "address": p["mac_address"]} for i, p in enumerate(c.ports)])
    elif remote.startswith("ip -j -4 addr"):
        out = json.dumps([{"ifname": "eth0", "addr_info": [{"local": c.mgmt, "prefixlen": 24}]}])
    elif remote.startswith("ip -j -4 route"):
        out = json.dumps([{"dev": "eth0", "gateway": c.net + ".1"}])
    elif remote.startswith("curl"):
        out = remote.split("--interface ")[1].split()[0] + "\n"
    elif "sh -s" in remote and stdin and "id -u" in stdin:
        out = "0\n"
    elif remote.startswith("command -v"):
        out = "/usr/sbin/ip\n/usr/bin/curl\n"
    elif remote.startswith("ss "):
        out = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    return subprocess.CompletedProcess(remote, 0, out, "")


m.Ssh.run = fake_run
m.Ssh.close_master = lambda self: None
m.Ssh.fresh_ok = lambda self: True
m.agent_keys = lambda: (True, ["ssh-ed25519 AAAAPUB"], "1 key")

verd = itertools.cycle(["REACHABLE", "BLOCKED", "BLOCKED"])


def fake_cycle(self, ip, purpose):
    v = "REACHABLE" if purpose == "baseline-mgmt" else next(verd)
    return {"verdict": v, "why": "mock", "ok": 5 if v == "REACHABLE" else 0, "fail": 0 if v == "REACHABLE" else 5,
            "unknown": 0, "control_ok": 3, "ok_ratio": 1.0 if v == "REACHABLE" else 0.0,
            "link": "https://check-host.net/check-report/x"}


ORIG_CYCLE, ORIG_PROBE = m.Reachability.cycle, m.CheckHost.probe_nodes
ORIG_RUN, ORIG_SUBMIT = m.CheckHost.run, m.CheckHost.submit
m.Reachability.cycle = fake_cycle
m.CheckHost.probe_nodes = lambda self: ["ir1", "ir2", "ir3"]

y = os.path.join(home, "in.yaml")


def yaml(text):
    open(y, "w").write(text)
    return ["--config", y]


S1, S2 = "185.1.1.10", "185.2.2.10"

# ---- single server ----------------------------------------------------------------
C = yaml("management_ip: %s\nssh_key: ssh-ed25519 AAAAPUB me@mac\n" % S1)
assert m.main(C + ["init"]) == 0
cfg = json.load(open(m.config_path(S1)))
assert cfg["MANAGEMENT_PORT_ID"] == "p-mgmt-srv1" and cfg["MANAGEMENT_GATEWAY"] == "185.1.1.1", cfg
assert m.main(C + ["preflight"]) == 0
assert m.main(C + ["inspect"]) == 0
insp = json.load(open(os.path.join(m.server_dir(S1), "inspect.json")))
assert insp["networks_for_this_server"][0]["subnets"][0]["servers"][0]["id"] == "srv1"
assert "someone-else" not in json.dumps(insp)
assert m.main(C + ["test", "--dry-run"]) == 0
assert m.main(C + ["test", "--yes"]) == 0
c1 = cloud["srv1"]
assert len(c1.detached) == 5 and [p["id"] for p in c1.ports] == ["p-mgmt-srv1"], c1.detached
rows = m.load_results()
assert len(rows) == 5 and all(r["server"] == S1 for r in rows), rows
assert any(s and 'ip rule add from "$MIP/32"' in s for _, _, s in scripts)
assert any(s and 'ip rule del from "$MIP/32"' in s for _, _, s in scripts)
# ssh used the inline public key through a written .pub file
idf = [x for x in ssh_cmds[-1] if x.startswith("IdentityFile=")][0].split("=", 1)[1]
assert idf.endswith(".pub") and open(idf).read().startswith("ssh-ed25519 AAAAPUB"), idf

# lost allocation reply -> reconciled by port diff
c1.fail_add = "lost"
assert m.main(C + ["test", "--yes", "--rounds", "1", "--no-baseline"]) == 0
assert [p["id"] for p in c1.ports] == ["p-mgmt-srv1"]
c1.fail_add = None

# crash after POST (pending left) -> refuses to test -> cleanup
orig_cat, orig_rel = m.Agent._configure_and_test, m.Agent.release


def boom(self, p, r):
    raise KeyboardInterrupt


m.Agent._configure_and_test = boom
m.Agent.release = lambda self, p: (_ for _ in ()).throw(KeyboardInterrupt())
m.main(C + ["test", "--yes", "--rounds", "1", "--no-baseline"])
m.Agent._configure_and_test, m.Agent.release = orig_cat, orig_rel
assert m.State(S1).pending and len(c1.ports) == 2
assert m.main(C + ["test", "--yes"]) == 1
assert m.main(C + ["cleanup", "--yes"]) == 0
assert [p["id"] for p in c1.ports] == ["p-mgmt-srv1"] and not m.State(S1).pending
print("SINGLE OK")

# ---- several servers, comma separated -------------------------------------------------
C = yaml('management_ip: "%s, %s"\nrounds: 2\nbaseline_check: false\n' % (S1, S2))
assert m.main(C + ["init"]) == 0
assert json.load(open(m.config_path(S2)))["SERVER_ID"] == "srv2"
assert m.main(C + ["preflight"]) == 0
n1, n2 = len(c1.detached), len(cloud["srv2"].detached)
assert m.main(C + ["test", "--yes"]) == 0
assert len(c1.detached) == n1 + 2 and len(cloud["srv2"].detached) == n2 + 2
assert [p["id"] for p in cloud["srv2"].ports] == ["p-mgmt-srv2"]
srv2_rows = [r for r in m.load_results() if r.get("server") == S2]
assert len(srv2_rows) == 2 and all(r["ip"].startswith("185.2.2.") for r in srv2_rows), srv2_rows
# --server limits a run to one of them
n1 = len(c1.detached)
assert m.main(C + ["--server", S2, "test", "--yes", "--rounds", "1"]) == 0
assert len(c1.detached) == n1
assert m.main(C + ["--server", "9.9.9.9", "status"]) == 1
# YAML list form works too
C = yaml("management_ip: [%s, %s]\n" % (S1, S2))
assert m.main(C + ["status"]) == 0
# server_id must match the number of IPs
C = yaml('management_ip: "%s, %s"\nserver_id: srv1\n' % (S1, S2))
assert m.main(C + ["status"]) == 1
print("MULTI OK")

# ---- API key: value or path ------------------------------------------------------------
saved = os.environ.pop("ARVAN_API_KEY")
kf = os.path.join(home, "key.txt")
open(kf, "w").write("Apikey from-file\n")
os.chmod(kf, 0o600)
assert m.load_api_key("apikey 11111111-2222-3333-4444-555555555555")[0] == "11111111-2222-3333-4444-555555555555"
assert m.load_api_key("11111111-2222-3333-4444-555555555555")[0] == "11111111-2222-3333-4444-555555555555"
assert m.load_api_key(kf) == ("from-file", "file:%s" % kf)
try:
    m.load_api_key("C:/nope/key.txt")
    raise SystemExit("accepted missing key file")
except m.AgentError as e:
    print("rejected:", e)
C = yaml('management_ip: %s\napi_key: "Apikey yaml-value"\n' % S1)
keys_seen.clear()
assert m.main(C + ["preflight"]) == 0 and keys_seen and set(keys_seen) == {"yaml-value"}
C = yaml("management_ip: %s\napi_key_file: %s\n" % (S1, kf))       # old name still works
keys_seen.clear()
assert m.main(C + ["preflight"]) == 0 and set(keys_seen) == {"from-file"}
os.environ["ARVAN_API_KEY"] = saved
print("API KEY OK")

# ---- SSH key: value or path --------------------------------------------------------------
priv_text = "-----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\nBBBB\\n-----END OPENSSH PRIVATE KEY-----"
base = m.load_config({}, None)
base.update(SSH_KEY=priv_text)
path, pub, kind = m.resolve_ssh_identity(base)
assert kind == "private" and open(path).read().splitlines()[1] == "AAAA"
assert (os.stat(path).st_mode & 0o777) == 0o600
pf = os.path.join(home, "id_test")
open(pf, "w").write("x")
base.update(SSH_KEY=pf)
assert m.resolve_ssh_identity(base) == (pf, None, "private")
open(pf + ".pub", "w").write("ssh-ed25519 AAAAPUB c\n")
base.update(SSH_KEY=pf + ".pub")
assert m.resolve_ssh_identity(base) == (pf + ".pub", "ssh-ed25519 AAAAPUB", "agent-pub")
base.update(SSH_KEY="~/nope/id_ed25519")
try:
    m.resolve_ssh_identity(base)
    raise SystemExit("accepted missing ssh key")
except m.AgentError as e:
    print("rejected:", e)
C = yaml('management_ip: %s\nssh_key: "%s"\n' % (S1, priv_text))
assert m.main(C + ["preflight"]) == 0
print("SSH KEY OK")

# ---- YAML parser ----------------------------------------------------------------------
repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
tpl = m.load_yaml_inputs(os.path.join(repo, "arvin-agent-badip.yaml"))
assert tpl["ROUNDS"] == 5 and tpl["PROBE_NODES"] == [] and "MANAGEMENT_IP" not in tpl, tpl
open(y, "w").write('management_ip: 185.1.1.10   # mgmt\nrounds: 2\nssh_extra_opts:\n  - "-o"\n'
                   '  - "ProxyJump=b # x"\ncheck_type: ping\nbaseline_check: no\n')
assert m.load_yaml_inputs(y) == {"MANAGEMENT_IP": "185.1.1.10", "ROUNDS": 2,
                                 "SSH_EXTRA_OPTS": ["-o", "ProxyJump=b # x"],
                                 "CHECK_TYPE": "ping", "BASELINE_CHECK": False}
for bad in ("rounds: five\n", "foo: 1\n", "a:\n  b: 1\n"):
    open(y, "w").write(bad)
    try:
        m.load_yaml_inputs(y)
        raise SystemExit("accepted bad yaml: %r" % bad)
    except m.AgentError as e:
        print("rejected:", e)
C = yaml("management_ip: 185.1.1.10, 1.2.3\n")
assert m.main(C + ["status"]) == 1
print("YAML OK")

# ---- Windows behaviour -------------------------------------------------------------------
m.IS_WINDOWS = True
cw = m.server_config(m.load_config({"SSH_USER": "root"}, None), S1, 0, 1)
ssh = m.Ssh(cw, m.EventLog(cw, quiet=True))
cmd = " ".join(ssh.base_cmd())
assert "ControlMaster" not in cmd and "ControlPath" not in cmd, cmd
assert ssh.sudo_prefix() == ""
os.chmod(kf, 0o644)
assert m.load_api_key(kf)[0] == "from-file"          # no chmod check on Windows
m.IS_WINDOWS = False
assert m.main([]) == 1
print("WINDOWS OK")
print("ALL OK")

# ---- TLS: empty default CA store falls back to a system bundle, still verifying ------------
ctx = m.make_ssl_context()
assert ctx.verify_mode == m.ssl.CERT_REQUIRED and ctx.check_hostname
print("TLS OK")

# ---- a port listed under two subnets is counted once -----------------------------------------
dup_nets = fake_networks()
dup_nets[0]["subnets"].append(dict(dup_nets[0]["subnets"][0]))
cdup = m.server_config(m.load_config({}, None), S1, 0, 1)
inv_dup = m.ArvanAPI(cdup, m.Http(cdup, m.EventLog(cdup, quiet=True)), "k")
inv_dup.server_id = "srv1"
assert len(inv_dup.public_inventory()) == len(inv_dup.public_inventory()) and \
    len(inv_dup.ports(dup_nets)) == len(inv_dup.ports(fake_networks()))
print("DUPLICATE OK")

# ---- SSH: normal commands reuse the master and never authenticate ---------------------------
cs = m.server_config(m.load_config({}, None), S1, 0, 1)
cmdl = m.Ssh(cs, m.EventLog(cs, quiet=True)).base_cmd()
assert "ControlMaster=no" in cmdl and "BatchMode=yes" in cmdl and "ControlPath=/tmp/abip-%C" in cmdl
print("SSH MASTER OK")

# ---- firewall by name ------------------------------------------------------------------------
cfw = m.server_config(m.load_config({}, None), S1, 0, 1)
apifw = m.ArvanAPI(cfw, m.Http(cfw, m.EventLog(cfw, quiet=True)), "k")
apifw.server_id = "srv1"
assert apifw.firewall_for_new_ip() == ["sg1"]                     # "Default" by name
cfw["FIREWALL_NAME"] = "allow-any"; assert apifw.firewall_for_new_ip() == ["sg2"]
cfw["FIREWALL_NAME"] = ""; cfw["FIREWALL_ID"] = "sg9"; assert apifw.firewall_for_new_ip() == ["sg9"]
cfw["FIREWALL_ID"] = ""; cfw["FIREWALL_NAME"] = "nope"
try:
    apifw.firewall_for_new_ip(); raise SystemExit("accepted unknown firewall name")
except m.AbortRun as e:
    print("rejected:", str(e)[:80])
print("FIREWALL OK")

# ---- regions, verdict rules, re-judging of saved results, state table ---------------------------
regs = {"iran": {"ok": 3, "fail": 0, "unknown": 0}, "europe": {"ok": 2, "fail": 1, "unknown": 0}}
assert m.regions_text(regs) == "IR 3/3  EU 2/3", m.regions_text(regs)

R_, I_, B_, D_, Q_ = m.REACHABLE, m.IRAN_ONLY, m.BLOCKED, m.DOWN, m.INCONCLUSIVE
agg = m.aggregate_verdict
assert agg([R_, R_]) == ("GOOD", "")
assert agg([I_, I_]) == ("BAD", "Iran only")
assert agg([B_, B_]) == ("BAD", "blocked in Iran")
assert agg([I_, B_]) == ("BAD", "Iran only / blocked in Iran")
assert agg([D_, D_]) == ("DOWN", "no region reached it")
assert agg([R_, D_]) == ("MIXED", "checks disagree: reachable, down")
assert agg([R_, I_])[0] == "MIXED" and agg([R_, B_])[0] == "MIXED"
assert agg([R_, Q_]) == ("GOOD", "") and agg([Q_, Q_])[0] == "INCONCLUSIVE"
assert agg([R_, R_, D_])[0] == "GOOD" and agg([I_, I_, R_])[0] == "BAD" and agg([D_, D_, R_])[0] == "DOWN"
assert m.checks_text([R_, I_, B_, D_, Q_]) == "RIBD?"


def old_row(ip, checks, regions, rnd=1, released=True, t="2026-11-11T14:26:12Z"):
    """A result as it was saved BEFORE the Iran-only rule: a check is REACHABLE whenever Iran
    reached the IP, and only control_ok says how many nodes outside Iran did."""
    return {"server": S1, "ip": ip, "round": rnd, "verdict": "GOOD", "released": released, "finished_at": t,
            "cycles": [{"verdict": v, "ok": 7, "fail": 0, "control_ok": c} for v, c in checks],
            "regions": {k: {"ok": o, "fail": f, "unknown": 0} for k, (o, f) in regions.items()}}


# the five IPs of a real run, as they were stored (all "GOOD" at the time)
iran_only = {"iran": (14, 0), "europe": (0, 34), "usa": (0, 6), "asia": (0, 8), "other": (0, 8)}
world = {"iran": (14, 0), "europe": (33, 2), "usa": (6, 0), "asia": (7, 1), "other": (8, 0)}
flaky = {"iran": (4, 10), "europe": (9, 27), "usa": (1, 5), "asia": (3, 5), "other": (4, 4)}
rows_s = [old_row("37.32.26.100", [(R_, 0), (R_, 0)], iran_only),
          old_row("37.32.26.26", [(R_, 0), (R_, 0)], iran_only),
          old_row("95.38.187.230", [(R_, 17), (D_, 0)], flaky),
          old_row("37.32.26.66", [(R_, 27), (R_, 27)], world),
          old_row("37.32.27.127", [(R_, 0), (R_, 0)], iran_only, released=False),
          {"server": S1, "ip": "94.101.185.166", "round": 1, "verdict": "ERROR", "released": True,
           "error": "released by cleanup", "finished_at": "t"},
          {"server": S1, "ip": S1, "round": 0, "verdict": "MGMT-GOOD"}]
assert m.judge_row(rows_s[0]) == ("BAD", "Iran only"), m.judge_row(rows_s[0])
assert m.judge_row(rows_s[2]) == ("MIXED", "checks disagree: reachable, down")
assert m.judge_row(rows_s[3]) == ("GOOD", "")
assert m.judge_row(rows_s[5]) == ("ERROR", "released by cleanup")
m.RULES["OUTSIDE_MIN_OK"] = 0                                  # rule off: Iran alone decides again
assert m.judge_row(rows_s[0]) == ("GOOD", "")
m.RULES["OUTSIDE_MIN_OK"] = 1
# a result with no evidence from outside Iran keeps what was stored
assert m.judge_row(old_row("9.9.9.9", [(R_, 0)], {"iran": (7, 0)})) == ("GOOD", "")
# a later "released by cleanup" row does not hide an earlier real test of the same IP
both = [rows_s[3], {"server": S1, "ip": "37.32.26.66", "round": 2, "verdict": "ERROR", "released": True}]
assert m.latest_per_ip(both)[0].get("cycles")

# a tested IP left attached, then released by `cleanup` later: no longer shown as attached
later = rows_s + [{"server": S1, "ip": "37.32.27.127", "round": 5, "verdict": "ERROR", "released": True,
                   "error": "released by cleanup", "finished_at": "t9"}]
row_127 = [r for r in m.latest_per_ip(later) if r["ip"] == "37.32.27.127"][0]
assert row_127["released"] is True and row_127.get("cycles") and m.judge_row(row_127)[0] == "BAD"
assert "STILL ATTACHED" not in m.state_table(m.latest_per_ip(later))
# an IP left attached before it could be tested is reported as attached, not as released
stuck = [{"server": S1, "ip": "5.5.5.5", "round": 1, "verdict": "ERROR", "released": False, "error": "x"}]
st_stuck = m.state_table(m.latest_per_ip(stuck))
assert "STILL ATTACHED, not tested: 5.5.5.5" in st_stuck and "released after an error" not in st_stuck, st_stuck

latest = m.latest_per_ip(rows_s)
assert S1 not in [r["ip"] for r in latest] and len(latest) == 6
st = m.state_table(latest)
print(st)
lines_st = st.split("\n")
assert lines_st[1].startswith("37.32.26.66") and " GOOD " in lines_st[1], lines_st[1]      # GOOD first
assert [l.split()[1] for l in lines_st[2:5]] == ["BAD", "BAD", "BAD"] and "Iran only" in lines_st[2]
assert "STILL ATTACHED" in st and "0/34" in st and "33/35" in st
assert "GOOD  1: 37.32.26.66" in st and "BAD   3: 37.32.26.26, 37.32.26.100, 37.32.27.127" in st
assert "MIXED 1: 95.38.187.230" in st and "not tested (released after an error): 94.101.185.166" in st
print("STATE OK")

# ---- one check reaches every region; GOOD needs Iran AND outside Iran ----------------------------
fake_nodes = {"ir1.node": {"location": ["ir"]}, "ir2.node": {"location": ["ir"]}, "ir3.node": {"location": ["ir"]},
              "de1.node": {"location": ["de"]}, "us1.node": {"location": ["us"]}, "sg1.node": {"location": ["sg"]}}
m.Reachability.cycle, m.CheckHost.probe_nodes = ORIG_CYCLE, ORIG_PROBE
cr = m.server_config(m.load_config({}, None), S1, 0, 1)
cr.update(PROBE_NODES=[], CONTROL_NODES=[], IRAN_CONTROL_TARGET="", CHECK_TYPE="tcp")
logr = m.EventLog(cr, quiet=True)
chr_ = m.CheckHost(cr, m.Http(cr, logr), logr)
chr_.nodes = lambda: fake_nodes
seen_nodes = []
failing = {"de1.node"}                                   # which nodes cannot reach the IP
def fake_run(self, ctype, host, nodes):
    seen_nodes.extend(nodes)
    raw = {n: ([{"error": "timeout"}] if n in failing else [{"time": 0.1, "address": "x"}]) for n in nodes}
    return raw, nodes, "https://check-host.net/check-report/y"
m.CheckHost.run = fake_run
m.CheckHost.submit = None
reach = m.Reachability(cr, chr_, logr)
res = reach.cycle(S1, "test")
assert set(seen_nodes) == {"ir1.node", "ir2.node", "ir3.node", "de1.node", "us1.node", "sg1.node"}, seen_nodes
assert res["by_region"]["iran"] == {"ok": 3, "fail": 0, "unknown": 0}, res["by_region"]
assert res["by_region"]["europe"] == {"ok": 0, "fail": 1, "unknown": 0}, res["by_region"]
assert res["verdict"] == "REACHABLE" and res["outside_ok"] == 2 and res["outside_fail"] == 1, res
# Iran reaches it, nobody outside Iran does -> Iran only (bad)
failing.clear(); failing.update({"de1.node", "us1.node", "sg1.node"})
res = reach.cycle(S1, "test")
assert res["verdict"] == "IRAN_ONLY" and res["outside_ok"] == 0 and res["outside_fail"] == 3, res
# one single node outside Iran is enough to not be "Iran only"
failing.clear(); failing.update({"de1.node", "us1.node"})
assert reach.cycle(S1, "test")["verdict"] == "REACHABLE"
# the rule can be turned off
cr["OUTSIDE_MIN_OK"] = 0
failing.clear(); failing.update({"de1.node", "us1.node", "sg1.node"})
assert reach.cycle(S1, "test")["verdict"] == "REACHABLE"
cr["OUTSIDE_MIN_OK"] = 1
# outside reaches it, Iran does not -> blocked in Iran (bad)
failing.clear(); failing.update({"ir1.node", "ir2.node", "ir3.node"})
assert reach.cycle(S1, "test")["verdict"] == "BLOCKED"
# nobody reaches it -> down
failing.update({"de1.node", "us1.node", "sg1.node"})
assert reach.cycle(S1, "test")["verdict"] == "DOWN"
print("REGIONS OK")

# ---- DOWN verdict: diagnostics are collected before the release ---------------------------------
m.Reachability.cycle = lambda self, ip, purpose: {"verdict": "DOWN", "why": "mock", "ok": 0, "fail": 5,
                                                  "unknown": 0, "control_ok": 0, "ok_ratio": 0.0,
                                                  "link": "l", "by_region": {"iran": {"ok": 0, "fail": 5, "unknown": 0}}}
C = yaml("management_ip: %s\n" % S1)
nd = len(cloud["srv1"].detached)
assert m.main(C + ["test", "--yes", "--rounds", "1"]) == 0
last = m.load_results()[-1]
assert last["verdict"] == "DOWN" and len(last["cycles"]) == 1 and os.path.isfile(last["diag_file"]), last
assert len(cloud["srv1"].detached) == nd + 1 and "ping gateway" in [s for _, _, s in scripts if s and "rp_filter" in s][-1]
print("DIAG OK")

# ---- panel mode (default): no ssh at all during init, preflight, test, cleanup ------------------
m.DEFAULTS["VM_CONFIG_MODE"] = "panel"
good = {"verdict": "REACHABLE", "why": "mock", "ok": 5, "fail": 0, "unknown": 0, "control_ok": 3,
        "ok_ratio": 1.0, "link": "l", "by_region": {"iran": {"ok": 5, "fail": 0, "unknown": 0},
                                                    "europe": {"ok": 3, "fail": 0, "unknown": 0}}}
m.Reachability.cycle = lambda self, ip, purpose: dict(good)
m.CheckHost.probe_nodes = lambda self: ["ir1", "ir2", "ir3"]
m.socket.create_connection = lambda *a, **k: __import__("contextlib").nullcontext()
C = yaml("management_ip: %s\nssh_key: ~/nope/missing_key\n" % S1)      # a bad ssh key must not matter
n_ssh, nd = len(scripts), len(cloud["srv1"].detached)
assert m.main(C + ["init"]) == 0
assert m.main(C + ["preflight"]) == 0
assert m.main(C + ["test", "--dry-run"]) == 0
assert m.main(C + ["test", "--yes", "--rounds", "2"]) == 0
assert len(scripts) == n_ssh, "panel mode must not use ssh"
assert len(cloud["srv1"].detached) == nd + 2 and [p["id"] for p in cloud["srv1"].ports] == ["p-mgmt-srv1"]
last = m.load_results()[-1]
assert last["verdict"] == "GOOD" and last["mgmt_back"] is True and last["regions"]["europe"]["ok"] == 6, last
assert os.path.isfile(os.path.join(home, "state.txt"))
# all checks DOWN in panel mode: every cycle is run, then the IP is still released
m.Reachability.cycle = lambda self, ip, purpose: {"verdict": "DOWN", "why": "mock", "ok": 0, "fail": 5,
                                                  "unknown": 0, "control_ok": 0, "ok_ratio": 0.0, "link": "l",
                                                  "by_region": {"iran": {"ok": 0, "fail": 5, "unknown": 0}}}
assert m.main(C + ["test", "--yes", "--rounds", "1"]) == 0
last = m.load_results()[-1]
assert last["verdict"] == "DOWN" and len(last["cycles"]) == 2 and last["released"] is True, last
assert len(scripts) == n_ssh
print("PANEL OK")

# ---- results.csv is rebuilt from results.jsonl: same columns in every row, current rules -------------
import csv as _csv
with open(os.path.join(home, "results.csv"), newline="", encoding="utf-8") as fh:
    rd = _csv.reader(fh)
    header = next(rd)
    body = list(rd)
all_rows = m.load_results()
assert header == m.RESULT_FIELDS and len(body) == len(all_rows), (len(body), len(all_rows))
assert all(len(r) == len(header) for r in body)
vcol, rcol = header.index("verdict"), header.index("reason")
assert [(r[vcol], r[rcol]) for r in body] == [m.judge_row(r) for r in all_rows]
print("CSV OK")

# ---- nap(): a worker is woken once by a stop request; a release is shielded from it -----------------
import threading
out_nap = {}


def nap_once():
    try:
        m.nap(5)
        out_nap["first"] = "slept"
    except m.StopRequested:
        out_nap["first"] = "woken"
    m.nap(5)                                   # the same worker is not interrupted a second time
    out_nap["second"] = "slept"


def nap_shielded():
    with m.shielded():
        m.nap(5)
        out_nap["shielded"] = "slept"
    try:
        m.nap(1)
        out_nap["after"] = "slept"
    except m.StopRequested:
        out_nap["after"] = "woken"


m.PARALLEL_ACTIVE = True
m.STOP.set()
for fn in (nap_once, nap_shielded):
    th = threading.Thread(target=fn)
    th.start()
    th.join(10)
m.PARALLEL_ACTIVE = False
m.STOP.clear()
assert out_nap == {"first": "woken", "second": "slept", "shielded": "slept", "after": "woken"}, out_nap
m.nap(0)                                       # outside a parallel run it is an ordinary sleep
print("NAP OK")

# ---- several servers are tested at the same time (panel mode) -----------------------------------------
import contextlib as _ctx
import io as _io
barrier = threading.Barrier(2, timeout=20)     # both servers must be inside a check at the same moment
met, calls, call_lock = set(), [], threading.Lock()


def par_cycle(self, ip, purpose):
    me = threading.current_thread().name
    with call_lock:
        calls.append((me, ip))
        first = me not in met
        met.add(me)
    if first:
        barrier.wait()                         # times out (and fails the test) if the run is sequential
    return dict(good)


m.Reachability.cycle = par_cycle
C = yaml('management_ip: "%s, %s"\nrounds: 3\n' % (S1, S2))
assert m.main(C + ["init"]) == 0
c2 = cloud["srv2"]
n1, n2, rows0 = len(c1.detached), len(c2.detached), len(m.load_results())
buf = _io.StringIO()
with _ctx.redirect_stdout(buf):
    rc = m.main(C + ["test", "--yes"])
text = buf.getvalue()
assert rc == 0, text[-1500:]
assert "testing 2 servers at the same time" in text
assert "[%s] " % S1 in text and "[%s] " % S2 in text          # every line says which server it is about
assert len(c1.detached) == n1 + 3 and len(c2.detached) == n2 + 3
assert [p["id"] for p in c1.ports] == ["p-mgmt-srv1"] and [p["id"] for p in c2.ports] == ["p-mgmt-srv2"]
new_rows = m.load_results()[rows0:]
assert len(new_rows) == 6 and sorted(r["server"] for r in new_rows) == [S1] * 3 + [S2] * 3, new_rows
assert all(r["verdict"] == "GOOD" and r["released"] is True for r in new_rows)
assert {name for name, _ in calls} == {S1, S2}                # one worker thread per server
assert all(ip.startswith("185.1.1.") == (name == S1) for name, ip in calls)   # each tests its own IPs
assert not m.State(S1).pending and not m.State(S2).pending
with open(os.path.join(home, "results.jsonl"), encoding="utf-8") as fh:        # no torn lines
    assert all(json.loads(line) for line in fh)

# --sequential: one server after another, in the main thread
calls.clear()
m.Reachability.cycle = lambda self, ip, purpose: (calls.append((threading.current_thread().name, ip)), dict(good))[1]
buf = _io.StringIO()
with _ctx.redirect_stdout(buf):
    rc = m.main(C + ["test", "--yes", "--sequential", "--rounds", "1"])
assert rc == 0 and "at the same time" not in buf.getvalue()
assert {name for name, _ in calls} == {"MainThread"} and len(calls) == 4
print("PARALLEL OK")

# ---- Ctrl-C in a parallel run: every server stops, and releases its test IP first -------------------
import _thread
fired = []


def stop_cycle(self, ip, purpose):
    with call_lock:
        first = not fired
        fired.append(ip)
    if first:
        _thread.interrupt_main()               # as if Ctrl-C was pressed during this check
        assert m.STOP.wait(30), "the main thread never asked the workers to stop"
    return dict(good)


m.Reachability.cycle = stop_cycle
n1, n2 = len(c1.detached), len(c2.detached)
buf = _io.StringIO()
with _ctx.redirect_stdout(buf):
    rc = m.main(C + ["test", "--yes", "--rounds", "50"])
text = buf.getvalue()
assert rc == 4, (rc, text[-1500:])
assert "Ctrl-C: stopping every server" in text
assert [p["id"] for p in c1.ports] == ["p-mgmt-srv1"] and [p["id"] for p in c2.ports] == ["p-mgmt-srv2"], text[-1500:]
assert not m.State(S1).pending and not m.State(S2).pending
done = (len(c1.detached) - n1) + (len(c2.detached) - n2)
assert 1 <= done < 100, done                   # it stopped long before the 50 rounds per server
assert not m.PARALLEL_ACTIVE and not m.STOP.is_set()
print("PARALLEL STOP OK")

# ---- Ctrl-C between the request for an IP and the API listing it: it is found and released ----------
orig_find = m.Agent._find_new_port
state_find = {"n": 0}


def slow_find(self, ports_before):
    state_find["n"] += 1
    if state_find["n"] == 1:
        raise KeyboardInterrupt            # Ctrl-C while the script waits for the new IP to be listed
    return orig_find(self, ports_before)


m.Agent._find_new_port = slow_find
m.Reachability.cycle = lambda self, ip, purpose: dict(good)
C = yaml("management_ip: %s\n" % S1)
nd = len(c1.detached)
rc = m.main(C + ["test", "--yes", "--rounds", "3"])
m.Agent._find_new_port = orig_find
assert rc == 4, rc
assert len(c1.detached) == nd + 1 and [p["id"] for p in c1.ports] == ["p-mgmt-srv1"]   # found and released
assert not m.State(S1).pending
print("STOP WINDOW OK")

# ---- check-host pacing: one queue for all servers; two checks of one IP are further apart ------------
m.CheckHost.run, m.CheckHost.submit = ORIG_RUN, ORIG_SUBMIT
naps, replies = [], []
real_nap, saved_request = m.nap, m.Http.request
m.nap = lambda sec: naps.append(float(sec))          # record the waits instead of waiting


def ch_http(self, method, url, headers=None, json_body=None, idempotent=None, retries=None, timeout=None,
            raw_body=None):
    if "/check-tcp?" in url:
        body = replies.pop(0) if replies else {"ok": 1, "request_id": "r1", "permanent_link": "l",
                                               "nodes": {"ir1": []}}
        return m.HttpResponse(200, {}, json.dumps(body).encode(), url)
    if "/check-result/" in url:
        return m.HttpResponse(200, {}, json.dumps({"ir1": [{"time": 0.1, "address": "x"}]}).encode(), url)
    raise AssertionError(url)


m.Http.request = ch_http
cp = m.server_config(m.load_config({}, None), S1, 0, 1)
assert cp["CHECKHOST_MIN_SPACING_SEC"] == 30 and cp["CHECK_SPACING_SEC"] == 60
lg = m.EventLog(cp, quiet=True)
ch_a, ch_b = m.CheckHost(cp, m.Http(cp, lg), lg), m.CheckHost(cp, m.Http(cp, lg), lg)     # two servers
m.CheckHost.last_submit = 0.0
ch_a.submit("tcp", "1.1.1.1:22", ["ir1"])
assert naps == []                                     # the first request goes out at once
ch_b.submit("tcp", "2.2.2.2:22", ["ir1"])             # another server, right after it
assert len(naps) == 1 and 29 <= naps[0] <= 30, naps   # it waits its turn in the shared queue
assert 0 < ch_a.last_own_submit <= ch_b.last_own_submit
# check-host answers "limit exceeded": the queue backs off for 2 minutes, for every server
naps.clear()
replies[:] = [{"error": "limit_exceeded"}]
m.CheckHost.last_submit = 0.0
ch_a.run("tcp", "1.1.1.1:22", ["ir1"])
assert any(119 <= x <= 120 for x in naps), naps
m.Http.request = saved_request


def paced_cycle(self, ip, purpose):                   # as a real check does: note when it was sent
    self.ch.last_own_submit = m.time.time()
    return dict(good)


m.Reachability.cycle = paced_cycle
m.CheckHost.last_submit = 0.0
naps.clear()
C = yaml("management_ip: %s\n" % S1)
assert m.main(C + ["test", "--yes", "--rounds", "1"]) == 0
assert any(59 <= x <= 60 for x in naps), naps         # the IP's second check: 60 s after its first
m.nap = real_nap
print("PACING OK")

# ---- a server in another region: init searches the regions and remembers the one it is in ---------
S3 = "185.3.3.10"
srv3 = FakeServer("srv3", "185.3.3")
other_region = "ir-tbz-dc1"
base_call = m.ArvanAPI.call
region_calls = []


def region_call(self, method, url, body=None, idempotent=None, allow_404=False, empty_body=False):
    if url.endswith("/ecc/v1/details"):
        return [{"code": "ir-thr-ba1", "dc": "x"}, {"code": other_region, "dc": "y"}, {"code": "not a code"}]
    region = url.split("/regions/")[1].split("/")[0]
    region_calls.append(region)
    if "/servers/nope" in url:                       # an ID that exists in no region
        raise m.ApiError(method, url, 404, "Instance not found", None)
    if region == other_region:
        path = url.split("/regions/" + other_region)[1]
        if method == "GET" and path == "/servers":
            return [srv3.server()]
        if method == "GET" and path == "/servers/srv3":
            return srv3.server()
        if method == "GET" and path == "/networks":
            return [{"id": "n-srv3", "name": "public", "subnets": [{
                "id": "sub3", "cidr": "185.3.3.0/24", "gateway_ip": "185.3.3.1",
                "servers": [{"id": "srv3", "ips": [{"ip": S3, "mac_address": "aa:3", "port_id": "p-mgmt-srv3",
                                                    "public": True, "float_ip": False}]}]}]}]
        raise AssertionError((method, path))
    if "/servers/srv3" in url:                       # srv3 does not exist in ir-thr-ba1
        raise m.ApiError(method, url, 404, "Instance not found", None)
    return base_call(self, method, url, body, idempotent, allow_404, empty_body)


m.ArvanAPI.call = region_call
assert m.ArvanAPI(m.load_config({}, None), None, "k").list_regions()[:2] == ["ir-thr-ba1", other_region]

# by server ID: not in ir-thr-ba1 -> found in ir-tbz-dc1, and saved
C = yaml('management_ip: "%s, %s"\nserver_id: "srv1, srv3"\nregion: ir-thr-ba1\n' % (S1, S3))
assert m.main(C + ["init"]) == 0
assert json.load(open(m.config_path(S3)))["REGION"] == other_region
assert json.load(open(m.config_path(S1)))["REGION"] == "ir-thr-ba1"
base3 = m.load_config({}, y)
assert m.server_config(base3, S3, 1, 2)["REGION"] == other_region          # the saved region wins
assert m.server_config(base3, S1, 0, 2)["REGION"] == "ir-thr-ba1"

# by IP (no server_id): found by searching the regions too
os.remove(m.config_path(S3))
C = yaml('management_ip: "%s, %s"\n' % (S1, S3))
assert m.main(C + ["init"]) == 0
cfg3 = json.load(open(m.config_path(S3)))
assert cfg3["REGION"] == other_region and cfg3["SERVER_ID"] == "srv3", cfg3

# a region per IP (comma list) is used as given; a wrong count is refused
C = yaml('management_ip: "%s, %s"\nregion: "ir-thr-ba1, %s"\n' % (S1, S3, other_region))
b3 = m.load_config({}, y)
assert m.server_config(b3, S1, 0, 2)["REGION"] == "ir-thr-ba1" and m.server_config(b3, S3, 1, 2)["REGION"] == other_region
C = yaml('management_ip: "%s, %s"\nregion: "a-b-c, d-e-f, g-h-i"\n' % (S1, S3))
assert m.main(C + ["status"]) == 1

# a server ID that exists nowhere: a clear error after searching
C = yaml('management_ip: "%s"\nserver_id: "nope"\n' % S3)
os.remove(m.config_path(S3))
assert m.main(C + ["init"]) == 1
m.ArvanAPI.call = base_call
print("REGIONS SEARCH OK")

# ---- a slow release: ArvanCloud ignores the first request; the script asks again and waits ---------
import contextlib as _ctx2
import io as _io2
ignored, base_call2 = set(), m.ArvanAPI.call


def slow_detach(self, method, url, body=None, idempotent=None, allow_404=False, empty_body=False):
    if method == "PATCH" and url.endswith("/detach"):
        pid = url.split("/networks/")[1].split("/")[0]
        if pid not in ignored:                    # the first request for each port is not carried out
            ignored.add(pid)
            return {}
    return base_call2(self, method, url, body, idempotent, allow_404, empty_body)


m.ArvanAPI.call = slow_detach
m.Reachability.cycle = lambda self, ip, purpose: dict(good)
C = yaml("management_ip: %s\nrelease_timeout_sec: 5\nrelease_retry_sec: 0.3\n" % S1)
old_ips = {r["ip"] for r in m.load_results() if r.get("ip")}
buf = _io2.StringIO()
with _ctx2.redirect_stdout(buf):
    rc = m.main(C + ["test", "--yes", "--rounds", "2"])
out2 = buf.getvalue()
m.ArvanAPI.call = base_call2
assert rc == 0, out2[-1500:]
assert out2.count("release_request_again") == 2 and [p["id"] for p in c1.ports] == ["p-mgmt-srv1"], out2[-1500:]
# the report at the end shows only the IPs of this run
report = out2.split("===== this run:")[1]
assert report.startswith(" 2 IP(s) tested"), report[:200]
run_ips = {r["ip"] for r in m.load_results()[-2:]}
assert all(ip in report for ip in run_ips) and not any(ip in report for ip in old_ips), report
print("SLOW RELEASE OK")
