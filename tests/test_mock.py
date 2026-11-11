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
    if parts[0] == "servers":
        c = cloud[parts[1]]
        if method == "GET" and len(parts) == 2:
            return c.server()
        if method == "POST" and parts[2] == "add-public-ip":
            if body is None:                         # like the real API: empty body refused
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
assert len(rows) == 6 and all(r["server"] == S1 for r in rows), rows
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

# ---- SSH: normal commands reuse the master and never authenticate ---------------------------
cs = m.server_config(m.load_config({}, None), S1, 0, 1)
cmdl = m.Ssh(cs, m.EventLog(cs, quiet=True)).base_cmd()
assert "ControlMaster=no" in cmdl and "BatchMode=yes" in cmdl and "ControlPath=/tmp/abip-%C" in cmdl
print("SSH MASTER OK")
