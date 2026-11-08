import os, sys, json, tempfile, subprocess, types, itertools
home = tempfile.mkdtemp(); os.chdir(home); os.environ["ABIP_HOME"] = home; os.environ["ARVAN_API_KEY"] = "Apikey xyz"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import arvin_agent_badip as m
m.time.sleep = lambda s: None
def _no_conn(*a, **k): raise OSError("mock")
m.socket.create_connection = _no_conn

class FakeCloud:
    def __init__(s):
        s.ports = [{"id":"p-mgmt","ips":["185.1.1.10"],"mac_address":"aa:00","network_id":"n1","security_group_ids":["sg1"],"status":"ACTIVE"}]
        s.n = itertools.count(20); s.detached=[]; s.fail_add=None
    def server(s):
        return {"id":"srv1","name":"vm1","addresses":{"pub":[{"addr":ip,"is_public":True} for p in s.ports for ip in p["ips"]]}}
cloud = FakeCloud()

def fake_call(self, method, url, body=None, idempotent=None, allow_404=False):
    path = url.split("/regions/ir-thr-ba1")[1]
    if method=="GET" and path=="/servers": return [cloud.server()]
    if method=="GET" and path=="/servers/srv1": return cloud.server()
    if method=="GET" and path=="/servers/srv1/ports": return [dict(p) for p in cloud.ports]
    if method=="GET" and path.startswith("/ports/"):
        pid=path.split("/")[2]; return next((p for p in cloud.ports if p["id"]==pid), None)
    if method=="GET" and path.startswith("/networks/"):
        return {"id":"n1","subnets":[{"cidr":"185.1.1.0/24","gateway_ip":"185.1.1.1"}]}
    if method=="GET" and path=="/quotas": return {}
    if method=="POST" and path.endswith("/add-public-ip"):
        assert body["security_groups"]==["sg1"]
        k=next(cloud.n); p={"id":"p-%d"%k,"ips":["185.1.1.%d"%k],"mac_address":"bb:%02d"%k,"network_id":"n1","security_group_ids":["sg1"],"status":"ACTIVE"}
        cloud.ports.append(p)
        if cloud.fail_add=="lost": raise m.AmbiguousRequestError("lost")
        return {"port_id":p["id"],"mac_addr":p["mac_address"],"fixed_ips":[{"ip_address":p["ips"][0]}]}
    if method=="PATCH" and path.endswith("/detach"):
        pid=path.split("/")[2]; assert pid!="p-mgmt"
        cloud.detached.append(pid); cloud.ports=[p for p in cloud.ports if p["id"]!=pid]; return {}
    raise AssertionError((method, path))
m.ArvanAPI.call = fake_call

scripts=[]
def fake_run(self, remote, stdin=None, check=True, timeout=60, multiplex=True):
    scripts.append((remote, stdin))
    out=""
    if remote.startswith("ip -j link"):
        out=json.dumps([{"ifname":"eth0","address":"aa:00"}]+[{"ifname":"eth%d"%i,"address":p["mac_address"]} for i,p in enumerate(cloud.ports[1:],1)])
    elif remote.startswith("ip -j -4 addr"):
        out=json.dumps([{"ifname":"eth0","addr_info":[{"local":"185.1.1.10","prefixlen":24}]}])
    elif remote.startswith("ip -j -4 route"):
        out=json.dumps([{"dev":"eth0","gateway":"185.1.1.1"}])
    elif remote.startswith("curl"):
        src=remote.split("--interface ")[1].split()[0]; out=src+"\n"
    elif "sh -s" in remote and stdin and "id -u" in stdin: out="0\n"
    elif remote.startswith("command -v"): out="/usr/sbin/ip\n/usr/bin/curl\n"
    elif remote.startswith("ss "): out="LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    return subprocess.CompletedProcess(remote, 0, out, "")
m.Ssh.run = fake_run
m.Ssh.close_master = lambda self: None
m.agent_keys = lambda: (True, ["ssh-ed25519 AAA"], "1 key")

verd = itertools.cycle(["REACHABLE","BLOCKED","BLOCKED"])
def fake_cycle(self, ip, purpose):
    v = "REACHABLE" if purpose=="baseline-mgmt" else next(verd)
    return {"verdict":v,"why":"mock","ok":5 if v=="REACHABLE" else 0,"fail":0 if v=="REACHABLE" else 5,"unknown":0,"control_ok":3,"ok_ratio":1.0 if v=="REACHABLE" else 0.0,"link":"https://check-host.net/check-report/x"}
m.Reachability.cycle = fake_cycle
m.CheckHost.probe_nodes = lambda self: ["ir1","ir2","ir3"]

rc = m.main(["init","--management-ip","185.1.1.10"]); print("init rc",rc); assert rc==0
cfg=json.load(open(home+"/config.json")); assert cfg["MANAGEMENT_PORT_ID"]=="p-mgmt" and cfg["MANAGEMENT_GATEWAY"]=="185.1.1.1", cfg
assert m.main(["preflight"])==0
assert m.main(["test","--dry-run"])==0
rc = m.main(["test","--yes"]); print("test rc", rc); assert rc==0
assert len(cloud.detached)==5 and [p["id"] for p in cloud.ports]==["p-mgmt"], cloud.detached
rows=m.load_results(); print([ (r["round"],r["ip"],r["verdict"]) for r in rows])
assert len(rows)==6
assert m.main(["results","--bad"])==0
# mgmt route pinned and unpinned
assert any(s and "ip rule add from \"$MIP/32\"" in s for _,s in scripts)
assert any(s and "MGMT" not in s and "ip rule del from \"$MIP/32\"" in s for _,s in scripts)

# lost allocation reply -> reconciled by port diff
cloud.fail_add="lost"
rc = m.main(["test","--yes","--rounds","1","--no-baseline"]); assert rc==0, rc
assert [p["id"] for p in cloud.ports]==["p-mgmt"]

# crash after POST (pending left) -> cleanup
cloud.fail_add=None
orig=m.Agent._configure_and_test
def boom(self,p,r): raise KeyboardInterrupt
m.Agent._configure_and_test=boom
orig_rel=m.Agent.release
m.Agent.release=lambda self,p: (_ for _ in ()).throw(KeyboardInterrupt())
rc=m.main(["test","--yes","--rounds","1","--no-baseline"]); print("crash rc",rc)
m.Agent.release=orig_rel; m.Agent._configure_and_test=orig
assert m.State().pending and len(cloud.ports)==2
assert m.main(["test","--yes"])==1   # refuses with pending
assert m.main(["cleanup","--yes"])==0
assert [p["id"] for p in cloud.ports]==["p-mgmt"] and not m.State().pending
print("ALL OK")

# ---- YAML inputs ----------------------------------------------------------
repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
tpl = m.load_yaml_inputs(os.path.join(repo, "arvin-agent-badip.yaml"))
assert tpl["SSH_USER"] == "hani" and tpl["ROUNDS"] == 5 and tpl["PROBE_NODES"] == [] \
    and tpl["IRAN_CONTROL_TARGET"] == "1.1.1.1:443" and "MANAGEMENT_IP" not in tpl, tpl
y = os.path.join(home, "in.yaml")
open(y, "w").write('management_ip: 185.1.1.10   # mgmt\nrounds: 2\nssh_extra_opts:\n  - "-o"\n  - "ProxyJump=b # x"\n'
                   'check_type: ping\nbaseline_check: no\n')
d = m.load_yaml_inputs(y)
assert d == {"MANAGEMENT_IP": "185.1.1.10", "ROUNDS": 2, "SSH_EXTRA_OPTS": ["-o", "ProxyJump=b # x"],
             "CHECK_TYPE": "ping", "BASELINE_CHECK": False}, d
for bad in ("rounds: five\n", "api_key: abc\n", "foo: 1\n", "a:\n  b: 1\n"):
    open(y, "w").write(bad)
    try:
        m.load_yaml_inputs(y); raise SystemExit("accepted bad yaml: %r" % bad)
    except m.AgentError as e:
        print("rejected:", e)
open(y, "w").write("rounds: 1\nno_baseline_dummy_removed: 1\n".split("\n")[0] + "\nbaseline_check: false\n")
n0 = len(cloud.detached)
assert m.main(["--config", y, "test", "--yes"]) == 0 and len(cloud.detached) == n0 + 1
open(y, "w").write("management_ip: 185.9.9.9\n")
assert m.main(["--config", y, "status"]) == 1     # differs from init -> must re-run init
print("YAML OK")

# ---- Windows behaviour -----------------------------------------------------
m.IS_WINDOWS = True
open(y, "w").write("ssh_user: root\n"); cfgw = m.load_config({}, y)
ssh = m.Ssh(cfgw, m.EventLog(cfgw, quiet=True))
cmd = " ".join(ssh.base_cmd())
assert "ControlMaster" not in cmd and "ControlPath" not in cmd, cmd
assert ssh.sudo_prefix() == ""
for bad in ("apikey 11111111-2222-3333-4444-555555555555", "11111111-2222-3333-4444-555555555555"):
    try:
        m.load_api_key(bad); raise SystemExit("accepted key as path")
    except m.AgentError as e:
        assert "1111" not in str(e); print("rejected key-as-path:", str(e)[:60])
kf = os.path.join(home, "k.txt"); open(kf, "w").write("Apikey abc\n"); os.chmod(kf, 0o644)
saved = os.environ.pop("ARVAN_API_KEY")
assert m.load_api_key(kf)[0] == "abc"          # no chmod check on Windows
os.environ["ARVAN_API_KEY"] = saved
m.IS_WINDOWS = False
assert m.main([]) == 1
print("WINDOWS OK")
