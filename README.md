# arvin-agent-badip

`arvin-agent-badip` finds out whether the public IPv4 addresses ArvanCloud gives your server are **GOOD** (reachable from Iran and from outside Iran) or **BAD** (reachable from one side only). Each run allocates a test IP, tests it, releases it, and saves the result. It does this `ROUNDS` times (5 by default).

The tool is one file, `arvin_agent_badip.py`, and needs only the Python 3.8+ standard library. It runs on **your Mac**, not on the server. It can test **several servers** in one run: list their management IPs separated by commas, and they are tested at the same time.

| Credential | Gives access to | Used for |
|---|---|---|
| ArvanCloud **API key** | the panel | add and remove public IPs, read ports, networks and subnets |
| SSH as **`hani`** with your **macOS ssh-agent** key (or a key file, or the key itself) | the VM itself, through the saved **management IP** | bring each test IP up on its NIC, check its egress, then remove it |

The management IP is never released, and neither is its port or any port that existed before a round. Only the port the round created is released.

## Two modes

`vm_config_mode` in the YAML file chooses how a new IP gets configured on the server.

**`panel` (default).** On ArvanCloud the panel does it: when an IP is added it writes the netplan config and the route on the server, and when the IP is deleted it removes them. While a test IP is attached the **management IP is unusable**, so in this mode the script never uses SSH:

1. Add the IP through the API.
2. Wait `new_ip_settle_sec` (45 s) for the panel to configure it.
3. Test it from Iran and the other regions.
4. Remove it through the API and wait for the management IP to answer again.

Only the API key is needed. `ssh_user` and `ssh_key` are ignored.

**`ssh`.** For images where nothing configures the new card: the script does it over SSH, as described below.

## What one round does (ssh mode)

1. **Allocate:** `POST /servers/{id}/add-public-ip` with the firewall named by `firewall_name`. This is billable. The pending allocation is written to `state.json` *before* the request is sent. The reply carries no port details, so the new port is found by comparing the port list from `GET /networks` with the one saved before the request.
2. **Configure (SSH + sudo):**
   - It waits for the new port to show up in `GET /networks` with its MAC, and for its NIC (matched by MAC) to appear in the VM.
   - It adds the address and a source policy route (`from <test-ip> lookup 2100`).
   - It removes any DHCP default route that the hot-plugged NIC added to `main`.
   - Then it checks that `curl --interface <test-ip>` sees the test IP.
3. **Test:** it runs `CHECKS_PER_IP` (default 2) check-host.net cycles against `<test-ip>:22`.
   - The probes come from up to 10 Iranian nodes.
   - Control nodes outside Iran tell "blocked in Iran" apart from "down".
   - A probe-health check against `1.1.1.1:443` from the Iranian nodes filters out nodes that are themselves broken.
4. **Release:** it removes the IP from the OS, sends `PATCH /networks/{port}/detach`, and waits until the panel no longer lists the port.
5. **Save:** the result goes to `~/arvin-agent-badip/results.csv` and `results.jsonl`.

Before the first round, the management IP's replies are pinned to its own NIC with a policy route (`from <mgmt-ip> lookup 2099`). A new NIC therefore can't take over your SSH return path. The pin is confirmed with a **fresh** SSH connection. If that confirmation fails, a watchdog inside the VM undoes the pin after 90 s. The pin is removed at the end of the run.

**Guard on the server:** on this ArvanCloud image, adding an IP can cut the management connection until the IP is removed, because the server's network service reconfigures when the new card appears. During a test a small guard loop runs on the server itself. Every second it restores the management rule and route and the test IP's rule and route, and removes a default route through the test card. It stops by itself 15 minutes after the last heartbeat from your computer (`mgmt_guard_life_sec`), and at the end of every run. SSH commands are retried (`ssh_retries`) instead of failing on the first lost connection.

## Setup (macOS)

```sh
# 1. SSH key in the agent (the matching public key must be in ~hani/.ssh/authorized_keys on the VM)
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
ssh-add -L

# 2. API key in the macOS Keychain (paste it at the prompt; it never goes into a file or the shell history)
security add-generic-password -U -a "$USER" -s arvin-agent-badip -w
#    alternatives: api_key in the YAML file (the key or a file path), or export ARVAN_API_KEY=...

# 3. Fill in the inputs file (at least management_ip, region, ssh_user, ssh_key)
mkdir -p ~/arvin-agent-badip
cp arvin-agent-badip.yaml ~/arvin-agent-badip/config.yaml   # or keep it next to the script
chmod 600 ~/arvin-agent-badip/config.yaml
nano ~/arvin-agent-badip/config.yaml

# 4. Save each management IP; the server UUID, management port, NIC and gateway are discovered and stored
./arvin_agent_badip.py init
#    (flags override the file: --management-ip, --region, --server-id, --ssh-user, --ssh-key, --server)
```

### Inputs file (`arvin-agent-badip.yaml`)

All inputs are in one flat YAML file. [`arvin-agent-badip.yaml`](arvin-agent-badip.yaml) is the template, with every key commented. The script looks for it in this order:
1. `--config PATH`
2. `./arvin-agent-badip.yaml`
3. `~/arvin-agent-badip/config.yaml`

| Required | Meaning |
|---|---|
| `management_ip` | the public IPv4 you SSH to; never released. Several servers: `"185.1.1.10, 185.2.2.20"` |
| `region` | ArvanCloud region code, e.g. `ir-thr-ba1` (in the panel URL after `/ecc/`). If a server is not in this region, `init` searches every region and remembers the one it is in. Several servers in different regions can also be given one region per IP: `"ir-thr-ba1, ir-tbz-dc1"` |
| `ssh_user` | `hani` |
| `ssh_key` | see below |

**Firewall:** ArvanCloud refuses a new public IP without a firewall. `firewall_name` (default `Default`) is the name shown in the panel's Firewall list, and the script uses that firewall for every new IP. `firewall_id` can be used instead.

Everything else is optional: `api_key`, `server_id`, `rounds`, `checks_per_ip`, `check_type`, `check_port`, timeouts, and so on.

**`api_key` and `ssh_key` each accept a file path or the value itself:**

| Field | File path | Value itself |
|---|---|---|
| `api_key` | `~/arvin-agent-badip/api_key` (a file holding only the key, chmod 600) | `"apikey 0000…"` (the `apikey ` prefix is optional) |
| `ssh_key` | `~/.ssh/id_ed25519.pub` (ssh-agent key) or `~/.ssh/id_ed25519` (private key file, no agent needed) | `ssh-ed25519 AAAA… me@mac` (agent must hold it), or the private key with `\n` for each line break |

A value written into the YAML file is stored in plain text, so `chmod 600` the file. If `api_key` is empty, the key comes from `$ARVAN_API_KEY`, then `~/arvin-agent-badip/api_key`, then the Keychain. If `ssh_key` is empty, any key in the agent is tried. (`api_key_file` and `ssh_pubkey` still work as older names.)

**Several servers:**
- `test` runs all servers **at the same time** (panel mode). Each server does its own rounds, and every output line starts with that server's management IP.
- `test --sequential`, or `parallel: false` in the YAML file, tests one server after another. `vm_config_mode: ssh` is always one after another.
- check-host.net requests are paced. Two checks of the same IP are `check_spacing_sec` (60 s) apart, and all servers together send at most one request per `checkhost_min_spacing_sec` (30 s). One server alone therefore sends one request a minute, and several servers interleave theirs.
- In a simulation with the timings of a real run, 2 servers finished 1.9× faster than one after another, 3 servers 2.4×, and 5 servers 3.0×. It is not N× because the servers share the check-host queue.
- check-host's limits are not documented. If it starts refusing requests, the script waits 2 minutes and that check may come out unclear; set `checkhost_min_spacing_sec: 60` in that case.
- **Ctrl-C** stops every server. Each one first releases the test IP it has attached.
- The other commands (`init`, `preflight`, `cleanup`, ...) go through the servers one after another. `--server IP` limits any command to one of them.
- `server_id` is optional. If you set it, give one UUID per IP, in the same order.
- Results get a `server` column.

Values override in this order, lowest first: script defaults, then what `init` discovered, then the YAML file, then command-line flags. An empty value keeps the default.

On the VM, `hani` needs **passwordless sudo**, at least for `ip`, `sysctl`, `sh` and `touch`. The VM also needs `ip` and `curl` (or `wget`), and sshd must listen on `0.0.0.0:22`, because check-host probes the test IP on port 22. `preflight` checks all of this.

With a `.pub` key, ssh asks the agent for exactly that key (`IdentitiesOnly=yes`).

**SSH login:** on macOS the script logs in to each server once with the terminal attached, so ssh can ask for a key passphrase, a security-key PIN or a touch. Every later command reuses that connection (for up to 30 minutes, `ssh_master_persist_sec`) and never authenticates again. If the login with `ssh_key` fails, it retries the way plain `ssh hani@<ip>` does.

## Results at a glance

Every check runs from Iran and from several other regions at once (Europe, USA, Asia, other). An IP is judged from both sides:

| State | Meaning |
|---|---|
| `GOOD` | reachable from Iran **and** from outside Iran |
| `BAD`, Iran only | Iran reaches it, but not a single node outside Iran does |
| `BAD`, blocked in Iran | nodes outside Iran reach it, but Iran does not |
| `DOWN` | no region reaches it: a fault on the server or in the network, not a block |
| `MIXED` | the checks of that IP disagree |
| `INCONCLUSIVE` | too few nodes answered |

- **Checks per IP:** each IP is checked `checks_per_ip` times (2 by default). A state needs more than half of the checks that gave a clear answer. With 2 checks both must agree, otherwise the IP is `MIXED`. `checks_per_ip: 3` gives fewer `MIXED` results.
- **"Not a single node outside Iran"** is `outside_min_ok: 1` in the YAML file. A larger number is stricter, and `0` turns the Iran-only rule off.
- **"Iran reaches it"** means at most half of the Iranian nodes failed (`fail_ratio_threshold`).
- **The management IP** is not tested or judged.

```sh
python3 arvin_agent_badip.py state     # one line per IP: STATE, WHY, then IRAN / EUROPE / USA / ASIA / OTHER counts
```

`state` lists GOOD IPs first, then BAD, then the rest, and ends with one line per state listing its IPs. It is also saved to `~/arvin-agent-badip/state.txt`. A counts column such as `EUROPE 2/3` means 2 of 3 European nodes reached the IP. `STILL ATTACHED` means the IP is still on the server and needs removing in the panel.

Saved results are judged again with the current rules every time they are shown, so changing a rule does not need a new test. `results.csv` is rebuilt from `results.jsonl` the same way.

Regions are set by `probe_regions` in the YAML file (check-host node country codes). `probe_per_region` sets how many nodes each region uses.

## Use

```sh
./arvin_agent_badip.py preflight              # read-only: API key, server, mgmt port, headroom, ssh, sudo, tools, listener, check-host nodes
./arvin_agent_badip.py test --dry-run         # prints every API request and VM script; makes 0 changes
./arvin_agent_badip.py test --rounds 1 --yes  # one billable round first
./arvin_agent_badip.py test --yes             # 5 rounds
./arvin_agent_badip.py state                  # latest GOOD/BAD per IP, with each region
./arvin_agent_badip.py results                # all results;  --bad / --good / --last N
./arvin_agent_badip.py --server 185.1.1.10 test --yes   # only one of the listed servers
./arvin_agent_badip.py status                 # saved config + anything pending
./arvin_agent_badip.py inspect                # read-only: saves what the API returns for the server to servers/<ip>/inspect.json
./arvin_agent_badip.py cleanup --yes          # release a test IP left behind by a crash
```

Useful flags for `test`: `--checks-per-ip N`, `--check-type tcp|ping|http`, `--check-port P` (only if a service listens on all addresses on that port), and `--sequential`.

The default check is a TCP connection to port 22. `--check-type ping` (or `check_type: ping`) uses ICMP ping instead; the firewall must then allow ping.

Exit codes: `0` ok · `1` error · `2` the run stopped early, or something is still pending · `4` interrupted.

**Ctrl-C** releases the in-flight test IP before exiting. If the Mac dies mid-round, the next `test` refuses to start until you run `cleanup --yes`. `cleanup` finds the port that round created by comparing the current port list with the list saved before the request, and only releases that port.

## Files (`~/arvin-agent-badip/`, override with `$ABIP_HOME`)

| File | Content |
|---|---|
| `config.yaml` | your inputs (optional location, see above) |
| `servers/<ip>/config.json` | per server: server ID, management port, NIC, gateway (written by `init`) |
| `servers/<ip>/state.json` | per server: the allocation in flight (if any) |
| `keys/` | key files written from key *values* given in the YAML file |
| `state.txt` | the `state` table: one line per IP |
| `results.jsonl` | the record: one row per tested IP, with every check, the per-region counts and the check-host report links |
| `results.csv` | the same rows for a spreadsheet: verdict, reason, one letter per check (`R` reachable, `I` Iran only, `B` blocked in Iran, `D` down, `?` unclear), `seen_before` (Arvan handed out the same IP again) |
| `checks.jsonl` | every check-host cycle, with per-node results |
| `events.jsonl` | every action |

## What has and has not been verified

**Run on a real ArvanCloud account (panel mode, one server):** `init`, `preflight`, and full rounds: add an IP with a firewall, wait for the panel, test from every region, release, management back.

**Only tested against mocks** (`python3 tests/test_mock.py`):
- several servers at the same time, and Ctrl-C during such a run
- `vm_config_mode: ssh` end to end
- Windows

Things to know:

- The API calls come from ArvanCloud's Terraform provider source (`arvancloud/terraform-provider-arvan`, last updated in 2023) and from what the real API answered. They are not in the published v3 reference:
  - `POST /servers/{id}/add-public-ip` with `{"type": "ipv4", "security_groups": [firewall id]}`
  - `PATCH /networks/{port_id}/detach` with `{"server_id": …}`
  - `GET /networks`, where `subnets[].servers[].ips[]` lists each port's IP, MAC and port ID
- It's unknown whether a few minutes of an extra IPv4 are billed pro-rata. Each additional IPv4 is €2.83/month.
- Caps: 4 IPs per server and 15 per account. During a parallel run every server holds two IPs at once (its management IP and a test IP), so more than 7 servers can hit the account cap; ArvanCloud then refuses that server's request and only that server stops. You can't choose which IP you get, and Arvan may hand out the same IP again (shown as `seen_before`).
- check-host.net results are public, its rate limits are not documented, and its Iranian nodes may not match what your users see.
- Repeatedly allocating and releasing IPs may be limited by ArvanCloud's ToS or abuse detection. Check before running large batches.
