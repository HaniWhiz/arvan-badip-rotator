# arvin-agent-badip

`arvin-agent-badip` finds out whether the public IPv4 addresses ArvanCloud gives your server are **reachable from Iran (GOOD)** or **blocked (BAD)**. Each run allocates a test IP, tests it, releases it, and saves the result. It does this `ROUNDS` times (5 by default).

The tool is one file, `arvin_agent_badip.py`, and needs only the Python 3.8+ standard library. It runs on **your Mac**, not on the server. It can test **several servers** in one run: list their management IPs separated by commas.

| Credential | Gives access to | Used for |
|---|---|---|
| ArvanCloud **API key** | the panel | add and remove public IPs, read ports, networks and subnets |
| SSH as **`hani`** with your **macOS ssh-agent** key (or a key file, or the key itself) | the VM itself, through the saved **management IP** | bring each test IP up on its NIC, check its egress, then remove it |

The management IP is never released, and neither is its port or any port that existed before a round. Only the port the round created is released.

## What one round does

1. **Allocate:** `POST /servers/{id}/add-public-ip` with an empty body. This is billable. The pending allocation is written to `state.json` *before* the request is sent. The reply carries no port details, so the new port is found by comparing the port list from `GET /networks` with the one saved before the request.
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

**Per-IP verdicts** (computed from that IP's cycles):

| Verdict | Meaning |
|---|---|
| `GOOD` | more cycles reachable than blocked |
| `BAD` | more cycles blocked than reachable |
| `MIXED` | equal numbers of reachable and blocked cycles |
| `UNTESTABLE` | down from outside Iran too, so it's an OS, firewall or security-group problem |
| `INCONCLUSIVE` | not enough Iranian nodes answered |

Each run also probes the management IP once and saves it as `MGMT-…` (round 0) for comparison.

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
| `region` | ArvanCloud region code, e.g. `ir-thr-ba1` |
| `ssh_user` | `hani` |
| `ssh_key` | see below |

Everything else is optional: `api_key`, `server_id`, `rounds`, `checks_per_ip`, `check_type`, `check_port`, timeouts, and so on.

**`api_key` and `ssh_key` each accept a file path or the value itself:**

| Field | File path | Value itself |
|---|---|---|
| `api_key` | `~/arvin-agent-badip/api_key` (a file holding only the key, chmod 600) | `"apikey 0000…"` (the `apikey ` prefix is optional) |
| `ssh_key` | `~/.ssh/id_ed25519.pub` (ssh-agent key) or `~/.ssh/id_ed25519` (private key file, no agent needed) | `ssh-ed25519 AAAA… me@mac` (agent must hold it), or the private key with `\n` for each line break |

A value written into the YAML file is stored in plain text, so `chmod 600` the file. If `api_key` is empty, the key comes from `$ARVAN_API_KEY`, then `~/arvin-agent-badip/api_key`, then the Keychain. If `ssh_key` is empty, any key in the agent is tried. (`api_key_file` and `ssh_pubkey` still work as older names.)

**Several servers:**
- Every command runs over each management IP in turn. `--server IP` limits a command to one of them.
- `server_id` is optional. If you set it, give one UUID per IP, in the same order.
- `test` stops before the next server if an IP is left pending.
- Results get a `server` column.

Values override in this order, lowest first: script defaults, then what `init` discovered, then the YAML file, then command-line flags. An empty value keeps the default.

On the VM, `hani` needs **passwordless sudo**, at least for `ip`, `sysctl`, `sh` and `touch`. The VM also needs `ip` and `curl` (or `wget`), and sshd must listen on `0.0.0.0:22`, because check-host probes the test IP on port 22. `preflight` checks all of this.

With a `.pub` key, ssh asks the agent for exactly that key (`IdentitiesOnly=yes`).

## Use

```sh
./arvin_agent_badip.py preflight              # read-only: API key, server, mgmt port, headroom, ssh, sudo, tools, listener, check-host nodes
./arvin_agent_badip.py test --dry-run         # prints every API request and VM script; makes 0 changes
./arvin_agent_badip.py test --rounds 1 --yes  # one billable round first
./arvin_agent_badip.py test --yes             # 5 rounds
./arvin_agent_badip.py results                # all results;  --bad / --good / --last N
./arvin_agent_badip.py --server 185.1.1.10 test --yes   # only one of the listed servers
./arvin_agent_badip.py status                 # saved config + anything pending
./arvin_agent_badip.py inspect                # read-only: saves what the API returns for the server to servers/<ip>/inspect.json
./arvin_agent_badip.py cleanup --yes          # release a test IP left behind by a crash
```

Useful flags for `test`: `--checks-per-ip N`, `--check-type tcp|ping|http`, `--check-port P` (only if a service listens on all addresses on that port), and `--no-baseline`.

Exit codes: `0` ok · `1` error · `2` the run stopped early, or something is still pending · `4` interrupted.

**Ctrl-C** releases the in-flight test IP before exiting. If the Mac dies mid-round, the next `test` refuses to start until you run `cleanup --yes`. `cleanup` finds the port that round created by comparing the current port list with the list saved before the request, and only releases that port.

## Files (`~/arvin-agent-badip/`, override with `$ABIP_HOME`)

| File | Content |
|---|---|
| `config.yaml` | your inputs (optional location, see above) |
| `servers/<ip>/config.json` | per server: server ID, management port, NIC, gateway (written by `init`) |
| `servers/<ip>/state.json` | per server: the allocation in flight (if any) |
| `keys/` | key files written from key *values* given in the YAML file |
| `results.csv` / `results.jsonl` | one row per tested IP: verdict, cycle counts, egress check, TCP check from the Mac, `seen_before` (Arvan handed out the same IP again), check-host report links |
| `checks.jsonl` | every check-host cycle, with per-node results |
| `events.jsonl` | every action |

## Not verified yet

This has **not** been run against the real ArvanCloud API. It passes a mock end-to-end test (`python3 tests/test_mock.py`), which covers:
- 5 rounds
- a lost allocation reply
- a crash with an IP left pending, then `cleanup`

These assumptions are carried over from the earlier rotator work:

- The v1 endpoints come from ArvanCloud's Terraform provider source (`arvancloud/terraform-provider-arvan`, last updated in 2023). They are not in the published v3 reference:
  - `POST /servers/{id}/add-public-ip`, empty body
  - `PATCH /networks/{port_id}/detach` with `{"server_id": …}`
  - `GET /networks`, where `subnets[].servers[].ips[]` lists each port's IP, MAC and port ID
- The provider only uses `detach` on ports it attached itself, so releasing a port made by `add-public-ip` this way is still unconfirmed. After every release the script checks that the management IP is still listed.
- It's unknown whether detaching **frees the IPv4 and stops billing**. Check the panel and your billing after the first round.
- The new IP is assumed to arrive as a **hot-plugged NIC**. If no NIC appears within 120 s, the round records an error and the IP is still released.
- Pricing: each additional IPv4 is €2.83/month. It's unknown whether a few minutes are billed pro-rata.
- Caps: 4 IPs per server and 15 per account. You can't choose which IP you get, and Arvan may hand out the same IP again (shown as `seen_before`).
- check-host.net results are public, and its Iranian nodes may not match what your users see.
- Repeatedly allocating and releasing IPs may be limited by ArvanCloud's ToS or abuse detection. Check before running large batches.

The original rotator (`arvan-ip-rotator.zip`) is unchanged.
