# asset-reachability

IPv4 host reachability sweeps from a single bash script. Every host gets a three-state verdict (**up / down / filtered**) together with the *evidence* behind it, so you can tell a confirmed ARP reply from a lone SYN-ACK that might be a firewall.

> **Only scan networks you own or are explicitly authorized to test.**

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/d0gban/asset_reachability/main/install.sh | sh
```

The installer:

- installs the `asset-reachability` command to `/usr/local/bin` (root/sudo) or `~/.local/bin` (otherwise);
- installs missing tools that unlock the accurate probe methods — `nmap`, `arping`, `dig`, `nc` (apt, dnf/yum, apk, pacman, zypper, brew);
- verifies the download (bash syntax check + SHA-256 against `SHA256SUMS`) before installing.

Options (pass after `sh -s --`):

```sh
curl -fsSL https://raw.githubusercontent.com/d0gban/asset_reachability/main/install.sh | sh -s -- --no-deps
curl -fsSL .../install.sh | sh -s -- --prefix "$HOME/.local/bin"
curl -fsSL .../install.sh | sh -s -- --ref v5.2.0          # pin a tag
curl -fsSL .../install.sh | sh -s -- --uninstall
```

For a hard integrity guarantee, pin the checksum yourself: `AR_SHA256=<sha256 of asset_reachability.sh> sh install.sh`.

**Requirements:** Linux or macOS (Windows: use WSL), bash ≥ 4.4 (macOS: `brew install bash coreutils`), `ping`, `awk`, `xargs`. Everything else is optional.

## Usage

```sh
asset-reachability -c 192.168.1.0/24                      # ICMP sweep of a /24
asset-reachability -c 192.168.1.0/24 -m arp -i eth0 -s   # ARP (root), split result files
asset-reachability -r 10.0.0.1-10.0.0.254 -m all -j      # every probe, plus JSON
asset-reachability -f hosts.txt -m tcp -v --resolve       # from a file, with reverse DNS
asset-reachability -c 10.0.0.0/24 -m ack                  # nmap engine auto-selected
```

| Input | Meaning |
|---|---|
| `-f FILE` | one IP per line; `#` comments; invalid lines are reported and skipped |
| `-l "a,b,c"` | comma-separated IPs |
| `-c CIDR` | CIDR block (network/broadcast excluded, except /31 and /32) |
| `-r A-B` | inclusive range |

| Option | Meaning |
|---|---|
| `-m METHOD` | `ping` (default) `icmp` `arp` `tcp` `udp` `all` — plus nmap-only `syn` `ack` `icmp-ts` `icmp-mask` |
| `-e ENGINE` | `auto` (default), `bash`, `nmap` |
| `-t N` / `-w SEC` | parallel workers (default 10) / per-probe timeout (default 2) |
| `-i IFACE` | interface for arp / nmap raw probes |
| `--check` `--strict` | capability report only · treat pre-flight warnings as errors |
| `--arp-tries N` `--recheck-delay S` | ARP requests per host (default 4) · pause before re-verifying silent "down" hosts (default 5, 0 = off) |
| `-o DIR` | output directory (default `scans/`) |
| `-s` `-j` | split up/filtered/down files · JSON output |
| `--resolve` `-v` `-y` `--no-color` | reverse DNS · list every host · skip the large-scan prompt · no ANSI |

Hard limit: 1,048,576 targets per run (a /12). Scans over 4,096 targets ask for confirmation unless `-y`.

## How verdicts are decided

| Verdict | Meaning |
|---|---|
| **UP** | A probe got a positive reply: `arp-reply`, `echo-reply`, `syn-ack`, `reset` (RST), or an application reply (`dns-response`, `snmp-response`, `nbt-response`). |
| **DOWN** | The *path* said the host isn't there: ICMP host-unreachable, or no ARP reply from a target proven to be on the local subnet. |
| **FILTERED** | Silence or an ambiguous error. A live host that drops probes lands here — re-check with `nmap -Pn`. |

Deliberate accuracy choices:

- **Silence is never "down"** (except on-subnet ARP). A firewalled host and a dead host look the same from outside.
- **TCP "no route to host" is `filtered`, not `down`.** Linux returns that error for firewall `REJECT` rules (e.g. firewalld's default) as well as for ARP failure.
- **ARP silence is only `down` when the target is directly attached** (`ip route get` shows no gateway). Otherwise it's `filtered`.
- **UDP requires a real application reply.** `nc -u -z` reports success on silence, so it isn't used.
- **A failing nmap aborts the run** instead of reporting every host as down.
- When positive and negative evidence conflict (method `all`), a positive reply wins.

Each result line carries its reason and a confidence hint, e.g. `10.0.0.5  [arp-reply — confirmed (L2)]`.

## Output

A text report, plus optional `-s` (three plain IP lists) and `-j` (JSON with per-host `reason`/`confidence`) in `scans/`. Colours turn off when piped, with `NO_COLOR`, or `--no-color`. Exit status: `0` completed, `1` error/usage, `2` pre-flight cancelled, `130` interrupted.

## Methods and dependencies

| Method | Bash engine needs | nmap engine |
|---|---|---|
| ping / icmp | `ping` | `-PE` |
| arp | `arping` + root (falls back to ping) | `-PR` |
| tcp | `timeout` (or `nc`); 9 ports probed concurrently | `-PS` |
| udp | `dig` / `snmpget` / `nmblookup` (nmap strongly preferred) | `-PU` |
| syn, ack, icmp-ts, icmp-mask | — (nmap only) | `-PS` `-PA` `-PP` `-PM` |
| all | all of the above | all probes |

Raw-packet methods (`arp`, `syn`, `ack`, `icmp-*`) need root; without it nmap degrades to TCP-connect probes and the reported reasons show what actually answered.

macOS: the script uses `ping -t` there (BSD `-W` is milliseconds) and `gtimeout` from Homebrew coreutils.

## Pre-flight capability check

Before sending a single probe, the tool verifies the chosen method can produce a **valid** answer on this host, so a probe that can't run never masquerades as "host is down":

| Outcome | Behaviour | Examples |
|---|---|---|
| ✓ capable | scan runs | root + working `arping` + interface up + on-subnet targets |
| ! degraded | WARN, names the fallback, continues (`--strict` cancels) | not root → `arp` falls back to ping; ARP aimed at a routed subnet; `iproute2` missing (false-positive guards off) |
| ✗ incapable | **cancelled, exit 2**, with a fix hint | interface doesn't exist; no UDP tooling and no nmap; nmap raw method (`arp`/`ack`/`icmp-ts`/`icmp-mask`/`udp`) without root; no `arping` *and* no `ping` |

```sh
asset-reachability --check -m arp -i eth1 -c 192.168.10.0/24   # report only, sends nothing
sudo asset-reachability -m arp -i eth1 -c 192.168.10.0/24 --strict
```

## Lossy ARP (Wi-Fi / power-save hosts)

Some devices answer only a fraction of ARP requests and even ICMP for seconds at a time. To avoid reporting live hosts as `down`, the `arp` method retries (`--arp-tries`, default 4), then escalates to 3 pings, the kernel's own ARP result and a TCP connect. A host is only `down` if all of that fails, **and** a second round after `--recheck-delay` seconds (default 5, `0` disables) also finds nothing. A host that stays silent but can't be proven absent is reported `filtered`.

## False-positive guards

Reachability scanners are easily fooled by anything on the path that answers on a host's behalf. These guards (v5.3.0) were developed against a real appliance that NAT-redirected every outgoing TCP/UDP port 53 to a local resolver — which made a naive scan report all 254 addresses "up":

| Guard | What it catches |
|---|---|
| **L2 corroboration** | A reply from a directly-attached host is only accepted if its MAC is in the neighbour table. No ARP entry ⇒ answered locally (NAT/proxy/VPN) ⇒ `filtered` (`unverified-no-l2`). |
| **Proxy-ARP check** | A reply whose MAC equals the gateway's ⇒ `filtered` (`shared-mac-with-gateway`). |
| **Canary address** | Before TCP/UDP probing, `192.0.2.1` (RFC 5737 TEST-NET, never a real host) is probed. Any port/service that "answers" there is intercepted and excluded from the scan; canary RSTs stop RST counting as proof for routed targets. |
| **Deterministic DOWN** | A directly-attached target whose ARP went unanswered is `down` (`no-arp-reply`) whatever the probe type — no race with ping's timeout. A host that answers ARP but ignores probes stays `filtered`. |

Routed targets (behind a gateway) have no MAC to check, so for them the canary is the guard. If you scan from a host with `iproute2` missing, the L2 guards are skipped and the tool says so.

## Updates

The installed command checks GitHub for a newer `VERSION` at most once every 24 hours, only in an interactive terminal, and asks:

```
Update available: 5.1.0 -> 5.2.0. Update now? [Y/n]
```

Answering yes re-runs the installer in place (same syntax and SHA-256 verification), then restarts your command with the same arguments. Scripted/piped runs are never interrupted.

```sh
asset-reachability --check-update    # report only
asset-reachability --update          # update now
asset-reachability --no-update-check # skip the prompt for this run (or AR_NO_UPDATE_CHECK=1 always)
```

The check is one small HTTPS request to `raw.githubusercontent.com` with a 3-second cap; offline hosts are unaffected. A copy run from a git checkout never self-updates (use `git pull`).

**Publishing a release:** bump `VERSION` in `asset_reachability.sh` and the `VERSION` file, run `sha256sum asset_reachability.sh > SHA256SUMS`, commit, push to `main` (optionally `git tag vX.Y.Z`). CI fails if the two version numbers or the checksum disagree.

## Development

```sh
bash tests/run.sh          # offline suite; ping/nmap are stubbed, no root or network needed
```

After editing `asset_reachability.sh`, refresh the checksum the installer verifies:

```sh
sha256sum asset_reachability.sh > SHA256SUMS
```

CI checks LF line endings, syntax, ShellCheck, the checksum, and the tests (Linux and macOS).

## License

MIT — see [LICENSE](LICENSE).
