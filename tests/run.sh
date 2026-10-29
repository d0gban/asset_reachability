#!/usr/bin/env bash
# Offline test-suite for asset_reachability.sh. No network, no root: ping, nmap
# and arping are replaced by stubs placed first on PATH.
#   bash tests/run.sh
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT="$HERE/../asset_reachability.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n       %s\n' "$1" "${2:-}"; }
eq()   { [[ $2 == "$3" ]] && ok "$1" || bad "$1" "expected [$3] got [$2]"; }
has()  { [[ $2 == *"$3"* ]] && ok "$1" || bad "$1" "missing [$3] in [$2]"; }
hasnt(){ [[ $2 != *"$3"* ]] && ok "$1" || bad "$1" "unexpected [$3] in [$2]"; }

# ---------------------------------------------------------------- stubs -----
STUBS="$WORK/stubs"; mkdir -p "$STUBS"
cat > "$STUBS/ping" <<'EOF'
#!/usr/bin/env bash
ip=${@: -1}
case $ip in
    10.0.0.1|127.0.0.1) echo "64 bytes from $ip: icmp_seq=1 ttl=64 time=0.1 ms"; exit 0 ;;
    10.0.0.2) echo "From 10.0.0.254 icmp_seq=1 Destination Host Unreachable"; exit 1 ;;
    *) exit 1 ;;
esac
EOF
cat > "$STUBS/nmap" <<'EOF'
#!/usr/bin/env bash
# minimal nmap: up hosts 10.0.0.1 (echo-reply) and 10.0.0.3 (arp-response)
[[ ${STUB_NMAP_FAIL:-0} == 1 ]] && { echo "Failed to resolve interface bogus0" >&2; exit 1; }
list="" og=""
while [[ $# -gt 0 ]]; do
    case $1 in -iL) list=$2; shift 2 ;; -oG) og=$2; shift 2 ;; *) shift ;; esac
done
{ echo "# Nmap 7.94 scan initiated"; } > "$og"
while read -r ip; do
    case $ip in
        10.0.0.1) echo "Nmap scan report for $ip"; echo "Host is up, received echo-reply ttl 64 (0.0010s latency)."
                  printf 'Host: %s ()\tStatus: Up\n' "$ip" >> "$og" ;;
        10.0.0.3) echo "Nmap scan report for $ip"; echo "Host is up, received arp-response (0.0004s latency)."
                  printf 'Host: %s ()\tStatus: Up\n' "$ip" >> "$og" ;;
    esac
done < "$list"
echo "# Nmap done at now" >> "$og"
exit 0
EOF
chmod +x "$STUBS/ping" "$STUBS/nmap"

run() { PATH="$STUBS:$PATH" NO_COLOR=1 AR_NO_UPDATE_CHECK=1 bash "$SCRIPT" "$@" 2>&1; }

# shellcheck disable=SC1090
source "$SCRIPT"

echo "== validation =="
validate_ip 192.168.1.1  && ok "valid ip"            || bad "valid ip"
validate_ip 256.1.1.1    && bad "reject 256"         || ok "reject 256"
validate_ip 1.2.3        && bad "reject short"       || ok "reject short"
validate_ip 08.09.01.001 && ok "leading zeros are not octal errors" || bad "leading zeros"
validate_cidr 10.0.0.0/8 && ok "valid cidr"          || bad "valid cidr"
validate_cidr 10.0.0.0/33 && bad "reject /33"        || ok "reject /33"
norm_ip 010.001.000.009; eq "norm_ip strips zeros" "$NORM_IP" "10.1.0.9"

echo "== targets =="
collect_targets cidr 192.168.1.0/30;  eq "/30 usable hosts" "${TARGETS[*]}" "192.168.1.1 192.168.1.2"
collect_targets cidr 192.168.1.4/31;  eq "/31 both addrs"   "${TARGETS[*]}" "192.168.1.4 192.168.1.5"
collect_targets cidr 192.168.1.9/32;  eq "/32 single"       "${TARGETS[*]}" "192.168.1.9"
collect_targets cidr 192.168.1.77/30; eq "host bits masked" "${TARGETS[*]}" "192.168.1.77 192.168.1.78"
collect_targets range 10.0.0.254-10.0.1.1; eq "range crosses octet" "${TARGETS[*]}" "10.0.0.254 10.0.0.255 10.0.1.0 10.0.1.1"
collect_targets list "10.0.0.2, 10.0.0.1,10.0.0.1"; eq "list trimmed+deduped+sorted" "${TARGETS[*]}" "10.0.0.1 10.0.0.2"
printf '# hdr\r\n10.0.0.5 router\r\n\r\nnot-an-ip\r\n10.0.0.4 # inline\r\n300.1.1.1\r\n' > "$WORK/hosts.txt"
out=$(collect_targets file "$WORK/hosts.txt" 2>&1 >/dev/null; true)
collect_targets file "$WORK/hosts.txt" 2>/dev/null; eq "file: CRLF/comments/invalid" "${TARGETS[*]}" "10.0.0.4 10.0.0.5"
has "file: warns on invalid lines" "$(collect_targets file "$WORK/hosts.txt" 2>&1 >/dev/null)" "not-an-ip"
has "huge cidr refused before expansion" "$(run -c 10.0.0.0/0 -m ping -y)" "exceeds the hard limit"
has "huge range refused"  "$(run -r 0.0.0.0-255.255.255.255 -m ping -y)" "exceeds the hard limit"
has "reversed range"      "$(run -r 10.0.0.9-10.0.0.1 -m ping)" "range start > end"

echo "== verdict logic (check_host with stubbed probes) =="
PING_RES=""; probe_ping() { REASON=$PING_RES; [[ $REASON == echo-reply ]]; }
probe_tcp()  { REASON=$TCP_REASON; REPLY_PORT=$TCP_PORT; [[ $REASON == syn-ack || $REASON == reset ]]; }
probe_udp()  { REASON=no-response; return 1; }
probe_arp()  { REASON=$ARP_REASON; case $ARP_REASON in arp-reply) return 0;; arping-absent) return 2;; *) return 1;; esac; }
on_link()    { return "${ON_LINK:-0}"; }

PING_RES=echo-reply;   eq "ping up"            "$(check_host 1.1.1.1 ping 1)" $'1.1.1.1\tup\techo-reply'
PING_RES=host-unreach; eq "ping host-unreach"  "$(check_host 1.1.1.1 ping 1)" $'1.1.1.1\tdown\thost-unreach'
PING_RES=no-response;  eq "ping silence"       "$(check_host 1.1.1.1 ping 1)" $'1.1.1.1\tfiltered\tno-response'

ARP_REASON=no-arp-reply; ON_LINK=0; eq "arp silence on-subnet = down"        "$(check_host 1.1.1.1 arp 1)" $'1.1.1.1\tdown\tno-arp-reply'
ARP_REASON=no-arp-reply; ON_LINK=1; eq "arp silence routed = filtered"       "$(check_host 1.1.1.1 arp 1)" $'1.1.1.1\tfiltered\tno-arp-reply-unverified'
ARP_REASON=no-arp-reply; ON_LINK=2; eq "arp silence unknown = filtered"      "$(check_host 1.1.1.1 arp 1)" $'1.1.1.1\tfiltered\tno-arp-reply-unverified'
ARP_REASON=arp-reply;               eq "arp reply = up"                      "$(check_host 1.1.1.1 arp 1)" $'1.1.1.1\tup\tarp-reply'
ARP_REASON=arping-absent; PING_RES=echo-reply; eq "arp falls back to ping"   "$(check_host 1.1.1.1 arp 1)" $'1.1.1.1\tup\techo-reply(arp-fallback)'

TCP_REASON=syn-ack;  TCP_PORT=22;  eq "tcp open = up"                        "$(check_host 1.1.1.1 tcp 1)" $'1.1.1.1\tup\tsyn-ack:22'
TCP_REASON=reset;    TCP_PORT=445; eq "tcp RST = up (stack answered)"        "$(check_host 1.1.1.1 tcp 1)" $'1.1.1.1\tup\treset:445'
TCP_REASON=no-route; TCP_PORT="";  eq "tcp no-route = filtered NOT down"     "$(check_host 1.1.1.1 tcp 1)" $'1.1.1.1\tfiltered\tno-route'

ARP_REASON=no-arp-reply; PING_RES=host-unreach; TCP_REASON=syn-ack; TCP_PORT=80
eq "all: positive beats host-unreach" "$(check_host 1.1.1.1 all 1)" $'1.1.1.1\tup\tsyn-ack:80'
TCP_REASON=no-route; TCP_PORT=""
eq "all: host-unreach + silent tcp = down" "$(check_host 1.1.1.1 all 1)" $'1.1.1.1\tdown\thost-unreach'
PING_RES=no-response
eq "all: no-route alone = filtered" "$(check_host 1.1.1.1 all 1)" $'1.1.1.1\tfiltered\tno-route'

echo "== confidence() =="
has "nmap arp-response known" "$(confidence arp-response)" "confirmed (L2)"
has "reset hint"              "$(confidence reset:80)"      "RST"
has "no-route is ambiguous"   "$(confidence no-route)"      "firewall REJECT"
eq  "json escaping" "$(json_str 'a"b\c')" 'a\"b\\c'

echo "== false-positive guards (L2 corroboration + canary) =="
# restore real functions that the verdict-logic section stubbed out
source "$SCRIPT"
ip() {   # stub for iproute2: ip -4 route get X | neigh show X | route show default
    case "$*" in
        "-4 route get 10.0.0.9")  echo "10.0.0.9 dev eth0 src 10.0.0.2" ;;
        "-4 route get 10.0.0.77") echo "10.0.0.77 dev eth0 src 10.0.0.2" ;;
        "-4 route get 10.0.0.6")  echo "10.0.0.6 dev eth0 src 10.0.0.2" ;;
        "-4 route get 10.0.0.5")  echo "10.0.0.5 dev eth0 src 10.0.0.2" ;;
        "-4 route get 8.8.4.4")   echo "8.8.4.4 via 10.0.0.1 dev eth0 src 10.0.0.2" ;;
        "-4 route show default")  echo "default via 10.0.0.1 dev eth0" ;;
        "-4 neigh show 10.0.0.1") echo "10.0.0.1 dev eth0 lladdr aa:aa:aa:aa:aa:01 REACHABLE" ;;
        "-4 neigh show 10.0.0.9") echo "10.0.0.9 dev eth0 lladdr bb:bb:bb:bb:bb:09 STALE" ;;
        "-4 neigh show 10.0.0.77") echo "10.0.0.77 dev eth0  INCOMPLETE" ;;
        "-4 neigh show 10.0.0.6") echo "10.0.0.6 dev eth0 lladdr AA:AA:AA:AA:AA:01 REACHABLE" ;;
        "-4 neigh show 10.0.0.5") ;;
    esac
}
l2_verify 10.0.0.9;  eq "l2_verify: resolved MAC -> corroborated"        "$?" 0
l2_verify 10.0.0.77; eq "l2_verify: INCOMPLETE -> not corroborated"      "$?" 1
l2_verify 10.0.0.5;  eq "l2_verify: no entry -> not corroborated"        "$?" 1
l2_verify 10.0.0.6;  eq "l2_verify: gateway's MAC -> shared (proxy-ARP)" "$?" 3
l2_verify 8.8.4.4;   eq "l2_verify: routed target -> can't judge"        "$?" 2
l2_unanswered 10.0.0.77 && ok "l2_unanswered: INCOMPLETE on-link" || bad "l2_unanswered INCOMPLETE"
l2_unanswered 10.0.0.5  && bad "l2_unanswered: absent entry must NOT count" || ok "l2_unanswered: absent entry must NOT count"
l2_unanswered 10.0.0.9  && bad "l2_unanswered: resolved host is not unanswered" || ok "l2_unanswered: resolved host is not unanswered"

# check_host end-to-end with the real l2 guards
probe_ping() { REASON=$PING_RES; [[ $REASON == echo-reply ]]; }
probe_tcp()  { REASON=$TCP_REASON; REPLY_PORT=$TCP_PORT; [[ $REASON == syn-ack || $REASON == reset ]]; }
probe_udp()  { REASON=$UDP_REASON; REPLY_PORT=53; [[ $REASON == dns-response ]]; }
PING_RES=no-response; TCP_REASON=syn-ack; TCP_PORT=53
eq "intercepted TCP reply on dead on-link host -> NOT up"      "$(check_host 10.0.0.77 tcp 1)" $'10.0.0.77\tfiltered\tunverified-no-l2:syn-ack:53'
eq "genuine TCP reply on resolved host -> up"                  "$(check_host 10.0.0.9 tcp 1)"  $'10.0.0.9\tup\tsyn-ack:53'
eq "proxy-ARP'd reply -> NOT up"                               "$(check_host 10.0.0.6 tcp 1)"  $'10.0.0.6\tfiltered\tshared-mac-with-gateway:syn-ack:53'
eq "routed target keeps its verdict (canary guards it)"        "$(check_host 8.8.4.4 tcp 1)"   $'8.8.4.4\tup\tsyn-ack:53'
UDP_REASON=dns-response
eq "intercepted UDP reply on dead on-link host -> NOT up"      "$(check_host 10.0.0.77 udp 1)" $'10.0.0.77\tfiltered\tunverified-no-l2:dns-response:53'
PING_RES=no-response
eq "silent + ARP unanswered = deterministic DOWN (ping)"       "$(check_host 10.0.0.77 ping 1)" $'10.0.0.77\tdown\tno-arp-reply'
eq "silent but answered ARP = stays FILTERED (live, quiet)"    "$(check_host 10.0.0.9 ping 1)"  $'10.0.0.9\tfiltered\tno-response'
eq "silent + no ARP attempt recorded = stays FILTERED"         "$(check_host 10.0.0.5 ping 1)"  $'10.0.0.5\tfiltered\tno-response'
TCP_REASON=no-route; TCP_PORT=""
eq "tcp no-route + ARP unanswered = DOWN"                      "$(check_host 10.0.0.77 tcp 1)"  $'10.0.0.77\tdown\tno-arp-reply'
eq "tcp no-route + host answers ARP = FILTERED (REJECT rule)"  "$(check_host 10.0.0.9 tcp 1)"   $'10.0.0.9\tfiltered\tno-route'

# canary: ports/services that answer on 192.0.2.1 are excluded
tcp_connect() { case $2 in 53) return 0;; 22) return 10;; *) return 1;; esac; }
TCP_PORTS="22 53 80"; CANARY_RST=0; tcp_canary 2>/dev/null
eq "tcp_canary drops intercepted port"        "$TCP_PORTS" "22 80"
eq "tcp_canary notes canary RSTs"             "$CANARY_RST" "1"
on_link() { return 1; }   # routed target
probe_tcp() { local ip=$1; REPLY_PORT=""; REASON="no-response"; return 1; }
unset -f probe_tcp; source "$SCRIPT"
tcp_ports_run() { for p in $TCP_PORTS; do echo 10 > "$3/$p"; done; }
CANARY_RST=1; probe_tcp 8.8.4.4 1; rc=$?
eq "RST on a routed target is not proof when canary RSTs" "$rc:$REASON" "1:reset-unverified"
CANARY_RST=0; probe_tcp 8.8.4.4 1; rc=$?
eq "RST on a routed target counts when canary is silent"  "$rc:$REASON" "0:reset"
source "$SCRIPT"
udp_svc() { [[ $1 == dns ]]; }
UDP_POISONED=""; udp_canary 2>/dev/null
eq "udp_canary excludes intercepted dns"      "$UDP_POISONED" "dns"
udp_svc() { [[ $1 == dns || $1 == snmp ]]; }
probe_udp 1.1.1.1 1; rc=$?; eq "poisoned dns skipped, healthy snmp still counts" "$rc:$REASON" "0:snmp-response"
UDP_POISONED="dns snmp"; probe_udp 1.1.1.1 1; rc=$?; eq "all services poisoned -> never up" "$rc:$REASON" "1:no-response"
source "$SCRIPT"; unset -f ip

echo "== versioning / update =="
version_gt 5.2.0 5.1.9  && ok "5.2.0 > 5.1.9"   || bad "5.2.0 > 5.1.9"
version_gt 5.10.0 5.9.0 && ok "5.10.0 > 5.9.0 (numeric, not lexical)" || bad "numeric compare"
version_gt 5.1.0 5.1.0  && bad "equal is not newer" || ok "equal is not newer"
version_gt 5.0.9 5.1.0  && bad "older is not newer" || ok "older is not newer"
eq "VERSION file matches script" "$(tr -d '[:space:]' < "$HERE/../VERSION")" "$VERSION"
fetch_latest_stub() { echo "$1"; }
has "--check-update unreachable fails cleanly" "$(AR_BASE_URL=file:///nonexistent run --check-update)" "reach GitHub"
has "--update refuses non-installed copy" "$(run --update)" "not an installed copy"

echo "== end-to-end (stubbed ping/nmap) =="
OUT="$WORK/out"
res=$(run -l 10.0.0.1,10.0.0.2,10.0.0.9 -m ping -e bash -o "$OUT" -j -s)
has "e2e: totals"        "$res" "up 1  down 1  filtered 1"
has "e2e: up evidence"   "$res" "10.0.0.1  [echo-reply"
has "e2e: down evidence" "$res" "10.0.0.2  [host-unreach — "
json=$(cat "$OUT"/scan-*.json 2>/dev/null)
has "e2e: json valid-ish" "$json" '"up":[{"ip":"10.0.0.1","reason":"echo-reply"'
eq  "e2e: split up file"   "$(cat "$OUT"/scan-*-up.txt)"       "10.0.0.1"
eq  "e2e: split down file" "$(cat "$OUT"/scan-*-down.txt)"     "10.0.0.2"
eq  "e2e: split filt file" "$(cat "$OUT"/scan-*-filtered.txt)" "10.0.0.9"

res=$(run -l 10.0.0.1,10.0.0.3,10.0.0.9 -m ack -o "$OUT")
has "nmap: engine auto-selected" "$res" "Engine: nmap"
has "nmap: up count"             "$res" "up 2  down 0  filtered 1"
has "nmap: arp-response reason"  "$res" "10.0.0.3  [arp-response"

res=$(STUB_NMAP_FAIL=1 run -l 10.0.0.1 -m ack -o "$OUT")
has   "nmap failure aborts loudly" "$res" "nmap failed"
hasnt "nmap failure is not 'all down'" "$res" "Result:"

has "nmap-only method rejects --engine bash" "$(run -l 10.0.0.1 -m syn -e bash)" "can't run on --engine bash"
has "invalid method"  "$(run -l 10.0.0.1 -m bogus)" "invalid method"
has "--version"       "$(run --version)" "asset_reachability $VERSION"
has "missing input"   "$(run -m ping)" "missing input"

grep -n 'echo.*%%' "$SCRIPT" >/dev/null && bad "progress bar prints %%" || ok "progress bar prints single %"
echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
(( fail == 0 ))
