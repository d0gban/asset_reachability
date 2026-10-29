#!/usr/bin/env bash
#
# asset_reachability.sh — IPv4 host reachability sweep
#
# Two engines:
#   bash  (default) — per-host parallel probes, live progress, zero deps beyond
#                     coreutils/ping; methods: ping icmp arp tcp udp all
#   nmap  (auto)    — unlocks methods bash can't do: syn ack icmp-ts icmp-mask,
#                     and gives better udp/arp. Used automatically when a chosen
#                     method needs it, or forced with --engine nmap.
#
# Every host gets a three-state verdict with the evidence that produced it:
#   up | down | filtered   (see --help)
#
# Only scan hosts you are authorized to test.

set -u

VERSION="5.3.0"
UPDATE_REPO="d0gban/asset_reachability"

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "asset_reachability requires bash >= 4.4 (found $BASH_VERSION)." >&2
    echo "macOS ships bash 3.2: brew install bash" >&2
    exit 1
fi

# GNU timeout is 'gtimeout' on macOS (brew install coreutils).
if ! command -v timeout >/dev/null 2>&1 && command -v gtimeout >/dev/null 2>&1; then
    timeout() { gtimeout "$@"; }
    export -f timeout
fi

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
progress_bar_width=34
PING_TIMEOUT_FLAG="-W"
ARPING_IFACE_FLAG="-I"
INTERFACE=""
TEMP_DIR=""
XARGS_PID=""
START_EPOCH=0
RANGE_WARN_LIMIT=4096
MAX_TARGETS=1048576          # hard cap (a /12); split bigger jobs
TIMEOUT_SECS=2
TCP_PORTS="22 80 443 8080 445 139 3389 53 25"
OPT_NO_COLOR="false"
OPT_NO_UPDATE_CHECK="false"
ORIG_ARGS=()
ASSUME_YES="false"
RESOLVE="false"
json_out="false"
engine="auto"                # auto | bash | nmap
EFFECTIVE_ENGINE="bash"
TARGETS=()
NORM_IP=""
CIDR_FIRST=0
CIDR_LAST=0
total_ips=0
IS_TTY="false"; [[ -t 1 ]] && IS_TTY="true"
declare -A REASON_OF=()
declare -A NAMES=()

# Methods that cannot be done in pure bash — require the nmap engine.
NMAP_ONLY_METHODS=" syn ack icmp-ts icmp-mask "
ALL_METHODS=" ping icmp arp tcp udp all syn ack icmp-ts icmp-mask "

# ---------------------------------------------------------------------------
# Colors (auto-off when piped, NO_COLOR is set, or --no-color)
# ---------------------------------------------------------------------------
setup_colors() {
    if [[ $IS_TTY == "true" && -z ${NO_COLOR:-} && $OPT_NO_COLOR != "true" ]]; then
        GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'
        YELLOW='\033[0;33m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
    else
        GREEN=''; CYAN=''; RED=''; YELLOW=''; BOLD=''; DIM=''; NC=''
    fi
}
setup_colors   # defaults so helpers work even before arg parsing

die() { echo -e "${RED}Error: $*${NC}" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Cleanup / signals
# ---------------------------------------------------------------------------
cleanup() {
    local code=${1:-1}
    if [[ -n $XARGS_PID ]]; then
        pkill -P "$XARGS_PID" 2>/dev/null
        kill "$XARGS_PID" 2>/dev/null
    fi
    pkill -P $$ 2>/dev/null
    [[ -n $TEMP_DIR && -d $TEMP_DIR ]] && rm -rf "$TEMP_DIR"
    exit "$code"
}
on_interrupt() { echo -e "\n${RED}Interrupted. Cleaning up...${NC}" >&2; cleanup 130; }

# ---------------------------------------------------------------------------
# IP helpers (integer math). 10# forces base-10 so "08"/"09" aren't octal.
# ---------------------------------------------------------------------------
ip_to_int() {
    local IFS=. a b c d
    read -r a b c d <<< "$1"
    echo $(( (10#$a<<24) + (10#$b<<16) + (10#$c<<8) + 10#$d ))
}
norm_ip() {   # strips leading zeros -> NORM_IP (no subshell)
    local IFS=. a b c d
    read -r a b c d <<< "$1"
    NORM_IP="$((10#$a)).$((10#$b)).$((10#$c)).$((10#$d))"
}
validate_ip() {
    local ip=$1 o
    [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    local IFS=.
    for o in $ip; do (( 10#$o <= 255 )) || return 1; done
    return 0
}
validate_cidr() {
    local c=$1 ip m
    [[ $c =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || return 1
    ip=${c%/*}; m=${c#*/}
    validate_ip "$ip" && (( 10#$m <= 32 ))
}
# Usable host range of a CIDR -> CIDR_FIRST/CIDR_LAST (network+broadcast
# excluded except for /31 and /32).
cidr_bounds() {
    local net=${1%/*} mask=$(( 10#${1#*/} )) base hb nm network bcast
    base=$(ip_to_int "$net"); hb=$(( 32-mask ))
    nm=$(( (0xFFFFFFFF<<hb) & 0xFFFFFFFF )); network=$(( base & nm ))
    bcast=$(( network + (1<<hb) - 1 ))
    if (( mask>=31 )); then CIDR_FIRST=$network; CIDR_LAST=$bcast
    else CIDR_FIRST=$(( network+1 )); CIDR_LAST=$(( bcast-1 )); fi
}
emit_range() {   # <start-int> <end-int>; no subshells, fast for large ranges
    local n
    for (( n=$1; n<=$2; n++ )); do
        printf '%d.%d.%d.%d\n' $(( (n>>24)&255 )) $(( (n>>16)&255 )) $(( (n>>8)&255 )) $(( n&255 ))
    done
}
sortip() { LC_ALL=C sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n; }
check_size() {
    (( $1 <= MAX_TARGETS )) || die "$1 targets exceeds the hard limit of $MAX_TARGETS. Split the scan into smaller blocks."
}

# Fill TARGETS from <type> <input>.
collect_targets() {
    local type=$1 input=$2 line tok item s e bad=0 lineno=0
    TARGETS=()
    case $type in
        file)
            [[ -f $input && -r $input ]] || die "'$input' missing/unreadable."
            while IFS= read -r line || [[ -n $line ]]; do
                lineno=$(( lineno+1 ))
                line=${line//$'\r'/}; line=${line%%#*}
                read -r tok _ <<< "$line"
                [[ -n ${tok:-} ]] || continue
                if validate_ip "$tok"; then norm_ip "$tok"; TARGETS+=("$NORM_IP")
                else
                    bad=$(( bad+1 ))
                    (( bad <= 5 )) && echo -e "${YELLOW}Skipping invalid entry on line $lineno: '$tok'${NC}" >&2
                fi
            done < "$input"
            (( bad > 5 )) && echo -e "${YELLOW}...and $(( bad-5 )) more invalid entries skipped.${NC}" >&2
            (( ${#TARGETS[@]} )) || die "'$input' has no valid IPs (empty, comments only, or all invalid)."
            check_size "${#TARGETS[@]}" ;;
        list)
            local items
            IFS=',' read -r -a items <<< "$input"
            for item in "${items[@]}"; do
                item=${item//[[:space:]]/}
                validate_ip "$item" || die "invalid IP '$item'."
                norm_ip "$item"; TARGETS+=("$NORM_IP")
            done
            check_size "${#TARGETS[@]}" ;;
        cidr)
            validate_cidr "$input" || die "invalid CIDR '$input'."
            cidr_bounds "$input"
            check_size $(( CIDR_LAST-CIDR_FIRST+1 ))
            mapfile -t TARGETS < <(emit_range "$CIDR_FIRST" "$CIDR_LAST") ;;
        range)
            [[ $input == *-* ]] || die "invalid range '$input' (use start-end)."
            s=${input%-*}; e=${input#*-}
            validate_ip "$s" && validate_ip "$e" || die "invalid range '$input'."
            s=$(ip_to_int "$s"); e=$(ip_to_int "$e")
            (( s<=e )) || die "range start > end."
            check_size $(( e-s+1 ))
            mapfile -t TARGETS < <(emit_range "$s" "$e") ;;
    esac
    mapfile -t TARGETS < <(printf '%s\n' "${TARGETS[@]}" | sortip)
    total_ips=${#TARGETS[@]}
    (( total_ips )) || die "No valid targets."
}

# ---------------------------------------------------------------------------
# Platform / dependency detection
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ $(id -u) -eq 0 ]]; }
run_to() { local t=$1; shift; if have timeout; then timeout "$t" "$@"; else "$@"; fi; }

detect_ping() {
    # Linux/busybox: -W <seconds>.  macOS/BSD: -W is *milliseconds* (would give a
    # 1ms wait), so use -t <seconds> there.
    case $(uname -s 2>/dev/null) in
        Darwin|*BSD) PING_TIMEOUT_FLAG="-t" ;;
        *)           PING_TIMEOUT_FLAG="-W" ;;
    esac
    have ping || { PING_TIMEOUT_FLAG=""; return 0; }
    ping -c 1 "$PING_TIMEOUT_FLAG" 1 127.0.0.1 >/dev/null 2>&1 || PING_TIMEOUT_FLAG=""
}
detect_arping() {   # iputils uses -I <iface>; Thomas Habets' arping uses -i
    ARPING_IFACE_FLAG="-I"
    have arping || return 0
    if arping -h 2>&1 | grep -qi 'thomas habets'; then ARPING_IFACE_FLAG="-i"; fi
}

# Decide which engine runs for <method>; error out on impossible combinations.
resolve_engine() {
    local method=$1
    EFFECTIVE_ENGINE=$engine
    if [[ $NMAP_ONLY_METHODS == *" $method "* ]]; then
        [[ $engine == "bash" ]] && die "Method '$method' needs nmap and can't run on --engine bash."
        have nmap || die "Method '$method' requires nmap, which isn't installed. Install nmap, or pick: ping, icmp, arp, tcp, udp, all."
        EFFECTIVE_ENGINE="nmap"
    elif [[ $engine == "auto" ]]; then
        EFFECTIVE_ENGINE="bash"
        # UDP discovery is only reliable via nmap (correct ICMP port-unreachable handling).
        [[ $method == udp ]] && have nmap && EFFECTIVE_ENGINE="nmap"
    fi
    if [[ $EFFECTIVE_ENGINE == "nmap" ]] && ! have nmap; then
        die "--engine nmap requested but nmap isn't installed."
    fi
}

# Confirm the chosen method can actually run; warn clearly otherwise.
preflight() {
    local method=$1 eng=$EFFECTIVE_ENGINE
    if [[ $eng == "nmap" ]]; then
        if [[ $method == arp || $method == syn || $method == ack || $method == icmp-ts || $method == icmp-mask || $method == all ]] && ! is_root; then
            echo -e "${YELLOW}Note: '$method' sends raw packets and needs root; without it nmap falls back to TCP connect probes (results are labelled with what actually answered).${NC}"
        fi
        return 0
    fi
    case $method in
        ping|icmp|all) have ping || die "ping not found." ;;
    esac
    case $method in
        arp)
            have arping || echo -e "${YELLOW}Note: arping not found — 'arp' falls back to ICMP ping.${NC}"
            is_root || echo -e "${YELLOW}Note: arping usually needs root.${NC}"
            have ip || echo -e "${YELLOW}Note: 'ip' (iproute2) not found — can't prove targets are on-subnet, so ARP silence is reported as 'filtered', not 'down'.${NC}" ;;
        tcp|all)
            if ! have timeout && ! have nc; then
                [[ $method == tcp ]] && die "tcp needs 'timeout' (coreutils) or 'nc'."
                echo -e "${YELLOW}Note: no 'timeout' or 'nc' — TCP probes in 'all' are skipped.${NC}"
            fi
            if have timeout && bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>&1 | grep -q 'No such file'; then
                have nc || die "this bash was built without /dev/tcp support and 'nc' is missing; tcp probes can't run."
            fi ;;
    esac
    if [[ $method == udp ]]; then
        have dig || have snmpget || have nmblookup || \
            echo -e "${YELLOW}Note: bash UDP needs dig/snmpget/nmblookup for a real reply; without them every host reads 'filtered'. Install nmap for UDP.${NC}"
    fi
}

# ---------------------------------------------------------------------------
# Bash-engine probes.  Each sets REASON (evidence) and, where relevant,
# REPLY_PORT.  Return 0 only on a POSITIVE (host/path answered).
# check_host turns these into a three-state verdict: up | down | filtered.
#
#   up       something answered, proving a live device is there
#   down     the path actively said "not there" (ICMP host-unreachable from
#            the path, or an ARP timeout on a *provably on-subnet* target)
#   filtered silence or an ambiguous error — could be a live host dropping
#            probes. VERIFY before trusting.
# ---------------------------------------------------------------------------
on_link() {   # 0 = target is directly attached (no gateway), 1 = routed, 2 = unknown
    have ip || return 2
    local r; r=$(ip -4 route get "$1" 2>/dev/null | head -n 1)
    [[ -n $r && $r != local* ]] || return 2
    [[ $r == *" via "* ]] && return 1
    return 0
}

# True when the kernel ARPed this directly-attached target and got no answer
# (INCOMPLETE/FAILED). Absent entries do NOT count: ARP may never have been
# attempted (e.g. a local OUTPUT rule dropped the probe).
l2_unanswered() {
    have ip || return 1
    on_link "$1" || return 1
    ip -4 neigh show "$1" 2>/dev/null | grep -qE 'INCOMPLETE|FAILED'
}
probe_ping() {      # REASON: echo-reply | host-unreach | no-response
    local ip=$1 to=$2 out rc
    if [[ -n $PING_TIMEOUT_FLAG ]]; then
        out=$(ping -c 1 "$PING_TIMEOUT_FLAG" "$to" "$ip" 2>&1); rc=$?
    else
        out=$(ping -c 1 "$ip" 2>&1); rc=$?
    fi
    if   (( rc==0 )); then REASON="echo-reply"; return 0       # exit 0 == reply received
    elif grep -qiE 'unreachable' <<<"$out"; then REASON="host-unreach"; return 1
    else REASON="no-response"; return 1; fi
}
probe_arp() {       # REASON: arp-reply | no-arp-reply | arping-absent ; rc 2 = arping absent
    local ip=$1 to=$2 ia=()
    have arping || { REASON="arping-absent"; return 2; }
    [[ -n $INTERFACE ]] && ia=("${ARPING_IFACE_FLAG:--I}" "$INTERFACE")
    if run_to "$to" arping -c 1 "${ia[@]}" "$ip" >/dev/null 2>&1; then REASON="arp-reply"; return 0; fi
    REASON="no-arp-reply"; return 1
}
# One TCP connect.  rc: 0 open | 10 refused (RST) | 11 ICMP unreachable | 1 silent
tcp_connect() {
    local ip=$1 port=$2 to=$3 err rc
    if have timeout; then
        err=$(timeout "$to" bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$ip" "$port" 2>&1); rc=$?
        (( rc==0 )) && return 0
        grep -qi 'refused' <<<"$err" && return 10
        grep -qiE 'no route|unreachable' <<<"$err" && return 11
        return 1
    elif have nc; then
        nc -z -w "$to" "$ip" "$port" >/dev/null 2>&1 && return 0
    fi
    return 1
}
# Probe every port in TCP_PORTS concurrently (worst case ≈ one timeout, not
# nine). Leaves one rc file per port in <dir>.
tcp_ports_run() {   # <ip> <timeout> <dir>
    local ip=$1 to=$2 dir=$3 port
    for port in $TCP_PORTS; do
        ( tcp_connect "$ip" "$port" "$to"; echo $? > "$dir/$port" ) &
    done
    wait
}
# REASON: syn-ack | reset | reset-unverified | no-route | no-response
probe_tcp() {
    local ip=$1 to=$2 port tmp rc open="" rst="" route=0
    REPLY_PORT=""; REASON="no-response"
    tmp=$(mktemp -d 2>/dev/null) || return 1
    tcp_ports_run "$ip" "$to" "$tmp"
    for port in $TCP_PORTS; do
        rc=$(<"$tmp/$port")
        case $rc in
            0)  [[ -z $open ]] && open=$port ;;
            10) [[ -z $rst ]]  && rst=$port ;;
            11) route=1 ;;
        esac
    done
    rm -rf "$tmp"
    if   [[ -n $open ]]; then REPLY_PORT=$open; REASON="syn-ack"; return 0
    elif [[ -n $rst  ]]; then
        # The canary found something RST-ing addresses that cannot exist (a REJECT
        # rule / middlebox). For targets not directly attached, an RST is then no
        # proof the target itself answered.
        if [[ ${CANARY_RST:-0} == 1 ]] && ! on_link "$ip"; then REASON="reset-unverified"; return 1; fi
        REPLY_PORT=$rst; REASON="reset"; return 0                            # a stack answered with RST
    elif (( route )); then REASON="no-route"                                 # host down OR firewall REJECT
    fi
    return 1
}

# L2 corroboration. A reply from a directly-attached host is only genuine if we
# hold that host's MAC: no ARP entry (INCOMPLETE/FAILED/absent) means the "reply"
# was produced locally (NAT REDIRECT, transparent proxy, VPN, ...). A MAC equal to
# the gateway's means the gateway is proxy-answering for it.
#   rc 0 = corroborated   1 = no L2 entry   3 = MAC shared with gateway
#   rc 2 = can't judge (routed target, or no iproute2) -> caller keeps the verdict
l2_verify() {
    local ip=$1 mac gwip gwmac
    have ip || return 2
    on_link "$ip" || return 2
    mac=$(ip -4 neigh show "$ip" 2>/dev/null | grep -oE 'lladdr [0-9a-fA-F:]+' | head -n 1)
    [[ -n $mac ]] || return 1
    gwip=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
    if [[ -n $gwip && $gwip != "$ip" ]]; then
        gwmac=$(ip -4 neigh show "$gwip" 2>/dev/null | grep -oE 'lladdr [0-9a-fA-F:]+' | head -n 1)
        [[ -n $gwmac && ${mac,,} == "${gwmac,,}" ]] && return 3
    fi
    return 0
}
# One UDP application probe. rc 0 only on a REAL application-layer reply.
udp_svc() {   # <dns|snmp|nbt> <ip> <timeout>
    local svc=$1 ip=$2 to=$3 out
    case $svc in
        # dig exits 0 whenever a DNS message came back (even REFUSED), 9 on timeout.
        dns)  have dig && dig +time="$to" +tries=1 +noall +comments "@$ip" -p 53 . NS >/dev/null 2>&1 ;;
        # SNMP: any reply — even an auth/community error — proves liveness; only a
        # timeout means silence.
        snmp) have snmpget || return 1
              out=$(run_to $(( to+2 )) snmpget -v2c -c public -t "$to" -r 0 "$ip" 1.3.6.1.2.1.1.1.0 2>&1)
              [[ -n $out && $out != *[Tt]imeout* && $out != *"No Response"* && $out != *"command not found"* ]] ;;
        nbt)  have nmblookup && run_to $(( to+2 )) nmblookup -A "$ip" 2>/dev/null | grep -q '<' ;;
        *)    return 1 ;;
    esac
}
udp_port_of() { case $1 in dns) echo 53;; snmp) echo 161;; nbt) echo 137;; esac; }
# 'nc -u -z' is deliberately NOT used — it reports success on silence and on
# router-sourced host-unreachable (false positives). Silence => return 1.
probe_udp() {       # REASON: dns-response | snmp-response | nbt-response | no-response
    local ip=$1 to=$2 svc
    REPLY_PORT=""; REASON="no-response"
    for svc in dns snmp nbt; do
        [[ " ${UDP_POISONED:-} " == *" $svc "* ]] && continue    # intercepted per the canary
        if udp_svc "$svc" "$ip" "$to"; then
            REPLY_PORT=$(udp_port_of "$svc"); REASON="${svc}-response"; return 0
        fi
    done
    return 1
}

# Emit: "<ip>\t<verdict>\t<reason>"  verdict in {up,down,filtered}
check_host() {
    local ip=$1 method=$2 to=${3:-2} verdict="filtered" reason="no-response" rc
    REPLY_PORT=""; REASON=""
    case $method in
        ping|icmp)
            if probe_ping "$ip" "$to"; then verdict="up"; reason="$REASON"
            elif [[ $REASON == host-unreach ]]; then verdict="down"; reason="$REASON"
            else verdict="filtered"; reason="$REASON"; fi ;;
        arp)
            probe_arp "$ip" "$to"; rc=$?
            if   (( rc==0 )); then verdict="up"; reason="arp-reply"
            elif (( rc==2 )); then   # no arping -> fall back to ping, inherit its reason
                if probe_ping "$ip" "$to"; then verdict="up"; reason="echo-reply(arp-fallback)"
                elif [[ $REASON == host-unreach ]]; then verdict="down"; reason="$REASON"
                else verdict="filtered"; reason="$REASON"; fi
            elif on_link "$ip"; then verdict="down"; reason="no-arp-reply"        # on-subnet silence = trustworthy down
            else verdict="filtered"; reason="no-arp-reply-unverified"; fi ;;       # can't prove on-subnet
        tcp)
            if probe_tcp "$ip" "$to"; then verdict="up"; reason="$REASON:$REPLY_PORT"
            else verdict="filtered"; reason="$REASON"; fi ;;
        udp)
            if probe_udp "$ip" "$to"; then verdict="up"; reason="$REASON:$REPLY_PORT"
            else verdict="filtered"; reason="no-response"; fi ;;
        all)
            # Gather evidence from every probe, then apply precedence:
            #   a positive reply (anything answered)  >  an explicit path "down"
            #   >  ambiguous (RST-less silence / ICMP errors on connect).
            local pos="" neg="" weak=""
            if probe_arp "$ip" 1; then pos="arp-reply"; fi
            if [[ -z $pos ]]; then
                if probe_ping "$ip" "$to"; then pos="echo-reply"
                elif [[ $REASON == host-unreach ]]; then neg="host-unreach"; fi
            fi
            if [[ -z $pos ]] && { have timeout || have nc; }; then
                if probe_tcp "$ip" "$to"; then pos="$REASON:$REPLY_PORT"
                elif [[ $REASON == no-route ]]; then weak="no-route"; fi
            fi
            if [[ -z $pos ]] && probe_udp "$ip" "$to"; then pos="$REASON:$REPLY_PORT"; fi
            if   [[ -n $pos ]]; then verdict="up"; reason="$pos"
            elif [[ -n $neg ]]; then verdict="down"; reason="$neg"
            else verdict="filtered"; reason="${weak:-no-response}"; fi ;;
        *) die "unknown method '$method'" ;;
    esac
    # Silence/ambiguous errors on a directly-attached target whose ARP went
    # unanswered is a reliable DOWN; deterministic (no race with ping's timeout).
    if [[ $verdict == filtered && ( $reason == no-response || $reason == no-route ) ]] && l2_unanswered "$ip"; then
        verdict="down"; reason="no-arp-reply"
    fi
    # Never trust an "up" the network layer can't back (arping replies are already L2).
    if [[ $verdict == up && $reason != arp-reply* ]]; then
        l2_verify "$ip"; rc=$?
        case $rc in
            1) verdict="filtered"; reason="unverified-no-l2:${reason}" ;;
            3) verdict="filtered"; reason="shared-mac-with-gateway:${reason}" ;;
        esac
    fi
    printf '%s\t%s\t%s\n' "$ip" "$verdict" "$reason"
}
export -f have run_to on_link l2_verify l2_unanswered probe_ping probe_arp tcp_connect tcp_ports_run probe_tcp udp_svc udp_port_of probe_udp check_host die

# ---------------------------------------------------------------------------
# Progress bar with rate + ETA (TTY only)
# ---------------------------------------------------------------------------
update_progress() {
    local processed=${1:-0} total=${2:-1} active=${3:-0} inactive=${4:-0}
    (( total==0 )) && total=1
    local pct=$(( processed*100/total ))
    local filled=$(( pct*progress_bar_width/100 )) empty
    empty=$(( progress_bar_width-filled ))
    local bar pad; printf -v bar '%*s' "$filled" ''; bar=${bar// /█}
    printf -v pad '%*s' "$empty" ''; pad=${pad// /░}
    local now rate=0 eta="" elapsed remain
    now=$(date +%s); elapsed=$(( now-START_EPOCH )); (( elapsed<1 )) && elapsed=1
    (( processed>0 )) && rate=$(( processed/elapsed ))
    if (( processed>0 && processed<total )); then
        remain=$(( (total-processed)*elapsed/processed ))
        eta=$(printf 'ETA %dm%02ds' $(( remain/60 )) $(( remain%60 )))
    fi
    printf '\r\033[K'
    echo -ne "${CYAN}[${bar}${pad}] ${pct}%${NC} "
    echo -ne "${GREEN}up ${active}${NC} ${RED}down/filt ${inactive}${NC} "
    echo -ne "${DIM}(${processed}/${total}) ${rate}/s ${eta}${NC}"
}

# ---------------------------------------------------------------------------
# Reverse DNS for active hosts (optional)
# ---------------------------------------------------------------------------
resolve_name() {
    local ip=$1 name=""
    if have getent; then name=$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')
    elif have host; then name=$(host "$ip" 2>/dev/null | awk '/pointer|name/{print $NF; exit}' | sed 's/\.$//'); fi
    echo "$name"
}

# ---------------------------------------------------------------------------
# Canary: 192.0.2.1 is RFC 5737 TEST-NET-1 — it can never be a real host. Any
# port that "answers" there is being answered by something local or upstream
# (NAT REDIRECT, transparent proxy, VPN, REJECT-everything firewall), so that
# port can't prove anything about a target. Poisoned ports are dropped from
# TCP_PORTS; RSTs from the canary disable RST-as-proof for routed targets.
# ---------------------------------------------------------------------------
CANARY_IP="192.0.2.1"
CANARY_RST=0
tcp_canary() {
    local tmp port rc keep="" poisoned=""
    have timeout || have nc || return 0
    tmp=$(mktemp -d 2>/dev/null) || return 0
    tcp_ports_run "$CANARY_IP" "$TIMEOUT_SECS" "$tmp"
    for port in $TCP_PORTS; do
        rc=$(<"$tmp/$port")
        case $rc in
            0)  poisoned="$poisoned $port" ;;
            10) CANARY_RST=1; keep="$keep $port" ;;
            *)  keep="$keep $port" ;;
        esac
    done
    rm -rf "$tmp"
    if [[ -n $poisoned ]]; then
        echo -e "${YELLOW}Warning: port(s)${poisoned} answer on the canary address ${CANARY_IP} — something local/upstream is intercepting them. Excluded from TCP probing.${NC}" >&2
        TCP_PORTS=${keep# }
    fi
    if (( CANARY_RST )); then
        echo -e "${YELLOW}Note: the canary address returns TCP resets — a RST is not accepted as proof of life for routed targets.${NC}" >&2
    fi
    [[ -n $TCP_PORTS ]] || die "every TCP probe port is intercepted; use ping/arp or --engine nmap."
    export CANARY_RST TCP_PORTS
}

# UDP canary (bash engine): a service that "replies" from the canary address is
# being answered locally/upstream, so it's switched off for this scan.
UDP_POISONED=""
udp_canary() {
    local svc found=""
    for svc in dns snmp nbt; do
        if udp_svc "$svc" "$CANARY_IP" "$TIMEOUT_SECS"; then found="$found $svc"; fi
    done
    if [[ -n $found ]]; then
        UDP_POISONED=${found# }
        echo -e "${YELLOW}Warning: UDP service(s)${found} \"reply\" on the canary address ${CANARY_IP} — intercepted locally/upstream. Excluded from UDP probing.${NC}" >&2
    fi
    export UDP_POISONED
}
# nmap engine: probe the canary with the exact same discovery flags. If it comes
# up, any routed "up" carrying that same reason is indistinguishable from the
# interception and is demoted (on-subnet hosts are still judged by their MAC).
CANARY_REASON=""
nmap_canary() {   # <probe flags>
    local out
    # shellcheck disable=SC2086
    out=$(nmap -sn -n --reason $1 "$CANARY_IP" 2>/dev/null) || return 0
    if grep -q 'Host is up' <<<"$out"; then
        CANARY_REASON=$(sed -n 's/.*received \([a-z-]*\).*/\1/p' <<<"$out" | head -n 1)
        echo -e "${YELLOW}Warning: the canary address ${CANARY_IP} came up (reason: ${CANARY_REASON:-?}) — routed hosts with that same reason will be reported as filtered.${NC}" >&2
    fi
}

# ---------------------------------------------------------------------------
# nmap engine — runs once over the whole target list. Writes the same
# "ip<TAB>verdict<TAB>reason" rows as the bash engine to <resultfile>.
# ---------------------------------------------------------------------------
scan_engine_nmap() {
    local method=$1 ipfile=$2 resultfile=$3 probe rc
    local gnmap="$TEMP_DIR/nmap.gnmap" reasons="$TEMP_DIR/nmap.reasons" errf="$TEMP_DIR/nmap.err"
    case $method in
        ping|icmp)  probe="-PE" ;;
        arp)        probe="-PR" ;;
        tcp|syn)    probe="-PS${TCP_PORTS// /,}" ;;
        ack)        probe="-PA80,443,3389" ;;
        udp)        probe="-PU53,161,137,123,500" ;;
        icmp-ts)    probe="-PP" ;;
        icmp-mask)  probe="-PM" ;;
        all)        probe="-PR -PE -PP -PM -PS22,80,443,3389,445 -PA80,443 -PU53,161,137" ;;
        *)          die "no nmap mapping for method '$method'" ;;
    esac
    [[ $method == arp ]] || nmap_canary "$probe"
    local ia=(); [[ -n $INTERFACE ]] && ia=(-e "$INTERFACE")
    echo -e "${CYAN}Running nmap host discovery ($method)...${NC}"
    # -sn: discovery only, -n: no DNS, --reason: record WHY each host is up.
    # stdout carries "received <reason>"; -oG carries the up/down list.
    # shellcheck disable=SC2086
    nmap -sn -n --reason $probe "${ia[@]}" -iL "$ipfile" -oG "$gnmap" 2>"$errf" \
        | awk '/scan report for/{ip=$NF} /Host is up/{for(i=1;i<=NF;i++)if($i=="received"){r=$(i+1);gsub(/[.,]$/,"",r);print ip"\t"r}}' \
        > "$reasons"
    rc=${PIPESTATUS[0]}
    # A failed nmap must NEVER look like "every host is down".
    if (( rc != 0 )) || ! grep -q '^# Nmap done' "$gnmap" 2>/dev/null; then
        echo -e "${RED}nmap failed (exit $rc):${NC}" >&2
        sed 's/^/  /' "$errf" >&2
        exit 1
    fi
    grep -i 'warning' "$errf" 2>/dev/null | sed "s/^/${YELLOW}nmap: /;s/\$/${NC}/" | head -n 3

    awk '/Status: Up/{print $2}' "$gnmap" | sortip > "$TEMP_DIR/up.txt"
    LC_ALL=C sort "$ipfile" | LC_ALL=C comm -23 - <(LC_ALL=C sort "$TEMP_DIR/up.txt") | sortip > "$TEMP_DIR/notup.txt"

    awk -F'\t' -v OFS='\t' 'FNR==NR{r[$1]=$2; next} {print $1,"up",(($1 in r)?r[$1]:"up")}' \
        "$reasons" "$TEMP_DIR/up.txt" > "$resultfile"
    local ip
    if [[ $method == arp ]]; then
        # Silence on a directly-attached subnet is a trustworthy down; otherwise it is only filtered.
        while IFS= read -r ip; do
            if on_link "$ip"; then printf '%s\tdown\tno-arp-reply\n' "$ip"
            else printf '%s\tfiltered\tno-arp-reply-unverified\n' "$ip"; fi
        done < "$TEMP_DIR/notup.txt" >> "$resultfile"
    else
        awk -v OFS='\t' '{print $1,"filtered","no-response"}' "$TEMP_DIR/notup.txt" >> "$resultfile"
    fi
    # Demote "up" rows the L2 table can't back (local interception, proxy-ARP).
    # arp-response is already L2 evidence.
    local tmpres="$TEMP_DIR/results.l2" v r vrc
    while IFS=$'\t' read -r ip v r; do
        if [[ $v == up && $r != arp-response* ]]; then
            l2_verify "$ip"; vrc=$?
            case $vrc in
                1) v="filtered"; r="unverified-no-l2:$r" ;;
                3) v="filtered"; r="shared-mac-with-gateway:$r" ;;
            esac
        fi
        if [[ $v == filtered && $r == no-response ]] && l2_unanswered "$ip"; then v="down"; r="no-arp-reply"; fi
        if [[ $v == up && -n $CANARY_REASON && $r == "$CANARY_REASON" ]] && ! on_link "$ip"; then
            v="filtered"; r="canary-matched:$r"
        fi
        printf '%s\t%s\t%s\n' "$ip" "$v" "$r"
    done < "$resultfile" > "$tmpres" && mv "$tmpres" "$resultfile"
}

# ---------------------------------------------------------------------------
# bash engine — parallel per-host via xargs, live progress
# ---------------------------------------------------------------------------
scan_engine_bash() {
    local method=$1 ipfile=$2 resultfile=$3 threads=$4 d a
    export METHOD=$method TIMEOUT=$TIMEOUT_SECS PING_TIMEOUT_FLAG ARPING_IFACE_FLAG INTERFACE TCP_PORTS CANARY_RST UDP_POISONED
    : > "$resultfile"
    xargs -P "$threads" -n 1 bash -c 'check_host "$1" "$METHOD" "$TIMEOUT"' _ \
        < "$ipfile" > "$resultfile" &
    XARGS_PID=$!
    if [[ $IS_TTY == "true" ]]; then
        update_progress 0 "$total_ips" 0 0
        while kill -0 "$XARGS_PID" 2>/dev/null; do
            sleep 0.2
            read -r d a < <(awk -F'\t' '{n++} $2=="up"{u++} END{print n+0, u+0}' "$resultfile" 2>/dev/null)
            update_progress "${d:-0}" "$total_ips" "${a:-0}" "$(( ${d:-0}-${a:-0} ))"
        done
    fi
    wait "$XARGS_PID" 2>/dev/null; XARGS_PID=""

    # Safety net: a worker that crashed must not make a host vanish from the report.
    LC_ALL=C sort "$ipfile" | LC_ALL=C comm -23 - <(cut -f1 "$resultfile" | LC_ALL=C sort) > "$TEMP_DIR/missing.txt"
    if [[ -s $TEMP_DIR/missing.txt ]]; then
        echo -e "\n${YELLOW}Warning: $(wc -l < "$TEMP_DIR/missing.txt" | tr -d ' ') host(s) produced no result; marked filtered (probe-error).${NC}" >&2
        awk -v OFS='\t' '{print $1,"filtered","probe-error"}' "$TEMP_DIR/missing.txt" >> "$resultfile"
    fi
    if [[ $IS_TTY == "true" ]]; then
        read -r d a < <(awk -F'\t' '{n++} $2=="up"{u++} END{print n+0, u+0}' "$resultfile")
        update_progress "$total_ips" "$total_ips" "$a" "$(( d-a ))"
        echo -e "\n"
    fi
}

# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------
# Map a reason -> short confidence hint so a verdict can be audited.
confidence() {
    case $1 in
        arp-reply|arp-response)                      echo "confirmed (L2)";;
        echo-reply*|timestamp-reply*|netmask-reply*) echo "confirmed (ICMP)";;
        dns-response*|snmp-response*|nbt-response*|udp-response*) echo "UDP service replied — host confirmed";;
        syn-ack*)                                    echo "service answered — verify it's the host, not a middlebox";;
        reset*|conn-refused*)                        echo "RST seen — a TCP stack (or firewall) answered; verify off-subnet";;
        host-unreach)                                echo "ICMP host-unreachable from the path";;
        no-arp-reply)                                echo "no L2 reply on a directly-attached subnet — reliable down";;
        no-arp-reply-unverified)                     echo "no ARP reply, but target not proven on-subnet — verify";;
        unverified-no-l2*)                           echo "reply but NO ARP entry for an on-subnet host — answered locally (NAT/proxy), not by the host";;
        shared-mac-with-gateway*)                    echo "reply carries the gateway's MAC — proxy-ARP/gateway answered, not the host";;
        canary-matched*)                             echo "routed reply identical to what the canary address returns — interception, not the host";;
        reset-unverified)                            echo "RST, but the canary address also RSTs — firewall/middlebox, not proof of life";;
        no-route)                                    echo "ICMP unreachable on connect — host down OR firewall REJECT; verify";;
        probe-error)                                 echo "probe failed to run — rerun";;
        no-response|"")                              echo "silent — could be filtered, verify (nmap -Pn)";;
        *)                                           echo "$1";;
    esac
}
fmt_host() {   # ip -> "ip  [reason — confidence]  (name)"
    local ip=$1 r=${REASON_OF[$1]:-no-response}
    printf '%s  [%s — %s]' "$ip" "$r" "$(confidence "$r")"
    [[ -n ${NAMES[$ip]:-} ]] && printf '  (%s)' "${NAMES[$ip]}"
    printf '\n'
}
json_str() {
    local s=$1
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/\\t}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}
    printf '%s' "$s"
}
json_hosts() {   # $1 = array name
    local -n arr=$1; local ip first=1 r
    for ip in "${arr[@]}"; do
        r=${REASON_OF[$ip]:-no-response}
        (( first )) || printf ','; first=0
        printf '{"ip":"%s","reason":"%s","confidence":"%s","name":"%s"}' \
            "$ip" "$(json_str "$r")" "$(json_str "$(confidence "$r")")" "$(json_str "${NAMES[$ip]:-}")"
    done
}
show_list() {   # <array-name> <limit> [verbose]
    local -n arr=$1; local limit=$2 i show
    show=$(( ${#arr[@]} > limit ? limit : ${#arr[@]} ))
    for (( i=0; i<show; i++ )); do echo -ne "  "; fmt_host "${arr[$i]}"; done
    (( ${#arr[@]} > limit )) && echo -e "  ${DIM}... and $(( ${#arr[@]}-limit )) more${NC}"
}

# ---------------------------------------------------------------------------
# Self-update (the VERSION file on GitHub is the source of truth)
# ---------------------------------------------------------------------------
update_base() { echo "${AR_BASE_URL:-https://raw.githubusercontent.com/$UPDATE_REPO/main}"; }
version_gt() {   # 0 if $1 is a newer x.y.z than $2
    local IFS=. i a b
    local -a x y
    read -r -a x <<< "$1"; read -r -a y <<< "$2"
    for i in 0 1 2; do
        a=$(( 10#${x[i]:-0} )); b=$(( 10#${y[i]:-0} ))
        (( a > b )) && return 0
        (( a < b )) && return 1
    done
    return 1
}
fetch_latest() {   # prints the latest version; non-zero if unreachable or garbled
    local v url; url="$(update_base)/VERSION"
    if   have curl; then v=$(curl -fsSL --max-time 3 "$url" 2>/dev/null)
    elif have wget; then v=$(wget -qO- -T 3 "$url" 2>/dev/null)
    else return 1; fi
    v=${v//[[:space:]]/}
    [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    echo "$v"
}
# Only the installed command updates itself; a git checkout should use git pull.
is_installed_copy() { [[ $(basename "$0") == "asset-reachability" ]]; }
self_update() {
    local latest dir
    is_installed_copy || die "not an installed copy (run it as 'asset-reachability'). From a git checkout use: git pull"
    latest=$(fetch_latest) || die "can't reach GitHub to check for updates."
    if ! version_gt "$latest" "$VERSION"; then echo "Already up to date ($VERSION)."; return 0; fi
    have curl || die "curl is required to update."
    echo -e "${CYAN}Updating $VERSION -> $latest ...${NC}"
    dir=$(cd "$(dirname "$0")" && pwd)
    # Reuses the installer, so the same syntax + SHA-256 verification applies.
    curl -fsSL "$(update_base)/install.sh" | sh -s -- --no-deps --prefix "$dir" || die "update failed; current version left in place."
}
# At most once per 24h, interactive terminals only, 3s network cap.
maybe_prompt_update() {
    [[ -z ${AR_NO_UPDATE_CHECK:-} && $OPT_NO_UPDATE_CHECK != "true" ]] || return 0
    [[ -t 0 && $IS_TTY == "true" ]] || return 0
    is_installed_copy || return 0
    local dir="${XDG_CACHE_HOME:-$HOME/.cache}/asset-reachability" stamp latest ans
    stamp="$dir/last_check"
    if [[ -f $stamp && -z $(find "$stamp" -mmin +1440 2>/dev/null) ]]; then return 0; fi
    mkdir -p "$dir" 2>/dev/null && : > "$stamp" 2>/dev/null    # touch first so failures throttle too
    latest=$(fetch_latest) || return 0
    version_gt "$latest" "$VERSION" || return 0
    echo -ne "${YELLOW}Update available: $VERSION -> $latest. Update now? [Y/n] ${NC}"
    read -r ans </dev/tty 2>/dev/null || ans="n"
    if [[ -z $ans || $ans =~ ^[Yy] ]]; then
        if self_update; then echo; AR_NO_UPDATE_CHECK=1 exec "$0" "${ORIG_ARGS[@]}"; fi
    fi
    echo
}

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
perform_reachability_test() {
    local input=$1 type=$2 verbose=$3 threads=$4 split_files=$5 output_dir=$6 method=$7
    local timestamp stamp base_name="scan" output_file ip i
    timestamp=$(date '+%b %d %Y %I:%M:%S %p'); stamp=$(date '+%Y%m%d-%H%M%S')
    [[ $type == "file" ]] && base_name=$(basename "$input" | sed 's/\.[^.]*$//')

    collect_targets "$type" "$input"

    resolve_engine "$method"
    preflight "$method"
    local eng=$EFFECTIVE_ENGINE

    mkdir -p "$output_dir" || die "can't create output dir '$output_dir'."
    output_file="${output_dir}/${base_name}-${stamp}.txt"

    # -- banner --------------------------------------------------------------
    echo -e "${BOLD}Asset Reachability Test${NC}  ${DIM}($type '$input')${NC}"
    echo -e "${DIM}$timestamp${NC}"
    echo -e "Method: ${BOLD}$method${NC}   Engine: ${BOLD}$eng${NC}   Threads: $threads   Targets: ${BOLD}$total_ips${NC}"
    echo ""

    # -- large-scan confirmation --------------------------------------------
    if (( total_ips > RANGE_WARN_LIMIT )) && [[ $ASSUME_YES != "true" ]]; then
        echo -ne "${YELLOW}$total_ips targets — this is loud and may take a while. Continue? [y/N] ${NC}"
        local ans; read -r ans </dev/tty 2>/dev/null || ans="n"
        [[ $ans =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
    fi

    TEMP_DIR=$(mktemp -d) || die "can't create temp dir."
    printf '%s\n' "${TARGETS[@]}" > "$TEMP_DIR/ips.txt"
    START_EPOCH=$(date +%s)
    local results="$TEMP_DIR/results.tsv"
    case $method in tcp|syn|all) tcp_canary ;; esac
    if [[ $eng == "bash" ]]; then case $method in udp|all) udp_canary ;; esac; fi

    # -- run -----------------------------------------------------------------
    if [[ $eng == "nmap" ]]; then
        scan_engine_nmap "$method" "$TEMP_DIR/ips.txt" "$results"
    else
        echo -e "${CYAN}Scanning with $threads parallel workers...${NC}\n"
        scan_engine_bash "$method" "$TEMP_DIR/ips.txt" "$results" "$threads"
    fi

    local up_ips=() down_ips=() filt_ips=()
    mapfile -t up_ips   < <(awk -F'\t' '$2=="up"{print $1}'       "$results" | sortip)
    mapfile -t down_ips < <(awk -F'\t' '$2=="down"{print $1}'     "$results" | sortip)
    mapfile -t filt_ips < <(awk -F'\t' '$2=="filtered"{print $1}' "$results" | sortip)
    REASON_OF=()
    local k _v r
    while IFS=$'\t' read -r k _v r; do REASON_OF[$k]=$r; done < "$results"

    local elapsed=$(( $(date +%s)-START_EPOCH )); (( elapsed<1 )) && elapsed=1
    local rate=$(( total_ips/elapsed ))

    # -- optional reverse DNS (up hosts only) --------------------------------
    NAMES=()
    if [[ $RESOLVE == "true" && ${#up_ips[@]} -gt 0 ]]; then
        echo -e "${DIM}Resolving names for ${#up_ips[@]} up hosts...${NC}"
        for ip in "${up_ips[@]}"; do NAMES[$ip]=$(resolve_name "$ip"); done
    fi

    # -- screen output -------------------------------------------------------
    echo -e "${BOLD}Result:${NC} ${GREEN}up ${#up_ips[@]}${NC}  ${RED}down ${#down_ips[@]}${NC}  ${YELLOW}filtered ${#filt_ips[@]}${NC}  / $total_ips"
    echo ""
    echo -e "${GREEN}${BOLD}UP (${#up_ips[@]})${NC} ${DIM}— something answered${NC}"
    if [[ $verbose == "true" ]]; then
        for ip in "${up_ips[@]}"; do echo -ne "${GREEN}  ✓ ${NC}"; fmt_host "$ip"; done
    else
        show_list up_ips 10
    fi

    if (( ${#filt_ips[@]} )); then
        echo ""
        echo -e "${YELLOW}${BOLD}FILTERED (${#filt_ips[@]})${NC} ${DIM}— silent or ambiguous; may be live hosts dropping probes. Re-check with: nmap -Pn${NC}"
        show_list filt_ips 10
    fi

    echo ""
    echo -e "${RED}${BOLD}DOWN (${#down_ips[@]})${NC} ${DIM}— path says the host isn't there${NC}"
    show_list down_ips 5
    echo ""
    echo -e "${DIM}Scanned $total_ips in ${elapsed}s (~${rate}/s)${NC}"

    # -- write output file ---------------------------------------------------
    {
        echo "Asset Reachability Test for $type '$input'"
        echo "Performed $timestamp"
        echo "Method: $method   Engine: $eng   Threads: $threads"
        echo "Total: $total_ips   Up: ${#up_ips[@]}   Down: ${#down_ips[@]}   Filtered: ${#filt_ips[@]}   Time: ${elapsed}s"
        echo ""
        echo "UP (${#up_ips[@]}) — something answered"
        for ip in "${up_ips[@]}"; do
            r=${REASON_OF[$ip]:-?}
            printf '%s  [%s — %s]%s\n' "$ip" "$r" "$(confidence "$r")" "${NAMES[$ip]:+  (${NAMES[$ip]})}"
        done
        echo ""
        echo "FILTERED (${#filt_ips[@]}) — silent or ambiguous, verify with nmap -Pn"
        for ip in "${filt_ips[@]}"; do printf '%s  [%s]\n' "$ip" "${REASON_OF[$ip]:-no-response}"; done
        echo ""
        echo "DOWN (${#down_ips[@]}) — path says not there"
        for ip in "${down_ips[@]}"; do printf '%s  [%s]\n' "$ip" "${REASON_OF[$ip]:-no-response}"; done
    } > "$output_file"

    if [[ $split_files == "true" ]]; then
        local af="${output_dir}/${base_name}-${stamp}-up.txt"
        local ff="${output_dir}/${base_name}-${stamp}-filtered.txt"
        local df="${output_dir}/${base_name}-${stamp}-down.txt"
        : > "$af"; : > "$ff"; : > "$df"
        (( ${#up_ips[@]} ))   && printf '%s\n' "${up_ips[@]}"   > "$af"
        (( ${#filt_ips[@]} )) && printf '%s\n' "${filt_ips[@]}" > "$ff"
        (( ${#down_ips[@]} )) && printf '%s\n' "${down_ips[@]}" > "$df"
        echo -e "${GREEN}Up list:       $af${NC}"
        echo -e "${YELLOW}Filtered list: $ff${NC}"
        echo -e "${RED}Down list:     $df${NC}"
    fi

    if [[ $json_out == "true" ]]; then
        local jf="${output_dir}/${base_name}-${stamp}.json"
        {
            printf '{"meta":{"version":"%s","type":"%s","input":"%s","method":"%s","engine":"%s","total":%d,"up":%d,"down":%d,"filtered":%d,"seconds":%d},' \
                "$VERSION" "$type" "$(json_str "$input")" "$method" "$eng" "$total_ips" "${#up_ips[@]}" "${#down_ips[@]}" "${#filt_ips[@]}" "$elapsed"
            printf '"up":[';       json_hosts up_ips;   printf '],'
            printf '"filtered":['; json_hosts filt_ips; printf '],'
            printf '"down":[';     json_hosts down_ips; printf ']}'
            printf '\n'
        } > "$jf"
        echo -e "${GREEN}JSON:          $jf${NC}"
    fi

    echo -e "${GREEN}Full scan:     $output_file${NC}"
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
display_help() {
    local me; me=$(basename "$0")
    cat <<EOF
$me $VERSION — IPv4 host reachability sweep

Usage: $me [OPTIONS]

Input (choose one):
  -f, --file <file>           One IP per line (# comments allowed; invalid lines skipped).
  -l, --list "ip1,ip2,..."    Comma-separated IPs.
  -c, --cidr "A.B.C.D/N"      CIDR block (network/broadcast excluded, except /31 /32).
  -r, --range "start-end"     e.g. 192.168.0.1-192.168.0.100.

Scan:
  -m, --method <method>       Discovery method (default: ping). See below.
  -e, --engine <bash|nmap>    Force engine. 'auto' (default) uses bash, and
                              switches to nmap for methods bash can't do.
  -t, --threads <n>           Parallel workers, bash engine (default: 10).
  -w, --timeout <sec>         Per-probe timeout, bash engine (default: 2).
  -i, --interface <iface>     Interface for arp / nmap raw probes.

Output / UX:
  -o, --output <dir>          Output directory (default: scans/).
  -s, --split-files           Separate up / filtered / down files.
  -j, --json                  Also write machine-readable JSON (with reasons).
      --resolve               Reverse-DNS active hosts.
  -v, --verbose               List every active host.
  -y, --yes                   Skip the large-scan confirmation.
      --no-color              Disable ANSI colors (also honours NO_COLOR).
      --update                Update to the latest release (installed copy only).
      --check-update          Report whether a newer release exists.
      --no-update-check       Skip the daily update prompt (or set AR_NO_UPDATE_CHECK=1).
  -V, --version               Print version.
  -h, --help                  This message.

Methods:
  ping / icmp   ICMP echo.                                  [bash]
  arp           ARP via arping (L2, most reliable on-subnet; root+iface).  [bash|nmap -PR]
  tcp           TCP connect on common ports; up = a port is OPEN or RST.   [bash|nmap -PS]
  udp           UDP probe (DNS/SNMP/NetBIOS). Silence is ambiguous —
                prefer --engine nmap for real UDP discovery.               [bash|nmap -PU]
  syn           TCP SYN ping (-PS). Half-open, slips some filters.         [nmap]
  ack           TCP ACK ping (-PA). Slips stateless firewalls.             [nmap]
  icmp-ts       ICMP timestamp (-PP, type 13). Catches echo-blockers.      [nmap]
  icmp-mask     ICMP address mask (-PM, type 17).                          [nmap]
  all           ARP+ICMP+TCP+UDP (bash) / full -PR -PE -PP -PM -PS -PA -PU (nmap).

Verdict (each host is graded, with the reason as evidence):
  UP        a probe got a positive reply (arp-reply, echo-reply, syn-ack, reset,
            udp-response). The reason tells you WHAT answered — an arp/icmp
            reply is the host; a lone syn-ack/reset off-subnet could be a firewall.
  DOWN      the path actively said the host isn't there: ICMP host-unreachable,
            or no ARP reply from a target proven to be on the local subnet.
  FILTERED  silence or an ambiguous error (e.g. "no route" on connect, which a
            firewall REJECT also produces). Could be a live host dropping your
            probes — re-check with 'nmap -Pn' before trusting it.

Exit status: 0 scan completed, 1 error/usage, 130 interrupted.

Examples:
  $me -c 192.168.1.0/24 -m arp -i eth0 -s
  $me -c 10.0.0.0/24 -m ack              # nmap engine auto-selected
  $me -r 10.0.0.1-10.0.0.254 -m all -e nmap -j
  $me -f hosts.txt -m tcp -v --resolve
EOF
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
require_arg() { [[ -n ${2:-} && ${2:0:1} != "-" ]] || { echo "Error: missing argument for $1." >&2; exit 1; }; }

main() {
    local verbose="false" split_files="false" threads=10 output_dir="scans" scan_method="ping"
    local input_type="" input_value="" latest
    ORIG_ARGS=("$@")

    trap on_interrupt INT TERM
    trap '[[ -n $TEMP_DIR && -d $TEMP_DIR ]] && rm -rf "$TEMP_DIR"' EXIT

    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)      require_arg "$1" "${2:-}"; input_type="file";  input_value=$2; shift 2 ;;
            -l|--list)      require_arg "$1" "${2:-}"; input_type="list";  input_value=$2; shift 2 ;;
            -c|--cidr)      require_arg "$1" "${2:-}"; input_type="cidr";  input_value=$2; shift 2 ;;
            -r|--range)     require_arg "$1" "${2:-}"; input_type="range"; input_value=$2; shift 2 ;;
            -m|--method)
                require_arg "$1" "${2:-}"; scan_method=$2
                [[ $ALL_METHODS == *" $scan_method "* ]] || { echo "Error: invalid method '$scan_method'." >&2; exit 1; }
                shift 2 ;;
            -e|--engine)
                require_arg "$1" "${2:-}"; engine=$2
                [[ $engine =~ ^(auto|bash|nmap)$ ]] || { echo "Error: engine must be auto|bash|nmap." >&2; exit 1; }
                shift 2 ;;
            -i|--interface) require_arg "$1" "${2:-}"; INTERFACE=$2; shift 2 ;;
            -o|--output)    require_arg "$1" "${2:-}"; output_dir=$2; shift 2 ;;
            -t|--threads)
                require_arg "$1" "${2:-}"; threads=$2
                [[ $threads =~ ^[0-9]+$ ]] && (( 10#$threads >= 1 && 10#$threads <= 1024 )) \
                    || { echo "Error: threads must be an integer 1-1024." >&2; exit 1; }
                threads=$(( 10#$threads ))
                shift 2 ;;
            -w|--timeout)
                require_arg "$1" "${2:-}"; TIMEOUT_SECS=$2
                [[ $TIMEOUT_SECS =~ ^[0-9]+$ ]] && (( 10#$TIMEOUT_SECS >= 1 && 10#$TIMEOUT_SECS <= 60 )) \
                    || { echo "Error: timeout must be an integer 1-60 seconds." >&2; exit 1; }
                TIMEOUT_SECS=$(( 10#$TIMEOUT_SECS ))
                shift 2 ;;
            -s|--split-files) split_files="true"; shift ;;
            -j|--json)        json_out="true"; shift ;;
            --resolve)        RESOLVE="true"; shift ;;
            -v|--verbose)     verbose="true"; shift ;;
            -y|--yes)         ASSUME_YES="true"; shift ;;
            --no-color)       OPT_NO_COLOR="true"; shift ;;
            --no-update-check) OPT_NO_UPDATE_CHECK="true"; shift ;;
            --update)         setup_colors; self_update; exit $? ;;
            --check-update)
                latest=$(fetch_latest) || { echo "Can't reach GitHub." >&2; exit 1; }
                if version_gt "$latest" "$VERSION"; then echo "Update available: $VERSION -> $latest (run: asset-reachability --update)"
                else echo "Up to date ($VERSION)."; fi
                exit 0 ;;
            -V|--version)     echo "asset_reachability $VERSION"; exit 0 ;;
            -h|--help)        setup_colors; display_help 0 ;;
            *) echo "Invalid option: $1" >&2; setup_colors; display_help 1 ;;
        esac
    done

    setup_colors
    [[ -n $input_type && -n $input_value ]] || { echo -e "${RED}Error: missing input (-f/-l/-c/-r).${NC}" >&2; display_help 1; }

    maybe_prompt_update
    detect_ping
    detect_arping
    perform_reachability_test "$input_value" "$input_type" "$verbose" "$threads" "$split_files" "$output_dir" "$scan_method"
}

# Run only when executed, not when sourced (lets tests import the functions).
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
