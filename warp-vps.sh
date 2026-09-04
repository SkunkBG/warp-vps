#!/usr/bin/env bash
#
# warp-vps — Cloudflare WARP as a host WireGuard interface, for Xray nodes.
#
# The tunnel is a kernel WireGuard interface named `warp`, brought up with
# `Table = off` so wg-quick installs NO routes at all. The host's routing is
# untouched; only sockets explicitly bound to the interface use the tunnel,
# which for Xray means `sockopt: { "interface": "warp" }`.
#
# That works with zero routes because of a deliberate kernel behaviour. From
# net/ipv4/route.c, where the FIB lookup fails and an output interface is set:
#
#   "Apparently, routing tables are wrong. Assume, that the destination is on
#    link. Because we are allowed to send to iface even if it has NO routes and
#    NO assigned addresses. When oif is specified, routing tables are looked up
#    with only one purpose: to catch if destination is gatewayed, rather than
#    direct."
#
# So a socket bound with SO_BINDTODEVICE reaches the peer regardless. No ip
# rule, no fwmark, no policy table, nothing to leak if a unit dies.
#
# https://github.com/SkunkBG/warp-vps
# SPDX-License-Identifier: MIT

set -euo pipefail

VERSION="2.0.0"

IFACE="warp"
WG_CONF="/etc/wireguard/${IFACE}.conf"
STATE_DIR="/etc/warp-vps"
ACCOUNT_FILE="${STATE_DIR}/account.json"
APP_DIR="/opt/warp-vps"
WATCHDOG_STATE="${STATE_DIR}/watchdog.state"
RAW_URL="https://raw.githubusercontent.com/SkunkBG/warp-vps/main/warp-vps.sh"

# 1280 is the IPv6 minimum MTU and clears every path we have measured. wgcf
# writes the same value; it is set explicitly here so it does not depend on
# whatever upstream decides to generate.
WARP_MTU=1280
KEEPALIVE=25

# --- Cloudflare WARP API ------------------------------------------------------
# Mirrors the official Android client. Three things are load-bearing and the API
# answers 403 (error 1020) if any is wrong:
#   * TLS pinned to exactly 1.2 — not "at least 1.2". curl needs both
#     --tlsv1.2 and --tls-max 1.2, matching the client's Min == Max TLS config.
#   * HTTP/1.1 — the client disables the H2 upgrade.
#   * The UA / CF-Client-Version pair below.
#
# Talking to the API directly is what removes the wgcf binary: no unsigned
# download executed as root, and nothing to keep in step with upstream releases.
CF_API="https://api.cloudflareclient.com"
CF_API_VERSION="v0a1922"
CF_UA="okhttp/3.12.1"
CF_CLIENT_VERSION="a-6.3-1922"
HTTP_TIMEOUT=30

# Anycast prefixes WARP peers answer on, used by `rotate` and by the watchdog.
# Endpoint entropy is a DPI countermeasure, not a latency optimisation — do not
# "improve" this into a ping-based picker.
CF_ENDPOINT_SUBNETS=(162.159.192 162.159.193 188.114.96 188.114.97)
CF_ENDPOINT_PORTS=(2408 500 1701 4500)

TRACE_URL="https://cloudflare.com/cdn-cgi/trace"

# Probe targets that answer a bare curl honestly. Deliberately NOT the sites'
# HTML roots: Cloudflare's bot protection rejects curl on its TLS fingerprint,
# so https://chatgpt.com returns 403 from a residential browser address just as
# readily as from a hosting range and the code says nothing about your IP.
# /cdn-cgi/trace is exempt and reports what the destination actually sees.
PROBE_AI="https://chatgpt.com/cdn-cgi/trace,https://claude.ai/cdn-cgi/trace,https://api.openai.com/v1/models,https://gemini.google.com"

RULES_AI="geosite:openai,domain:openai.com,domain:chatgpt.com,domain:oaistatic.com,domain:oaiusercontent.com,domain:sora.com,domain:anthropic.com,domain:claude.ai,domain:claudeusercontent.com,domain:gemini.google.com,domain:aistudio.google.com,domain:generativelanguage.googleapis.com,domain:x.ai,domain:grok.com,domain:perplexity.ai,domain:deepseek.com,domain:mistral.ai,domain:meta.ai,domain:copilot.microsoft.com,domain:githubcopilot.com,domain:huggingface.co,domain:midjourney.com,domain:suno.com,domain:elevenlabs.io,domain:runwayml.com,domain:leonardo.ai,domain:character.ai,domain:poe.com,domain:cursor.com,domain:phind.com"

expand_rules() { case "$1" in ai) printf '%s' "$RULES_AI" ;; *) printf '%s' "$1" ;; esac; }
expand_probe() { case "$1" in ai) printf '%s' "$PROBE_AI" ;; *) printf '%s' "$1" ;; esac; }

# --- Output -------------------------------------------------------------------
if [[ -t 2 ]]; then
    C_RST=$'\e[0m'; C_BLD=$'\e[1m'; C_CYN=$'\e[36m'; C_GRN=$'\e[32m'
    C_YLW=$'\e[33m'; C_RED=$'\e[31m'; C_GRY=$'\e[90m'
else
    C_RST=""; C_BLD=""; C_CYN=""; C_GRN=""; C_YLW=""; C_RED=""; C_GRY=""
fi

step() { printf '\n%s▶%s %s%s%s\n'  "$C_CYN" "$C_RST" "$C_BLD" "$1" "$C_RST" >&2; }
ok()   { printf '  %s✔%s %s%s%s\n'  "$C_GRN" "$C_RST" "$C_GRY" "$1" "$C_RST" >&2; }
warn() { printf '  %s⚠%s  %s%s%s\n' "$C_YLW" "$C_RST" "$C_YLW" "$1" "$C_RST" >&2; }
die()  { printf '\n  %s✖ Error:%s %s\n\n' "$C_RED" "$C_RST" "$1" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "This command needs root (sudo)."; }

# --- Dependencies -------------------------------------------------------------
detect_pm() {
    local pm
    for pm in apt-get dnf yum zypper pacman apk; do
        command -v "$pm" >/dev/null 2>&1 && { printf '%s' "$pm"; return 0; }
    done
    return 1
}

pkg_for() {
    # $1 = command, $2 = package manager
    case "$1" in
        wg-quick) case "$2" in apt-get) echo wireguard ;; *) echo wireguard-tools ;; esac ;;
        wg)       case "$2" in apt-get) echo wireguard-tools ;; *) echo wireguard-tools ;; esac ;;
        ping)     case "$2" in apt-get|apk) echo iputils-ping ;; *) echo iputils ;; esac ;;
        ip)       case "$2" in dnf|yum) echo iproute ;; *) echo iproute2 ;; esac ;;
        *)        echo "$1" ;;
    esac
}

pm_install() {
    local pm="$1"; shift
    case "$pm" in
        apt-get) apt-get update -qq >/dev/null 2>&1
                 DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 ;;
        dnf)     dnf install -y "$@" >/dev/null 2>&1 ;;
        yum)     yum install -y "$@" >/dev/null 2>&1 ;;
        zypper)  zypper --non-interactive --quiet install "$@" >/dev/null 2>&1 ;;
        pacman)  pacman -Sy --needed --noconfirm "$@" >/dev/null 2>&1 ;;
        apk)     apk add --no-cache "$@" >/dev/null 2>&1 ;;
        *)       return 1 ;;
    esac
}

# Install only what is actually missing, verified with `command -v` so it works
# on any distro. Note what is NOT here: this never touches /etc/resolv.conf.
# Rewriting the resolver to reach GitHub and restoring it from an EXIT trap
# leaves a node permanently pointed at someone else's DNS if the script is
# SIGKILLed or the box reboots mid-run — and there is nothing to fix, since the
# API is reached over whatever resolver the node already has.
ensure_deps() {
    local -a want=(curl jq wg wg-quick ip ping) missing=()
    local c
    for c in "${want[@]}"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
    command -v openssl >/dev/null 2>&1 || command -v wg >/dev/null 2>&1 || missing+=(openssl)
    [[ ${#missing[@]} -eq 0 ]] && return 0

    local pm
    pm=$(detect_pm) || die "Missing: ${missing[*]}. No supported package manager found."
    if [[ $EUID -ne 0 ]]; then
        die "Missing: ${missing[*]}. Install them first, e.g.: sudo ${pm} install -y ${missing[*]}"
    fi

    local -a pkgs=()
    for c in "${missing[@]}"; do pkgs+=("$(pkg_for "$c" "$pm")"); done
    # De-duplicate: wg and wg-quick come from one package on most distros.
    mapfile -t pkgs < <(printf '%s\n' "${pkgs[@]}" | sort -u)

    step "Installing dependencies (${pkgs[*]})"
    pm_install "$pm" "${pkgs[@]}" || die "Failed to install: ${pkgs[*]} (via ${pm})"
    for c in "${missing[@]}"; do
        command -v "$c" >/dev/null 2>&1 || die "'${c}' still missing after install"
    done
    ok "dependencies ready"
}

# --- Primitives ---------------------------------------------------------------
b64d() { openssl base64 -d -A; }

rfc3339_now() {
    local t
    t=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ 2>/dev/null || true)
    if [[ "$t" == *N* || -z "$t" ]]; then date -u +%Y-%m-%dT%H:%M:%SZ; else printf '%s' "$t"; fi
}

# "<private> <public>", raw-32-byte base64 as WireGuard wants. Prefers
# wireguard-tools; otherwise derives the pair from OpenSSL, where an X25519 key
# in DER is a fixed structure whose last 32 bytes are the raw key (48 B private,
# 44 B public). OpenSSL clamps the scalar itself per RFC 7748, so the result
# matches what `wg genkey` would have produced.
keypair() {
    local priv pub tmp
    if command -v wg >/dev/null 2>&1; then
        priv=$(wg genkey); pub=$(printf '%s' "$priv" | wg pubkey)
        printf '%s %s' "$priv" "$pub"; return 0
    fi
    tmp=$(mktemp) || die "mktemp failed"
    if ! openssl genpkey -algorithm X25519 -out "$tmp" 2>/dev/null; then
        rm -f "$tmp"; die "This OpenSSL cannot generate X25519 keys. Install wireguard-tools."
    fi
    priv=$(openssl pkey -in "$tmp" -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A)
    pub=$(openssl pkey -in "$tmp" -pubout -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A)
    rm -f "$tmp"
    [[ ${#priv} -eq 44 && ${#pub} -eq 44 ]] || die "X25519 key derivation produced an unexpected length"
    printf '%s %s' "$priv" "$pub"
}

random_endpoint() {
    local s p h
    s=${CF_ENDPOINT_SUBNETS[RANDOM % ${#CF_ENDPOINT_SUBNETS[@]}]}
    p=${CF_ENDPOINT_PORTS[RANDOM % ${#CF_ENDPOINT_PORTS[@]}]}
    h=$(( RANDOM % 254 + 1 ))
    printf '%s.%s:%s' "$s" "$h" "$p"
}

CF_API_SOFT=0
cf_api() {
    local method="$1" path="$2" token="${3:-}" body="${4:-}"
    local -a args=(
        -sS -m "$HTTP_TIMEOUT" --tlsv1.2 --tls-max 1.2 --http1.1
        -H "User-Agent: ${CF_UA}" -H "CF-Client-Version: ${CF_CLIENT_VERSION}"
        -H "Accept: application/json" -X "$method" -w $'\n%{http_code}'
    )
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer ${token}")
    [[ -n "$body" ]]  && args+=(-H "Content-Type: application/json" --data-binary "$body")

    local raw code payload
    if ! raw=$(curl "${args[@]}" "${CF_API}/${CF_API_VERSION}${path}"); then
        (( CF_API_SOFT )) && return 1
        die "Cannot reach ${CF_API} (network blocked, or curl lacks TLS 1.2 pinning support)."
    fi
    code=${raw##*$'\n'}; payload=${raw%$'\n'*}
    if [[ "$code" != 2* ]] && (( CF_API_SOFT )); then return 1; fi
    case "$code" in
        2*)  printf '%s' "$payload" ;;
        403) die "Cloudflare refused the request (HTTP 403) — usually a datacenter-IP block or a rate limit. Register from another machine and copy ${ACCOUNT_FILE} over; the key is not tied to an address." ;;
        429) die "Rate limited by Cloudflare (HTTP 429). Wait a few minutes." ;;
        *)   die "Cloudflare API returned HTTP ${code}: ${payload:0:400}" ;;
    esac
}

# --- Account ------------------------------------------------------------------
# The account file keeps what the API returned plus our private key, so a later
# `license` or `rotate` needs no re-registration.
#
# Note what is deliberately absent: `reserved`. WARP's client_id rides in the
# reserved bytes of the WireGuard header, and only a userspace implementation
# can set them. Kernel WireGuard cannot, so host mode does not use it and does
# not need it — the tunnel authenticates on the key pair alone.
build_account() {
    local resp="$1" priv="$2" pub="$3" token="$4" device_id="$5"
    jq -n \
        --arg device_id "$device_id" --arg access_token "$token" \
        --arg private_key "$priv" --arg public_key "$pub" --argjson resp "$resp" \
        '{
            schema: 2,
            device_id: $device_id, access_token: $access_token,
            private_key: $private_key, public_key: $public_key,
            license_key: ($resp.account.license // ""),
            account_type: ($resp.account.account_type // "free"),
            warp_plus: ($resp.account.warp_plus // false),
            address_v4: $resp.config.interface.addresses.v4,
            address_v6: $resp.config.interface.addresses.v6,
            peer_public_key: $resp.config.peers[0].public_key,
            endpoint_host: $resp.config.peers[0].endpoint.host,
            updated: (now | todate)
        }'
}

write_account() {
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    ( umask 077; printf '%s\n' "$1" > "$ACCOUNT_FILE" )
    chmod 600 "$ACCOUNT_FILE"
}

load_account() {
    [[ -f "$ACCOUNT_FILE" ]] || die "No account at ${ACCOUNT_FILE} — run 'warp-vps install' first."
    jq -e . "$ACCOUNT_FILE" >/dev/null 2>&1 || die "Account file is not valid JSON: ${ACCOUNT_FILE}"
    cat "$ACCOUNT_FILE"
}

register_device() {
    local kp priv pub body resp device_id token
    kp=$(keypair); priv=${kp%% *}; pub=${kp##* }
    body=$(jq -n --arg key "$pub" --arg tos "$(rfc3339_now)" \
        '{fcm_token:"", install_id:"", key:$key, locale:"en_US", model:"PC", tos:$tos, type:"Android"}')
    resp=$(cf_api POST "/reg" "" "$body")
    device_id=$(jq -r '.id' <<< "$resp"); token=$(jq -r '.token' <<< "$resp")
    [[ -n "$device_id" && "$device_id" != "null" ]] || die "Registration returned no device id"
    build_account "$resp" "$priv" "$pub" "$token" "$device_id"
}

# --- WireGuard config ---------------------------------------------------------
# `Table = off` is the whole design. wg-quick's add_route() returns immediately
# on it, so not one route is installed and the host's routing stays exactly as
# it was. Only sockets bound to the interface reach the tunnel.
#
# IPv4 only: the v6 address is dropped along with ::/0. Many providers blackhole
# IPv6, and a peer advertising a v6 path that does not work stalls every
# AAAA-first dial made through the interface.
write_wg_conf() {
    local a="$1" endpoint="$2"
    mkdir -p /etc/wireguard
    ( umask 077; cat > "$WG_CONF" <<EOF
# Generated by warp-vps ${VERSION} — regenerated by 'warp-vps install'.
[Interface]
PrivateKey = $(jq -r .private_key <<< "$a")
Address = $(jq -r .address_v4 <<< "$a")/32
MTU = ${WARP_MTU}
Table = off

[Peer]
PublicKey = $(jq -r .peer_public_key <<< "$a")
AllowedIPs = 0.0.0.0/0
Endpoint = ${endpoint}
PersistentKeepalive = ${KEEPALIVE}
EOF
    )
    chmod 600 "$WG_CONF"
}

current_endpoint() { grep -m1 '^Endpoint' "$WG_CONF" 2>/dev/null | awk '{print $3}'; }

handshake_age() {
    local ts
    ts=$(wg show "$IFACE" latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
    ts=${ts:-0}
    [[ "$ts" -eq 0 ]] && { printf ''; return 1; }
    printf '%s' "$(( $(date +%s) - ts ))"
}

# The only claim that counts. A tunnel can be up, handshaking and pinging while
# not actually being WARP — check what Cloudflare says, through the interface.
warp_state() {
    curl -s --interface "$IFACE" -m 10 "$TRACE_URL" 2>/dev/null | sed -n 's/^warp=//p'
}

wait_handshake() {
    local i
    for (( i = 0; i < ${1:-15}; i++ )); do
        handshake_age >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

# --- install ------------------------------------------------------------------
cmd_install() {
    local license="" interval=10 endpoint_mode="api" reuse=1 no_watchdog=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --license)      license="$2"; shift 2 ;;
            --interval)     interval="$2"; shift 2 ;;
            --endpoint)     endpoint_mode="$2"; shift 2 ;;
            --new-account)  reuse=0; shift ;;
            --no-watchdog)  no_watchdog=1; shift ;;
            *) die "install: unknown option '$1'" ;;
        esac
    done
    need_root
    [[ "$interval" =~ ^[1-9][0-9]*$ ]] || die "install: --interval must be minutes, a positive integer"
    [[ -d /run/systemd/system ]] || warn "systemd not detected — autostart and the watchdog will not work"

    ensure_deps

    local a
    if (( reuse )) && [[ -f "$ACCOUNT_FILE" ]]; then
        step "Reusing the existing WARP account"
        a=$(load_account)
        ok "device $(jq -r .device_id <<< "$a")"
    else
        step "Registering a WARP device"
        a=$(register_device)
        write_account "$a"
        ok "device $(jq -r .device_id <<< "$a") — account at ${ACCOUNT_FILE}"
    fi

    if [[ -n "$license" ]]; then
        license=$(printf '%s' "$license" | tr -cd 'a-zA-Z0-9-')
        step "Applying WARP+ license"
        local device_id token
        device_id=$(jq -r .device_id <<< "$a"); token=$(jq -r .access_token <<< "$a")
        if CF_API_SOFT=1 cf_api PUT "/reg/${device_id}/account" "$token" \
                "$(jq -n --arg l "$license" '{license:$l}')" >/dev/null 2>&1; then
            a=$(build_account "$(cf_api GET "/reg/${device_id}" "$token")" \
                "$(jq -r .private_key <<< "$a")" "$(jq -r .public_key <<< "$a")" "$token" "$device_id")
            write_account "$a"
            ok "WARP+ applied"
        else
            warn "License rejected — continuing on the free tier"
        fi
    fi

    local endpoint
    case "$endpoint_mode" in
        api)    endpoint=$(jq -r .endpoint_host <<< "$a") ;;
        random) endpoint=$(random_endpoint) ;;
        *:*)    endpoint="$endpoint_mode" ;;
        *)      die "install: --endpoint takes 'api', 'random' or 'host:port'" ;;
    esac

    step "Writing ${WG_CONF}"
    write_wg_conf "$a" "$endpoint"
    ok "Table = off — no routes are installed, host routing untouched"

    step "Bringing up ${IFACE}"
    systemctl enable "wg-quick@${IFACE}" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${IFACE}" >/dev/null 2>&1 \
        || die "wg-quick@${IFACE} failed to start. See: journalctl -u wg-quick@${IFACE} -n 40"
    if wait_handshake 15; then
        ok "handshake after $(handshake_age)s"
    else
        warn "no handshake yet — the endpoint may be blocked, try 'warp-vps rotate'"
    fi

    (( no_watchdog )) || install_watchdog "$interval"

    step "Verifying"
    local st; st=$(warp_state)
    case "$st" in
        on)   ok "Cloudflare reports warp=on (free tier)" ;;
        plus) ok "Cloudflare reports warp=plus (WARP+)" ;;
        *)    warn "Cloudflare does not report WARP (warp=${st:-no answer}) — run 'warp-vps verify' for detail" ;;
    esac

    printf '\n  %sXray outbound:%s warp-vps outbound --rules ai --full\n' "$C_BLD" "$C_RST" >&2
    printf '  %sStatus:%s        warp-vps status\n\n' "$C_BLD" "$C_RST" >&2
}

# --- watchdog -----------------------------------------------------------------
# A systemd timer rather than cron: it survives a missed tick (Persistent), logs
# to the journal instead of a hand-rolled rotating file, and carries its own
# ordering against wg-quick.
#
# Two behaviours upstream watchdogs lack, and both matter under a block:
#   * exponential backoff — a fixed retry restarts WireGuard hundreds of times a
#     day when Cloudflare is unreachable wholesale, which is itself a signature;
#   * endpoint rotation — when one anycast address is filtered, restarting the
#     same endpoint cannot help, whereas moving to another one can.
install_watchdog() {
    local interval="$1"
    step "Installing watchdog (every ${interval} min)"
    mkdir -p "$APP_DIR"; chmod 755 "$APP_DIR"
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"

    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' '# Generated by warp-vps — edits are lost on reinstall.'
        printf 'IFACE=%q\n'       "$IFACE"
        printf 'WG_CONF=%q\n'     "$WG_CONF"
        printf 'STATE_FILE=%q\n'  "$WATCHDOG_STATE"
        printf 'TRACE_URL=%q\n'   "$TRACE_URL"
    } > "${APP_DIR}/watchdog.sh"

    cat >> "${APP_DIR}/watchdog.sh" <<'WD'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Silent when the operator stopped the tunnel deliberately.
systemctl is-active --quiet "wg-quick@${IFACE}" || exit 0
[[ -f "$WG_CONF" ]] || { echo "warp-vps: ${WG_CONF} missing"; exit 1; }

# Default to 0 before the arithmetic: `wg show` prints nothing when the
# interface exists with no peer session yet, and $(( now -  )) is a syntax
# error rather than a zero — which is exactly the state to repair.
hs=$(wg show "$IFACE" latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
hs=${hs:-0}
now=$(date +%s)
age=$(( now - hs ))

healthy=1
[[ "$hs" -eq 0 || $age -gt 180 ]] && healthy=0

# Ping alone would pass on a tunnel that is up but no longer WARP, so ask
# Cloudflare through the interface. Fall back to ping if the trace is
# unreachable for reasons of its own.
if [[ $healthy -eq 1 ]]; then
    state=$(curl -s --interface "$IFACE" -m 8 "$TRACE_URL" 2>/dev/null | sed -n 's/^warp=//p')
    case "$state" in
        on|plus) : ;;
        "")      ping -I "$IFACE" -c 1 -W 3 1.1.1.1 >/dev/null 2>&1 || healthy=0 ;;
        *)       healthy=0 ;;
    esac
fi

fails=0; last=0
[[ -f "$STATE_FILE" ]] && read -r fails last < "$STATE_FILE" 2>/dev/null
fails=${fails:-0}; last=${last:-0}

if [[ $healthy -eq 1 ]]; then
    [[ $fails -ne 0 ]] && printf '0 %s\n' "$last" > "$STATE_FILE"
    exit 0
fi

exp=$(( fails > 4 ? 4 : fails ))
backoff=$(( 180 * (2 ** exp) ))
[[ $backoff -gt 1800 ]] && backoff=1800
if [[ $(( now - last )) -lt $backoff ]]; then
    echo "warp-vps: still down (fail #${fails}), next rotation in $(( backoff - (now - last) ))s"
    exit 0
fi

SUBNETS=(162.159.192 162.159.193 188.114.96 188.114.97)
PORTS=(2408 500 1701 4500)
ep="${SUBNETS[RANDOM % ${#SUBNETS[@]}]}.$(( RANDOM % 254 + 1 )):${PORTS[RANDOM % ${#PORTS[@]}]}"
sed -i "s|^Endpoint = .*|Endpoint = ${ep}|" "$WG_CONF"
systemctl restart "wg-quick@${IFACE}"
printf '%s %s\n' "$(( fails + 1 ))" "$now" > "$STATE_FILE"
echo "warp-vps: unhealthy (handshake ${age}s). Rotated endpoint to ${ep}"
WD
    chmod 700 "${APP_DIR}/watchdog.sh"

    cat > /etc/systemd/system/warp-vps-watchdog.service <<EOF
[Unit]
Description=warp-vps tunnel watchdog
After=wg-quick@${IFACE}.service

[Service]
Type=oneshot
ExecStart=${APP_DIR}/watchdog.sh
EOF

    cat > /etc/systemd/system/warp-vps-watchdog.timer <<EOF
[Unit]
Description=Run the warp-vps watchdog every ${interval} minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${interval}min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    chmod 644 /etc/systemd/system/warp-vps-watchdog.{service,timer}
    systemctl daemon-reload
    systemctl enable --now warp-vps-watchdog.timer >/dev/null 2>&1 || true
    ok "watchdog active (backoff 3→30 min, rotates the endpoint)"
}

# --- status -------------------------------------------------------------------
fmt_bytes() {
    local b=${1:-0}
    if   [[ -z "$b" || "$b" == 0 ]];  then echo "0 B"
    elif [[ $b -lt 1048576 ]];        then echo "$(( b / 1024 )) KB"
    elif [[ $b -lt 1073741824 ]];     then echo "$(( b / 1048576 )) MB"
    else echo "$(awk "BEGIN {printf \"%.1f\", $b/1073741824}") GB"; fi
}

cmd_status() {
    need_root
    local up="no" age ep rx tx st ip4
    systemctl is-active --quiet "wg-quick@${IFACE}" && up="yes"
    ep=$(current_endpoint)
    ip4=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}')
    read -r _ rx tx < <(wg show "$IFACE" transfer 2>/dev/null | head -1) || true
    age=$(handshake_age 2>/dev/null || true)

    printf '\n  %s⚡ warp-vps%s %sv%s%s\n' "$C_BLD" "$C_RST" "$C_GRY" "$VERSION" "$C_RST" >&2
    printf '  %s───────────────────────────────────%s\n\n' "$C_GRY" "$C_RST" >&2
    if [[ "$up" == yes ]]; then
        printf '   %sInterface:%s   %s● up%s\n' "$C_GRY" "$C_RST" "$C_GRN" "$C_RST" >&2
    else
        printf '   %sInterface:%s   %s○ down%s\n' "$C_GRY" "$C_RST" "$C_RED" "$C_RST" >&2
    fi
    printf '   %sAddress:%s     %s%s%s\n'   "$C_GRY" "$C_RST" "$C_CYN" "${ip4:-–}" "$C_RST" >&2
    printf '   %sEndpoint:%s    %s%s%s\n'   "$C_GRY" "$C_RST" "$C_CYN" "${ep:-–}" "$C_RST" >&2
    if [[ -n "$age" ]]; then
        printf '   %sHandshake:%s   %s%ss ago%s\n' "$C_GRY" "$C_RST" "$C_GRN" "$age" "$C_RST" >&2
    else
        printf '   %sHandshake:%s   %snone%s\n' "$C_GRY" "$C_RST" "$C_RED" "$C_RST" >&2
    fi
    printf '   %sRouting:%s     %sTable = off — no routes, bind-only%s\n' \
        "$C_GRY" "$C_RST" "$C_GRY" "$C_RST" >&2
    printf '   %sTraffic:%s     %s↓ %s  ↑ %s%s\n' "$C_GRY" "$C_RST" "$C_YLW" \
        "$(fmt_bytes "${rx:-0}")" "$(fmt_bytes "${tx:-0}")" "$C_RST" >&2

    if [[ "$up" == yes ]]; then
        st=$(warp_state)
        case "$st" in
            on)   printf '   %sCloudflare:%s  %s● warp=on%s\n' "$C_GRY" "$C_RST" "$C_GRN" "$C_RST" >&2 ;;
            plus) printf '   %sCloudflare:%s  %s● warp=plus%s\n' "$C_GRY" "$C_RST" "$C_GRN" "$C_RST" >&2 ;;
            *)    printf '   %sCloudflare:%s  %s○ %s%s\n' "$C_GRY" "$C_RST" "$C_RED" "${st:-no answer}" "$C_RST" >&2 ;;
        esac
    fi
    printf '\n  %sCommands:%s status | verify | rotate | outbound | license | update | uninstall\n\n' \
        "$C_GRY" "$C_RST" >&2
}

# --- verify -------------------------------------------------------------------
cmd_verify() {
    local probe=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --probe) probe=$(expand_probe "$2"); shift 2 ;;
            *) die "verify: unknown option '$1'" ;;
        esac
    done
    need_root
    systemctl is-active --quiet "wg-quick@${IFACE}" \
        || die "wg-quick@${IFACE} is not running. Start it, or run 'warp-vps install'."

    step "Baseline (not through the tunnel)"
    local direct; direct=$(curl -s -m 12 "$TRACE_URL" 2>/dev/null | sed -n 's/^ip=//p')
    ok "egress IP: ${direct:-unknown}"

    step "Through ${IFACE}"
    local trace st tip loc
    trace=$(curl -s --interface "$IFACE" -m 15 "$TRACE_URL" 2>/dev/null) \
        || die "No answer through ${IFACE}. Try 'warp-vps rotate'."
    st=$(sed -n 's/^warp=//p' <<< "$trace")
    tip=$(sed -n 's/^ip=//p' <<< "$trace")
    loc=$(sed -n 's/^loc=//p' <<< "$trace")
    printf '\n   %sWARP:%s       %s\n' "$C_GRY" "$C_RST" \
        "$(case "$st" in
             on)   printf '%s● on (free tier)%s' "$C_GRN" "$C_RST" ;;
             plus) printf '%s● on (WARP+)%s' "$C_GRN" "$C_RST" ;;
             *)    printf '%s○ %s%s' "$C_RED" "${st:-unknown}" "$C_RST" ;;
           esac)" >&2
    printf '   %sEgress IP:%s  %s%s%s  %s(direct: %s)%s\n' "$C_GRY" "$C_RST" \
        "$C_CYN" "${tip:-unknown}" "$C_RST" "$C_GRY" "${direct:-unknown}" "$C_RST" >&2
    printf '   %sLocation:%s   %s\n\n' "$C_GRY" "$C_RST" "${loc:-unknown}" >&2

    if [[ -n "$probe" ]]; then
        step "Destinations through the tunnel"
        local url code body seen
        for url in $(printf '%s' "$probe" | sed 's/,/ /g'); do
            [[ "$url" == http*://* ]] || url="https://${url}"
            body=""; seen=""
            if [[ "$url" == */cdn-cgi/trace ]]; then
                body=$(curl -s --interface "$IFACE" -m 20 -w $'\n%{http_code}' "$url" 2>/dev/null) || true
                code=${body##*$'\n'}
                # grep -E, not sed: BSD sed has no \| alternation in BREs.
                seen=$(printf '%s' "${body%$'\n'*}" | grep -E '^(ip|loc|warp)=' | tr '\n' ' ')
            else
                # curl already prints 000 through -w on failure; a `|| echo 000`
                # fallback would concatenate into "000000" and match no case arm.
                code=$(curl -s --interface "$IFACE" -o /dev/null -m 20 -w '%{http_code}' "$url" 2>/dev/null) || true
            fi
            code=${code:-000}
            case "$code" in
                2*|3*)   printf '   %s%-40s%s %s%s%s %s%s%s\n' "$C_GRY" "$url" "$C_RST" "$C_GRN" "$code" "$C_RST" "$C_GRY" "$seen" "$C_RST" >&2 ;;
                401)     printf '   %s%-40s%s %s401 (reached; needs an API key)%s\n' "$C_GRY" "$url" "$C_RST" "$C_GRN" "$C_RST" >&2 ;;
                403|451) printf '   %s%-40s%s %s%s (refused)%s\n' "$C_GRY" "$url" "$C_RST" "$C_RED" "$code" "$C_RST" >&2 ;;
                000)     printf '   %s%-40s%s %sno answer%s\n' "$C_GRY" "$url" "$C_RST" "$C_RED" "$C_RST" >&2 ;;
                *)       printf '   %s%-40s%s %s%s%s\n' "$C_GRY" "$url" "$C_RST" "$C_YLW" "$code" "$C_RST" >&2 ;;
            esac
        done
        printf '\n' >&2
    fi

    case "$st" in
        on|plus) ok "Verified — the interface exits through Cloudflare WARP" ;;
        *) die "The interface answers but Cloudflare does not see it as WARP (warp=${st:-empty}). Do not point Xray at it yet." ;;
    esac
}

# --- rotate / license ---------------------------------------------------------
cmd_rotate() {
    local ep=""
    while [[ $# -gt 0 ]]; do
        case "$1" in --to) ep="$2"; shift 2 ;; *) die "rotate: unknown option '$1'" ;; esac
    done
    need_root
    [[ -f "$WG_CONF" ]] || die "No ${WG_CONF} — run 'warp-vps install' first."
    ep=${ep:-$(random_endpoint)}
    step "Rotating endpoint to ${ep}"
    sed -i "s|^Endpoint = .*|Endpoint = ${ep}|" "$WG_CONF" || die "cannot write ${WG_CONF}"
    systemctl restart "wg-quick@${IFACE}" || die "restart failed"
    # A manual rotation means the operator is intervening; clear the backoff so
    # the watchdog is not still sitting in a 30-minute cooldown afterwards.
    rm -f "$WATCHDOG_STATE"
    wait_handshake 10 && ok "handshake after $(handshake_age)s" || warn "no handshake yet"
    cmd_status
}

cmd_license() {
    local key=""
    while [[ $# -gt 0 ]]; do
        case "$1" in --key|-k) key="$2"; shift 2 ;; *) die "license: unknown option '$1'" ;; esac
    done
    need_root; ensure_deps
    [[ -n "$key" ]] || die "license: --key is required"
    key=$(printf '%s' "$key" | tr -cd 'a-zA-Z0-9-')
    local a device_id token
    a=$(load_account); device_id=$(jq -r .device_id <<< "$a"); token=$(jq -r .access_token <<< "$a")
    step "Applying WARP+ license"
    cf_api PUT "/reg/${device_id}/account" "$token" "$(jq -n --arg l "$key" '{license:$l}')" >/dev/null
    a=$(build_account "$(cf_api GET "/reg/${device_id}" "$token")" \
        "$(jq -r .private_key <<< "$a")" "$(jq -r .public_key <<< "$a")" "$token" "$device_id")
    write_account "$a"
    ok "applied — plan now: $(jq -r .account_type <<< "$a")"
    warn "Restart the tunnel for it to take effect: systemctl restart wg-quick@${IFACE}"
}

# --- outbound / merge ---------------------------------------------------------
# The Xray side of host mode is a plain freedom outbound bound to the interface.
# `sockopt.interface` sets SO_BINDTODEVICE, which is why no routes are needed —
# see the kernel note at the top of this file.
#
# The node's Xray must share the host's network namespace to see the interface
# at all (network_mode: host in the node's compose file), and binding a socket
# to a device needs CAP_NET_ADMIN. A Remnawave node has both by default.
cmd_outbound() {
    local tag="warp" rules="" all_traffic=0 full=0 out="" strategy="UseIP"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tag|-t)          tag="$2"; shift 2 ;;
            --rules)           rules=$(expand_rules "$2"); shift 2 ;;
            --all-traffic)     all_traffic=1; shift ;;
            --domain-strategy) strategy="$2"; shift 2 ;;
            --full)            full=1; shift ;;
            --out|-o)          out="$2"; shift 2 ;;
            *) die "outbound: unknown option '$1'" ;;
        esac
    done
    command -v jq >/dev/null 2>&1 || die "'jq' is required"
    [[ -n "$rules" && $all_traffic -eq 1 ]] && die "outbound: --rules and --all-traffic are mutually exclusive"

    local ob
    ob=$(jq -n --arg tag "$tag" --arg iface "$IFACE" --arg ds "$strategy" \
        '{tag:$tag, protocol:"freedom",
          settings:{domainStrategy:$ds},
          streamSettings:{sockopt:{interface:$iface, tcpFastOpen:true}}}')

    local result="$ob"
    if (( full )) || [[ -n "$rules" ]] || (( all_traffic )); then
        local rule='null'
        if (( all_traffic )); then
            rule=$(jq -n --arg t "$tag" '{type:"field", network:"tcp,udp", outboundTag:$t}')
        elif [[ -n "$rules" ]]; then
            rule=$(jq -n --arg t "$tag" --arg csv "$rules" \
                '{type:"field", domain:($csv|split(",")|map(gsub("^\\s+|\\s+$";""))|map(select(length>0))), outboundTag:$t}')
        fi
        result=$(jq -n --argjson ob "$ob" --argjson rule "$rule" \
            '{outbounds:[$ob]} + (if $rule == null then {} else {routing:{rules:[$rule]}} end)')
    fi

    if [[ -n "$out" ]]; then printf '%s\n' "$result" > "$out"; ok "wrote ${out}"
    else printf '%s\n' "$result"; fi

    if (( full )); then
        printf '\n  %sNote:%s a fragment to paste, not a whole Xray config.\n' "$C_BLD" "$C_RST" >&2
        printf '  %sWhole config:%s warp-vps merge -c <exported-panel-config.json> %s\n\n' \
            "$C_GRY" "$C_RST" "$([[ $all_traffic -eq 1 ]] && echo '--all-traffic' || echo '--rules ai')" >&2
    fi
}

# Splices the outbound and rule into an existing config. Two Xray properties
# make hand-editing risky and both are guarded:
#   1. Unmatched traffic goes to the FIRST outbound (app/proxyman sets
#      defaultHandler on the first AddHandler), so prepending would route
#      everything through WARP. We only ever append.
#   2. Routing takes the FIRST matching rule, not the most specific, so the rule
#      is inserted above any catch-all rather than after it.
cmd_merge() {
    local cfg="" rules="" tag="warp" all_traffic=0 backup=1 replace=0 dry=0 force_path=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config|-c)   cfg="$2"; shift 2 ;;
            --rules)       rules=$(expand_rules "$2"); shift 2 ;;
            --all-traffic) all_traffic=1; shift ;;
            --tag|-t)      tag="$2"; shift 2 ;;
            --no-backup)   backup=0; shift ;;
            --replace)     replace=1; shift ;;
            --dry-run)     dry=1; shift ;;
            --force-path)  force_path=1; shift ;;
            *) die "merge: unknown option '$1'" ;;
        esac
    done
    command -v jq >/dev/null 2>&1 || die "'jq' is required"
    [[ -n "$cfg" ]] || die "merge: --config is required"
    [[ -f "$cfg" ]] || die "merge: config not found: ${cfg}"
    [[ -n "$rules" || $all_traffic -eq 1 ]] || die "merge: pass --rules \"a,b\" or --all-traffic"
    [[ -n "$rules" && $all_traffic -eq 1 ]] && die "merge: --rules and --all-traffic are mutually exclusive"
    jq -e . "$cfg" >/dev/null 2>&1 || die "merge: ${cfg} is not valid JSON"

    # On a Remnawave node the config is panel-managed: an edit on the node
    # survives only to the next sync, then reverts with no error anywhere.
    case "$(cd "$(dirname "$cfg")" && pwd)/$(basename "$cfg")" in
        */remnanode/*|*/remnawave/*|*/opt/remnanode*|*/var/lib/remnanode*)
            (( force_path )) || die "merge: ${cfg} looks panel-managed. Edits there are overwritten on the next sync — export the config from the panel, merge into that copy, paste it back. --force-path overrides."
            warn "path looks panel-managed, proceeding because --force-path was given" ;;
    esac

    local n_out; n_out=$(jq '.outbounds // [] | length' "$cfg")
    (( n_out > 0 )) || die "merge: ${cfg} has no outbounds. Ours would become the default route for everything."
    if jq -e --arg t "$tag" '[.outbounds[]?.tag] | index($t)' "$cfg" >/dev/null 2>&1; then
        (( replace )) || die "merge: an outbound tagged '${tag}' already exists. Use --replace, or --tag."
    fi

    local ob merged
    ob=$(cmd_outbound --tag "$tag")
    merged=$(jq --argjson ob "$ob" --arg tag "$tag" --arg csv "$rules" --argjson all "$all_traffic" '
        def is_catchall:
            (has("domain") or has("ip") or has("inboundTag") or has("user")
             or has("source") or has("sourcePort") or has("port")
             or has("protocol") or has("attrs")) | not;
        ($csv | split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length>0))) as $domains
        | .outbounds = ([ .outbounds[] | select(.tag != $tag) ] + [$ob])
        | .routing = (.routing // {})
        | .routing.rules = (.routing.rules // [])
        | (if $all == 1 then {type:"field", network:"tcp,udp", outboundTag:$tag}
           else {type:"field", domain:$domains, outboundTag:$tag} end) as $rule
        | .routing.rules = ([ .routing.rules[] | select(.outboundTag != $tag) ])
        | ([ .routing.rules | to_entries[] | select(.value | is_catchall) | .key ] | first) as $cut
        | .routing.rules = (if $cut == null then .routing.rules + [$rule]
                            else .routing.rules[0:$cut] + [$rule] + .routing.rules[$cut:] end)
    ' "$cfg") || die "merge: jq failed to splice the config"

    (( dry )) && { printf '%s\n' "$merged"; return 0; }

    if (( backup )); then
        local bak; bak="${cfg}.$(date -u +%Y%m%dT%H%M%SZ).bak"
        cp -p "$cfg" "$bak" || die "merge: cannot write backup ${bak}"
        ok "backup: ${bak}"
    fi
    local tmp; tmp=$(mktemp "${cfg}.XXXXXX") || die "mktemp failed"
    printf '%s\n' "$merged" > "$tmp"
    jq -e . "$tmp" >/dev/null || { rm -f "$tmp"; die "merge: produced invalid JSON, ${cfg} untouched"; }

    # Valid JSON is not a valid Xray config; let Xray parse it when available.
    local xb; xb=$(command -v xray 2>/dev/null || true)
    [[ -z "$xb" && -x /usr/local/bin/xray ]] && xb=/usr/local/bin/xray
    if [[ -n "$xb" ]]; then
        "$xb" run -test -c "$tmp" >/dev/null 2>&1 \
            && ok "validated with $("$xb" version 2>/dev/null | head -1)" \
            || { rm -f "$tmp"; die "merge: xray rejected the merged config, ${cfg} untouched"; }
    else
        warn "no xray binary — checked for JSON validity only"
    fi

    local mode; mode=$(stat -c '%a' "$cfg" 2>/dev/null || stat -f '%Lp' "$cfg" 2>/dev/null || echo 600)
    chmod "$mode" "$tmp"; mv "$tmp" "$cfg"
    ok "outbound '${tag}' appended; rule at index $(jq --arg t "$tag" '[.routing.rules[].outboundTag]|index($t)' <<< "$merged") of $(jq '.routing.rules|length' <<< "$merged")"
    printf '\n  %sRollback:%s restore the .bak and reload Xray\n\n' "$C_BLD" "$C_RST" >&2
}

# --- uninstall / update -------------------------------------------------------
cmd_uninstall() {
    local yes=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --yes|-y) yes=1; shift ;; *) die "uninstall: unknown option '$1'" ;; esac
    done
    need_root
    if (( ! yes )); then
        warn "This removes the ${IFACE} interface, the watchdog and ${STATE_DIR}."
        local reply; read -r -p "  Type 'yes' to confirm: " reply </dev/tty || reply=""
        [[ "$reply" == "yes" ]] || die "Aborted."
    fi
    systemctl disable --now "wg-quick@${IFACE}" >/dev/null 2>&1 || true
    systemctl disable --now warp-vps-watchdog.timer warp-vps-watchdog.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/warp-vps-watchdog.service /etc/systemd/system/warp-vps-watchdog.timer
    systemctl daemon-reload >/dev/null 2>&1 || true
    # Belt and braces: if the unit ever died without wg-quick down running.
    ip link del "$IFACE" 2>/dev/null || true
    rm -f "$WG_CONF"
    rm -rf "$APP_DIR" "$STATE_DIR"
    ok "removed. The wireguard package was left installed."
    warn "The WARP device stays registered at Cloudflare — its API has no self-delete."
}

cmd_update() {
    need_root
    local tmp remote
    step "Checking for updates"
    tmp=$(mktemp) || die "mktemp failed"
    curl -fsSL -m 30 "$RAW_URL" -o "$tmp" || { rm -f "$tmp"; die "download failed"; }
    remote=$(grep -m1 -E '^VERSION="' "$tmp" | cut -d'"' -f2)
    [[ -n "$remote" ]] || { rm -f "$tmp"; die "cannot read the remote version"; }
    if [[ "$remote" == "$VERSION" ]]; then
        rm -f "$tmp"; ok "already up to date (v${VERSION})"; return 0
    fi
    install -m 0755 "$tmp" /usr/local/bin/warp-vps || { rm -f "$tmp"; die "install failed"; }
    rm -f "$tmp"
    ok "updated v${VERSION} → v${remote}"
}

# --- entry point --------------------------------------------------------------
usage() {
    cat >&2 <<'USAGE_EOF'
warp-vps — Cloudflare WARP as a host WireGuard interface, for Xray nodes

  The tunnel is a kernel `warp` interface brought up with Table = off, so no
  routes are installed and host routing is untouched. Only sockets bound to the
  interface use it — for Xray that is sockopt.interface.

USAGE
    warp-vps <command> [options]

COMMANDS
    install     Register a WARP device, write the interface, start it, arm the watchdog
    status      Interface, handshake, endpoint, traffic and what Cloudflare reports
    verify      Prove the interface really exits through WARP, optionally probing sites
    rotate      Move to another Cloudflare endpoint and restart
    outbound    Emit the Xray outbound (freedom + sockopt.interface) and routing rule
    merge       Splice that into an existing Xray config, with a backup
    license     Apply a WARP+ key to the saved account
    update      Fetch a newer warp-vps
    uninstall   Remove the interface, watchdog and state

INSTALL
        --license KEY     Apply a WARP+ key during install
        --interval N      Watchdog period in minutes (default: 10)
        --endpoint MODE   api (default) | random | host:port
        --new-account     Register a fresh device instead of reusing the saved one
        --no-watchdog     Skip the watchdog

VERIFY
        --probe SET       Fetch these URLs through the tunnel and report status.
                          "ai" expands to endpoints that answer curl honestly.
                          Do NOT probe a site's HTML root: Cloudflare rejects
                          curl on its TLS fingerprint, so 403 there says nothing

OUTBOUND / MERGE
    -t, --tag TAG         Outbound tag (default: warp)
        --rules SET       Domains through WARP; "ai" is the built-in set
        --all-traffic     Everything not already claimed by an earlier rule
        --full            outbound + rule together (a fragment, not a whole config)
    -c, --config FILE     merge only: config to edit in place (a .bak is written)
        --dry-run         merge only: print the result instead of writing
        --replace         merge only: overwrite an existing outbound with the tag
        --force-path      merge only: proceed on a path that looks panel-managed

EXAMPLES
    warp-vps install --interval 10
    warp-vps verify --probe ai
    warp-vps outbound --rules ai --full
    warp-vps merge -c panel-config.json --all-traffic

USAGE_EOF
}

main() {
    local cmd="${1:-help}"
    [[ $# -gt 0 ]] && shift
    case "$cmd" in
        install)              cmd_install "$@" ;;
        status|"")            cmd_status "$@" ;;
        verify|test)          cmd_verify "$@" ;;
        rotate)               cmd_rotate "$@" ;;
        outbound|gen)         cmd_outbound "$@" ;;
        merge)                cmd_merge "$@" ;;
        license)              cmd_license "$@" ;;
        update)               cmd_update "$@" ;;
        uninstall)            cmd_uninstall "$@" ;;
        log)                  journalctl -u warp-vps-watchdog.service -f ;;
        version|--version|-v) printf 'warp-vps %s\n' "$VERSION" ;;
        help|--help|-h)       usage ;;
        *) printf '\n  %sUnknown command: %s%s\n\n' "$C_RED" "$cmd" "$C_RST" >&2; usage; exit 1 ;;
    esac
}

main "$@"
