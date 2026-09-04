#!/usr/bin/env bash
#
# warp-vps — Cloudflare WARP as a native Xray outbound for Remnawave nodes.
#
# Unlike host-tunnel installers, this touches nothing on the node: no wg-quick,
# no ip rule, no sysctl, no fwmark, no root. It registers an anonymous WARP
# device straight against Cloudflare's own API and emits a ready-to-paste Xray
# `wireguard` outbound. The tunnel lives inside Xray's process.
#
# The wgcf binary is deliberately not used: it only ever writes device_id,
# access_token, private_key and license_key, so `reserved` (the client_id the
# WARP peer expects) cannot be recovered from its files at all. We call the same
# API it calls and keep the one field it drops.
#
# https://github.com/SkunkBG/warp-vps
# SPDX-License-Identifier: MIT

set -euo pipefail

VERSION="1.0.0"

# --- Cloudflare WARP API ------------------------------------------------------
# Mirrors the official Android client. Three things are load-bearing and the API
# answers 403 (error 1020) if any is wrong:
#   * TLS pinned to exactly 1.2 — not "at least 1.2". curl must be told both
#     --tlsv1.2 and --tls-max 1.2, matching the client's Min==Max TLS config.
#   * HTTP/1.1 — the client disables H2 upgrade.
#   * The UA / CF-Client-Version pair below.
CF_API="https://api.cloudflareclient.com"
CF_API_VERSION="v0a1922"
CF_UA="okhttp/3.12.1"
CF_CLIENT_VERSION="a-6.3-1922"
HTTP_TIMEOUT=30

# Anycast prefixes WARP peers are reachable on. Only consulted for
# `--endpoint random`; the default is whatever the API itself hands back, which
# is authoritative. Rotating the endpoint is a DPI countermeasure, not a
# latency optimisation — do not "improve" this into a ping-based picker.
CF_ENDPOINT_SUBNETS=(162.159.192 162.159.193 188.114.96 188.114.97)
CF_ENDPOINT_PORTS=(2408 500 1701 4500)

# Xray's own default is 1420, which is wrong for WARP: the WireGuard header on
# top of the provider's path reliably strands large packets. 1280 is the IPv6
# minimum MTU and survives every path we have measured.
DEFAULT_MTU=1280
DEFAULT_KEEPALIVE=15
DEFAULT_TAG="warp"

# Named domain sets usable as `--rules <name>`, so a curl-piped run needs no
# files from the repository. templates/rules-ai.json carries the same list with
# the reasoning; the workflow asserts the two never drift apart.
# Probe targets that answer a bare curl honestly. Deliberately NOT the sites'
# HTML roots: Cloudflare's bot protection rejects curl on its TLS fingerprint, so
# https://chatgpt.com returns 403 from a residential browser IP just as readily
# as from a hosting range — the code says nothing about the address. /cdn-cgi/trace
# is exempt and additionally reports what the destination sees, and OpenAI's API
# answers 401 (reached, unauthenticated) rather than 403 when it is not blocking.
PROBE_AI="https://chatgpt.com/cdn-cgi/trace,https://claude.ai/cdn-cgi/trace,https://api.openai.com/v1/models,https://gemini.google.com"

expand_probe() {
    case "$1" in
        ai) printf '%s' "$PROBE_AI" ;;
        *)  printf '%s' "$1" ;;
    esac
}

RULES_AI="geosite:openai,domain:openai.com,domain:chatgpt.com,domain:oaistatic.com,domain:oaiusercontent.com,domain:sora.com,domain:anthropic.com,domain:claude.ai,domain:claudeusercontent.com,domain:gemini.google.com,domain:aistudio.google.com,domain:generativelanguage.googleapis.com,domain:x.ai,domain:grok.com,domain:perplexity.ai,domain:deepseek.com,domain:mistral.ai,domain:meta.ai,domain:copilot.microsoft.com,domain:githubcopilot.com,domain:huggingface.co,domain:midjourney.com,domain:suno.com,domain:elevenlabs.io,domain:runwayml.com,domain:leonardo.ai,domain:character.ai,domain:poe.com,domain:cursor.com,domain:phind.com"

# Expand a preset name; anything else is passed through as a literal list.
expand_rules() {
    case "$1" in
        ai) printf '%s' "$RULES_AI" ;;
        *)  printf '%s' "$1" ;;
    esac
}

# --- Output -------------------------------------------------------------------
if [[ -t 2 ]]; then
    C_RST=$'\e[0m'; C_BLD=$'\e[1m'; C_CYN=$'\e[36m'; C_GRN=$'\e[32m'
    C_YLW=$'\e[33m'; C_RED=$'\e[31m'; C_GRY=$'\e[90m'
else
    C_RST=""; C_BLD=""; C_CYN=""; C_GRN=""; C_YLW=""; C_RED=""; C_GRY=""
fi

step() { printf '\n%s▶%s %s%s%s\n'   "$C_CYN" "$C_RST" "$C_BLD" "$1" "$C_RST" >&2; }
ok()   { printf '  %s✔%s %s%s%s\n'   "$C_GRN" "$C_RST" "$C_GRY" "$1" "$C_RST" >&2; }
warn() { printf '  %s⚠%s  %s%s%s\n'  "$C_YLW" "$C_RST" "$C_YLW" "$1" "$C_RST" >&2; }
die()  { printf '\n  %s✖ Error:%s %s\n\n' "$C_RED" "$C_RST" "$1" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed.${2:+ $2}"
}

# Echo the first supported package manager, or return 1.
detect_pm() {
    local pm
    for pm in apt-get dnf yum zypper pacman apk; do
        command -v "$pm" >/dev/null 2>&1 && { printf '%s' "$pm"; return 0; }
    done
    return 1
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

# curl and jq are hard requirements; key generation needs openssl or wg. A bare
# Debian node ships curl and openssl but almost never jq, which is exactly the
# case that would otherwise stop a one-command run halfway through.
ensure_deps() {
    local -a missing=()
    command -v curl    >/dev/null 2>&1 || missing+=(curl)
    command -v jq      >/dev/null 2>&1 || missing+=(jq)
    command -v openssl >/dev/null 2>&1 || command -v wg >/dev/null 2>&1 || missing+=(openssl)
    [[ ${#missing[@]} -eq 0 ]] && return 0

    local pm
    pm=$(detect_pm) || die "Missing: ${missing[*]}. No supported package manager found — install them by hand."

    if [[ $EUID -ne 0 ]]; then
        die "Missing: ${missing[*]}. Install them first, e.g.:  sudo ${pm} install -y ${missing[*]}"
    fi

    step "Installing missing dependencies (${missing[*]})"
    pm_install "$pm" "${missing[@]}" || die "Failed to install: ${missing[*]} (via ${pm})"
    local c
    for c in "${missing[@]}"; do
        command -v "$c" >/dev/null 2>&1 || die "'${c}' still missing after install"
    done
    ok "dependencies ready"
}

# --- Primitives ---------------------------------------------------------------

# base64 decode, portable across GNU coreutils, BSD/macOS and busybox.
b64d() { openssl base64 -d -A; }

# RFC3339Nano, the format the API's `tos` field expects. GNU date does
# nanoseconds; BSD date does not, and plain-second RFC3339 is accepted too.
rfc3339_now() {
    local t
    t=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ 2>/dev/null || true)
    if [[ "$t" == *N* || -z "$t" ]]; then
        date -u +%Y-%m-%dT%H:%M:%SZ
    else
        printf '%s' "$t"
    fi
}

# Emit "<private_key> <public_key>", both raw-32-byte base64 as WireGuard wants.
#
# Prefers wireguard-tools when present, else derives the pair from OpenSSL: an
# X25519 key in DER is a fixed-length structure whose last 32 bytes are the raw
# key, for both the private (48 B) and public (44 B) form. This is what removes
# the wgcf dependency, and with it downloading an unsigned binary and running it
# as root.
keypair() {
    local priv pub tmp
    if command -v wg >/dev/null 2>&1; then
        priv=$(wg genkey)
        pub=$(printf '%s' "$priv" | wg pubkey)
        printf '%s %s' "$priv" "$pub"
        return 0
    fi
    need_cmd openssl "Install openssl, or wireguard-tools for 'wg genkey'."
    tmp=$(mktemp) || die "mktemp failed"
    if ! openssl genpkey -algorithm X25519 -out "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        die "This OpenSSL build cannot generate X25519 keys. Install wireguard-tools."
    fi
    priv=$(openssl pkey -in "$tmp" -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A)
    pub=$(openssl pkey -in "$tmp" -pubout -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A)
    rm -f "$tmp"
    # 32 raw bytes always base64-encode to 44 characters; anything else means the
    # DER layout shifted and we would ship an unusable key pair.
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

# cf_api <METHOD> <PATH> [TOKEN] [JSON_BODY] -> response body on stdout.
#
# Fatal by default. Set CF_API_SOFT=1 for a call whose failure is a branch
# rather than an error (applying an optional license), since die() exits the
# shell outright and would never let an `if` fall through.
CF_API_SOFT=0
cf_api() {
    local method="$1" path="$2" token="${3:-}" body="${4:-}"
    local -a args=(
        -sS -m "$HTTP_TIMEOUT"
        --tlsv1.2 --tls-max 1.2 --http1.1
        -H "User-Agent: ${CF_UA}"
        -H "CF-Client-Version: ${CF_CLIENT_VERSION}"
        -H "Accept: application/json"
        -X "$method"
        -w $'\n%{http_code}'
    )
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer ${token}")
    [[ -n "$body" ]]  && args+=(-H "Content-Type: application/json" --data-binary "$body")

    local raw code payload
    if ! raw=$(curl "${args[@]}" "${CF_API}/${CF_API_VERSION}${path}"); then
        (( CF_API_SOFT )) && return 1
        die "Cannot reach ${CF_API} (network blocked, or curl lacks TLS 1.2 pinning support)."
    fi
    code=${raw##*$'\n'}
    payload=${raw%$'\n'*}

    if [[ "$code" != 2* ]] && (( CF_API_SOFT )); then
        return 1
    fi
    case "$code" in
        2*) printf '%s' "$payload" ;;
        403) die "Cloudflare refused the request (HTTP 403). Usually a datacenter-IP block or a rate limit — retry later or from another IP." ;;
        429) die "Rate limited by Cloudflare (HTTP 429). Wait a few minutes before retrying." ;;
        *)   die "Cloudflare API returned HTTP ${code}: ${payload:0:400}" ;;
    esac
}

# client_id is 4 base64 chars over 3 raw bytes; Xray wants those bytes as a
# 3-element array. Anything else means the API changed and we must not guess.
client_id_to_reserved() {
    local cid="$1" bytes
    bytes=$(printf '%s' "$cid" | b64d | od -An -tu1 | tr -s ' ' | sed 's/^ //;s/ $//')
    local -a arr
    read -r -a arr <<< "$bytes"
    [[ ${#arr[@]} -eq 3 ]] || die "client_id '${cid}' did not decode to 3 bytes (got ${#arr[@]})"
    printf '[%s, %s, %s]' "${arr[0]}" "${arr[1]}" "${arr[2]}"
}

# Turn a Register/GetSourceDevice response plus our local keys into the account
# file. Kept in one place so `register` and `refresh` cannot drift apart.
build_account() {
    local resp="$1" priv="$2" pub="$3" token="$4" device_id="$5"
    local cid reserved
    cid=$(jq -r '.config.client_id' <<< "$resp")
    [[ -n "$cid" && "$cid" != "null" ]] || die "API response carried no config.client_id"
    reserved=$(client_id_to_reserved "$cid")

    jq -n \
        --arg device_id "$device_id" \
        --arg access_token "$token" \
        --arg private_key "$priv" \
        --arg public_key "$pub" \
        --arg client_id "$cid" \
        --argjson reserved "$reserved" \
        --argjson resp "$resp" \
        '{
            schema:          1,
            device_id:       $device_id,
            access_token:    $access_token,
            private_key:     $private_key,
            public_key:      $public_key,
            client_id:       $client_id,
            reserved:        $reserved,
            license_key:     ($resp.account.license // ""),
            account_type:    ($resp.account.account_type // "free"),
            warp_plus:       ($resp.account.warp_plus // false),
            address_v4:      $resp.config.interface.addresses.v4,
            address_v6:      $resp.config.interface.addresses.v6,
            peer_public_key: $resp.config.peers[0].public_key,
            endpoint_host:   $resp.config.peers[0].endpoint.host,
            endpoint_v4:     ($resp.config.peers[0].endpoint.v4 // ""),
            endpoint_v6:     ($resp.config.peers[0].endpoint.v6 // ""),
            updated:         (now | todate)
        }'
}

write_account() {
    local file="$1" content="$2" dir
    dir=$(dirname "$file")
    mkdir -p "$dir"
    # Create with restrictive permissions before any content lands in it: the
    # file holds a WireGuard private key and a bearer token for the account.
    ( umask 077; printf '%s\n' "$content" > "$file" )
    chmod 600 "$file"
}

load_account() {
    local file="$1"
    [[ -f "$file" ]] || die "Account file not found: ${file} — run 'warp-vps register' first."
    jq -e . "$file" >/dev/null 2>&1 || die "Account file is not valid JSON: ${file}"
    cat "$file"
}

# --- register -----------------------------------------------------------------
cmd_register() {
    local out="warp-account.json" license="" model="PC" force=0 hint=1
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --out|-o)   out="$2"; shift 2 ;;
            --license)  license="$2"; shift 2 ;;
            --model)    model="$2"; shift 2 ;;
            --force|-f) force=1; shift ;;
            --no-hint)  hint=0; shift ;;
            *) die "register: unknown option '$1'" ;;
        esac
    done

    ensure_deps
    if [[ -f "$out" && $force -eq 0 ]]; then
        die "${out} already exists. Registering again would orphan the old WARP device — pass --force to overwrite, or --out to write elsewhere."
    fi

    step "Registering a new WARP device"
    local priv pub kp
    kp=$(keypair); priv=${kp%% *}; pub=${kp##* }
    ok "X25519 keypair generated ($(command -v wg >/dev/null 2>&1 && echo 'wg' || echo 'openssl'))"

    local body resp device_id token
    body=$(jq -n --arg key "$pub" --arg tos "$(rfc3339_now)" --arg model "$model" \
        '{fcm_token:"", install_id:"", key:$key, locale:"en_US", model:$model, tos:$tos, type:"Android"}')
    resp=$(cf_api POST "/reg" "" "$body")

    device_id=$(jq -r '.id' <<< "$resp")
    token=$(jq -r '.token' <<< "$resp")
    [[ -n "$device_id" && "$device_id" != "null" ]] || die "Registration succeeded but returned no device id"
    ok "Device registered: ${device_id}"

    if [[ -n "$license" ]]; then
        # Only letters, digits and dashes reach the API — the key is
        # interpolated into a request we sign with our bearer token.
        license=$(printf '%s' "$license" | tr -cd 'a-zA-Z0-9-')
        step "Applying WARP+ license"
        if CF_API_SOFT=1 cf_api PUT "/reg/${device_id}/account" "$token" \
                "$(jq -n --arg l "$license" '{license:$l}')" >/dev/null 2>&1; then
            # The device config (and with it the plan) is only refreshed on a
            # re-read; the PUT response describes the account, not the peer.
            resp=$(cf_api GET "/reg/${device_id}" "$token")
            ok "WARP+ applied"
        else
            warn "License rejected — continuing on the free tier"
        fi
    fi

    local account
    account=$(build_account "$resp" "$priv" "$pub" "$token" "$device_id")
    write_account "$out" "$account"

    ok "Account written to ${out} (mode 0600)"
    print_account_summary "$account"
    (( hint )) && printf '\n  %sNext:%s %swarp-vps generate --account %s%s\n\n' \
        "$C_BLD" "$C_RST" "$C_CYN" "$out" "$C_RST" >&2
    return 0
}

print_account_summary() {
    local a="$1"
    printf '\n' >&2
    printf '   %sPlan:%s      %s\n' "$C_GRY" "$C_RST" \
        "$(jq -r '.account_type + (if .warp_plus then "  (warp_plus flag set)" else "" end)' <<< "$a")" >&2
    printf '   %sAddress:%s   %s\n' "$C_GRY" "$C_RST" "$(jq -r .address_v4 <<< "$a")" >&2
    printf '   %sEndpoint:%s  %s\n' "$C_GRY" "$C_RST" "$(jq -r .endpoint_host <<< "$a")" >&2
    printf '   %sReserved:%s  %s\n' "$C_GRY" "$C_RST" "$(jq -c .reserved <<< "$a")" >&2
}

# --- refresh ------------------------------------------------------------------
# Re-reads the device from Cloudflare. Worth doing when an endpoint stops
# answering or after the plan changes; the private key is untouched.
cmd_refresh() {
    local file="warp-account.json"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --account|-a) file="$2"; shift 2 ;;
            *) die "refresh: unknown option '$1'" ;;
        esac
    done
    ensure_deps

    local a resp
    a=$(load_account "$file")
    step "Refreshing device from Cloudflare"
    resp=$(cf_api GET "/reg/$(jq -r .device_id <<< "$a")" "$(jq -r .access_token <<< "$a")")
    local updated
    updated=$(build_account "$resp" \
        "$(jq -r .private_key <<< "$a")" "$(jq -r .public_key <<< "$a")" \
        "$(jq -r .access_token <<< "$a")" "$(jq -r .device_id <<< "$a")")
    write_account "$file" "$updated"
    ok "Refreshed ${file}"
    print_account_summary "$updated"
}

# --- license ------------------------------------------------------------------
cmd_license() {
    local file="warp-account.json" key=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --account|-a) file="$2"; shift 2 ;;
            --key|-k)     key="$2"; shift 2 ;;
            *) die "license: unknown option '$1'" ;;
        esac
    done
    ensure_deps
    [[ -n "$key" ]] || die "license: --key is required"
    key=$(printf '%s' "$key" | tr -cd 'a-zA-Z0-9-')

    local a device_id token
    a=$(load_account "$file")
    device_id=$(jq -r .device_id <<< "$a")
    token=$(jq -r .access_token <<< "$a")

    step "Applying WARP+ license"
    cf_api PUT "/reg/${device_id}/account" "$token" "$(jq -n --arg l "$key" '{license:$l}')" >/dev/null
    local resp updated
    resp=$(cf_api GET "/reg/${device_id}" "$token")
    updated=$(build_account "$resp" "$(jq -r .private_key <<< "$a")" \
        "$(jq -r .public_key <<< "$a")" "$token" "$device_id")
    write_account "$file" "$updated"
    ok "License applied"
    print_account_summary "$updated"
}

# --- info ---------------------------------------------------------------------
cmd_info() {
    local file="warp-account.json"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --account|-a) file="$2"; shift 2 ;;
            *) die "info: unknown option '$1'" ;;
        esac
    done
    ensure_deps
    print_account_summary "$(load_account "$file")"
    printf '\n' >&2
}

# --- generate -----------------------------------------------------------------
# Emits the Xray outbound. Field names and semantics are taken from
# infra/conf/wireguard.go, not from folklore:
#   * `address` accepts a bare IP or a prefix — client.go tries ParseAddr then
#     ParsePrefix — so the /32 form used by wgcf profiles is fine.
#   * `reserved` must be empty or exactly 3 bytes; Build() rejects anything else.
#   * `mtu` defaults to 1420 when omitted, which is wrong for WARP.
#   * `noKernelTun` selects the userspace gVisor stack. Default on because the
#     kernel path needs CAP_NET_ADMIN and writes rp_filter under /proc/sys,
#     read-only in an unprivileged container. Xray probes the capability itself
#     (proxy/wireguard/tun_linux.go, KernelTunSupported) and falls back to gVisor
#     anyway, so this is a guarantee rather than the only thing preventing a
#     failed start. --kernel-tun asks for the faster path explicitly.
#
# Verified against Xray-core v26.3.27, the latest stable. Do NOT port field names
# from the main branch: `remoteDNS` is on main and in no release, while `workers`
# is in the release and not on main. An unknown key is silently ignored by Go's
# JSON decoder, so a wrong name fails as "nothing happened", never as an error.
cmd_generate() {
    local file="warp-account.json" tag="$DEFAULT_TAG" mtu="$DEFAULT_MTU"
    local keepalive="$DEFAULT_KEEPALIVE" endpoint_mode="api" endpoint=""
    local with_ipv6=0 domain_strategy="" kernel_tun=0 with_reserved=1
    local rules="" full=0 out="" all_traffic=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --account|-a)      file="$2"; shift 2 ;;
            --tag|-t)          tag="$2"; shift 2 ;;
            --mtu)             mtu="$2"; shift 2 ;;
            --keepalive)       keepalive="$2"; shift 2 ;;
            --endpoint)        endpoint_mode="$2"; shift 2 ;;
            --ipv6)            with_ipv6=1; shift ;;
            --domain-strategy) domain_strategy="$2"; shift 2 ;;
            --kernel-tun)      kernel_tun=1; shift ;;
            --no-reserved)     with_reserved=0; shift ;;
            --rules)           rules=$(expand_rules "$2"); shift 2 ;;
            --all-traffic)     all_traffic=1; shift ;;
            --full)            full=1; shift ;;
            --out|-o)          out="$2"; shift 2 ;;
            *) die "generate: unknown option '$1'" ;;
        esac
    done
    ensure_deps

    [[ "$mtu" =~ ^[0-9]+$ ]]       || die "generate: --mtu must be a number"
    [[ "$keepalive" =~ ^[0-9]+$ ]] || die "generate: --keepalive must be a number"

    local a
    a=$(load_account "$file")

    case "$endpoint_mode" in
        api)    endpoint=$(jq -r .endpoint_host <<< "$a") ;;
        random) endpoint=$(random_endpoint) ;;
        *:*)    endpoint="$endpoint_mode" ;;
        *)      die "generate: --endpoint takes 'api', 'random' or 'host:port'" ;;
    esac

    if [[ -z "$domain_strategy" ]]; then
        (( with_ipv6 )) && domain_strategy="ForceIP" || domain_strategy="ForceIPv4"
    fi

    local addresses allowed
    if (( with_ipv6 )); then
        addresses=$(jq -c '[(.address_v4 + "/32"), (.address_v6 + "/128")]' <<< "$a")
        allowed='["0.0.0.0/0", "::/0"]'
    else
        # IPv4 only by default: many providers blackhole IPv6, and a peer that
        # advertises ::/0 with no working v6 path stalls every AAAA-first dial.
        addresses=$(jq -c '[(.address_v4 + "/32")]' <<< "$a")
        allowed='["0.0.0.0/0"]'
    fi

    local reserved='null'
    (( with_reserved )) && reserved=$(jq -c .reserved <<< "$a")

    local outbound
    outbound=$(jq -n \
        --arg tag "$tag" \
        --arg secretKey "$(jq -r .private_key <<< "$a")" \
        --arg publicKey "$(jq -r .peer_public_key <<< "$a")" \
        --arg endpoint "$endpoint" \
        --argjson address "$addresses" \
        --argjson allowedIPs "$allowed" \
        --argjson mtu "$mtu" \
        --argjson keepAlive "$keepalive" \
        --argjson reserved "$reserved" \
        --arg domainStrategy "$domain_strategy" \
        --argjson noKernelTun "$([[ $kernel_tun -eq 1 ]] && echo false || echo true)" \
        '{
            tag: $tag,
            protocol: "wireguard",
            settings: ({
                secretKey: $secretKey,
                address: $address,
                peers: [{
                    publicKey: $publicKey,
                    endpoint: $endpoint,
                    keepAlive: $keepAlive,
                    allowedIPs: $allowedIPs
                }],
                mtu: $mtu,
                domainStrategy: $domainStrategy,
                noKernelTun: $noKernelTun
            } | if $reserved == null then . else . + {reserved: $reserved} end)
        }')

    [[ -n "$rules" && $all_traffic -eq 1 ]] \
        && die "generate: --rules and --all-traffic are mutually exclusive"

    local result="$outbound"
    if (( full )) || [[ -n "$rules" ]] || (( all_traffic )); then
        local rule='null'
        if (( all_traffic )); then
            # A rule with only `network` matches every TCP/UDP connection that
            # reached it — everything the rules above did not already claim.
            rule=$(jq -n --arg tag "$tag" '{type:"field", network:"tcp,udp", outboundTag:$tag}')
        elif [[ -n "$rules" ]]; then
            rule=$(jq -n --arg tag "$tag" --arg csv "$rules" \
                '{type:"field", domain:($csv | split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length>0))), outboundTag:$tag}')
        fi
        result=$(jq -n --argjson ob "$outbound" --argjson rule "$rule" \
            '{outbounds: [$ob]} + (if $rule == null then {} else {routing: {rules: [$rule]}} end)')
    fi

    if [[ -n "$out" ]]; then
        printf '%s\n' "$result" > "$out"
        ok "Wrote ${out}"
    else
        printf '%s\n' "$result"
    fi

    # "--full" reads like "the full config" to anyone who has not read the help,
    # so say plainly what this is. stderr, so a redirect still gets clean JSON.
    if (( full )); then
        printf '\n  %sNote:%s this is a fragment for pasting, not a complete Xray config.\n' \
            "$C_BLD" "$C_RST" >&2
        printf '  %sFor a complete config:%s warp-vps merge -c <exported-panel-config.json> -a %s %s\n\n' \
            "$C_GRY" "$C_RST" "$file" "$([[ $all_traffic -eq 1 ]] && echo '--all-traffic' || echo '--rules ai')" >&2
    fi
}

# --- batch --------------------------------------------------------------------
# One WARP account per node, not one shared across nodes. Two Xray instances
# using the same WireGuard keypair are the same peer to Cloudflare: the second
# handshake displaces the first, and the two nodes take turns knocking each
# other offline while both look "connected" locally.
cmd_batch() {
    local count=0 dir="./warp-nodes" prefix="node" license="" delay=5
    local -a passthru=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --count|-n)  count="$2"; shift 2 ;;
            --out-dir|-d) dir="$2"; shift 2 ;;
            --prefix)    prefix="$2"; shift 2 ;;
            --license)   license="$2"; shift 2 ;;
            --delay)     delay="$2"; shift 2 ;;
            --)          shift; passthru=("$@"); break ;;
            *) die "batch: unknown option '$1' (put generate options after --)" ;;
        esac
    done
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || die "batch: --count must be a positive integer"

    mkdir -p "$dir"
    local i name acct
    for (( i = 1; i <= count; i++ )); do
        name="${prefix}-${i}"
        acct="${dir}/${name}.account.json"
        step "[${i}/${count}] ${name}"
        # Cloudflare rate-limits registrations per source IP; pacing the loop is
        # cheaper than losing the whole batch to a 429 halfway through.
        (( i > 1 )) && sleep "$delay"
        local -a reg_args=(--out "$acct" --no-hint)
        [[ -n "$license" ]] && reg_args+=(--license "$license")
        cmd_register "${reg_args[@]}"
        ok "account → ${acct}"
        cmd_generate --account "$acct" --out "${dir}/${name}.outbound.json" \
            ${passthru[@]+"${passthru[@]}"}
    done
    printf '\n  %s✔%s %d node configs in %s\n\n' "$C_GRN" "$C_RST" "$count" "$dir" >&2
}

# --- merge --------------------------------------------------------------------
# Splices the outbound and its routing rule into an existing Xray config.
#
# Two properties of Xray make hand-editing risky, and both are guarded here.
#
# 1. Unmatched traffic goes to the FIRST outbound. app/proxyman/outbound sets
#    defaultHandler on the first AddHandler call, and the dispatcher falls back
#    to it whenever no rule matches. Prepending the WARP outbound therefore
#    silently reroutes *everything* through WARP. We only ever append.
#
# 2. Routing takes the FIRST matching rule, not the most specific one. A config
#    ending in a catch-all (a rule with no domain/ip/inboundTag/... selector)
#    swallows our rule if we append after it, so we insert just above it.
cmd_merge() {
    local cfg="" acct="warp-account.json" rules="" tag="" backup=1 replace=0
    local dry=0 all_traffic=0 force_path=0
    local -a passthru=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config|-c)  cfg="$2"; shift 2 ;;
            --account|-a) acct="$2"; shift 2 ;;
            --rules)      rules=$(expand_rules "$2"); shift 2 ;;
            --all-traffic) all_traffic=1; shift ;;
            --tag|-t)     tag="$2"; shift 2 ;;
            --no-backup)  backup=0; shift ;;
            --replace)    replace=1; shift ;;
            --dry-run)    dry=1; shift ;;
            --force-path) force_path=1; shift ;;
            --)           shift; passthru=("$@"); break ;;
            *) die "merge: unknown option '$1' (put generate options after --)" ;;
        esac
    done
    ensure_deps
    [[ -n "$cfg" ]]   || die "merge: --config is required"
    [[ -f "$cfg" ]]   || die "merge: config not found: ${cfg}"
    [[ -n "$rules" || $all_traffic -eq 1 ]] \
        || die "merge: pass --rules \"a,b,c\" for selected domains, or --all-traffic for everything"
    [[ -n "$rules" && $all_traffic -eq 1 ]] \
        && die "merge: --rules and --all-traffic are mutually exclusive"
    jq -e . "$cfg" >/dev/null 2>&1 || die "merge: ${cfg} is not valid JSON"

    # On a Remnawave node the Xray config is panel-managed: the node fetches it
    # and hands it to Xray, so an edit made on the node survives only until the
    # next sync. It then reverts with no error anywhere, and the operator hunts a
    # tunnel that "stopped working on its own". Edit an export of the panel
    # config and paste the result back into the panel instead.
    case "$(cd "$(dirname "$cfg")" && pwd)/$(basename "$cfg")" in
        */remnanode/*|*/remnawave/*|*/opt/remnanode*|*/var/lib/remnanode*)
            (( force_path )) || die "merge: ${cfg} looks like a node's panel-managed config. Edits there are overwritten on the next panel sync. Export the config from the panel, run merge on that copy, paste it back — or pass --force-path if you are certain this file is not panel-managed."
            warn "Editing a path that looks panel-managed, because --force-path was given" ;;
    esac

    local -a gen_args=(--account "$acct")
    [[ -n "$tag" ]] && gen_args+=(--tag "$tag")
    local outbound
    outbound=$(cmd_generate "${gen_args[@]}" ${passthru[@]+"${passthru[@]}"})
    tag=$(jq -r .tag <<< "$outbound")

    # An empty outbounds array would make ours the default handler.
    local n_out
    n_out=$(jq '.outbounds // [] | length' "$cfg")
    (( n_out > 0 )) || die "merge: ${cfg} has no outbounds. Adding ours would make WARP the default route for all traffic — add a direct outbound first."

    if jq -e --arg t "$tag" '[.outbounds[]?.tag] | index($t)' "$cfg" >/dev/null 2>&1; then
        (( replace )) || die "merge: an outbound tagged '${tag}' already exists in ${cfg}. Pass --replace to overwrite it, or --tag to use a different name."
    fi

    local merged
    merged=$(jq \
        --argjson ob "$outbound" \
        --arg tag "$tag" \
        --arg csv "$rules" \
        --argjson allTraffic "$all_traffic" \
        '
        def is_catchall:
            # A rule with no selector matches every connection.
            (has("domain") or has("ip") or has("inboundTag") or has("user")
             or has("source") or has("sourcePort") or has("port")
             or has("protocol") or has("attrs")) | not;

        ($csv | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))) as $domains
        | .outbounds = ([ .outbounds[] | select(.tag != $tag) ] + [$ob])
        | .routing = (.routing // {})
        | .routing.rules = (.routing.rules // [])
        | (if $allTraffic == 1
           then {type: "field", network: "tcp,udp", outboundTag: $tag}
           else {type: "field", domain: $domains, outboundTag: $tag}
           end) as $rule
        # Drop every rule already pointing at our tag so --replace is idempotent
        # rather than appending a second copy on each run.
        | .routing.rules = ([ .routing.rules[] | select(.outboundTag != $tag) ])
        | ([ .routing.rules | to_entries[] | select(.value | is_catchall) | .key ] | first) as $cut
        | .routing.rules = (
            if $cut == null
            then .routing.rules + [$rule]
            else .routing.rules[0:$cut] + [$rule] + .routing.rules[$cut:]
            end
          )
        ' "$cfg") || die "merge: jq failed to splice the config"

    local pos
    pos=$(jq --arg t "$tag" '[.routing.rules[].outboundTag] | index($t)' <<< "$merged")
    local total
    total=$(jq '.routing.rules | length' <<< "$merged")

    if (( dry )); then
        printf '%s\n' "$merged"
        return 0
    fi

    if (( backup )); then
        local bak
        bak="${cfg}.$(date -u +%Y%m%dT%H%M%SZ).bak"
        cp -p "$cfg" "$bak" || die "merge: could not write backup ${bak}"
        ok "backup: ${bak}"
    fi

    # Write via a temp file in the same directory so a full disk or a crash
    # cannot leave a half-written Xray config behind.
    local tmp
    tmp=$(mktemp "${cfg}.XXXXXX") || die "mktemp failed"
    printf '%s\n' "$merged" > "$tmp"
    jq -e . "$tmp" >/dev/null || { rm -f "$tmp"; die "merge: produced invalid JSON, ${cfg} left untouched"; }

    # Valid JSON is not a valid Xray config. When an xray binary is around, let
    # it parse the result before this lands anywhere a restart would pick it up:
    # `run -test` builds the config and exits without serving.
    local xb
    xb=$(command -v xray 2>/dev/null || true)
    [[ -z "$xb" && -x /usr/local/bin/xray ]] && xb=/usr/local/bin/xray
    if [[ -n "$xb" ]]; then
        if "$xb" run -test -c "$tmp" >/dev/null 2>&1; then
            ok "validated with $("$xb" version 2>/dev/null | head -1)"
        else
            printf '%s\n' "$("$xb" run -test -c "$tmp" 2>&1 | tail -5 | sed 's/^/    /')" >&2
            rm -f "$tmp"
            die "merge: xray rejected the merged config, ${cfg} left untouched"
        fi
    else
        warn "no xray binary found — merged config checked for JSON validity only"
    fi

    # Carry the original mode across rather than defaulting to something wider:
    # this file now holds a WireGuard private key.
    local mode
    mode=$(stat -c '%a' "$cfg" 2>/dev/null || stat -f '%Lp' "$cfg" 2>/dev/null || echo 600)
    chmod "$mode" "$tmp"
    mv "$tmp" "$cfg"

    ok "outbound '${tag}' appended (position $(( n_out + 1 )) of $(( n_out + 1 )))"
    ok "routing rule inserted at index ${pos} of ${total}"
    printf '\n  %sRollback:%s restore the .bak file and reload Xray\n\n' "$C_BLD" "$C_RST" >&2
}

# --- verify -------------------------------------------------------------------
# Proves the outbound really exits through WARP *before* it goes near a
# production config: stands up a throwaway Xray with a loopback SOCKS inbound,
# routes everything into the warp outbound and reads Cloudflare's own trace
# endpoint back through it.
#
# `warp=on` (or `plus`) is the only claim that counts. A changed egress IP alone
# proves nothing — it also changes if the tunnel silently fell back to direct
# through a different provider path.
TRACE_URL="https://cloudflare.com/cdn-cgi/trace"

cmd_verify() {
    local file="warp-account.json" xray_bin="" port="" image="teddysun/xray:latest"
    local wait_secs=10 probe=""
    local -a passthru=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --account|-a) file="$2"; shift 2 ;;
            --xray)       xray_bin="$2"; shift 2 ;;
            --port|-p)    port="$2"; shift 2 ;;
            --image)      image="$2"; shift 2 ;;
            --wait)       wait_secs="$2"; shift 2 ;;
            --probe)      probe=$(expand_probe "$2"); shift 2 ;;
            --)           shift; passthru=("$@"); break ;;
            *) die "verify: unknown option '$1' (put generate options after --)" ;;
        esac
    done
    ensure_deps

    port=${port:-$(( RANDOM % 10000 + 40000 ))}

    local mode="binary"
    if [[ -z "$xray_bin" ]]; then
        if command -v xray >/dev/null 2>&1; then
            xray_bin=$(command -v xray)
        elif [[ -x /usr/local/bin/xray ]]; then
            xray_bin=/usr/local/bin/xray
        elif command -v docker >/dev/null 2>&1; then
            mode="docker"
        else
            die "No xray binary found and docker is unavailable. Pass --xray /path/to/xray."
        fi
    fi

    local tmpdir cfg
    tmpdir=$(mktemp -d) || die "mktemp -d failed"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" EXIT
    cfg="${tmpdir}/verify.json"

    local outbound tag
    outbound=$(cmd_generate --account "$file" ${passthru[@]+"${passthru[@]}"})
    # Read the tag back off the generated outbound: a --tag in the passthrough
    # args would otherwise leave the routing rule pointing at a tag that no
    # outbound carries, and Xray would refuse to start.
    tag=$(jq -r .tag <<< "$outbound")
    jq -n --argjson ob "$outbound" --argjson port "$port" --arg tag "$tag" \
        '{
            log: {loglevel: "warning"},
            inbounds: [{tag:"in", port:$port, listen:"127.0.0.1", protocol:"socks",
                        settings:{auth:"noauth", udp:true}}],
            outbounds: [$ob, {tag:"direct", protocol:"freedom"}],
            routing: {rules: [{type:"field", inboundTag:["in"], outboundTag:$tag}]}
        }' > "$cfg"
    chmod 600 "$cfg"

    step "Baseline (no tunnel)"
    local direct_trace direct_ip
    direct_trace=$(curl -sS -m 15 "$TRACE_URL" || true)
    direct_ip=$(sed -n 's/^ip=//p' <<< "$direct_trace")
    ok "egress IP: ${direct_ip:-unknown}"

    step "Starting throwaway Xray (SOCKS 127.0.0.1:${port})"
    local pid="" cid=""
    if [[ "$mode" == "docker" ]]; then
        cid=$(docker run -d --rm --network host --entrypoint xray \
                -v "${cfg}:/tmp/verify.json:ro" "$image" run -c /tmp/verify.json) \
            || die "docker run failed"
        # shellcheck disable=SC2064
        trap "docker stop '$cid' >/dev/null 2>&1 || true; rm -rf '$tmpdir'" EXIT
        ok "container ${cid:0:12} (${image})"
    else
        "$xray_bin" run -c "$cfg" >"${tmpdir}/xray.log" 2>&1 &
        pid=$!
        # shellcheck disable=SC2064
        trap "kill '$pid' 2>/dev/null || true; rm -rf '$tmpdir'" EXIT
        ok "pid ${pid} ($("$xray_bin" version 2>/dev/null | head -1))"
    fi

    local i up=0
    for (( i = 0; i < wait_secs * 2; i++ )); do
        if curl -sS -m 2 --socks5-hostname "127.0.0.1:${port}" -o /dev/null "$TRACE_URL" 2>/dev/null; then
            up=1; break
        fi
        sleep 0.5
    done
    if (( ! up )); then
        [[ -f "${tmpdir}/xray.log" ]] && sed 's/^/    /' "${tmpdir}/xray.log" >&2
        [[ -n "$cid" ]] && docker logs "$cid" 2>&1 | sed 's/^/    /' >&2
        die "Xray never served the SOCKS port. Most often: an unsupported field for this Xray version, or kernel-TUN denied in a container (try without --kernel-tun)."
    fi

    step "Probing through the tunnel"
    local trace warp_state tunnel_ip loc
    trace=$(curl -sS -m 20 --socks5-hostname "127.0.0.1:${port}" "$TRACE_URL") \
        || die "Tunnel came up but the trace request failed"
    warp_state=$(sed -n 's/^warp=//p' <<< "$trace")
    tunnel_ip=$(sed -n 's/^ip=//p' <<< "$trace")
    loc=$(sed -n 's/^loc=//p' <<< "$trace")

    printf '\n' >&2
    printf '   %sWARP:%s       %s\n' "$C_GRY" "$C_RST" \
        "$(case "$warp_state" in
             on)   printf '%s● on (free tier)%s' "$C_GRN" "$C_RST" ;;
             plus) printf '%s● on (WARP+)%s'     "$C_GRN" "$C_RST" ;;
             *)    printf '%s○ %s%s'             "$C_RED" "${warp_state:-unknown}" "$C_RST" ;;
           esac)" >&2
    printf '   %sEgress IP:%s  %s%s%s  %s(direct: %s)%s\n' \
        "$C_GRY" "$C_RST" "$C_CYN" "${tunnel_ip:-unknown}" "$C_RST" \
        "$C_GRY" "${direct_ip:-unknown}" "$C_RST" >&2
    printf '   %sLocation:%s   %s\n\n' "$C_GRY" "$C_RST" "${loc:-unknown}" >&2

    # warp=on only proves the packets go through Cloudflare. For the usual
    # reason to want WARP on a VPN node — a datacenter IP that services refuse —
    # the question is whether the destination accepts the new address at all, so
    # probe the real endpoints through the same tunnel.
    if [[ -n "$probe" ]]; then
        step "Probing destinations through the tunnel"
        local url code body seen
        # shellcheck disable=SC2001  # a plain , -> space split, no array needed
        for url in $(printf '%s' "$probe" | sed 's/,/ /g'); do
            [[ "$url" == http*://* ]] || url="https://${url}"
            # curl already prints 000 through -w when the request fails, so a
            # `|| echo 000` fallback would concatenate into "000000" and match
            # none of the cases below. Capture, then default the empty value.
            body=""; seen=""
            if [[ "$url" == */cdn-cgi/trace ]]; then
                body=$(curl -s -m 20 -w $'\n%{http_code}' \
                         --socks5-hostname "127.0.0.1:${port}" "$url" 2>/dev/null) || true
                code=${body##*$'\n'}
                # What the destination itself reports about the connection —
                # the only direct answer to "which address does it see".
                # grep -E, not sed: BSD sed has no \| alternation in BREs, so a
                # sed version of this silently returns nothing on macOS.
                seen=$(printf '%s' "${body%$'\n'*}" | grep -E '^(ip|loc|warp)=' | tr '\n' ' ')
            else
                code=$(curl -s -o /dev/null -m 20 -w '%{http_code}' \
                         --socks5-hostname "127.0.0.1:${port}" "$url" 2>/dev/null) || true
            fi
            code=${code:-000}
            case "$code" in
                2*|3*)   printf '   %s%-40s%s %s%s%s %s%s%s\n' "$C_GRY" "$url" "$C_RST" "$C_GRN" "$code" "$C_RST" "$C_GRY" "$seen" "$C_RST" >&2 ;;
                # 401 means the request arrived and was answered by the service.
                401)     printf '   %s%-40s%s %s401 (reached; needs an API key)%s\n' "$C_GRY" "$url" "$C_RST" "$C_GRN" "$C_RST" >&2 ;;
                403|451) printf '   %s%-40s%s %s%s (refused)%s\n' "$C_GRY" "$url" "$C_RST" "$C_RED" "$code" "$C_RST" >&2 ;;
                000)     printf '   %s%-40s%s %sno answer%s\n' "$C_GRY" "$url" "$C_RST" "$C_RED" "$C_RST" >&2 ;;
                *)       printf '   %s%-40s%s %s%s%s\n' "$C_GRY" "$url" "$C_RST" "$C_YLW" "$code" "$C_RST" >&2 ;;
            esac
        done
        printf '\n' >&2
    fi

    case "$warp_state" in
        on|plus) ok "Verified — traffic exits through Cloudflare WARP" ;;
        *) die "Tunnel is up but Cloudflare does not see it as WARP (warp=${warp_state:-empty}). The outbound is reaching the internet some other way — do not deploy this." ;;
    esac
}

# --- entry point --------------------------------------------------------------
usage() {
    cat >&2 <<'USAGE_EOF'
warp-vps — Cloudflare WARP as a native Xray outbound (for Remnawave nodes)

USAGE
    warp-vps <command> [options]

COMMANDS
    register    Register a new anonymous WARP device and save the account
    refresh     Re-read endpoint / addresses / client_id from Cloudflare
    license     Apply a WARP+ license key to an existing account
    info        Show the saved account's plan, address and endpoint
    generate    Emit the Xray `wireguard` outbound (stdout by default)
    batch       Register N independent accounts — one per node — and emit N outbounds
    merge       Splice the outbound + routing rule into an existing Xray config
    verify      Stand up a throwaway Xray and prove the outbound really exits via WARP

REGISTER
    -o, --out FILE        Account file (default: warp-account.json)
        --license KEY     Apply a WARP+ key during registration
        --model NAME      Device model reported to Cloudflare (default: PC)
    -f, --force           Overwrite an existing account file

GENERATE
    -a, --account FILE    Account file (default: warp-account.json)
    -t, --tag TAG         Outbound tag (default: warp)
        --mtu N           Tunnel MTU (default: 1280; Xray's own default of 1420 breaks WARP)
        --keepalive N     PersistentKeepalive seconds (default: 15)
        --endpoint MODE   api (default) | random | host:port
        --ipv6            Include the IPv6 address and ::/0 (off by default)
        --domain-strategy S   ForceIP | ForceIPv4 | ForceIPv6 | ForceIPv4v6 | ForceIPv6v4
        --kernel-tun      Use the kernel TUN path (faster; needs a privileged container)
        --no-reserved     Omit the `reserved` client_id bytes
        --rules SET       Routing rule for these domains. "ai" expands to the
                          built-in AI service set; anything else is taken literally
        --all-traffic     Emit a catch-all rule instead: everything not already
                          claimed by an earlier rule goes through the tunnel
        --full            Emit both pieces as {outbounds:[…], routing:{rules:[…]}}.
                          Still a FRAGMENT to paste into a config, not a whole
                          Xray config — for that use `merge`, which splices the
                          fragment into an existing config and prints the result
    -o, --out FILE        Write to FILE instead of stdout

BATCH
    -n, --count N         How many independent node accounts to create
    -d, --out-dir DIR     Output directory (default: ./warp-nodes)
        --prefix NAME     File name prefix (default: node)
        --delay SECS      Pause between registrations (default: 5, avoids 429)
        -- <generate opts>    Everything after -- is passed to generate

MERGE
    -c, --config FILE     Xray config to edit in place (a .bak is written first)
    -a, --account FILE    Account file
        --rules SET       Domains to send through WARP. "ai" expands to the
                          built-in AI service set
        --all-traffic     Send everything through WARP instead of selected domains
                          (one of --rules / --all-traffic is required)
    -t, --tag TAG         Outbound tag (default: warp)
        --replace         Overwrite an existing outbound with the same tag
        --dry-run         Print the merged config instead of writing it
        --no-backup       Skip the .bak (not recommended)
        --force-path      Proceed even though the path looks panel-managed
        -- <generate opts>    Everything after -- is passed to generate

VERIFY
    -a, --account FILE    Account file
        --xray PATH       Xray binary (auto-detected; falls back to docker)
        --image REF       Docker image for the fallback (default: teddysun/xray:latest)
    -p, --port N          Loopback SOCKS port for the probe
        --probe SET       Also fetch these URLs through the tunnel and report the
                          status — warp=on says the packets reach Cloudflare, not
                          that the destination accepts the address. "ai" expands
                          to endpoints that answer curl honestly. Do NOT probe a
                          site's HTML root: Cloudflare rejects curl on its TLS
                          fingerprint, so 403 there says nothing about your IP
        -- <generate opts>    Everything after -- is passed to generate

EXAMPLES
    warp-vps register --out de-1.account.json
    warp-vps verify   --account de-1.account.json
    warp-vps generate --account de-1.account.json --rules ai --full
    warp-vps merge -c panel-config.json -a de-1.account.json --all-traffic
    warp-vps batch --count 3 --prefix eu -- --endpoint random

USAGE_EOF
}

main() {
    local cmd="${1:-help}"
    [[ $# -gt 0 ]] && shift
    case "$cmd" in
        register)        cmd_register "$@" ;;
        refresh)         cmd_refresh "$@" ;;
        license)         cmd_license "$@" ;;
        info)            cmd_info "$@" ;;
        generate|gen)    cmd_generate "$@" ;;
        batch)           cmd_batch "$@" ;;
        merge)           cmd_merge "$@" ;;
        verify|test)     cmd_verify "$@" ;;
        version|--version|-v) printf 'warp-vps %s\n' "$VERSION" ;;
        help|--help|-h)  usage ;;
        *) printf '\n  %sUnknown command: %s%s\n\n' "$C_RED" "$cmd" "$C_RST" >&2; usage; exit 1 ;;
    esac
}

main "$@"
