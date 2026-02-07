#!/bin/bash
#
# License: BSD 3-Clause
# It is provided "AS IS", without warranty of any kind.
#
# Arqma Service Node + Storage Node setup/extend/update script (fresh/add/report/update/dashboard)
# Tested on Ubuntu (apt), x86_64
# Debian (apt) is expected to work but is not guaranteed.
# RedHat-based systems are not supported yet.
#
# Use at your own risk.
# Review the script before running it.
#
# What it does:
# - No-args behavior:
#   - If sn*.service exists: print dashboard (states, ports, public ip, tips) and exit.
#   - If no services exist: start interactive fresh generator (as before).
# - Fresh mode (default when no services exist): interactively generate N SN+ST pairs, install systemd units, open firewall ports (ufw), optional initial sync.
# - Report mode (--report-existing): print ports and data dirs from existing sn*/st* units (plus SN pubkey best-effort).
# - Add mode (--add-pairs N): add N new pairs after existing ones without touching existing running nodes
#   (except temporary stop of the chosen seed SN if seeding is used).
# - Update mode (--update-binaries): download new binaries (GitHub by default; endpoint override), backup old binaries,
#   atomically replace, daemon-reload, then rolling restart with a gate on sn1/st1.
#
# Safety / production notes:
# - Creates dedicated service users/groups if missing (privilege separation):
#     arqd       for Service Nodes (sn*.service)
#     arqstorage for Storage Nodes (st*.service)
# - Add-mode never overwrites existing sn*.service/st*.service.
# - Never overwrites existing SN/ST data dirs unless --yes-i-really-know-what-i-am-doing.
# - Seeding copies only blockchain db directory lmdb/ (no keys, no logs).
# - Checks port collisions using: ss -lntH
# - If the detected "step" would exceed port 65535 for new nodes, the step is auto-reduced for the new batch.
#
# Network ports (per node index):
# - p2p     : base + 0  (open to internet)
# - rpc     : base + 1  (localhost only)
# - ss      : base + 3  (open to internet, used by storage node)
# - zmq     : base + 4  (opened to internet only if enabled AND bind-ip != 127.0.0.1)
# - arqnet  : base + 5  (open to internet if enabled)
#
# Binaries:
# - Fresh default installs BOTH:
#   - core (arqmad + arqma-blockchain-import) from GitHub core release
#   - storage (arqma-storage) from GitHub storage release
# - Endpoint override (--my-endpoint) expects all three binaries at:
#     {endpoint}/arqmad
#     {endpoint}/arqma-blockchain-import
#     {endpoint}/arqma-storage
# - If storage download fails, it is tolerated (services still generated/enabled), and can be fixed later with update mode.
#
# Operational note (important):
# - Recommended: max 10 nodes on 1 public IP.
#   If you run too many nodes per public IP (or insufficient CPU/RAM/disk), the network may reject them
#   and they can be deregistered.
#   If you can route/forward different public IPs to the host and the host has enough resources, that is preferred.
#

set -euo pipefail

# ---------------- Config defaults ----------------

BASE_DATA_DIR_DEFAULT="/data"

ARQMAD_BIN="/usr/local/bin/arqmad"
ARQSTORAGE_BIN="/usr/local/bin/arqma-storage"
ARQIMPORT_BIN="/usr/local/bin/arqma-blockchain-import"

BASE_PORT_DEFAULT=10001

P2P_OFFSET=0
RPC_OFFSET=1
SS_OFFSET=3
ZMQ_OFFSET=4
ARQNET_OFFSET=5

BLOCKCHAIN_URL_DEFAULT="https://downloads.arqma.com/RAW/blockchain.raw"

# Core binaries release (arqmad + arqma-blockchain-import)
GITHUB_RELEASE_DEFAULT="https://github.com/arqma/arqma/releases/latest/download/build-depends-x86_64-linux.tar.gz"
STORAGE_RELEASE_DEFAULT="https://github.com/arqma/arqma-storage-server/releases/download/v1.1.0/arqma-storage-linux-ubuntu-22.04-x86_64.tar.gz"

INFO_FILE_DEFAULT="$HOME/ARQMA-setup.info"

RESERVE_RATIO_DEFAULT="0.10"
SEED_TIMEOUT_DEFAULT=180
RESTART_TIMEOUT_DEFAULT=180

DEFAULT_SN_USER="arqd"
DEFAULT_SN_GROUP="arqd"
DEFAULT_ST_USER="arqstorage"
DEFAULT_ST_GROUP="arqstorage"

OUTPUT_DIR_DEFAULT="./generated_services"

# ---------------- Globals ----------------

DOWNLOAD_TOOL=""

EXIST_MIN_N=""
EXIST_MAX_N=""
EXIST_STEP=""
EXIST_BASE_P2P=""
EXIST_BASE_RPC=""
EXIST_BASE_SS=""
EXIST_BASE_ARQNET=""
EXIST_PUBLIC_IP=""
EXIST_ARQNET_PRESENT="false"
EXIST_ZMQ_PRESENT="false"
EXIST_ZMQ_BIND_IP="127.0.0.1"

SN_USER="$DEFAULT_SN_USER"
SN_GROUP="$DEFAULT_SN_GROUP"
ST_USER="$DEFAULT_ST_USER"
ST_GROUP="$DEFAULT_ST_GROUP"

# computed ports
PORT_P2P=""
PORT_RPC=""
PORT_SS=""
PORT_ZMQ=""
PORT_ARQNET=""

CHOSEN_STEP=""

# ---------------- Helpers ----------------

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "No-args behavior:"
    echo "  If services exist: prints dashboard and exits"
    echo "  If no services exist: starts interactive fresh generator"
    echo ""
    echo "Modes:"
    echo "  --report-existing      Report existing sn*/st* ports and dirs; exit"
    echo "  --add-pairs N          Add N new pairs after existing ones"
    echo "  --update-binaries      Update binaries (GitHub default; endpoint override), rolling restart gate on sn1/st1"
    echo ""
    echo "Options:"
    echo "  --base-data-dir PATH        Base data dir (default: ${BASE_DATA_DIR_DEFAULT})"
    echo "  --blockchain-url URL        Raw blockchain URL (default: ${BLOCKCHAIN_URL_DEFAULT})"
    echo "  --github-release URL        Core GitHub release tar.gz URL (default: ${GITHUB_RELEASE_DEFAULT})"
    echo "  --storage-release URL       arqma-storage URL (default: ${STORAGE_RELEASE_DEFAULT})"
    echo "  --my-endpoint URL           Endpoint (expects arqmad, arqma-blockchain-import, arqma-storage)"
    echo "  --sync-method METHOD        safe, fast, dangerous (default: safe) [fresh mode]"
    echo "                              Initial blockchain sync method for SN1 (fresh mode only):"
    echo "                                safe      = start SN1 and sync from p2p network (slowest, fully verified)"
    echo "                                fast      = import blockchain.raw snapshot with full verification (faster)"
    echo "                                dangerous = import snapshot without verification (fastest, UNSAFE)"
    echo "  --info-file PATH            Setup info file path (default: ${INFO_FILE_DEFAULT})"
    echo "  --output-dir PATH           Generated services dir (default: ${OUTPUT_DIR_DEFAULT})"
    echo "  --backup-dir PATH           Backup dir (default: /root/arqma-backups)"
    echo ""
    echo "Update mode flags:"
    echo "  --restart-timeout SEC       Timeout waiting for unit to become active (default: ${RESTART_TIMEOUT_DEFAULT})"
    echo "  --rpc-healthcheck           Enable SN RPC healthcheck (requires curl+jq)"
    echo "  --no-rpc-healthcheck        Disable SN RPC healthcheck"
    echo "  --rollback-on-fail          Restore binaries from backup tarball if gate or later restart fails"
    echo ""
    echo "Network flags:"
    echo "  --enable-arqnet             Enable arqnet (default: enabled in fresh; auto in add)"
    echo "  --disable-arqnet            Disable arqnet"
    echo "  --enable-zmq                Enable ZMQ (default: disabled in fresh; auto in add)"
    echo "  --disable-zmq               Disable ZMQ"
    echo "  --zmq-bind-ip IP            ZMQ bind IP (default: 127.0.0.1 in fresh; auto in add)"
    echo ""
    echo "Add-mode flags:"
    echo "  --seed-from N               Seed new nodes from snN (default: 1)"
    echo "  --seed-timeout SEC          Timeout waiting for seed stop (default: ${SEED_TIMEOUT_DEFAULT})"
    echo ""
    echo "Safety override:"
    echo "  --yes-i-really-know-what-i-am-doing  Force overwrite existing data in target dirs"
    echo ""
}

die() { echo "ERROR: $*" >&2; exit 1; }

is_tty() { [[ -t 0 && -t 1 ]]; }

read_or_fail() {
    local prompt="$1"
    local __var="$2"
    local val=""
    if ! is_tty; then
        die "Non-interactive run cannot prompt: $prompt"
    fi
    read -rp "$prompt" val || die "Failed to read input"
    printf -v "$__var" '%s' "$val"
}

confirm_or_default_no() {
    local q="$1"
    local a=""
    if ! is_tty; then
        return 1
    fi
    read -rp "$q" a || return 1
    [[ "$a" =~ ^[Yy]$ ]]
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_packages() {
    local pkgs=("$@")
    [[ ${#pkgs[@]} -gt 0 ]] || return 0
    apt update >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt install -y "${pkgs[@]}" >/dev/null 2>&1
}

require_or_install_base_deps() {
    local missing=()

    need_cmd systemctl || die "systemd required (systemctl not found)"

    need_cmd awk || missing+=("awk")
    need_cmd ss || missing+=("iproute2")
    need_cmd rsync || missing+=("rsync")
    need_cmd tar || missing+=("tar")

    need_cmd grep || missing+=("grep")
    need_cmd sed || missing+=("sed")
    need_cmd df || missing+=("coreutils")
    need_cmd du || missing+=("coreutils")
    need_cmd find || missing+=("findutils")

    if [[ ${#missing[@]} -gt 0 ]]; then
        ensure_packages "${missing[@]}"
    fi

    need_cmd awk || die "awk missing after install"
    need_cmd ss || die "ss missing after install"
    need_cmd rsync || die "rsync missing after install"
    need_cmd tar || die "tar missing after install"
    need_cmd grep || die "grep missing after install"
    need_cmd sed || die "grep missing after install"
    need_cmd df || die "df missing after install"
    need_cmd du || die "du missing after install"
    need_cmd find || die "find missing after install"
}

setup_download_tools() {
    if command -v wget >/dev/null 2>&1; then
        DOWNLOAD_TOOL="wget"
    elif command -v curl >/dev/null 2>&1; then
        DOWNLOAD_TOOL="curl"
    else
        ensure_packages wget
        DOWNLOAD_TOOL="wget"
    fi
}

download_file() {
    local url="$1"
    local out="$2"
    if [[ "$DOWNLOAD_TOOL" == "wget" ]]; then
        wget -q -O "$out" "$url"
    else
        curl -s -L -o "$out" "$url"
    fi
}

download_with_progress() {
    local url="$1"
    local out="$2"
    if [[ "$DOWNLOAD_TOOL" == "wget" ]]; then
        wget --show-progress -q -O "$out" "$url"
    else
        curl -L --progress-bar -o "$out" "$url"
    fi
}

get_public_ip() {
    local ip=""
    if command -v curl >/dev/null 2>&1; then
        ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || true)
    elif command -v wget >/dev/null 2>&1; then
        ip=$(wget -qO- --timeout=5 https://api.ipify.org 2>/dev/null || true)
    fi
    if [[ -z "$ip" ]] || ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(hostname -I | awk '{print $1}')
    fi
    echo "$ip"
}

wait_unit_inactive() {
    local unit="$1"
    local timeout_s="${2:-180}"
    local t=0
    while systemctl is-active --quiet "$unit"; do
        if [[ $t -ge $timeout_s ]]; then
            return 1
        fi
        sleep 1
        t=$((t+1))
    done
    return 0
}

wait_unit_active() {
    local unit="$1"
    local timeout_s="${2:-180}"
    local t=0
    while ! systemctl is-active --quiet "$unit"; do
        if systemctl is-failed --quiet "$unit"; then
            return 2
        fi
        if [[ $t -ge $timeout_s ]]; then
            return 1
        fi
        sleep 1
        t=$((t+1))
    done
    return 0
}

# ---------------- Ports ----------------

assert_port_range() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] || die "Invalid port (not integer): $p"
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || die "Invalid port (out of range 1..65535): $p"
}

port_is_listening() {
    local port="$1"
    ss -lntH 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}$"
}

assert_ports_free() {
    local ports=("$@")
    local p
    for p in "${ports[@]}"; do
        [[ -n "$p" ]] || continue
        assert_port_range "$p"
        if port_is_listening "$p"; then
            die "Port already listening: $p"
        fi
    done
}

# ---------------- Disk space ----------------

bytes_dir_size() {
    local path="$1"
    if du -sb "$path" >/dev/null 2>&1; then
        du -sb "$path" | awk '{print $1}'
    else
        du -sB1 "$path" | awk '{print $1}'
    fi
}

bytes_fs_avail() {
    local path="$1"
    df -B1 --output=avail "$path" | tail -n1 | tr -d ' '
}

human_gib() {
    awk -v b="$1" 'BEGIN{printf "%.2f GiB", b/1024/1024/1024}'
}

check_space_for_seeds() {
    local seed_lmdb="$1"
    local target_root="$2"
    local new_nodes="$3"
    local reserve_ratio="$4"

    [[ -d "$seed_lmdb" ]] || die "Seed lmdb dir missing: $seed_lmdb"
    [[ "$new_nodes" -ge 1 ]] || die "Invalid new_nodes: $new_nodes"

    local lmdb_bytes avail_bytes need_bytes reserve_bytes total_bytes
    lmdb_bytes=$(bytes_dir_size "$seed_lmdb")
    avail_bytes=$(bytes_fs_avail "$target_root")

    need_bytes=$(( lmdb_bytes * new_nodes ))
    reserve_bytes=$(awk -v n="$need_bytes" -v r="$reserve_ratio" 'BEGIN{printf "%.0f", n*r}')
    total_bytes=$(( need_bytes + reserve_bytes ))

    echo "Disk check:"
    echo "  lmdb_size: $(human_gib "$lmdb_bytes")"
    echo "  nodes_to_seed: $new_nodes"
    echo "  total_required: $(human_gib "$total_bytes") (reserve_ratio=$reserve_ratio)"
    echo "  fs_avail: $(human_gib "$avail_bytes")"

    if [[ "$avail_bytes" -lt "$total_bytes" ]]; then
        die "Not enough free space for seeding"
    fi
}

# ---------------- UFW ----------------

ufw_allow() {
    local port="$1"
    local proto="$2"
    local cmt="${3:-}"

    assert_port_range "$port"

    if [[ -n "$cmt" ]]; then
        if ufw allow "${port}/${proto}" comment "$cmt" >/dev/null 2>&1; then
            return 0
        fi
    fi
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || die "ufw allow failed for ${port}/${proto}"
}

# ---------------- Install binaries ----------------

is_elf() {
    local f="$1"
    [[ -s "$f" ]] || return 1
    head -c 4 "$f" 2>/dev/null | grep -q $'\x7fELF'
}

run_version_check() {
    local f="$1"
    [[ -x "$f" ]] || chmod 0755 "$f" || true

    local out

    # Some binaries do not implement --version and/or return non-zero for --help.
    out="$("$f" --version 2>&1 || true)"
    if [[ -n "$out" ]]; then
        return 0
    fi

    out="$("$f" --help 2>&1 || true)"
    if [[ -n "$out" ]]; then
        return 0
    fi

    out="$("$f" 2>&1 || true)"
    [[ -n "$out" ]]
}

install_atomic() {
    local src="$1"
    local dst="$2"
    local dir base tmp
    dir=$(dirname "$dst")
    base=$(basename "$dst")
    tmp="${dir}/.${base}.new.$$"
    install -o root -g root -m 0755 "$src" "$tmp"
    mv -f "$tmp" "$dst"
}

download_to_tmp_or_fail() {
    local url="$1"
    local out="$2"
    download_file "$url" "$out"
    [[ -s "$out" ]] || die "Download failed/empty: $url"
}

download_to_tmp_or_warn() {
    local url="$1"
    local out="$2"
    if download_file "$url" "$out" 2>/dev/null && [[ -s "$out" ]]; then
        return 0
    fi
    rm -f -- "$out" 2>/dev/null || true
    return 1
}

install_core_from_endpoint_or_fail() {
    local endpoint="$1"
    local tmpdir="$2"

    download_to_tmp_or_fail "$endpoint/arqmad" "$tmpdir/arqmad"
    download_to_tmp_or_fail "$endpoint/arqma-blockchain-import" "$tmpdir/arqma-blockchain-import"

    is_elf "$tmpdir/arqmad" || die "Endpoint arqmad is not ELF/empty"
    is_elf "$tmpdir/arqma-blockchain-import" || die "Endpoint arqma-blockchain-import is not ELF/empty"
    run_version_check "$tmpdir/arqmad" || die "Endpoint arqmad failed to run"
    run_version_check "$tmpdir/arqma-blockchain-import" || die "Endpoint arqma-blockchain-import failed to run"

    install_atomic "$tmpdir/arqmad" "$ARQMAD_BIN"
    install_atomic "$tmpdir/arqma-blockchain-import" "$ARQIMPORT_BIN"
}

install_storage_from_endpoint_or_warn() {
    local endpoint="$1"
    local tmpdir="$2"

    local tmp="$tmpdir/arqma-storage"
    if download_to_tmp_or_warn "$endpoint/arqma-storage" "$tmp"; then
        if is_elf "$tmp" && run_version_check "$tmp"; then
            install_atomic "$tmp" "$ARQSTORAGE_BIN"
            echo "Installed arqma-storage from endpoint"
            return 0
        fi
        rm -f -- "$tmp" 2>/dev/null || true
        echo "WARNING: endpoint arqma-storage downloaded but failed ELF/run checks; keeping existing binary"
        return 1
    fi
    echo "WARNING: endpoint arqma-storage not available; keeping existing binary"
    return 1
}

install_core_from_github_or_fail() {
    local release_url="$1"
    local tmpdir="$2"

    echo "Installing core binaries from GitHub release..."
    echo "Downloading: $release_url"

    download_to_tmp_or_fail "$release_url" "$tmpdir/arqma-release.tar.gz"
    tar -xzf "$tmpdir/arqma-release.tar.gz" -C "$tmpdir"

    local fa fi
    fa=$(find "$tmpdir" -type f -name arqmad | head -n1 || true)
    fi=$(find "$tmpdir" -type f -name arqma-blockchain-import | head -n1 || true)

    [[ -n "$fa" ]] || die "Missing arqmad in core release"
    [[ -n "$fi" ]] || die "Missing arqma-blockchain-import in core release"

    cp -f "$fa" "$tmpdir/arqmad"
    cp -f "$fi" "$tmpdir/arqma-blockchain-import"

    is_elf "$tmpdir/arqmad" || die "Core arqmad is not ELF/empty"
    is_elf "$tmpdir/arqma-blockchain-import" || die "Core arqma-blockchain-import is not ELF/empty"
    run_version_check "$tmpdir/arqmad" || die "New arqmad failed to run"
    run_version_check "$tmpdir/arqma-blockchain-import" || die "New arqma-blockchain-import failed to run"

    install_atomic "$tmpdir/arqmad" "$ARQMAD_BIN"
    install_atomic "$tmpdir/arqma-blockchain-import" "$ARQIMPORT_BIN"
}

install_storage_from_release_or_warn() {
    local storage_url="$1"
    local tmpdir="$2"

    [[ -n "$storage_url" ]] || { echo "WARNING: no storage release URL configured"; return 1; }

    echo "Installing arqma-storage from release URL (best-effort): $storage_url"

    local tmp="$tmpdir/storage.bin"
    if ! download_to_tmp_or_warn "$storage_url" "$tmp"; then
        echo "WARNING: storage download failed/empty: $storage_url"
        return 1
    fi

    if tar -tzf "$tmp" >/dev/null 2>&1; then
        local exdir="$tmpdir/storage_ex"
        mkdir -p "$exdir"
        tar -xzf "$tmp" -C "$exdir"
        local fs
        fs=$(find "$exdir" -type f -name "arqma-storage" | head -n1 || true)
        if [[ -z "$fs" ]]; then
            echo "WARNING: storage tarball does not contain arqma-storage"
            return 1
        fi
        cp -f "$fs" "$tmpdir/arqma-storage"
    else
        mv -f "$tmp" "$tmpdir/arqma-storage"
    fi

    if ! is_elf "$tmpdir/arqma-storage"; then
        echo "WARNING: downloaded arqma-storage is not ELF/empty; keeping existing binary"
        return 1
    fi
    if ! run_version_check "$tmpdir/arqma-storage"; then
        echo "WARNING: downloaded arqma-storage failed to run (--version/--help); keeping existing binary"
        return 1
    fi

    install_atomic "$tmpdir/arqma-storage" "$ARQSTORAGE_BIN"
    echo "Installed arqma-storage from storage release"
    return 0
}

# ---------------- systemd parsing/report ----------------

normalize_unit_name() {
    local u="$1"
    if [[ "$u" =~ \.service$ ]]; then
        echo "$u"
    else
        echo "${u}.service"
    fi
}

get_execstart_line() {
    local unit
    unit=$(normalize_unit_name "$1")
    systemctl show -p ExecStart --value "$unit" 2>/dev/null | head -n1 || true
}

get_unit_user() {
    local unit
    unit=$(normalize_unit_name "$1")
    systemctl show -p User --value "$unit" 2>/dev/null | head -n1 || true
}

get_unit_group() {
    local unit
    unit=$(normalize_unit_name "$1")
    systemctl show -p Group --value "$unit" 2>/dev/null | head -n1 || true
}

sn_get_pubkey_for_unit() {
    local unit="$1"
    local exec rpc key

    if ! systemctl is-active --quiet "$unit"; then
        echo "not-running"
        return 0
    fi

    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        echo "no-curl-jq"
        return 0
    fi

    exec=$(get_execstart_line "$unit")
    rpc=$(awk 'match($0, /--rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    if [[ -z "$rpc" ]]; then
        echo "no-rpc-port"
        return 0
    fi

    key=$(curl -s "http://127.0.0.1:${rpc}/json_rpc" \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_service_node_key"}' \
        -H 'Content-Type: application/json' \
        | jq -r '.result.service_node_pubkey' 2>/dev/null || true)

    if [[ -n "$key" && "$key" != "null" ]]; then
        echo "$key"
    else
        echo "rpc-error"
    fi
}

sn_extract_report() {
    local exec="$1"
    local datadir p2p rpc arqnet ss zmq_port zmq_enabled snip

    datadir=$(awk 'match($0, /--data-dir[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")
    p2p=$(awk 'match($0, /--p2p-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    rpc=$(awk 'match($0, /--rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    ss=$(awk 'match($0, /--ss-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    arqnet=$(awk 'match($0, /--arqnet-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    zmq_port=$(awk 'match($0, /--zmq-rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    snip=$(awk 'match($0, /--sn-ip[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")

    if grep -q -- '--zmq-enabled' <<<"$exec"; then
        zmq_enabled="yes"
    else
        zmq_enabled="no"
    fi

    echo "service node data_dir: ${datadir:-unknown}"
    echo "sn_ip: ${snip:-unknown}"
    echo -n "sn_ports: p2p=${p2p:-?} rpc=${rpc:-?} ss=${ss:-?}"
    if [[ -n "${arqnet:-}" ]]; then echo -n " arqnet=$arqnet"; fi
    if [[ -n "${zmq_port:-}" ]]; then echo -n " zmq=$zmq_port"; fi
    echo ""
    echo "zmq_enabled: $zmq_enabled"
}

st_extract_report() {
    local exec="$1"
    local datadir public_port

    datadir=$(awk 'match($0, /--data-dir[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")
    public_port=$(awk 'match($0, /arqma-storage[[:space:]]+[^[:space:]]+[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")

    echo "storage node data_dir: ${datadir:-unknown}"
    echo "st_port=${public_port:-?}"
}

report_existing() {
    local dir="/etc/systemd/system"
    local f found=0

    shopt -s nullglob
    for f in "$dir"/sn*.service; do
        [[ "$f" =~ /sn([0-9]+)\.service$ ]] || continue
        found=1

        local sn_num="${BASH_REMATCH[1]}"
        local sn_unit="sn${sn_num}.service"
        local exec
        exec=$(get_execstart_line "$sn_unit")
        [[ -n "$exec" ]] || continue

        echo "=== Service Node $sn_num ==="
        sn_extract_report "$exec"
        echo "sn_pubkey: $(sn_get_pubkey_for_unit "$sn_unit")"

        local st_unit="st${sn_num}.service"
        local st_exec
        st_exec=$(get_execstart_line "$st_unit")
        if [[ -n "$st_exec" ]]; then
            st_extract_report "$st_exec"
        fi
        echo ""
    done
    shopt -u nullglob

    [[ $found -eq 1 ]] || die "No existing sn*.service found in /etc/systemd/system"
}

# ---------------- Dashboard (no-args) ----------------

services_exist() {
    compgen -G "/etc/systemd/system/sn*.service" >/dev/null 2>&1
}

get_max_sn_num_from_units() {
    local nums=() f
    shopt -s nullglob
    for f in /etc/systemd/system/sn*.service; do
        [[ "$f" =~ /sn([0-9]+)\.service$ ]] || continue
        nums+=("${BASH_REMATCH[1]}")
    done
    shopt -u nullglob
    [[ ${#nums[@]} -gt 0 ]] || return 1
    IFS=$'\n' nums=($(printf '%s\n' "${nums[@]}" | sort -n)); unset IFS
    echo "${nums[-1]}"
}

extract_sn_ports_line() {
    local unit="$1"
    local exec p2p rpc ss arqnet zmq snip
    exec=$(get_execstart_line "$unit")
    p2p=$(awk 'match($0, /--p2p-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    rpc=$(awk 'match($0, /--rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    ss=$(awk 'match($0, /--ss-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    arqnet=$(awk 'match($0, /--arqnet-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    zmq=$(awk 'match($0, /--zmq-rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    snip=$(awk 'match($0, /--sn-ip[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")
    echo "${snip:-?} p2p=${p2p:-?} rpc=${rpc:-?} ss=${ss:-?} arqnet=${arqnet:-off} zmq=${zmq:-?}"
}

extract_st_port() {
    local unit="$1"
    local exec port
    exec=$(get_execstart_line "$unit")
    port=$(awk 'match($0, /arqma-storage[[:space:]]+[^[:space:]]+[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    echo "${port:-?}"
}

extract_exec_bin_path() {
    local unit="$1"
    local exec
    exec=$(get_execstart_line "$unit")
    [[ -n "$exec" ]] || { echo ""; return 0; }
    awk '{for(i=1;i<=NF;i++){if($i ~ /^\//){print $i; exit}}}' <<<"$exec"
}

st_bin_status() {
    local unit="$1"
    local bin
    bin=$(extract_exec_bin_path "$unit")
    if [[ -z "$bin" ]]; then
        echo "unknown"
        return 0
    fi
    if [[ -x "$bin" ]]; then
        echo "ok"
        return 0
    fi
    if systemctl is-active --quiet "$unit"; then
        echo "missing_on_disk_but_running"
    else
        echo "missing"
    fi
}

run_dashboard() {
    local max_n
    max_n=$(get_max_sn_num_from_units) || die "No sn*.service found"
    local ip
    ip=$(hostname -I | awk '{print $1}')

    echo "ARQMA dashboard"
    echo "host_ip: ${ip:-unknown}"
    echo "nodes_detected: 1..${max_n}"
    echo "NOTE: Recommended max 10 nodes per public IP."
    echo ""
    echo "Hint: --help for full options."
    echo ""

    echo "Per-node summary:"
    echo "  n  sn_state  st_state  st_bin  sn_ip  p2p  rpc  ss  arqnet  st_port  sn_key"
    local n snu stu sn_state st_state line stp stbin
    for n in $(seq 1 "$max_n"); do
        snu="sn${n}.service"
        stu="st${n}.service"

        if systemctl is-active --quiet "$snu"; then
            sn_state="active"
        else
            sn_state="$(systemctl is-failed "$snu" 2>/dev/null || echo inactive)"
        fi

        if systemctl cat "$stu" >/dev/null 2>&1; then
            if systemctl is-active --quiet "$stu"; then
                st_state="active"
            else
                st_state="$(systemctl is-failed "$stu" 2>/dev/null || echo inactive)"
            fi
            stbin="$(st_bin_status "$stu")"
        else
            st_state="missing"
            stbin="-"
        fi

        line=$(extract_sn_ports_line "$snu")
        stp="$(extract_st_port "$stu")"

        local snip p2p rpc ss arqnet
        snip=$(awk '{print $1}' <<<"$line")
        p2p=$(awk -F'[ =]' '{for(i=1;i<=NF;i++) if($i=="p2p"){print $(i+1)} }' <<<"$line")
        rpc=$(awk -F'[ =]' '{for(i=1;i<=NF;i++) if($i=="rpc"){print $(i+1)} }' <<<"$line")
        ss=$(awk -F'[ =]' '{for(i=1;i<=NF;i++) if($i=="ss"){print $(i+1)} }' <<<"$line")
        arqnet=$(awk -F'[ =]' '{for(i=1;i<=NF;i++) if($i=="arqnet"){print $(i+1)} }' <<<"$line")

        local snkey
        snkey="$(sn_get_pubkey_for_unit "$snu")"

        printf "  %-2s %-8s %-8s %-22s %-15s %-5s %-5s %-5s %-6s %-6s %s\n" \
            "$n" "$sn_state" "$st_state" "${stbin:-unknown}" "${snip:-?}" "${p2p:-?}" "${rpc:-?}" "${ss:-?}" "${arqnet:-off}" "${stp:-?}" "${snkey:-?}"
    done

    echo ""
    echo "Examples:"
    echo "  systemctl status sn{1..${max_n}} st{1..${max_n}} | grep -i active | grep -i ago"
    echo "  for i in \$(seq 1 ${max_n}); do journalctl -n 10 --no-pager -u sn\${i}; echo '-----'; done"
    echo "  for i in \$(seq 1 ${max_n}); do journalctl -n 10 --no-pager -u st\${i}; echo '-----'; done"
    echo ""
    echo "Shortcuts:"
    echo "  add pairs: $0 --add-pairs 2 --seed-from 1"
    echo "  update bins: $0 --update-binaries --rpc-healthcheck --rollback-on-fail"
    echo "  report: $0 --report-existing"
}

# ---------------- Users/dirs ----------------

ensure_users_and_dirs() {
    mkdir -p "$BASE_DATA_DIR"/{arqma_d,arqma_storage}

    if ! id -u "$SN_USER" >/dev/null 2>&1; then
        useradd -r -s /bin/false "$SN_USER"
    fi
    if ! getent group "$SN_GROUP" >/dev/null 2>&1; then
        groupadd "$SN_GROUP"
    fi
    usermod -g "$SN_GROUP" "$SN_USER" >/dev/null 2>&1 || true

    if ! id -u "$ST_USER" >/dev/null 2>&1; then
        useradd -r -s /bin/false "$ST_USER"
    fi
    if ! getent group "$ST_GROUP" >/dev/null 2>&1; then
        groupadd "$ST_GROUP"
    fi
    usermod -g "$ST_GROUP" "$ST_USER" >/dev/null 2>&1 || true

    chown -R "$SN_USER:$SN_GROUP" "$BASE_DATA_DIR/arqma_d"
    chown -R "$ST_USER:$ST_GROUP" "$BASE_DATA_DIR/arqma_storage"
}

# ---------------- Backup helpers ----------------

backup_existing_services() {
    local dst="$1"
    local ts
    ts="$(date +%F_%H%M%S)"
    local out="${dst}/arqma_services_${ts}.tar.gz"
    mkdir -p "$dst"
    find /etc/systemd/system -maxdepth 1 -type f \( -name 'sn*.service' -o -name 'st*.service' \) -print0 \
      | tar --null -czf "$out" --files-from=-
    echo "$out"
}

backup_keys_and_certs() {
    local dst="$1"
    local ts
    ts="$(date +%F_%H%M%S)"
    local out="${dst}/arqma_keys_${ts}.tar.gz"
    mkdir -p "$dst"
    find "$BASE_DATA_DIR/arqma_d" "$BASE_DATA_DIR/arqma_storage" -type f \
      \( -name 'pub' -o -name 'key*' -o -name 'cert.pem' -o -name 'key.pem' \) -print0 2>/dev/null \
      | tar --null -czf "$out" --files-from=- 2>/dev/null || true
    echo "$out"
}

# ---------------- Update mode (binaries only) ----------------

backup_binaries() {
    local backup_dir="$1"
    local ts out
    ts="$(date +%F_%H%M%S)"
    out="${backup_dir}/arqma_bins_${ts}.tar.gz"
    mkdir -p "$backup_dir"
    
    local files_to_backup=()
    [[ -f /usr/local/bin/arqmad ]] && files_to_backup+=("arqmad")
    [[ -f /usr/local/bin/arqma-blockchain-import ]] && files_to_backup+=("arqma-blockchain-import")
    [[ -f /usr/local/bin/arqma-storage ]] && files_to_backup+=("arqma-storage")
    
    if [[ ${#files_to_backup[@]} -gt 0 ]]; then
        tar -czf "$out" -C /usr/local/bin "${files_to_backup[@]}" 2>/dev/null || true
    fi
    echo "$out"
}

restore_binaries_from_tar() {
    local tarball="$1"
    [[ -f "$tarball" ]] || return 1
    tar -xzf "$tarball" -C /usr/local/bin || return 1
    chmod 0755 /usr/local/bin/arqmad /usr/local/bin/arqma-blockchain-import 2>/dev/null || true
    chmod 0755 /usr/local/bin/arqma-storage 2>/dev/null || true
    return 0
}

unit_debug_dump() {
    local unit="$1"
    systemctl --no-pager -l status "$unit" || true
    systemctl show -p Result,ExecMainStatus,ExecMainCode,ActiveState,SubState "$unit" || true
    journalctl -u "$unit" -n 80 --no-pager || true
}

sn_rpc_healthcheck() {
    local unit="$1"
    need_cmd curl || return 1
    need_cmd jq || return 1

    local exec rpc key
    exec=$(get_execstart_line "$unit")
    rpc=$(awk 'match($0, /--rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    [[ -n "$rpc" ]] || return 1

    key=$(curl -s "http://127.0.0.1:${rpc}/json_rpc" \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_service_node_key"}' \
        -H 'Content-Type: application/json' \
        | jq -r '.result.service_node_pubkey' 2>/dev/null || true)

    [[ -n "$key" && "$key" != "null" ]]
}

restart_pair_checked() {
    local n="$1"
    local timeout="$2"
    local rpc_check="$3"

    systemctl restart "sn${n}.service"
    wait_unit_active "sn${n}.service" "$timeout" || { unit_debug_dump "sn${n}.service"; return 1; }

    if [[ "$rpc_check" == "true" ]]; then
        sn_rpc_healthcheck "sn${n}.service" || { unit_debug_dump "sn${n}.service"; return 1; }
    fi

    if systemctl cat "st${n}.service" >/dev/null 2>&1; then
        local stbin
        stbin="$(extract_exec_bin_path "st${n}.service")"
        if [[ -n "$stbin" && -x "$stbin" ]]; then
            systemctl restart "st${n}.service" || true
            wait_unit_active "st${n}.service" "$timeout" || { unit_debug_dump "st${n}.service"; return 1; }
        fi
    fi

    return 0
}

get_max_sn_num() {
    get_max_sn_num_from_units
}

run_update_mode() {
    local my_endpoint="$1"
    local github_release="$2"
    local storage_release="$3"
    local backup_dir="$4"
    local restart_timeout="$5"
    local rpc_healthcheck="$6"
    local rollback_on_fail="$7"

    local max_n
    max_n=$(get_max_sn_num) || die "No sn*.service found"

    local rpc_check="false"
    if [[ "$rpc_healthcheck" == "true" ]]; then
        rpc_check="true"
    elif [[ "$rpc_healthcheck" == "auto" ]]; then
        if need_cmd curl && need_cmd jq; then
            rpc_check="true"
        fi
    fi

    local bkp
    bkp=$(backup_binaries "$backup_dir")
    echo "binaries backup: $bkp"

    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf -- "$tmpdir"' RETURN

    if [[ -n "$my_endpoint" ]]; then
        install_core_from_endpoint_or_fail "$my_endpoint" "$tmpdir"
        install_storage_from_endpoint_or_warn "$my_endpoint" "$tmpdir" || true
    else
        install_core_from_github_or_fail "$github_release" "$tmpdir"
        install_storage_from_release_or_warn "$storage_release" "$tmpdir" || true
    fi

    systemctl daemon-reload

    if ! restart_pair_checked 1 "$restart_timeout" "$rpc_check"; then
        echo "update gate failed on sn1/st1"
        if [[ "$rollback_on_fail" == "true" ]]; then
            restore_binaries_from_tar "$bkp" || die "rollback failed"
            systemctl daemon-reload
        fi
        die "aborting update (sn1/st1 not ok)"
    fi

    local n
    for n in $(seq 2 "$max_n"); do
        if ! restart_pair_checked "$n" "$restart_timeout" "$rpc_check"; then
            echo "update failed on sn${n}/st${n}"
            if [[ "$rollback_on_fail" == "true" ]]; then
                restore_binaries_from_tar "$bkp" || die "rollback failed"
                systemctl daemon-reload
            fi
            die "aborting update (sn${n}/st${n} not ok)"
        fi
    done

    echo "update complete"
}

# ---------------- Port computation ----------------

compute_ports_for_batchpos() {
    local base_port="$1"
    local step="$2"
    local k="$3"

    local offset=$(( k * step ))
    PORT_P2P=$((base_port + P2P_OFFSET + offset))
    PORT_RPC=$((base_port + RPC_OFFSET + offset))
    PORT_SS=$((base_port + SS_OFFSET + offset))
    PORT_ZMQ=$((base_port + ZMQ_OFFSET + offset))
    PORT_ARQNET=$((base_port + ARQNET_OFFSET + offset))
}

choose_step_for_new_batch() {
    local first_p2p="$1"
    local want_step="$2"
    local count="$3"

    assert_port_range "$first_p2p"

    if [[ "$count" -le 1 ]]; then
        CHOSEN_STEP="$want_step"
        return 0
    fi

    local max_step
    max_step=$(( (65535 - first_p2p) / (count - 1) ))
    if [[ "$max_step" -lt 1 ]]; then
        die "Cannot allocate ports for $count nodes starting at p2p=$first_p2p within 1..65535"
    fi

    if [[ "$want_step" -le "$max_step" ]]; then
        CHOSEN_STEP="$want_step"
        return 0
    fi

    local step_adj="$max_step"
    if [[ "$step_adj" -ge 1000 ]]; then
        step_adj=$(( (step_adj / 1000) * 1000 ))
        [[ "$step_adj" -ge 1 ]] || step_adj="$max_step"
    fi

    local min_safe_step=$((ARQNET_OFFSET + 1))
    if [[ "$step_adj" -lt "$min_safe_step" ]]; then
        step_adj="$max_step"
    fi
    if [[ "$step_adj" -lt "$min_safe_step" ]]; then
        die "Max step too small (${max_step}) for offsets"
    fi

    CHOSEN_STEP="$step_adj"
    return 0
}

check_ports_free_for_new_batch() {
    local base_port="$1"
    local step="$2"
    local count="$3"
    local open_arqnet="$4"
    local open_zmq_to_net="$5"

    local k
    for k in $(seq 0 $((count - 1))); do
        compute_ports_for_batchpos "$base_port" "$step" "$k"

        local to_check=("$PORT_P2P" "$PORT_RPC" "$PORT_SS")
        if [[ "$open_arqnet" == "true" ]]; then
            to_check+=("$PORT_ARQNET")
        fi
        if [[ "$open_zmq_to_net" == "true" ]]; then
            to_check+=("$PORT_ZMQ")
        fi
        assert_ports_free "${to_check[@]}"
    done
}

# ---------------- Generate systemd services (batch) ----------------

generate_services_for_new_batch() {
    local output_dir="$1"
    local public_ip="$2"
    local first_node_num="$3"
    local count="$4"
    local base_port="$5"
    local step="$6"
    local enable_arqnet="$7"
    local enable_zmq="$8"
    local zmq_bind_ip="$9"

    mkdir -p "$output_dir"

    local k node_num
    for k in $(seq 0 $((count - 1))); do
        node_num=$((first_node_num + k))

        compute_ports_for_batchpos "$base_port" "$step" "$k"
        local p2p_port="$PORT_P2P"
        local rpc_port="$PORT_RPC"
        local ss_port="$PORT_SS"
        local zmq_port="$PORT_ZMQ"
        local arqnet_port="$PORT_ARQNET"

        local sn_dir="$BASE_DATA_DIR/arqma_d/SN${node_num}"
        local st_dir="$BASE_DATA_DIR/arqma_storage/ST${node_num}"
        mkdir -p "$sn_dir" "$st_dir"
        chown -R "$SN_USER:$SN_GROUP" "$sn_dir"
        chown -R "$ST_USER:$ST_GROUP" "$st_dir"

        local args=(
            "--rpc-bind-ip" "127.0.0.1"
            "--rpc-bind-port" "$rpc_port"
            "--p2p-bind-port" "$p2p_port"
            "--service-node"
            "--sn-ip" "$public_ip"
            "--ss-port" "$ss_port"
            "--data-dir" "$sn_dir"
            "--pidfile" "/run/arqmad${node_num}/arqmad${node_num}.pid"
        )

        if [[ "$enable_zmq" == "true" ]]; then
            args+=("--zmq-enabled" "--zmq-rpc-bind-ip" "$zmq_bind_ip" "--zmq-rpc-bind-port" "$zmq_port")
        else
            args+=("--zmq-rpc-bind-port" "$zmq_port")
        fi

        if [[ "$enable_arqnet" == "true" ]]; then
            args+=("--arqnet-port" "$arqnet_port")
        fi

        local args_no_ni=("${args[@]}")
        args+=("--non-interactive")

        local manual_cmd="${ARQMAD_BIN} ${args_no_ni[*]}"

        cat > "$output_dir/sn${node_num}.service" <<EOF
[Unit]
Description=Arqmad Service Node ${node_num}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SN_USER}
Group=${SN_GROUP}

RuntimeDirectory=arqmad${node_num}
RuntimeDirectoryMode=0750
PIDFile=/run/arqmad${node_num}/arqmad${node_num}.pid

ExecStart=${ARQMAD_BIN} ${args[*]}

# Manual (no non-interactive):
# systemctl stop sn${node_num}.service && sudo -u ${SN_USER} ${manual_cmd}

Restart=on-failure
RestartSec=60
KillSignal=SIGINT
StandardOutput=journal
StandardError=journal
SyslogIdentifier=arqmad${node_num}

[Install]
WantedBy=multi-user.target
EOF

        cat > "$output_dir/st${node_num}.service" <<EOF
[Unit]
Description=Arqma Storage Node ${node_num}
After=network-online.target sn${node_num}.service
Wants=network-online.target

[Service]
Type=simple
User=${ST_USER}
Group=${ST_GROUP}

RuntimeDirectory=arqstorage${node_num}
RuntimeDirectoryMode=0750
PIDFile=/run/arqstorage${node_num}/arqstorage${node_num}.pid

ExecStart=${ARQSTORAGE_BIN} ${public_ip} ${ss_port} --arqmad-rpc-port ${rpc_port} --arqmad-rpc-ip 127.0.0.1 --data-dir ${st_dir}

Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=arqma-storage${node_num}

[Install]
WantedBy=multi-user.target
EOF
    done
}

install_new_services_only() {
    local generated_dir="$1"
    shift
    local units=("$@")
    [[ ${#units[@]} -ge 1 ]] || die "install_new_services_only: no units"

    local u
    for u in "${units[@]}"; do
        local src="${generated_dir}/${u}"
        local dst="/etc/systemd/system/${u}"
        [[ -f "$src" ]] || die "Missing generated unit: $src"
        if [[ -f "$dst" ]]; then
            die "Refusing to overwrite existing unit: $dst"
        fi
        cp -a "$src" "$dst"
    done

    systemctl daemon-reload
}

enable_services_batch() {
    local first_node_num="$1"
    local count="$2"
    local k node_num
    for k in $(seq 0 $((count - 1))); do
        node_num=$((first_node_num + k))
        systemctl enable "sn${node_num}.service" >/dev/null 2>&1 || true
        systemctl enable "st${node_num}.service" >/dev/null 2>&1 || true
    done
}

stop_services_batch_safe() {
    local first_node_num="$1"
    local count="$2"
    local k node_num
    for k in $(seq 0 $((count - 1))); do
        node_num=$((first_node_num + k))
        systemctl stop "sn${node_num}.service" >/dev/null 2>&1 || true
        systemctl stop "st${node_num}.service" >/dev/null 2>&1 || true
    done
}

start_services_batch() {
    local first_node_num="$1"
    local count="$2"
    local k node_num
    for k in $(seq 0 $((count - 1))); do
        node_num=$((first_node_num + k))
        systemctl start "sn${node_num}.service"
        systemctl start "st${node_num}.service" || true
    done
}

# ---------------- Firewall ----------------

configure_firewall_ports_for_new_batch() {
    local first_node_num="$1"
    local count="$2"
    local base_port="$3"
    local step="$4"
    local enable_arqnet="$5"
    local open_zmq_to_net="$6"

    if command -v ufw >/dev/null 2>&1; then
        echo "UFW detected. Opening required ports..."

        if ! ufw status 2>/dev/null | grep -qE '(^|[[:space:]])22/tcp[[:space:]]+ALLOW'; then
            echo ""
            echo "WARNING: No explicit UFW ALLOW rule for 22/tcp detected."
            echo "If you enable UFW without SSH allow rule, you may lose access."
            echo ""
        fi

        local k node_num
        for k in $(seq 0 $((count - 1))); do
            node_num=$((first_node_num + k))
            compute_ports_for_batchpos "$base_port" "$step" "$k"

            ufw_allow "$PORT_P2P" "tcp" "Service_Node_P2P${node_num}"
            ufw_allow "$PORT_SS" "tcp" "Storage_Node${node_num}"

            if [[ "$enable_arqnet" == "true" ]]; then
                ufw_allow "$PORT_ARQNET" "tcp" "Service_Node_Arqnet${node_num}"
            fi

            if [[ "$open_zmq_to_net" == "true" ]]; then
                ufw_allow "$PORT_ZMQ" "tcp" "Service_Node_ZMQ${node_num}"
            fi
        done

        echo "UFW rules added"
    else
        echo ""
        echo "WARNING: No firewall (UFW) detected!"
        echo ""
        echo "Suggested UFW setup:"
        echo "  apt install ufw"
        echo ""
        echo "  ufw allow 22/tcp"
        echo "  ufw logging off"
        echo "  ufw enable"
        echo ""
    fi
}

# ---------------- Seeding (lmdb only) ----------------

seed_lmdb_to_new_nodes() {
    local seed_n="$1"
    local first_new="$2"
    local count="$3"
    local timeout="$4"
    local reserve_ratio="$5"

    local seed_unit="sn${seed_n}.service"
    local seed_lmdb="$BASE_DATA_DIR/arqma_d/SN${seed_n}/lmdb"

    [[ -d "$seed_lmdb" ]] || die "Seed lmdb not found: $seed_lmdb"

    check_space_for_seeds "$seed_lmdb" "$BASE_DATA_DIR/arqma_d" "$count" "$reserve_ratio"

    echo "Stopping new target services (if any running)..."
    stop_services_batch_safe "$first_new" "$count"

    echo "Stopping seed service: $seed_unit"
    systemctl stop "$seed_unit" || true
    if ! wait_unit_inactive "$seed_unit" "$timeout"; then
        die "Seed service $seed_unit did not stop within ${timeout}s"
    fi

    echo "Seeding lmdb/ from SN${seed_n} to new nodes..."
    local k node_num tgt
    for k in $(seq 0 $((count - 1))); do
        node_num=$((first_new + k))
        tgt="$BASE_DATA_DIR/arqma_d/SN${node_num}/lmdb"
        mkdir -p "$tgt"
        rsync -aH --delete "$seed_lmdb"/ "$tgt"/
        chown -R "$SN_USER:$SN_GROUP" "$tgt"
    done

    echo "Starting seed service: $seed_unit"
    systemctl start "$seed_unit"

    echo "Starting new services..."
    start_services_batch "$first_new" "$count"
}

# ---------------- Add-mode ----------------

detect_existing_layout() {
    local dir="/etc/systemd/system"
    local f
    local nums=()
    local p2p_by_num=()
    local rpc_by_num=()
    local ss_by_num=()
    local arqnet_by_num=()
    local public_ip_by_num=()
    local zmq_enabled_by_num=()
    local zmq_bind_ip_by_num=()

    shopt -s nullglob
    for f in "$dir"/sn*.service; do
        [[ "$f" =~ /sn([0-9]+)\.service$ ]] || continue
        local n="${BASH_REMATCH[1]}"

        local unit="sn${n}.service"
        local exec
        exec=$(get_execstart_line "$unit")
        [[ -n "$exec" ]] || continue

        local p2p rpc ss arqnet snip zenabled zbind
        p2p=$(awk 'match($0, /--p2p-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        rpc=$(awk 'match($0, /--rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        ss=$(awk 'match($0, /--ss-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        arqnet=$(awk 'match($0, /--arqnet-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        snip=$(awk 'match($0, /--sn-ip[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")

        if grep -q -- '--zmq-enabled' <<<"$exec"; then
            zenabled="true"
        else
            zenabled="false"
        fi
        zbind=$(awk 'match($0, /--zmq-rpc-bind-ip[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")

        nums+=("$n")
        p2p_by_num[$n]="${p2p:-}"
        rpc_by_num[$n]="${rpc:-}"
        ss_by_num[$n]="${ss:-}"
        arqnet_by_num[$n]="${arqnet:-}"
        public_ip_by_num[$n]="${snip:-}"
        zmq_enabled_by_num[$n]="${zenabled:-false}"
        zmq_bind_ip_by_num[$n]="${zbind:-127.0.0.1}"
    done
    shopt -u nullglob

    [[ ${#nums[@]} -gt 0 ]] || die "Cannot detect existing layout: no parsable sn*.service"

    IFS=$'\n' nums=($(printf '%s\n' "${nums[@]}" | sort -n)); unset IFS
    local min_n="${nums[0]}"
    local max_n="${nums[-1]}"

    local base_p2p="${p2p_by_num[$min_n]}"
    local base_rpc="${rpc_by_num[$min_n]}"
    local base_ss="${ss_by_num[$min_n]}"
    local base_arqnet="${arqnet_by_num[$min_n]}"
    local public_ip="${public_ip_by_num[$min_n]}"

    [[ -n "$base_p2p" ]] || die "Cannot detect p2p port from sn$min_n"
    [[ -n "$base_rpc" ]] || die "Cannot detect rpc port from sn$min_n"
    [[ -n "$base_ss" ]] || die "Cannot detect ss port from sn$min_n"
    [[ -n "$public_ip" ]] || die "Cannot detect sn-ip from sn$min_n"

    local step=1000
    if [[ ${#nums[@]} -ge 2 ]]; then
        local n2="${nums[1]}"
        local p2="${p2p_by_num[$n2]}"
        if [[ -n "$p2" ]]; then
            local diff=$((p2 - base_p2p))
            if [[ $diff -gt 0 ]]; then
                step=$diff
            fi
        fi
    fi

    EXIST_MIN_N="$min_n"
    EXIST_MAX_N="$max_n"
    EXIST_STEP="$step"
    EXIST_BASE_P2P="$base_p2p"
    EXIST_BASE_RPC="$base_rpc"
    EXIST_BASE_SS="$base_ss"
    EXIST_BASE_ARQNET="$base_arqnet"
    EXIST_PUBLIC_IP="$public_ip"

    if [[ -n "${base_arqnet:-}" ]]; then
        EXIST_ARQNET_PRESENT="true"
    else
        EXIST_ARQNET_PRESENT="false"
    fi

    if [[ "${zmq_enabled_by_num[$min_n]:-false}" == "true" ]]; then
        EXIST_ZMQ_PRESENT="true"
    else
        EXIST_ZMQ_PRESENT="false"
    fi
    EXIST_ZMQ_BIND_IP="${zmq_bind_ip_by_num[$min_n]:-127.0.0.1}"

    local u g
    u=$(get_unit_user "sn${min_n}.service")
    g=$(get_unit_group "sn${min_n}.service")
    [[ -n "$u" ]] && SN_USER="$u"
    [[ -n "$g" ]] && SN_GROUP="$g"

    u=$(get_unit_user "st${min_n}.service" 2>/dev/null || true)
    g=$(get_unit_group "st${min_n}.service" 2>/dev/null || true)
    [[ -n "$u" ]] && ST_USER="$u"
    [[ -n "$g" ]] && ST_GROUP="$g"
}

run_add_mode() {
    local add_pairs="$1"
    local seed_from="$2"
    local seed_timeout="$3"
    local output_dir="$4"
    local force_overwrite="$5"
    local enable_arqnet="$6"
    local enable_zmq="$7"
    local zmq_bind_ip="$8"
    local backup_dir="$9"

    [[ "$add_pairs" =~ ^[0-9]+$ ]] || die "--add-pairs requires integer"
    [[ "$add_pairs" -ge 1 ]] || die "--add-pairs must be >= 1"
    [[ "$seed_from" =~ ^[0-9]+$ ]] || die "--seed-from requires integer"
    [[ "$seed_from" -ge 1 ]] || die "--seed-from must be >= 1"

    detect_existing_layout

    echo "Detected existing layout:"
    echo "  existing range: sn${EXIST_MIN_N}..sn${EXIST_MAX_N}"
    echo "  step: ${EXIST_STEP}"
    echo "  base p2p (sn${EXIST_MIN_N}): ${EXIST_BASE_P2P}"
    echo "  base rpc (sn${EXIST_MIN_N}): ${EXIST_BASE_RPC}"
    echo "  base ss  (sn${EXIST_MIN_N}): ${EXIST_BASE_SS}"
    echo "  base arqnet (sn${EXIST_MIN_N}): ${EXIST_BASE_ARQNET:-off}"
    echo "  public ip (sn${EXIST_MIN_N}): ${EXIST_PUBLIC_IP}"
    echo "  sn user/group: ${SN_USER}:${SN_GROUP}"
    echo "  st user/group: ${ST_USER}:${ST_GROUP}"

    local first_new=$((EXIST_MAX_N + 1))
    local count="$add_pairs"
    local last_new=$((first_new + count - 1))
    echo "Will add nodes: sn${first_new}..sn${last_new}"

    local pub_ip="$EXIST_PUBLIC_IP"
    if ! [[ "$pub_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        pub_ip=$(get_public_ip)
        if ! [[ "$pub_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if is_tty; then
                read_or_fail "Enter public IPv4 for --sn-ip: " pub_ip
            else
                die "Existing sn-ip invalid and auto-detect failed"
            fi
        fi
        if is_tty; then
            echo "Detected public IP: $pub_ip"
            if ! confirm_or_default_no "Use this for new nodes? [y/N]: "; then
                read_or_fail "Enter desired public IPv4: " pub_ip
            fi
        fi
    fi

    local arqnet_for_new="$enable_arqnet"
    if [[ "$enable_arqnet" == "auto" ]]; then
        arqnet_for_new="$EXIST_ARQNET_PRESENT"
    fi

    local zmq_for_new="$enable_zmq"
    if [[ "$enable_zmq" == "auto" ]]; then
        zmq_for_new="$EXIST_ZMQ_PRESENT"
    fi

    local zmq_bind_for_new="$zmq_bind_ip"
    if [[ "$zmq_bind_ip" == "auto" ]]; then
        zmq_bind_for_new="$EXIST_ZMQ_BIND_IP"
        [[ -n "$zmq_bind_for_new" ]] || zmq_bind_for_new="127.0.0.1"
    fi

    local open_zmq_to_net="false"
    if [[ "$zmq_for_new" == "true" && "$zmq_bind_for_new" != "127.0.0.1" ]]; then
        open_zmq_to_net="true"
    fi

    local first_new_p2p=$((EXIST_BASE_P2P + ( (first_new - 1) * EXIST_STEP )))
    assert_port_range "$first_new_p2p"

    choose_step_for_new_batch "$first_new_p2p" "$EXIST_STEP" "$count"
    local step_new="$CHOSEN_STEP"
    if [[ "$step_new" -ne "$EXIST_STEP" ]]; then
        echo "NOTE: Existing step=${EXIST_STEP} would exceed max port; using reduced step for new nodes: ${step_new}"
    fi

    local base_port_new=$((first_new_p2p - P2P_OFFSET))

    ensure_users_and_dirs

    echo "Checking target directories..."
    local k node_num sn_dir st_dir
    for k in $(seq 0 $((count - 1))); do
        node_num=$((first_new + k))
        sn_dir="$BASE_DATA_DIR/arqma_d/SN${node_num}"
        st_dir="$BASE_DATA_DIR/arqma_storage/ST${node_num}"
        mkdir -p "$sn_dir" "$st_dir"

        if [[ -n "$(ls -A "$sn_dir" 2>/dev/null || true)" || -n "$(ls -A "$st_dir" 2>/dev/null || true)" ]]; then
            if [[ "$force_overwrite" != "true" ]]; then
                die "Target dir not empty: $sn_dir or $st_dir"
            fi
        fi
    done

    echo "Checking port range and collisions for new nodes..."
    check_ports_free_for_new_batch "$base_port_new" "$step_new" "$count" "$arqnet_for_new" "$open_zmq_to_net"

    echo "Creating backups before installing new services..."
    local svc_bkp key_bkp
    svc_bkp=$(backup_existing_services "$backup_dir")
    key_bkp=$(backup_keys_and_certs "$backup_dir")
    echo "  services backup: $svc_bkp"
    echo "  keys/certs backup: $key_bkp"

    local gen_dir
    gen_dir=$(mktemp -d)
    trap 'rm -rf -- "$gen_dir"' RETURN

    generate_services_for_new_batch "$gen_dir" "$pub_ip" "$first_new" "$count" "$base_port_new" "$step_new" "$arqnet_for_new" "$zmq_for_new" "$zmq_bind_for_new"

    mkdir -p "$output_dir"
    cp -a "$gen_dir"/*.service "$output_dir"/

    local units=()
    for k in $(seq 0 $((count - 1))); do
        node_num=$((first_new + k))
        units+=("sn${node_num}.service")
        units+=("st${node_num}.service")
    done

    install_new_services_only "$gen_dir" "${units[@]}"
    enable_services_batch "$first_new" "$count"

    configure_firewall_ports_for_new_batch "$first_new" "$count" "$base_port_new" "$step_new" "$arqnet_for_new" "$open_zmq_to_net"

    seed_lmdb_to_new_nodes "$seed_from" "$first_new" "$count" "$seed_timeout" "$RESERVE_RATIO_DEFAULT"

    echo "Add-pairs complete."
}

# ---------------- Fresh-mode ----------------

run_fresh_mode() {
    local base_data_dir="$1"
    local my_endpoint="$2"
    local sync_method="$3"
    local info_file="$4"
    local output_dir="$5"
    local enable_arqnet="$6"
    local enable_zmq="$7"
    local zmq_bind_ip="$8"
    local blockchain_url="$9"
    local github_release="${10}"
    local storage_release="${11}"
    local force_overwrite="${12}"
    local backup_dir="${13}"

    local cpu_cores ram_gb max_nodes_cpu max_nodes_ram max_nodes
    cpu_cores=$(nproc)
    ram_gb=$(( $(free -m | awk '/^Mem:/{print $2}') / 1024 ))
    max_nodes_cpu=$(( cpu_cores / 2 ))
    max_nodes_ram=$(( ram_gb / 4 ))
    max_nodes=$(( max_nodes_cpu < max_nodes_ram ? max_nodes_cpu : max_nodes_ram ))
    [[ $max_nodes -ge 1 ]] || die "Insufficient resources (min 2 cores + 4GB RAM)"

    echo "System resources:"
    echo "  CPU cores: $cpu_cores"
    echo "  RAM: ${ram_gb}GB"
    echo "  Recommended max nodes: $max_nodes"
    echo "NOTE: Recommended max 10 nodes per public IP."

    local num_pairs
    while true; do
        read_or_fail "How many service pairs do you want to generate? (max $max_nodes): " num_pairs
        if ! [[ "$num_pairs" =~ ^[0-9]+$ ]] || [[ "$num_pairs" -le 0 ]]; then
            echo "Invalid number."
            continue
        fi
        if [[ "$num_pairs" -gt "$max_nodes" ]]; then
            echo "WARNING: Requested $num_pairs exceeds recommended $max_nodes"
            echo "NOTE: Recommended max 10 nodes per public IP; too many nodes may be rejected/deregistered."
            if confirm_or_default_no "Continue anyway? [y/N]: "; then
                break
            else
                continue
            fi
        else
            break
        fi
    done

    local data_exists="false"
    local i
    for i in $(seq 1 "$num_pairs"); do
        if [[ -d "$base_data_dir/arqma_d/SN$i" ]] && [[ -n "$(ls -A "$base_data_dir/arqma_d/SN$i" 2>/dev/null || true)" ]]; then
            echo "WARNING: $base_data_dir/arqma_d/SN$i contains data"
            data_exists="true"
        fi
        if [[ -d "$base_data_dir/arqma_storage/ST$i" ]] && [[ -n "$(ls -A "$base_data_dir/arqma_storage/ST$i" 2>/dev/null || true)" ]]; then
            echo "WARNING: $base_data_dir/arqma_storage/ST$i contains data"
            data_exists="true"
        fi
    done

    if [[ "$data_exists" == "true" && "$force_overwrite" != "true" ]]; then
        die "Existing data found. Use --yes-i-really-know-what-i-am-doing to proceed."
    fi

    local public_ip
    public_ip=$(get_public_ip)
    if ! [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        read_or_fail "Enter public IPv4: " public_ip
    fi
    echo "Detected public IP: $public_ip"
    if ! confirm_or_default_no "Is this correct? [y/N]: "; then
        read_or_fail "Enter desired public IPv4: " public_ip
    fi

    if [[ "$sync_method" == "fast" || "$sync_method" == "dangerous" ]]; then
        need_cmd tmux || ensure_packages tmux
        need_cmd tmux || die "tmux missing after install"
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf -- "$tmpdir"' RETURN

    if [[ -n "$my_endpoint" ]]; then
        install_core_from_endpoint_or_fail "$my_endpoint" "$tmpdir"
        install_storage_from_endpoint_or_warn "$my_endpoint" "$tmpdir" || true
    else
        install_core_from_github_or_fail "$github_release" "$tmpdir"
        install_storage_from_release_or_warn "$storage_release" "$tmpdir" || true
    fi

    if [[ -f "$ARQMAD_BIN" ]]; then chown root:root "$ARQMAD_BIN" 2>/dev/null || true; chmod 0755 "$ARQMAD_BIN" || true; fi
    if [[ -f "$ARQIMPORT_BIN" ]]; then chown root:root "$ARQIMPORT_BIN" 2>/dev/null || true; chmod 0755 "$ARQIMPORT_BIN" || true; fi
    if [[ -f "$ARQSTORAGE_BIN" ]]; then chown root:root "$ARQSTORAGE_BIN" 2>/dev/null || true; chmod 0755 "$ARQSTORAGE_BIN" || true; fi

    SN_USER="$DEFAULT_SN_USER"
    SN_GROUP="$DEFAULT_SN_GROUP"
    ST_USER="$DEFAULT_ST_USER"
    ST_GROUP="$DEFAULT_ST_GROUP"

    BASE_DATA_DIR="$base_data_dir"
    ensure_users_and_dirs

    echo "Creating backups before installing services..."
    local svc_bkp key_bkp
    svc_bkp=$(backup_existing_services "$backup_dir")
    key_bkp=$(backup_keys_and_certs "$backup_dir")
    echo "  services backup: $svc_bkp"
    echo "  keys/certs backup: $key_bkp"

    local base_port="$BASE_PORT_DEFAULT"
    local step=1000

    echo "Checking port range and collisions..."
    local open_zmq_to_net="false"
    if [[ "$enable_zmq" == "true" && "$zmq_bind_ip" != "127.0.0.1" ]]; then
        open_zmq_to_net="true"
    fi
    check_ports_free_for_new_batch "$base_port" "$step" "$num_pairs" "$enable_arqnet" "$open_zmq_to_net"

    local gen_dir
    gen_dir=$(mktemp -d)
    trap 'rm -rf -- "$gen_dir"' RETURN

    generate_services_for_new_batch "$gen_dir" "$public_ip" 1 "$num_pairs" "$base_port" "$step" "$enable_arqnet" "$enable_zmq" "$zmq_bind_ip"

    mkdir -p "$output_dir"
    cp -a "$gen_dir"/*.service "$output_dir"/

    local units=()
    for i in $(seq 1 "$num_pairs"); do
        units+=("sn${i}.service")
        units+=("st${i}.service")
    done

    install_new_services_only "$gen_dir" "${units[@]}"
    enable_services_batch 1 "$num_pairs"

    configure_firewall_ports_for_new_batch 1 "$num_pairs" "$base_port" "$step" "$enable_arqnet" "$open_zmq_to_net"

    case "$sync_method" in
        safe)
            systemctl start sn1.service
            echo "SN1 started for safe sync"
            echo "Monitor: journalctl -fu sn1"
            echo "After sync you can start remaining nodes: systemctl start sn{2..$num_pairs}"
            ;;
        fast)
            cd /tmp || die "Cannot cd /tmp"
            download_with_progress "$blockchain_url" blockchain.raw
            local session="bc-import"
            if tmux has-session -t "$session" 2>/dev/null; then
                session="bc-import-$(date +%s)"
            fi
            tmux new-session -d -s "$session" "$ARQIMPORT_BIN --data-dir $base_data_dir/arqma_d/SN1 --input-file /tmp/blockchain.raw"
            echo "Import started in tmux session: $session"
            echo "After import you can start remaining nodes: systemctl start sn{2..$num_pairs}"
            ;;
        dangerous)
            cd /tmp || die "Cannot cd /tmp"
            download_with_progress "$blockchain_url" blockchain.raw
            local session="bc-import"
            if tmux has-session -t "$session" 2>/dev/null; then
                session="bc-import-$(date +%s)"
            fi
            tmux new-session -d -s "$session" "$ARQIMPORT_BIN --data-dir $base_data_dir/arqma_d/SN1 --input-file /tmp/blockchain.raw --fast-block-sync 1 --no-verify 1"
            echo "Dangerous import started in tmux session: $session"
            echo "After import you can start remaining nodes: systemctl start sn{2..$num_pairs}"
            ;;
        *)
            die "Unknown sync method: $sync_method"
            ;;
    esac

    cat > "$info_file" <<EOF
ARQMA SETUP INFO
Generated: $(date)

NOTE:
  Recommended max 10 nodes per public IP. Too many nodes or insufficient resources may cause deregistration.

Base data dir: $base_data_dir
Public IP: $public_ip
Pairs: $num_pairs
Base port: $base_port
Step: $step

Service users/groups (created if missing):
  Service Nodes (sn*.service): user=$SN_USER group=$SN_GROUP
  Storage Nodes (st*.service): user=$ST_USER group=$ST_GROUP

URLs:
  github_release(core): $github_release
  storage_release: $storage_release
  blockchain_url: $blockchain_url

Per-node ports:
  P2P:    base+0 (open)
  RPC:    base+1 (localhost only)
  SS:     base+3 (open)
  ZMQ:    base+4 (open only if enabled and bind-ip != 127.0.0.1)
  ARQNET: base+5 (open if enabled)

Flags:
  arqnet: $enable_arqnet
  zmq:    $enable_zmq
  zmq_bind_ip: $zmq_bind_ip

Backups created:
  services: $svc_bkp
  keys/certs: $key_bkp

Important keys to backup (per SN):
EOF

    for i in $(seq 1 "$num_pairs"); do
        cat >> "$info_file" <<EOF
  $base_data_dir/arqma_d/SN$i/key
  $base_data_dir/arqma_d/SN$i/key_ed25519
EOF
    done

    cat >> "$info_file" <<EOF

Storage Node cert/key locations (per ST):
EOF

    for i in $(seq 1 "$num_pairs"); do
        cat >> "$info_file" <<EOF
  $base_data_dir/arqma_storage/ST$i/cert.pem
  $base_data_dir/arqma_storage/ST$i/key.pem
EOF
    done

    cat >> "$info_file" <<EOF

Service management:
  Status SN: systemctl status sn{1..$num_pairs}
  Logs SN:   journalctl -fu sn{1..$num_pairs}
  Stop SN:   systemctl stop sn{1..$num_pairs}
  Start SN:  systemctl start sn{1..$num_pairs}

  Status ST: systemctl status st{1..$num_pairs}
  Logs ST:   journalctl -fu st{1..$num_pairs}
  Stop ST:   systemctl stop st{1..$num_pairs}
  Start ST:  systemctl start st{1..$num_pairs}

Report existing config:
  $0 --report-existing

Add nodes (example add 2, seed from sn1):
  $0 --add-pairs 2 --seed-from 1

Update binaries:
  $0 --update-binaries
  $0 --update-binaries --rpc-healthcheck --rollback-on-fail
  $0 --update-binaries --my-endpoint http://your.endpoint/path --rpc-healthcheck --rollback-on-fail

EOF

    echo "Setup complete. Info saved to: $info_file"
}

# ---------------- CLI parsing ----------------

MODE="auto"

FORCE_OVERWRITE="false"
MY_ENDPOINT=""
SYNC_METHOD="safe"

ENABLE_ARQNET="auto"
ENABLE_ZMQ="auto"
ZMQ_BIND_IP="auto"

SEED_FROM=1
SEED_TIMEOUT="$SEED_TIMEOUT_DEFAULT"

RESTART_TIMEOUT="$RESTART_TIMEOUT_DEFAULT"
RPC_HEALTHCHECK="auto"
ROLLBACK_ON_FAIL="false"

BASE_DATA_DIR="$BASE_DATA_DIR_DEFAULT"
BLOCKCHAIN_URL="$BLOCKCHAIN_URL_DEFAULT"
GITHUB_RELEASE="$GITHUB_RELEASE_DEFAULT"
STORAGE_RELEASE="$STORAGE_RELEASE_DEFAULT"
INFO_FILE="$INFO_FILE_DEFAULT"
OUTPUT_DIR="$OUTPUT_DIR_DEFAULT"

BACKUP_DIR_DEFAULT="/root/arqma-backups"
BACKUP_DIR="$BACKUP_DIR_DEFAULT"

ADD_PAIRS=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --report-existing)
            MODE="report"
            shift
            ;;
        --add-pairs)
            [[ $# -ge 2 ]] || die "--add-pairs requires N"
            ADD_PAIRS="$2"
            MODE="add"
            shift 2
            ;;
        --update-binaries)
            MODE="update"
            shift
            ;;
        --seed-from)
            [[ $# -ge 2 ]] || die "--seed-from requires N"
            SEED_FROM="$2"
            shift 2
            ;;
        --seed-timeout)
            [[ $# -ge 2 ]] || die "--seed-timeout requires seconds"
            SEED_TIMEOUT="$2"
            shift 2
            ;;
        --restart-timeout)
            [[ $# -ge 2 ]] || die "--restart-timeout requires seconds"
            RESTART_TIMEOUT="$2"
            shift 2
            ;;
        --rpc-healthcheck)
            RPC_HEALTHCHECK="true"
            shift
            ;;
        --no-rpc-healthcheck)
            RPC_HEALTHCHECK="false"
            shift
            ;;
        --rollback-on-fail)
            ROLLBACK_ON_FAIL="true"
            shift
            ;;
        --base-data-dir)
            [[ $# -ge 2 ]] || die "--base-data-dir requires PATH"
            BASE_DATA_DIR="$2"
            shift 2
            ;;
        --blockchain-url)
            [[ $# -ge 2 ]] || die "--blockchain-url requires URL"
            BLOCKCHAIN_URL="$2"
            shift 2
            ;;
        --github-release)
            [[ $# -ge 2 ]] || die "--github-release requires URL"
            GITHUB_RELEASE="$2"
            shift 2
            ;;
        --storage-release)
            [[ $# -ge 2 ]] || die "--storage-release requires URL"
            STORAGE_RELEASE="$2"
            shift 2
            ;;
        --my-endpoint)
            [[ $# -ge 2 ]] || die "--my-endpoint requires URL"
            MY_ENDPOINT="$2"
            shift 2
            ;;
        --sync-method)
            [[ $# -ge 2 ]] || die "--sync-method requires value"
            SYNC_METHOD="$2"
            shift 2
            ;;
        --info-file)
            [[ $# -ge 2 ]] || die "--info-file requires path"
            INFO_FILE="$2"
            shift 2
            ;;
        --output-dir)
            [[ $# -ge 2 ]] || die "--output-dir requires path"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --backup-dir)
            [[ $# -ge 2 ]] || die "--backup-dir requires path"
            BACKUP_DIR="$2"
            shift 2
            ;;
        --enable-arqnet)
            ENABLE_ARQNET="true"
            shift
            ;;
        --disable-arqnet)
            ENABLE_ARQNET="false"
            shift
            ;;
        --enable-zmq)
            ENABLE_ZMQ="true"
            shift
            ;;
        --disable-zmq)
            ENABLE_ZMQ="false"
            shift
            ;;
        --zmq-bind-ip)
            [[ $# -ge 2 ]] || die "--zmq-bind-ip requires IP"
            ZMQ_BIND_IP="$2"
            shift 2
            ;;
        --yes-i-really-know-what-i-am-doing)
            FORCE_OVERWRITE="true"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

# ---------------- System checks ----------------

if [[ $EUID -ne 0 ]]; then
    die "Must run as root (sudo)"
fi

command -v apt >/dev/null 2>&1 || die "Requires apt (Ubuntu/Debian)"
[[ "$(uname -m)" == "x86_64" ]] || die "Only tested on x86_64"

require_or_install_base_deps
setup_download_tools

# ---------------- Dispatch ----------------

if [[ "$MODE" == "report" ]]; then
    report_existing
    exit 0
fi

if [[ "$MODE" == "update" ]]; then
    run_update_mode "$MY_ENDPOINT" "$GITHUB_RELEASE" "$STORAGE_RELEASE" "$BACKUP_DIR" "$RESTART_TIMEOUT" "$RPC_HEALTHCHECK" "$ROLLBACK_ON_FAIL"
    exit 0
fi

if [[ "$MODE" == "add" ]]; then
    run_add_mode "$ADD_PAIRS" "$SEED_FROM" "$SEED_TIMEOUT" "$OUTPUT_DIR" "$FORCE_OVERWRITE" "$ENABLE_ARQNET" "$ENABLE_ZMQ" "$ZMQ_BIND_IP" "$BACKUP_DIR"
    exit 0
fi

# MODE auto:
# - no args and services exist -> dashboard
# - else -> fresh generator
if [[ "$MODE" == "auto" ]]; then
    if services_exist; then
        run_dashboard
        exit 0
    fi
fi

# Fresh mode defaults: arqnet enabled, zmq disabled, zmq bind 127.0.0.1
run_fresh_mode "$BASE_DATA_DIR" "$MY_ENDPOINT" "$SYNC_METHOD" "$INFO_FILE" "$OUTPUT_DIR" \
    "${ENABLE_ARQNET/auto/true}" \
    "${ENABLE_ZMQ/auto/false}" \
    "${ZMQ_BIND_IP/auto/127.0.0.1}" \
    "$BLOCKCHAIN_URL" \
    "$GITHUB_RELEASE" \
    "$STORAGE_RELEASE" \
    "$FORCE_OVERWRITE" \
    "$BACKUP_DIR"
