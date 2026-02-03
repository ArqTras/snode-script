#!/bin/bash

# Arqma Service Node + Storage Node Setup/Extend Script
# Ubuntu/Debian (apt), x86_64
#
# Features:
# - Fresh install/generate services (interactive).
# - Report existing sn*/st* config (no changes).
# - Add new node pairs to an already running setup:
#   - Auto-detect base ports/step from existing sn*.service
#   - Generate snN/stN services for new indices
#   - Seed new nodes by copying only lmdb/ from a chosen seed SN (default sn1)
#   - Stop only the seed SN (and the new targets), never touch other running nodes
#   - Wait for stop to complete
#   - Disk space check before copying
#   - Port collision check before starting new nodes
#
# Security/production:
# - Never copy keys; only lmdb/ is copied.
# - Refuses to proceed if target dirs contain data unless forced.
# - /usr/local/bin binaries use 0755 by default (root:root).
# - Default creates dedicated service users/groups:
#     arqd: runs Service Nodes (sn*.service)
#     arqstorage: runs Storage Nodes (st*.service)
#   This is intentional for privilege separation.
# - Firewall: opens P2P + SS + ARQNET; opens ZMQ only if enabled and bind-ip != 127.0.0.1

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

GITHUB_RELEASE_DEFAULT="https://github.com/arqma/arqma/releases/latest/download/build-depends-x86_64-linux.tar.gz"
INFO_FILE_DEFAULT="$HOME/ARQMA-setup.info"

RESERVE_RATIO_DEFAULT="0.10"

# ---------------- Helpers ----------------

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Modes:"
    echo "  (default interactive)  Generate N service pairs and optionally sync"
    echo "  --report-existing      Only report existing sn*/st* config; exit"
    echo "  --add-pairs N          Add N new service pairs to existing config"
    echo ""
    echo "Options:"
    echo "  --base-data-dir PATH        Base data dir (default: ${BASE_DATA_DIR_DEFAULT})"
    echo "  --github-release URL        GitHub release tar.gz URL (default: ${GITHUB_RELEASE_DEFAULT})"
    echo "  --my-endpoint URL           Custom endpoint for binaries"
    echo "  --info-file PATH            Setup info file path (default: ${INFO_FILE_DEFAULT})"
    echo "  --enable-arqnet             Enable arqnet per node (default: enabled)"
    echo "  --disable-arqnet            Disable arqnet per node"
    echo "  --enable-zmq                Enable ZMQ per node (default: disabled)"
    echo "  --zmq-bind-ip IP            ZMQ bind IP (default: 127.0.0.1)"
    echo "  --seed-from N               Seed new nodes from snN (default: 1) [--add-pairs]"
    echo "  --seed-timeout SEC          Wait timeout for stopping seed service (default: 180) [--add-pairs]"
    echo "  --yes-i-really-know-what-i-am-doing  Force overwrite existing data"
    echo "  -h, --help                  Show help"
    echo ""
    echo "Security note:"
    echo "  Script creates dedicated service users/groups (if missing):"
    echo "    arqd       - runs sn*.service"
    echo "    arqstorage - runs st*.service"
    echo ""
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

is_tty() {
    [[ -t 0 && -t 1 ]]
}

read_or_fail() {
    local prompt="$1"
    local __var="$2"
    local val=""
    if ! is_tty; then
        die "Non-interactive run requires all inputs via args; cannot prompt: $prompt"
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

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

ensure_packages() {
    local pkgs=("$@")
    [[ ${#pkgs[@]} -gt 0 ]] || return 0
    apt update >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt install -y "${pkgs[@]}" >/dev/null 2>&1
}

require_or_install_base_deps() {
    local missing=()

    need_cmd systemctl || die "systemd required (systemctl not found)"

    need_cmd awk || missing+=("gawk")
    need_cmd ss || missing+=("iproute2")
    need_cmd rsync || missing+=("rsync")
    need_cmd tar || missing+=("tar")

    need_cmd grep || missing+=("grep")
    need_cmd sed || missing+=("sed")
    need_cmd df || missing+=("coreutils")
    need_cmd du || missing+=("coreutils")

    if [[ ${#missing[@]} -gt 0 ]]; then
        ensure_packages "${missing[@]}"
    fi

    need_cmd awk || die "awk still missing after install"
    need_cmd ss || die "ss still missing after install"
    need_cmd rsync || die "rsync still missing after install"
    need_cmd tar || die "tar still missing after install"
    need_cmd grep || die "grep still missing after install"
    need_cmd sed || die "sed still missing after install"
    need_cmd df || die "df still missing after install"
    need_cmd du || die "du still missing after install"
}

# ---------------- Port checks ----------------

port_is_listening() {
    local port="$1"
    ss -lntH 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}$"
}

assert_ports_free() {
    local ports=("$@")
    local p
    for p in "${ports[@]}"; do
        [[ -n "$p" ]] || continue
        if port_is_listening "$p"; then
            die "Port already listening: $p"
        fi
    done
}

# ---------------- Download helpers ----------------

DOWNLOAD_TOOL=""

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

# ---------------- Size/space helpers ----------------

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
    echo "  need: $(human_gib "$need_bytes")"
    echo "  reserve: $(human_gib "$reserve_bytes") (ratio=$reserve_ratio)"
    echo "  total_required: $(human_gib "$total_bytes")"
    echo "  fs_avail: $(human_gib "$avail_bytes")"

    if [[ "$avail_bytes" -lt "$total_bytes" ]]; then
        die "Not enough free space for seeding (required=$(human_gib "$total_bytes"), avail=$(human_gib "$avail_bytes"))"
    fi
}

# ---------------- Install helpers ----------------

install_from_endpoint() {
    local endpoint="$1"
    echo "Installing from endpoint: $endpoint"
    cd /usr/local/bin/ || die "Cannot cd to /usr/local/bin"

    echo "Downloading arqmad..."
    download_file "$endpoint/arqmad" arqmad
    echo "Downloading arqma-blockchain-import..."
    download_file "$endpoint/arqma-blockchain-import" arqma-blockchain-import

    echo "Attempting to download arqma-storage..."
    if download_file "$endpoint/arqma-storage" arqma-storage 2>/dev/null; then
        :
    fi

    chown root:root arqmad arqma-blockchain-import 2>/dev/null || true
    chmod 0755 arqmad arqma-blockchain-import

    if [[ -f arqma-storage ]]; then
        chown root:root arqma-storage 2>/dev/null || true
        chmod 0755 arqma-storage
        echo "arqma-storage downloaded"
    else
        echo "arqma-storage not available at endpoint"
    fi
}

install_from_github() {
    local release_url="$1"
    local arqmad_bin="$2"
    local arqimport_bin="$3"

    echo "Installing core binaries from GitHub release..."
    echo "Downloading: $release_url"

    local temp_dir
    temp_dir=$(mktemp -d)
    cd "$temp_dir" || die "Cannot cd to temp dir"

    download_file "$release_url" arqma-release.tar.gz
    tar -xzf arqma-release.tar.gz

    find . \( -name "arqmad" -o -name "arqma-blockchain-import" \) -type f -exec sh -c '
        for file; do
            case "$(basename "$file")" in
                arqmad) cp "$file" "'"$arqmad_bin"'" ;;
                arqma-blockchain-import) cp "$file" "'"$arqimport_bin"'" ;;
            esac
        done
    ' sh {} +

    [[ -f "$arqmad_bin" ]] || die "Missing arqmad after install"
    [[ -f "$arqimport_bin" ]] || die "Missing arqma-blockchain-import after install"

    chown root:root "$arqmad_bin" "$arqimport_bin" 2>/dev/null || true
    chmod 0755 "$arqmad_bin" "$arqimport_bin"

    cd - >/dev/null 2>&1 || true
    rm -rf -- "$temp_dir"
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

sn_extract_report() {
    local exec="$1"
    local datadir p2p rpc arqnet zmq_port zmq_enabled

    datadir=$(awk 'match($0, /--data-dir[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")
    p2p=$(awk 'match($0, /--p2p-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    rpc=$(awk 'match($0, /--rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    arqnet=$(awk 'match($0, /--arqnet-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
    zmq_port=$(awk 'match($0, /--zmq-rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")

    if grep -q -- '--zmq-enabled' <<<"$exec"; then
        zmq_enabled="yes"
    else
        zmq_enabled="no"
    fi

    echo "service node data_dir: ${datadir:-unknown}"
    echo -n "sn_ports: p2p=${p2p:-?} rpc=${rpc:-?}"
    if [[ -n "${arqnet:-}" ]]; then
        echo -n " arqnet=$arqnet"
    fi
    if [[ "$zmq_enabled" == "yes" && -n "${zmq_port:-}" ]]; then
        echo -n " zmq=$zmq_port"
    fi
    echo ""
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

detect_existing_layout() {
    local dir="/etc/systemd/system"
    local f
    local nums=()
    local p2p_by_num=()
    local rpc_by_num=()
    local ss_by_num=()
    local arqnet_by_num=()
    local public_ip_by_num=()

    shopt -s nullglob
    for f in "$dir"/sn*.service; do
        [[ "$f" =~ /sn([0-9]+)\.service$ ]] || continue
        local n="${BASH_REMATCH[1]}"

        local unit="sn${n}.service"
        local exec
        exec=$(get_execstart_line "$unit")
        [[ -n "$exec" ]] || continue

        local p2p rpc ss arqnet snip
        p2p=$(awk 'match($0, /--p2p-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        rpc=$(awk 'match($0, /--rpc-bind-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        ss=$(awk 'match($0, /--ss-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        arqnet=$(awk 'match($0, /--arqnet-port[[:space:]]+([0-9]+)/, a){print a[1]}' <<<"$exec")
        snip=$(awk 'match($0, /--sn-ip[[:space:]]+([^[:space:]]+)/, a){print a[1]}' <<<"$exec")

        nums+=("$n")
        p2p_by_num[$n]="${p2p:-}"
        rpc_by_num[$n]="${rpc:-}"
        ss_by_num[$n]="${ss:-}"
        arqnet_by_num[$n]="${arqnet:-}"
        public_ip_by_num[$n]="${snip:-}"
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
}

# ---------------- Shared setup: users + dirs ----------------

ensure_users_and_dirs() {
    mkdir -p "$BASE_DATA_DIR"/{arqma_d,arqma_storage}

    id -u arqd >/dev/null 2>&1 || useradd -r -s /bin/false arqd
    id -u arqstorage >/dev/null 2>&1 || useradd -r -s /bin/false arqstorage

    chown -R arqd:arqd "$BASE_DATA_DIR/arqma_d"
    chown -R arqstorage:arqstorage "$BASE_DATA_DIR/arqma_storage"
}

# ---------------- Generate services ----------------

generate_service_files_for_range() {
    local output_dir="$1"
    local public_ip="$2"
    local first="$3"
    local last="$4"
    local base_port="$5"
    local step="$6"

    mkdir -p "$output_dir"

    local i
    for i in $(seq "$first" "$last"); do
        local offset=$(( (i - 1) * step ))

        local p2p_port=$((base_port + P2P_OFFSET + offset))
        local rpc_port=$((base_port + RPC_OFFSET + offset))
        local ss_port=$((base_port + SS_OFFSET + offset))
        local zmq_port=$((base_port + ZMQ_OFFSET + offset))
        local arqnet_port=$((base_port + ARQNET_OFFSET + offset))

        local args=(
            "--rpc-bind-ip" "127.0.0.1"
            "--rpc-bind-port" "$rpc_port"
            "--p2p-bind-port" "$p2p_port"
            "--service-node"
            "--sn-ip" "$public_ip"
            "--ss-port" "$ss_port"
            "--data-dir" "$BASE_DATA_DIR/arqma_d/SN$i"
            "--pidfile" "/run/arqmad$i/arqmad$i.pid"
            "--non-interactive"
        )

        if [[ "$ENABLE_ZMQ" == true ]]; then
            args+=("--zmq-enabled" "--zmq-rpc-bind-ip" "$ZMQ_BIND_IP" "--zmq-rpc-bind-port" "$zmq_port")
        fi
        if [[ "$ENABLE_ARQNET" == true ]]; then
            args+=("--arqnet-port" "$arqnet_port")
        fi

        cat > "$output_dir/sn$i.service" <<EOF
[Unit]
Description=Arqmad Service Node $i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=arqd
Group=arqd

RuntimeDirectory=arqmad$i
RuntimeDirectoryMode=0750
PIDFile=/run/arqmad$i/arqmad$i.pid

ExecStart=$ARQMAD_BIN ${args[*]}

Restart=on-failure
RestartSec=60
KillSignal=SIGINT
StandardOutput=journal
StandardError=journal
SyslogIdentifier=arqmad$i

[Install]
WantedBy=multi-user.target
EOF

        cat > "$output_dir/st$i.service" <<EOF
[Unit]
Description=Arqma Storage Node $i
After=network-online.target sn$i.service
Wants=network-online.target

[Service]
Type=simple
User=arqstorage
Group=arqstorage

RuntimeDirectory=arqstorage$i
RuntimeDirectoryMode=0750
PIDFile=/run/arqstorage$i/arqstorage$i.pid

ExecStart=$ARQSTORAGE_BIN $public_ip $ss_port --arqmad-rpc-port $rpc_port --arqmad-rpc-ip 127.0.0.1 --data-dir $BASE_DATA_DIR/arqma_storage/ST$i

Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=arqma-storage$i

[Install]
WantedBy=multi-user.target
EOF
    done
}

install_services_from_dir() {
    local output_dir="$1"
    cp "$output_dir"/*.service /etc/systemd/system/
    systemctl daemon-reload
}

enable_services_range() {
    local first="$1"
    local last="$2"

    local i
    for i in $(seq "$first" "$last"); do
        systemctl enable "sn$i.service" >/dev/null 2>&1 || true
        if [[ -x "$ARQSTORAGE_BIN" ]]; then
            systemctl enable "st$i.service" >/dev/null 2>&1 || true
        fi
    done
}

start_services_range() {
    local first="$1"
    local last="$2"
    local i
    for i in $(seq "$first" "$last"); do
        systemctl start "sn$i.service"
        if [[ -x "$ARQSTORAGE_BIN" ]]; then
            systemctl start "st$i.service" || true
        fi
    done
}

stop_services_range_safe() {
    local first="$1"
    local last="$2"
    local i
    for i in $(seq "$first" "$last"); do
        systemctl stop "sn$i.service" >/dev/null 2>&1 || true
        if [[ -x "$ARQSTORAGE_BIN" ]]; then
            systemctl stop "st$i.service" >/dev/null 2>&1 || true
        fi
    done
}

# ---------------- Ports math helpers ----------------

compute_ports_for_index() {
    local base_port="$1"
    local step="$2"
    local idx="$3"

    local offset=$(( (idx - 1) * step ))
    PORT_P2P=$((base_port + P2P_OFFSET + offset))
    PORT_RPC=$((base_port + RPC_OFFSET + offset))
    PORT_SS=$((base_port + SS_OFFSET + offset))
    PORT_ZMQ=$((base_port + ZMQ_OFFSET + offset))
    PORT_ARQNET=$((base_port + ARQNET_OFFSET + offset))
}

check_ports_free_for_new_range() {
    local base_port="$1"
    local step="$2"
    local first="$3"
    local last="$4"

    local open_zmq=false
    if [[ "$ENABLE_ZMQ" == true && "$ZMQ_BIND_IP" != "127.0.0.1" ]]; then
        open_zmq=true
    fi

    local i
    for i in $(seq "$first" "$last"); do
        compute_ports_for_index "$base_port" "$step" "$i"
        local to_check=("$PORT_P2P" "$PORT_SS" "$PORT_RPC")
        if [[ "$ENABLE_ARQNET" == true ]]; then
            to_check+=("$PORT_ARQNET")
        fi
        if [[ "$open_zmq" == true ]]; then
            to_check+=("$PORT_ZMQ")
        fi
        assert_ports_free "${to_check[@]}"
    done
}

# ---------------- Seeding (lmdb only) ----------------

seed_lmdb_to_new_nodes() {
    local seed_n="$1"
    local first_new="$2"
    local last_new="$3"
    local timeout="$4"
    local reserve_ratio="$5"

    local seed_unit="sn${seed_n}.service"
    local seed_dir="$BASE_DATA_DIR/arqma_d/SN${seed_n}"
    local seed_lmdb="$seed_dir/lmdb"

    [[ -d "$seed_lmdb" ]] || die "Seed lmdb not found: $seed_lmdb"

    local new_count=$(( last_new - first_new + 1 ))
    check_space_for_seeds "$seed_lmdb" "$BASE_DATA_DIR/arqma_d" "$new_count" "$reserve_ratio"

    echo "Stopping new target services (if any running)..."
    stop_services_range_safe "$first_new" "$last_new"

    echo "Stopping seed service: sn${seed_n}.service"
    systemctl stop "$seed_unit" || true
    if ! wait_unit_inactive "$seed_unit" "$timeout"; then
        die "Seed service $seed_unit did not stop within ${timeout}s"
    fi

    echo "Seeding lmdb/ from SN$seed_n to SN${first_new}..SN${last_new}"
    local i tgt
    for i in $(seq "$first_new" "$last_new"); do
        tgt="$BASE_DATA_DIR/arqma_d/SN$i/lmdb"
        mkdir -p "$tgt"
        rsync -aH --delete "$seed_lmdb"/ "$tgt"/
        chown -R arqd:arqd "$tgt"
    done

    echo "Starting seed service: $seed_unit"
    systemctl start "$seed_unit"

    echo "Starting new services..."
    start_services_range "$first_new" "$last_new"
}

# ---------------- Firewall ----------------

configure_firewall_ports() {
    local num_pairs="$1"
    local base_p2p="$2"
    local step="$3"
    local base_ss="$4"
    local base_arqnet="$5"
    local first_index="$6"

    local open_zmq=false
    if [[ "$ENABLE_ZMQ" == true && "$ZMQ_BIND_IP" != "127.0.0.1" ]]; then
        open_zmq=true
    fi

    if command -v ufw >/dev/null 2>&1; then
        echo "UFW detected. Opening required ports..."

        if ! ufw status | grep -qE '(^|[[:space:]])22/tcp[[:space:]]+ALLOW'; then
            echo ""
            echo "WARNING: No explicit UFW ALLOW rule for 22/tcp detected."
            echo "If you enable UFW without SSH allow rule, you may lose access."
            echo ""
        fi

        local k idx p2p ss arqnet base_port zmq
        for k in $(seq 0 $((num_pairs - 1))); do
            idx=$((first_index + k))
            p2p=$((base_p2p + ( (idx - 1) * step )))
            ss=$((base_ss + ( (idx - 1) * step )))
            ufw allow ${p2p}/tcp comment "Service_Node_P2P$idx" >/dev/null 2>&1
            ufw allow ${ss}/tcp comment "Storage_Node$idx" >/dev/null 2>&1

            if [[ "$ENABLE_ARQNET" == true && -n "${base_arqnet:-}" ]]; then
                arqnet=$((base_arqnet + ( (idx - 1) * step )))
                ufw allow ${arqnet}/tcp comment "Service_Node_Arqnet$idx" >/dev/null 2>&1
            fi

            if [[ "$open_zmq" == true ]]; then
                base_port=$((base_p2p - P2P_OFFSET))
                zmq=$((base_port + ZMQ_OFFSET + ( (idx - 1) * step )))
                ufw allow ${zmq}/tcp comment "Service_Node_ZMQ$idx" >/dev/null 2>&1
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
        echo "  # SSH examples:"
        echo "  ufw allow 22/tcp"
        echo "  ufw allow from ADMIN_IP to any port 22 proto tcp"
        echo "  ufw allow from ADMIN_NET_CIDR to any port 22 proto tcp"
        echo "  # Examples:"
        echo "  # ufw allow from 198.51.100.10 to any port 22 proto tcp"
        echo "  # ufw allow from 198.51.100.0/24 to any port 22 proto tcp"
        echo ""
        echo "  # Ports to open:"
        local k idx p2p ss arqnet
        for k in $(seq 0 $((num_pairs - 1))); do
            idx=$((first_index + k))
            p2p=$((base_p2p + ( (idx - 1) * step )))
            ss=$((base_ss + ( (idx - 1) * step )))
            echo "  ufw allow ${p2p}/tcp"
            echo "  ufw allow ${ss}/tcp"
            if [[ "$ENABLE_ARQNET" == true && -n "${base_arqnet:-}" ]]; then
                arqnet=$((base_arqnet + ( (idx - 1) * step )))
                echo "  ufw allow ${arqnet}/tcp"
            fi
        done
        echo ""
        echo "  ufw logging off"
        echo "  ufw enable"
        echo ""
    fi
}

# ---------------- Add mode (function) ----------------

run_add_mode() {
    local add_pairs="$1"
    local seed_from="$2"
    local seed_timeout="$3"

    [[ "$add_pairs" =~ ^[0-9]+$ ]] || die "--add-pairs requires integer"
    [[ "$add_pairs" -ge 1 ]] || die "--add-pairs must be >= 1"
    [[ "$seed_from" =~ ^[0-9]+$ ]] || die "--seed-from requires integer"
    [[ "$seed_from" -ge 1 ]] || die "--seed-from must be >= 1"

    detect_existing_layout

    echo "Detected existing layout:"
    echo "  existing range: sn${EXIST_MIN_N}..sn${EXIST_MAX_N}"
    echo "  step: $EXIST_STEP"
    echo "  base p2p (sn${EXIST_MIN_N}): $EXIST_BASE_P2P"
    echo "  base rpc (sn${EXIST_MIN_N}): $EXIST_BASE_RPC"
    echo "  base ss  (sn${EXIST_MIN_N}): $EXIST_BASE_SS"
    echo "  base arqnet (sn${EXIST_MIN_N}): ${EXIST_BASE_ARQNET:-off}"
    echo "  public ip (sn${EXIST_MIN_N}): ${EXIST_PUBLIC_IP}"

    local first_new=$((EXIST_MAX_N + 1))
    local last_new=$((EXIST_MAX_N + add_pairs))
    echo "Will add nodes: sn${first_new}..sn${last_new}"

    ensure_users_and_dirs

    echo "Checking target directories..."
    local i sn_dir st_dir
    for i in $(seq "$first_new" "$last_new"); do
        sn_dir="$BASE_DATA_DIR/arqma_d/SN$i"
        st_dir="$BASE_DATA_DIR/arqma_storage/ST$i"
        mkdir -p "$sn_dir" "$st_dir"
        if [[ -n "$(ls -A "$sn_dir" 2>/dev/null || true)" || -n "$(ls -A "$st_dir" 2>/dev/null || true)" ]]; then
            if [[ "$FORCE_OVERWRITE" == false ]]; then
                die "Target dir not empty: $sn_dir or $st_dir (use --yes-i-really-know-what-i-am-doing to force)"
            fi
        fi
    done

    local base_port=$((EXIST_BASE_P2P - P2P_OFFSET))

    echo "Checking port collisions for new nodes..."
    check_ports_free_for_new_range "$base_port" "$EXIST_STEP" "$first_new" "$last_new"

    configure_firewall_ports "$add_pairs" "$EXIST_BASE_P2P" "$EXIST_STEP" "$EXIST_BASE_SS" "${EXIST_BASE_ARQNET:-}" "$first_new"

    local output_dir="./generated_services"
    if [[ -d "$output_dir" ]]; then
        local backup_name="${output_dir}-backup-$(date +%s).tar.gz"
        tar -czf "$backup_name" "$output_dir" 2>/dev/null || true
    fi

    generate_service_files_for_range "$output_dir" "$EXIST_PUBLIC_IP" "$first_new" "$last_new" "$base_port" "$EXIST_STEP"
    install_services_from_dir "$output_dir"
    enable_services_range "$first_new" "$last_new"

    seed_lmdb_to_new_nodes "$seed_from" "$first_new" "$last_new" "$seed_timeout" "$RESERVE_RATIO_DEFAULT"

    echo "Add-pairs complete."
}

# ---------------- CLI parsing ----------------

MODE="fresh"
ADD_PAIRS=0
REPORT_ONLY=false

FORCE_OVERWRITE=false
MY_ENDPOINT=""

ENABLE_ARQNET=true
ENABLE_ZMQ=false
ZMQ_BIND_IP="127.0.0.1"

SEED_FROM=1
SEED_TIMEOUT=180

BASE_DATA_DIR="$BASE_DATA_DIR_DEFAULT"
GITHUB_RELEASE="$GITHUB_RELEASE_DEFAULT"
INFO_FILE="$INFO_FILE_DEFAULT"

while [[ $# -gt 0 ]]; do
    case $1 in
        --report-existing)
            REPORT_ONLY=true
            MODE="report"
            shift
            ;;
        --add-pairs)
            [[ $# -ge 2 ]] || die "--add-pairs requires N"
            ADD_PAIRS="$2"
            MODE="add"
            shift 2
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
        --base-data-dir)
            [[ $# -ge 2 ]] || die "--base-data-dir requires PATH"
            BASE_DATA_DIR="$2"
            shift 2
            ;;
        --github-release)
            [[ $# -ge 2 ]] || die "--github-release requires URL"
            GITHUB_RELEASE="$2"
            shift 2
            ;;
        --my-endpoint)
            [[ $# -ge 2 ]] || die "--my-endpoint requires URL"
            MY_ENDPOINT="$2"
            shift 2
            ;;
        --info-file)
            [[ $# -ge 2 ]] || die "--info-file requires path"
            INFO_FILE="$2"
            shift 2
            ;;
        --enable-arqnet)
            ENABLE_ARQNET=true
            shift
            ;;
        --disable-arqnet)
            ENABLE_ARQNET=false
            shift
            ;;
        --enable-zmq)
            ENABLE_ZMQ=true
            shift
            ;;
        --zmq-bind-ip)
            [[ $# -ge 2 ]] || die "--zmq-bind-ip requires IP"
            ZMQ_BIND_IP="$2"
            shift 2
            ;;
        --yes-i-really-know-what-i-am-doing)
            FORCE_OVERWRITE=true
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

# ---------------- Dispatch modes ----------------

if [[ "$MODE" == "report" ]]; then
    report_existing
    exit 0
fi

if [[ "$MODE" == "add" ]]; then
    run_add_mode "$ADD_PAIRS" "$SEED_FROM" "$SEED_TIMEOUT"
    exit 0
fi

# ---------------- Fresh mode (interactive) ----------------

CPU_CORES=$(nproc)
RAM_GB=$(( $(free -m | awk '/^Mem:/{print $2}') / 1024 ))
MAX_NODES_CPU=$(( CPU_CORES / 2 ))
MAX_NODES_RAM=$(( RAM_GB / 4 ))
MAX_NODES=$(( MAX_NODES_CPU < MAX_NODES_RAM ? MAX_NODES_CPU : MAX_NODES_RAM ))
[[ $MAX_NODES -ge 1 ]] || die "Insufficient resources (min 2 cores + 4GB RAM)"

echo "System resources:"
echo "  CPU cores: $CPU_CORES"
echo "  RAM: ${RAM_GB}GB"
echo "  Recommended max nodes: $MAX_NODES"

while true; do
    read_or_fail "How many service pairs do you want to generate? (max $MAX_NODES): " NUM_PAIRS
    if ! [[ "$NUM_PAIRS" =~ ^[0-9]+$ ]] || [[ "$NUM_PAIRS" -le 0 ]]; then
        echo "Invalid number."
        continue
    fi
    if [[ "$NUM_PAIRS" -gt "$MAX_NODES" ]]; then
        echo "WARNING: Requested $NUM_PAIRS exceeds recommended $MAX_NODES"
        if confirm_or_default_no "Continue anyway? [y/N]: "; then
            break
        else
            continue
        fi
    else
        break
    fi
done

DATA_EXISTS=false
for i in $(seq 1 "$NUM_PAIRS"); do
    if [[ -d "$BASE_DATA_DIR/arqma_d/SN$i" ]] && [[ -n "$(ls -A "$BASE_DATA_DIR/arqma_d/SN$i" 2>/dev/null || true)" ]]; then
        echo "WARNING: $BASE_DATA_DIR/arqma_d/SN$i contains data"
        DATA_EXISTS=true
    fi
    if [[ -d "$BASE_DATA_DIR/arqma_storage/ST$i" ]] && [[ -n "$(ls -A "$BASE_DATA_DIR/arqma_storage/ST$i" 2>/dev/null || true)" ]]; then
        echo "WARNING: $BASE_DATA_DIR/arqma_storage/ST$i contains data"
        DATA_EXISTS=true
    fi
done

if [[ "$DATA_EXISTS" == true && "$FORCE_OVERWRITE" == false ]]; then
    die "Existing data found. Use --yes-i-really-know-what-i-am-doing to proceed."
fi

PUBLIC_IP=$(get_public_ip)
if ! [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    read_or_fail "Enter your public IPv4: " PUBLIC_IP
fi
echo "Detected public IP: $PUBLIC_IP"
if ! confirm_or_default_no "Is this correct? [y/N]: "; then
    read_or_fail "Enter desired public IPv4: " PUBLIC_IP
fi

# Install binaries
if [[ -n "${MY_ENDPOINT:-}" ]]; then
    install_from_endpoint "$MY_ENDPOINT"
else
    install_from_github "$GITHUB_RELEASE" "$ARQMAD_BIN" "$ARQIMPORT_BIN"
fi

if [[ -f "$ARQMAD_BIN" ]]; then chown root:root "$ARQMAD_BIN" 2>/dev/null || true; chmod 0755 "$ARQMAD_BIN" || true; fi
if [[ -f "$ARQIMPORT_BIN" ]]; then chown root:root "$ARQIMPORT_BIN" 2>/dev/null || true; chmod 0755 "$ARQIMPORT_BIN" || true; fi
if [[ -f "$ARQSTORAGE_BIN" ]]; then chown root:root "$ARQSTORAGE_BIN" 2>/dev/null || true; chmod 0755 "$ARQSTORAGE_BIN" || true; fi

ensure_users_and_dirs

for i in $(seq 1 "$NUM_PAIRS"); do
    mkdir -p "$BASE_DATA_DIR/arqma_d/SN$i" "$BASE_DATA_DIR/arqma_storage/ST$i"
done
chown -R arqd:arqd "$BASE_DATA_DIR/arqma_d"
chown -R arqstorage:arqstorage "$BASE_DATA_DIR/arqma_storage"

BASE_PORT="$BASE_PORT_DEFAULT"
STEP=1000

echo "Checking port collisions for requested nodes..."
check_ports_free_for_new_range "$BASE_PORT" "$STEP" 1 "$NUM_PAIRS"

BASE_P2P=$((BASE_PORT + P2P_OFFSET))
BASE_SS=$((BASE_PORT + SS_OFFSET))
BASE_ARQNET=$((BASE_PORT + ARQNET_OFFSET))
if [[ "$ENABLE_ARQNET" != true ]]; then
    BASE_ARQNET=""
fi

configure_firewall_ports "$NUM_PAIRS" "$BASE_P2P" "$STEP" "$BASE_SS" "${BASE_ARQNET:-}" 1

OUTPUT_DIR="./generated_services"
if [[ -d "$OUTPUT_DIR" ]]; then
    BACKUP_NAME="${OUTPUT_DIR}-backup-$(date +%s).tar.gz"
    tar -czf "$BACKUP_NAME" "$OUTPUT_DIR" 2>/dev/null || true
fi

generate_service_files_for_range "$OUTPUT_DIR" "$PUBLIC_IP" 1 "$NUM_PAIRS" "$BASE_PORT" "$STEP"
install_services_from_dir "$OUTPUT_DIR"
enable_services_range 1 "$NUM_PAIRS"

# Start first service node for blockchain sync
systemctl start sn1.service
echo "SN1 started for blockchain synchronization"
echo "Monitor: journalctl -fu sn1.service"

cat > "$INFO_FILE" <<EOF
ARQMA SETUP INFO
Generated: $(date)

Base data dir: $BASE_DATA_DIR
Public IP: $PUBLIC_IP
Pairs: $NUM_PAIRS
Base port: $BASE_PORT
Step: $STEP

Service users/groups (created if missing, for privilege separation):
  Service Nodes (sn*.service):   user=arqd group=arqd
  Storage Nodes (st*.service):   user=arqstorage group=arqstorage

URLs:
  github_release: $GITHUB_RELEASE

Per-node ports:
  P2P:    base+0 (open)
  RPC:    base+1 (localhost only)
  SS:     base+3 (open)
  ZMQ:    base+4 (open only if enabled and bind-ip != 127.0.0.1)
  ARQNET: base+5 (open if enabled)

Flags:
  arqnet: $ENABLE_ARQNET
  zmq:    $ENABLE_ZMQ
  zmq_bind_ip: $ZMQ_BIND_IP

Important keys to backup (per SN):
EOF

for i in $(seq 1 "$NUM_PAIRS"); do
    cat >> "$INFO_FILE" <<EOF
  $BASE_DATA_DIR/arqma_d/SN$i/key
  $BASE_DATA_DIR/arqma_d/SN$i/key_ed25519
EOF
done

cat >> "$INFO_FILE" <<EOF

Storage Node cert/key locations (per ST):
EOF

for i in $(seq 1 "$NUM_PAIRS"); do
    cat >> "$INFO_FILE" <<EOF
  $BASE_DATA_DIR/arqma_storage/ST$i/cert.pem
  $BASE_DATA_DIR/arqma_storage/ST$i/key.pem
EOF
done

cat >> "$INFO_FILE" <<EOF

Service management:
  Status SN: systemctl status sn{1..$NUM_PAIRS}
  Logs SN:   journalctl -fu sn{1..$NUM_PAIRS}
  Stop SN:   systemctl stop sn{1..$NUM_PAIRS}
  Start SN:  systemctl start sn{1..$NUM_PAIRS}

  Status ST: systemctl status st{1..$NUM_PAIRS}
  Logs ST:   journalctl -fu st{1..$NUM_PAIRS}
  Stop ST:   systemctl stop st{1..$NUM_PAIRS}
  Start ST:  systemctl start st{1..$NUM_PAIRS}

Report existing config:
  $0 --report-existing

Add nodes to existing setup (example add 2, seed from sn1):
  $0 --add-pairs 2 --seed-from 1

Seeding notes:
  Only lmdb/ is copied, keys are NOT copied.
  Seed stop timeout: $SEED_TIMEOUT seconds
  Disk reserve ratio: $RESERVE_RATIO_DEFAULT
EOF

echo "Setup complete. Info saved to: $INFO_FILE"
