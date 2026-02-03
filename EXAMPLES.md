# Usage Examples

Practical examples of using the `arqma-node-setup.sh` script.

## Table of Contents

- [Basic Installation](#basic-installation)
- [Advanced Scenarios](#advanced-scenarios)
- [Node Management](#node-management)
- [Expanding Installation](#expanding-installation)
- [Backup and Restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)

---

## Basic Installation

### Example 1: Installing 1 node pair (minimal setup)

```bash
# Download and run
git clone https://github.com/arqma/snode-script.git
cd snode-script
chmod +x arqma-node-setup.sh

# Installation (interactive)
sudo ./arqma-node-setup.sh
# Select: 1
# Confirm public IP
# Wait for completion

# Check status
sudo systemctl status sn1.service st1.service

# Monitor synchronization
sudo journalctl -fu sn1.service
```

### Example 2: Installation on custom path

```bash
# Use SSD/NVMe for better performance
sudo mkdir -p /mnt/nvme-data
sudo ./arqma-node-setup.sh \
  --base-data-dir /mnt/nvme-data

# Structure will be:
# /mnt/nvme-data/arqma_d/SN1/
# /mnt/nvme-data/arqma_storage/ST1/
```

---

## Advanced Scenarios

### Example 3: Installation with custom binaries

```bash
# If you have your own endpoint with binaries
sudo ./arqma-node-setup.sh \
  --my-endpoint https://your-server.com/arqma/binaries
```

### Example 4: Installation without ARQNET, with public ZMQ

```bash
# Disable ARQNET, enable ZMQ on all interfaces
sudo ./arqma-node-setup.sh \
  --disable-arqnet \
  --enable-zmq \
  --zmq-bind-ip 0.0.0.0

# WARNING: ZMQ on 0.0.0.0 will be opened in firewall!
# Make sure you understand the security implications
```

### Example 5: Maximum resource utilization

```bash
# On server with 32 CPU and 128GB RAM
# Can run 16 node pairs (theoretically)

sudo ./arqma-node-setup.sh
# Select: 16
# System will create 16x Service Node + 16x Storage Node

# WARNING: Make sure you have enough disk space!
# Each node needs ~100GB+ for blockchain
```

---

## Node Management

### Example 6: Checking status of all nodes

```bash
# Status of all Service Nodes
sudo systemctl status sn*.service

# Status of all Storage Nodes
sudo systemctl status st*.service

# Concise status
sudo systemctl is-active sn{1..3}.service st{1..3}.service

# Status with uptime
sudo systemctl list-units "sn*.service" "st*.service" --all
```

### Example 7: Restarting specific nodes

```bash
# Restart single node
sudo systemctl restart sn1.service

# Restart pair (SN + ST)
sudo systemctl restart sn1.service st1.service

# Restart all nodes (sequentially)
for i in {1..3}; do
    echo "Restarting SN$i and ST$i..."
    sudo systemctl restart sn$i.service
    sleep 10  # Wait 10s between restarts
    sudo systemctl restart st$i.service
    sleep 5
done
```

### Example 8: Monitoring logs from multiple nodes

```bash
# Logs from all SNs in one window
sudo journalctl -fu sn1 -fu sn2 -fu sn3

# Logs with filters (errors only)
sudo journalctl -u sn1.service -p err -n 100

# Logs from last 24h
sudo journalctl -u sn1.service --since "24 hours ago"

# Export logs to file
sudo journalctl -u sn1.service --since today > sn1_logs_$(date +%Y%m%d).txt

# Real-time monitoring with grep
sudo journalctl -fu sn1.service | grep -i "error\|warning\|failed"
```

---

## Expanding Installation

### Example 9: Adding 1 node pair to existing installation

```bash
# First check current configuration
sudo ./arqma-node-setup.sh --report-existing

# Example output:
# === Service Node 1 ===
# sn_ports: p2p=10001 rpc=10002 arqnet=10006
# ...
# === Service Node 2 ===
# ...

# Add new pair (seed from sn1)
sudo ./arqma-node-setup.sh --add-pairs 1 --seed-from 1

# Process:
# 1. Will stop sn1 (seed source)
# 2. Will copy blockchain (lmdb/) to new sn3
# 3. Will start sn1 back
# 4. Will start new sn3 and st3
```

### Example 10: Bulk adding nodes with custom seed

```bash
# Add 5 new pairs, seed from sn2 (if sn1 is busy)
sudo ./arqma-node-setup.sh \
  --add-pairs 5 \
  --seed-from 2 \
  --seed-timeout 300

# Use longer timeout for large blockchains
# Default 180s may not be enough on some systems
```

### Example 11: Verification before and after adding nodes

```bash
# PRE-CHECK: Check resources
df -h /data
free -h
sudo ss -lntp | grep -E ':(10[0-9]{3}|11[0-9]{3})'

# ADD NODES
sudo ./arqma-node-setup.sh --add-pairs 2

# POST-CHECK: Verification
sudo ./arqma-node-setup.sh --report-existing
sudo systemctl status sn{1..4}.service --no-pager
sudo journalctl -u sn3.service -n 50
sudo journalctl -u sn4.service -n 50

# Check if new nodes are synchronizing
# They should start from the same block as source node
```

---

## Backup and Restore

### Example 12: Backup all keys

```bash
#!/bin/bash
# Script: backup_arqma_keys.sh

BACKUP_DIR="$HOME/arqma-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Backing up to: $BACKUP_DIR"

# Backup Service Node keys
for sn in /data/arqma_d/SN*; do
    if [ -d "$sn" ]; then
        name=$(basename "$sn")
        echo "Backing up $name..."
        mkdir -p "$BACKUP_DIR/$name"
        
        # Critical files
        sudo cp "$sn/key" "$BACKUP_DIR/$name/" 2>/dev/null || echo "  key not found"
        sudo cp "$sn/key_ed25519" "$BACKUP_DIR/$name/" 2>/dev/null || echo "  key_ed25519 not found"
        
        # Optional: wallet files
        sudo cp "$sn/"*.keys "$BACKUP_DIR/$name/" 2>/dev/null || true
    fi
done

# Backup Storage Node certs
for st in /data/arqma_storage/ST*; do
    if [ -d "$st" ]; then
        name=$(basename "$st")
        echo "Backing up $name..."
        mkdir -p "$BACKUP_DIR/$name"
        
        sudo cp "$st/cert.pem" "$BACKUP_DIR/$name/" 2>/dev/null || echo "  cert.pem not found"
        sudo cp "$st/key.pem" "$BACKUP_DIR/$name/" 2>/dev/null || echo "  key.pem not found"
    fi
done

# Backup setup info
cp ~/ARQMA-setup.info "$BACKUP_DIR/" 2>/dev/null || true

# Create compressed archive
tar -czf "${BACKUP_DIR}.tar.gz" -C "$HOME" "$(basename "$BACKUP_DIR")"

echo ""
echo "Backup completed:"
echo "  Directory: $BACKUP_DIR"
echo "  Archive: ${BACKUP_DIR}.tar.gz"
echo ""
echo "IMPORTANT: Store this backup in a secure location!"

# Optional: Encrypt backup
# gpg -c "${BACKUP_DIR}.tar.gz"
```

### Example 13: Restore keys from backup

```bash
#!/bin/bash
# Script: restore_arqma_keys.sh

BACKUP_ARCHIVE="$1"

if [ -z "$BACKUP_ARCHIVE" ]; then
    echo "Usage: $0 <backup_archive.tar.gz>"
    exit 1
fi

if [ ! -f "$BACKUP_ARCHIVE" ]; then
    echo "Error: Backup file not found: $BACKUP_ARCHIVE"
    exit 1
fi

# Extract backup
TEMP_DIR=$(mktemp -d)
tar -xzf "$BACKUP_ARCHIVE" -C "$TEMP_DIR"

BACKUP_DIR=$(find "$TEMP_DIR" -mindepth 1 -maxdepth 1 -type d)

echo "Restoring from: $BACKUP_DIR"
echo ""

# Restore Service Node keys
for sndir in "$BACKUP_DIR"/SN*; do
    if [ -d "$sndir" ]; then
        sn=$(basename "$sndir")
        target="/data/arqma_d/$sn"
        
        echo "Restoring $sn to $target..."
        
        # Stop service before restore
        sudo systemctl stop "${sn,,}.service" 2>/dev/null || true
        
        # Restore keys
        if [ -f "$sndir/key" ]; then
            sudo cp "$sndir/key" "$target/"
            sudo chown arqd:arqd "$target/key"
            sudo chmod 600 "$target/key"
            echo "  ✓ key restored"
        fi
        
        if [ -f "$sndir/key_ed25519" ]; then
            sudo cp "$sndir/key_ed25519" "$target/"
            sudo chown arqd:arqd "$target/key_ed25519"
            sudo chmod 600 "$target/key_ed25519"
            echo "  ✓ key_ed25519 restored"
        fi
        
        # Restart service
        sudo systemctl start "${sn,,}.service"
    fi
done

# Restore Storage Node certs
for stdir in "$BACKUP_DIR"/ST*; do
    if [ -d "$stdir" ]; then
        st=$(basename "$stdir")
        target="/data/arqma_storage/$st"
        
        echo "Restoring $st to $target..."
        
        sudo systemctl stop "${st,,}.service" 2>/dev/null || true
        
        if [ -f "$stdir/cert.pem" ]; then
            sudo cp "$stdir/cert.pem" "$target/"
            sudo chown arqstorage:arqstorage "$target/cert.pem"
            sudo chmod 600 "$target/cert.pem"
            echo "  ✓ cert.pem restored"
        fi
        
        if [ -f "$stdir/key.pem" ]; then
            sudo cp "$stdir/key.pem" "$target/"
            sudo chown arqstorage:arqstorage "$target/key.pem"
            sudo chmod 600 "$target/key.pem"
            echo "  ✓ key.pem restored"
        fi
        
        sudo systemctl start "${st,,}.service"
    fi
done

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "Restore completed!"
```

---

## Troubleshooting

### Example 14: Diagnosing node that won't start

```bash
#!/bin/bash
# diagnose_node.sh

NODE="sn1"  # Change to problematic node

echo "=== Diagnostics: $NODE ==="
echo ""

# 1. Systemd status
echo "1. Systemd status:"
sudo systemctl status "$NODE.service" --no-pager
echo ""

# 2. Recent logs
echo "2. Last 50 lines of logs:"
sudo journalctl -u "$NODE.service" -n 50 --no-pager
echo ""

# 3. Errors in logs
echo "3. Errors in logs (last 24h):"
sudo journalctl -u "$NODE.service" --since "24 hours ago" -p err --no-pager
echo ""

# 4. Port checks
echo "4. Port checking:"
NODE_NUM="${NODE//[!0-9]/}"
BASE_PORT=$((10000 + (NODE_NUM - 1) * 1000))

P2P=$((BASE_PORT + 1))
RPC=$((BASE_PORT + 2))
SS=$((BASE_PORT + 4))

echo "  P2P ($P2P):"
sudo ss -lntp | grep ":$P2P " || echo "    Not listening"

echo "  RPC ($RPC):"
sudo ss -lntp | grep ":$RPC " || echo "    Not listening"

echo "  SS ($SS):"
sudo ss -lntp | grep ":$SS " || echo "    Not listening"
echo ""

# 5. Data directory
echo "5. Data directory:"
DATA_DIR="/data/arqma_d/${NODE^^}"
ls -lah "$DATA_DIR" 2>/dev/null || echo "  Directory not found: $DATA_DIR"
echo ""

# 6. Permissions
echo "6. Permissions:"
stat "$DATA_DIR" 2>/dev/null || echo "  Cannot stat: $DATA_DIR"
echo ""

# 7. Disk space
echo "7. Disk space:"
df -h /data
echo ""

# 8. Process check
echo "8. Running processes:"
ps aux | grep -E "arqmad.*$NODE_NUM" | grep -v grep || echo "  No process found"
echo ""

# 9. Binary check
echo "9. Binary check:"
if [ -x "/usr/local/bin/arqmad" ]; then
    ls -lh /usr/local/bin/arqmad
    /usr/local/bin/arqmad --version 2>&1 || echo "  Cannot get version"
else
    echo "  Binary not found or not executable: /usr/local/bin/arqmad"
fi
```

### Example 15: Cleanup and reinstall single node

```bash
#!/bin/bash
# reinstall_node.sh SN_NUMBER

SN_NUM="$1"

if [ -z "$SN_NUM" ]; then
    echo "Usage: $0 <node_number>"
    echo "Example: $0 1"
    exit 1
fi

SN_SERVICE="sn${SN_NUM}.service"
ST_SERVICE="st${SN_NUM}.service"

echo "WARNING: This will remove all data from node SN$SN_NUM!"
echo "Keys will be lost if you don't have a backup!"
read -p "Continue? (type 'YES' to confirm): " confirm

if [ "$confirm" != "YES" ]; then
    echo "Cancelled."
    exit 0
fi

# Stop services
echo "Stopping services..."
sudo systemctl stop "$SN_SERVICE" "$ST_SERVICE"
sudo systemctl disable "$SN_SERVICE" "$ST_SERVICE"

# Backup existing data (just in case)
BACKUP="/tmp/arqma_backup_sn${SN_NUM}_$(date +%s)"
echo "Creating emergency backup at: $BACKUP"
sudo mkdir -p "$BACKUP"
sudo cp -r "/data/arqma_d/SN$SN_NUM" "$BACKUP/" 2>/dev/null || true
sudo cp -r "/data/arqma_storage/ST$SN_NUM" "$BACKUP/" 2>/dev/null || true

# Remove data directories
echo "Removing data directories..."
sudo rm -rf "/data/arqma_d/SN$SN_NUM"
sudo rm -rf "/data/arqma_storage/ST$SN_NUM"

# Recreate directories
echo "Recreating directories..."
sudo mkdir -p "/data/arqma_d/SN$SN_NUM"
sudo mkdir -p "/data/arqma_storage/ST$SN_NUM"
sudo chown -R arqd:arqd "/data/arqma_d/SN$SN_NUM"
sudo chown -R arqstorage:arqstorage "/data/arqma_storage/ST$SN_NUM"

# Reseed from SN1 (if exists and not reinstalling SN1)
if [ "$SN_NUM" != "1" ] && [ -d "/data/arqma_d/SN1/lmdb" ]; then
    echo "Seeding blockchain from SN1..."
    sudo systemctl stop sn1.service
    sleep 5
    
    sudo rsync -aH --delete /data/arqma_d/SN1/lmdb/ "/data/arqma_d/SN$SN_NUM/lmdb/"
    sudo chown -R arqd:arqd "/data/arqma_d/SN$SN_NUM/lmdb"
    
    sudo systemctl start sn1.service
fi

# Re-enable and start
echo "Starting services..."
sudo systemctl enable "$SN_SERVICE" "$ST_SERVICE"
sudo systemctl start "$SN_SERVICE"
sleep 10
sudo systemctl start "$ST_SERVICE"

# Check status
echo ""
echo "Status check:"
sudo systemctl status "$SN_SERVICE" --no-pager
echo ""
sudo systemctl status "$ST_SERVICE" --no-pager

echo ""
echo "Reinstall completed!"
echo "Emergency backup at: $BACKUP"
echo "Monitor logs: sudo journalctl -fu $SN_SERVICE"
```

---

## Additional Tools

### Example 16: Monitoring all nodes (dashboard)

```bash
#!/bin/bash
# monitor_dashboard.sh - Simple terminal dashboard

while true; do
    clear
    echo "============================================"
    echo "   ARQMA NODES MONITORING DASHBOARD"
    echo "   $(date)"
    echo "============================================"
    echo ""
    
    echo "SERVICE NODES:"
    echo "----------------------------------------"
    for sn in /data/arqma_d/SN*; do
        if [ -d "$sn" ]; then
            name=$(basename "$sn")
            num="${name//[!0-9]/}"
            service="sn${num}.service"
            
            status=$(systemctl is-active "$service")
            uptime=$(systemctl show "$service" -p ActiveEnterTimestamp --value)
            
            printf "%-5s [%-10s] %s\n" "$name" "$status" "$uptime"
        fi
    done
    
    echo ""
    echo "STORAGE NODES:"
    echo "----------------------------------------"
    for st in /data/arqma_storage/ST*; do
        if [ -d "$st" ]; then
            name=$(basename "$st")
            num="${name//[!0-9]/}"
            service="st${num}.service"
            
            status=$(systemctl is-active "$service")
            uptime=$(systemctl show "$service" -p ActiveEnterTimestamp --value)
            
            printf "%-5s [%-10s] %s\n" "$name" "$status" "$uptime"
        fi
    done
    
    echo ""
    echo "SYSTEM RESOURCES:"
    echo "----------------------------------------"
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo "RAM: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
    echo "Disk: $(df -h /data | awk 'NR==2 {print $3 "/" $2 " (" $5 " used)"}')"
    
    echo ""
    echo "Press Ctrl+C to exit"
    echo "Refresh in 5s..."
    
    sleep 5
done
```

---

**More examples can be found in the main README.md or ask questions on Discord!**
