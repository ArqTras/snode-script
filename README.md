# Arqma Service Node + Storage Node - Setup Script

Automated script for installing and managing Arqma Service Nodes and Storage Nodes on Ubuntu/Debian (x86_64) systems.

## Description

This bash script offers a complete solution for managing Arqma nodes:

- **Fresh installation** - interactive configuration of N node pairs (Service Node + Storage Node)
- **Reporting** - display configuration of existing nodes
- **Expansion** - add new node pairs to running installation with automatic blockchain seeding

## Features

### Security and Production

- **Privilege separation** - dedicated system users:
  - `arqd` - runs Service Nodes (sn*.service)
  - `arqstorage` - runs Storage Nodes (st*.service)

- **Safe seeding**:
  - ONLY blockchain database is copied (`lmdb/` directory)
  - Keys are NEVER copied between nodes
  - Each node generates its own keys

- **Error prevention**:
  - Refuses to operate on data directories (unless forced)
  - Checks available disk space before seeding
  - Port collision detection before startup

- **Firewall**:
  - Automatic UFW configuration
  - Opens ports: P2P, SS, ARQNET
  - ZMQ opened only if enabled and bind-ip ≠ 127.0.0.1

### Automatic Features

- Port configuration detection from existing services
- Automatic installation of required dependencies
- Generation of systemd service files
- System resource control (CPU, RAM)
- Configuration backup before changes

## System Requirements

- **Operating system**: Ubuntu/Debian (apt)
- **Architecture**: x86_64
- **Minimum**: 2 CPU cores + 4GB RAM (for 1 node pair)
- **Permissions**: root (sudo)
- **Systemd**: required for service management

### Recommended Resources

Script automatically calculates maximum number of nodes:
- **CPU**: 2 cores per node pair
- **RAM**: 4GB per node pair

## Installation and Usage

### 1. Download Script

```bash
# Clone repository
git clone https://github.com/arqma/snode-script.git
cd snode-script

# Set execute permissions
chmod +x arqma-node-setup.sh
```

### 2. Operation Modes

#### a) Fresh Installation (Interactive Mode)

Default mode - configures N node pairs from scratch.

```bash
sudo ./arqma-node-setup.sh
```

Script will ask for:
- Number of node pairs to create
- Server's public IP address
- Configuration confirmation

After setup, the first node will start synchronizing with the network automatically.

#### b) Report Existing Configuration

Displays information about existing nodes without making changes.

```bash
sudo ./arqma-node-setup.sh --report-existing
```

**Example output:**
```
=== Service Node 1 ===
service node data_dir: /data/arqma_d/SN1
sn_ports: p2p=10001 rpc=10002 arqnet=10006
storage node data_dir: /data/arqma_storage/ST1
st_port=10004
```

#### c) Adding New Nodes (Expansion)

Adds new node pairs to existing installation with automatic blockchain seeding.

```bash
# Add 2 node pairs, seed from sn1 (default)
sudo ./arqma-node-setup.sh --add-pairs 2

# Add 3 pairs, seed from sn2
sudo ./arqma-node-setup.sh --add-pairs 3 --seed-from 2

# With custom stop timeout
sudo ./arqma-node-setup.sh --add-pairs 1 --seed-from 1 --seed-timeout 300
```

**Seeding process:**
1. Check available disk space
2. Check port collisions
3. Stop seed node and new target nodes
4. Copy ONLY `lmdb/` directory from seed node
5. Start seed node
6. Start new nodes

**IMPORTANT**: Other running nodes are NOT stopped during the process.

### 3. Configuration Options

```bash
# Data directory
--base-data-dir /custom/path          # Default: /data

# Binary sources
--github-release URL                   # URL to tar.gz from GitHub
--my-endpoint URL                      # Custom endpoint for binaries

# Ports and network
--enable-arqnet                        # Enable arqnet (default)
--disable-arqnet                       # Disable arqnet
--enable-zmq                           # Enable ZMQ (default: disabled)
--zmq-bind-ip IP                       # IP for ZMQ (default: 127.0.0.1)

# Seeding (--add-pairs only)
--seed-from N                          # Seed from node snN (default: 1)
--seed-timeout SEC                     # Stop timeout (default: 180s)

# Other
--info-file PATH                       # Info file path (default: ~/ARQMA-setup.info)
--yes-i-really-know-what-i-am-doing   # Force overwrite existing data
-h, --help                             # Display help
```

## Port Structure

Default port configuration for each node (base_port = 10001, step = 1000):

| Node | P2P (base+0) | RPC (base+1) | SS (base+3) | ZMQ (base+4) | ARQNET (base+5) |
|------|-------------|--------------|-------------|--------------|-----------------|
| sn1  | 10001       | 10002        | 10004       | 10005        | 10006           |
| sn2  | 11001       | 11002        | 11004       | 11005        | 11006           |
| sn3  | 12001       | 12002        | 12004       | 12005        | 12006           |

**Notes:**
- **RPC**: access ONLY from localhost (127.0.0.1)
- **ZMQ**: opened in firewall ONLY if enabled and bind-ip ≠ 127.0.0.1
- **ARQNET**: opened if enabled

## Service Management

### Status Check

```bash
# Status of specific node
sudo systemctl status sn1.service
sudo systemctl status st1.service

# Status of all Service Nodes
sudo systemctl status sn*.service

# Status of all Storage Nodes
sudo systemctl status st*.service
```

### Logs

```bash
# Real-time logs
sudo journalctl -fu sn1.service
sudo journalctl -fu st1.service

# Last 100 lines
sudo journalctl -u sn1.service -n 100

# Logs from last 24h
sudo journalctl -u sn1.service --since "24 hours ago"
```

### Starting and Stopping

```bash
# Single node
sudo systemctl start sn1.service
sudo systemctl stop sn1.service
sudo systemctl restart sn1.service

# All nodes
sudo systemctl start sn{1..3}.service st{1..3}.service
sudo systemctl stop sn{1..3}.service st{1..3}.service

# Autostart on system boot
sudo systemctl enable sn1.service st1.service
sudo systemctl disable sn1.service st1.service
```

## Directory Structure

```
/data/
├── arqma_d/
│   ├── SN1/
│   │   ├── lmdb/           # Blockchain database
│   │   ├── key             # Service Node key (BACKUP!)
│   │   ├── key_ed25519     # Ed25519 key (BACKUP!)
│   │   └── ...
│   ├── SN2/
│   └── SN3/
│
└── arqma_storage/
    ├── ST1/
    │   ├── cert.pem        # Storage Node certificate (BACKUP!)
    │   ├── key.pem         # Storage Node key (BACKUP!)
    │   └── ...
    ├── ST2/
    └── ST3/
```

## Key Backup

**CRITICALLY IMPORTANT**: Backup keys before starting nodes!

### Service Node Keys

```bash
# For each node
sudo cp /data/arqma_d/SN1/key ~/backup/SN1_key
sudo cp /data/arqma_d/SN1/key_ed25519 ~/backup/SN1_key_ed25519
```

### Storage Node Certificates

```bash
# For each node
sudo cp /data/arqma_storage/ST1/cert.pem ~/backup/ST1_cert.pem
sudo cp /data/arqma_storage/ST1/key.pem ~/backup/ST1_key.pem
```

### Automatic Backup (Recommended)

```bash
#!/bin/bash
BACKUP_DIR="$HOME/arqma-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup all SN keys
for sn in /data/arqma_d/SN*; do
    if [ -d "$sn" ]; then
        name=$(basename "$sn")
        mkdir -p "$BACKUP_DIR/$name"
        sudo cp "$sn/key" "$BACKUP_DIR/$name/" 2>/dev/null || true
        sudo cp "$sn/key_ed25519" "$BACKUP_DIR/$name/" 2>/dev/null || true
    fi
done

# Backup all ST certificates
for st in /data/arqma_storage/ST*; do
    if [ -d "$st" ]; then
        name=$(basename "$st")
        mkdir -p "$BACKUP_DIR/$name"
        sudo cp "$st/cert.pem" "$BACKUP_DIR/$name/" 2>/dev/null || true
        sudo cp "$st/key.pem" "$BACKUP_DIR/$name/" 2>/dev/null || true
    fi
done

echo "Backup saved to: $BACKUP_DIR"
```

## Firewall (UFW)

Script automatically configures UFW, but ensure SSH is allowed:

```bash
# Before enabling UFW!
sudo ufw allow 22/tcp

# OR for specific IP
sudo ufw allow from 198.51.100.10 to any port 22 proto tcp

# OR for network
sudo ufw allow from 198.51.100.0/24 to any port 22 proto tcp

# Disable logging (recommended for production)
sudo ufw logging off

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

## Troubleshooting

### Service Node won't start

```bash
# Check logs
sudo journalctl -u sn1.service -n 200

# Check if port is free
sudo ss -lntp | grep 10001

# Check permissions
sudo ls -la /data/arqma_d/SN1/
sudo systemctl status sn1.service
```

### Storage Node won't connect

```bash
# Check if Service Node is running
sudo systemctl status sn1.service

# Check Storage Node logs
sudo journalctl -u st1.service -n 100

# Check if RPC port is accessible
sudo ss -lntp | grep 10002
```

### Insufficient disk space during seeding

```bash
# Check available space
df -h /data

# Check lmdb size
du -sh /data/arqma_d/SN1/lmdb/

# Script requires 10% reserve - ensure you have enough space
```

### Port collision

```bash
# Check occupied ports
sudo ss -lntp

# Stop conflicting service or use different ports
```

## Information File

After installation, script generates `~/ARQMA-setup.info` containing:
- Configuration of all nodes
- Port assignments
- Paths to keys
- Management commands

```bash
# Display configuration information
cat ~/ARQMA-setup.info
```

## Usage Examples

### Example 1: Simple installation of 2 nodes

```bash
sudo ./arqma-node-setup.sh
# Select: 2
# Confirm IP
# Wait for completion
```

### Example 2: Installation with custom directory

```bash
sudo ./arqma-node-setup.sh \
  --base-data-dir /mnt/nvme/arqma
```

### Example 3: Adding 2 nodes to existing installation

```bash
# First check current configuration
sudo ./arqma-node-setup.sh --report-existing

# Add 2 new pairs
sudo ./arqma-node-setup.sh --add-pairs 2 --seed-from 1
```

### Example 4: Installation without ARQNET, with ZMQ

```bash
sudo ./arqma-node-setup.sh \
  --disable-arqnet \
  --enable-zmq \
  --zmq-bind-ip 0.0.0.0
```

## Security

### Production Recommendations

1. **Always backup keys** before starting nodes
2. **Use firewall** - script configures UFW automatically
3. **Restrict SSH access** - only from trusted IPs
4. **Monitor logs** - regularly check journalctl
5. **Update system** - apt update && apt upgrade
6. **User separation** - don't run as root except during installation

### Privilege Separation

Script creates dedicated users:
- `arqd` - has access ONLY to `/data/arqma_d/`
- `arqstorage` - has access ONLY to `/data/arqma_storage/`

This limits potential damage in case of service compromise.

## FAQ

**Q: Can I run more nodes than recommended?**  
A: Yes, but performance may be poor. Script will warn you before exceeding.

**Q: What happens to keys during seeding?**  
A: Keys are NOT copied. Each node generates its own keys.

**Q: Can I change ports after installation?**  
A: Yes, edit `/etc/systemd/system/sn*.service` files and run `systemctl daemon-reload`.

**Q: Can I use this script in production?**  
A: Yes, script is designed with production security in mind.

**Q: What to do if seeding fails?**  
A: Check logs, ensure seed node was stopped, check disk space.

## Support and Contact

- **GitHub Issues**: [https://github.com/arqma/snode-script/issues](https://github.com/arqma/snode-script/issues)
- **Arqma Discord**: [https://discord.gg/arqma](https://discord.gg/arqma)
- **Arqma Documentation**: [https://docs.arqma.com](https://docs.arqma.com)

## License

This script is released under MIT License. See LICENSE file for details.

## Changelog

### v1.0.0
- First stable release
- Modes: fresh install, report, add-pairs
- Automatic blockchain seeding for new nodes
- User privilege separation
- Firewall detection and configuration
- Resource and port collision checking

## Authors

Script created for Arqma project.

---

**IMPORTANT**: Always test on a test environment before using in production!
