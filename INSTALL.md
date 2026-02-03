# Quick Start - Arqma Nodes Installation

Quick start guide for installing Arqma nodes.

## Requirements

- Ubuntu/Debian (x86_64)
- Root/sudo
- Minimum: 2 CPU cores + 4GB RAM

## Installation in 3 Steps

### 1. Download Script

```bash
git clone https://github.com/arqma/snode-script.git
cd snode-script
chmod +x arqma-node-setup.sh
```

### 2. Run Installation

```bash
sudo ./arqma-node-setup.sh
```

Script will ask:
- How many node pairs do you want to create?
- What is your public IP?

### 3. Monitor Installation

```bash
# Check status
sudo systemctl status sn1.service

# View logs
sudo journalctl -fu sn1.service
```

## What's Next?

After blockchain synchronization completes:

### Register Service Node

```bash
# Connect to node
arqmad --rpc-bind-port 10002

# Prepare registration (requires ARQMA collateral)
prepare_registration
```

### Backup Keys

```bash
# Service Node keys
sudo cp /data/arqma_d/SN1/key ~/backup/
sudo cp /data/arqma_d/SN1/key_ed25519 ~/backup/

# Storage Node keys
sudo cp /data/arqma_storage/ST1/cert.pem ~/backup/
sudo cp /data/arqma_storage/ST1/key.pem ~/backup/
```

### Check Firewall

```bash
# If UFW is not enabled
sudo ufw allow 22/tcp
sudo ufw allow 10001/tcp  # P2P
sudo ufw allow 10004/tcp  # Storage
sudo ufw allow 10006/tcp  # Arqnet
sudo ufw logging off
sudo ufw enable
```

## Basic Commands

```bash
# Node status
sudo systemctl status sn1.service st1.service

# Restart nodes
sudo systemctl restart sn1.service st1.service

# Live logs
sudo journalctl -fu sn1.service

# Check synchronization
arqmad --rpc-bind-port 10002 status
```

## Troubleshooting

### Node won't start

```bash
# Check error logs
sudo journalctl -u sn1.service -n 100 --no-pager

# Check if ports are free
sudo ss -lntp | grep 10001
```

### Storage Node won't connect

```bash
# Check if Service Node is running
sudo systemctl status sn1.service

# Check Storage Node logs
sudo journalctl -u st1.service -n 50
```

## Adding More Nodes

```bash
# Add 2 new node pairs
sudo ./arqma-node-setup.sh --add-pairs 2 --seed-from 1
```

## Documentation

Full documentation: [README.md](README.md)

## Support

- GitHub Issues: https://github.com/arqma/snode-script/issues
- Discord: https://discord.gg/arqma
- Docs: https://docs.arqma.com

---

**NOTE**: Always backup keys before starting production nodes!
