# Service Node Registration Guide

This guide explains how to register your Arqma Service Node after setup and synchronization.

## Prerequisites

Before registering your service node, ensure:

1. **Service Node is running and synchronized**
   - Check status: `systemctl status sn1.service`
   - Monitor sync: `journalctl -fu sn1.service`
   
2. **Storage Server is connected**
   - Check status: `systemctl status st1.service`
   - Verify ping: `journalctl -u sn1.service | grep -i storage`

3. **You have an Arqma wallet**
   - With at least 20,000 ARQMA for staking
   - Wallet address starting with `ar`

4. **Required tools installed** (automatically installed if missing)
   - `curl` - for RPC calls
   - `jq` - for JSON parsing

## Registration Process

### Step 1: Run the Registration Command

```bash
sudo ./arqma-node-setup.sh --register 1 --wallet arYOUR_WALLET_ADDRESS_HERE
```

Or without wallet address (will prompt):

```bash
sudo ./arqma-node-setup.sh --register 1
```

### Step 2: What the Script Does

The script performs these checks automatically:

1. **Service Status Check**
   - Verifies `sn1.service` is active
   - Error if service is not running

2. **Synchronization Check**
   - Calls RPC `get_info` method
   - Checks if node height matches target height
   - Allows up to 10 blocks difference
   - Retries 3 times with 5-second intervals

3. **Storage Server Check**
   - Scans recent logs (200 lines) for storage ping
   - Looks for keywords:
     - "storage.*server.*registered"
     - "Received.*ping.*storage"
     - "Successfully.*registered"
     - "Connection.*established"
     - "Ping.*successful"
   - Shows warning if not detected (can continue)

4. **Wallet Address Validation**
   - Basic format check (starts with `ar`, ~95+ chars)
   - Shows warning if format seems invalid

5. **Registration Command Generation**
   - Calls RPC `prepare_registration` with:
     - Operator cut: 0%
     - Staking amount: 20,000 ARQMA (20000000000000 atomic units)
     - Contributor: your wallet address
   - Saves command to file

### Step 3: Registration Output

The script generates a file: `~/arqma-register-sn1.txt`

Example output:

```
===================================
Service Node Registration: sn1
===================================

[1/4] Checking service status...
✓ Service sn1.service is active

[2/4] Checking blockchain synchronization...
✓ Node is synchronized (height: 123456)

[3/4] Checking storage server connection...
✓ Storage server is connected and pinging

[4/4] Using provided wallet address: arYOUR_WALLET_ADDRESS

Generating registration command...

======================================
Registration command generated!
======================================

Saved to: /root/arqma-register-sn1.txt

NEXT STEPS:
1. Open the file: cat /root/arqma-register-sn1.txt
2. Copy the 'register_service_node' command
3. Open your Arqma wallet CLI
4. Paste and execute the command
5. Wait for transaction confirmation

Registration command preview:
---
register_service_node [FULL_COMMAND_HERE]
---
```

### Step 4: Execute in Wallet

1. Open your Arqma wallet CLI:
   ```bash
   ./arqma-wallet-cli --wallet-file your-wallet
   ```

2. View the registration command:
   ```bash
   cat ~/arqma-register-sn1.txt
   ```

3. Copy the `register_service_node` command (the entire line)

4. Paste into wallet CLI and press Enter

5. Confirm the transaction

6. Wait for blockchain confirmation (typically 10-20 blocks)

### Step 5: Verify Registration

After transaction confirmation, check node status:

```bash
curl -s http://127.0.0.1:10002/json_rpc \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_service_node_key"}' \
  -H 'Content-Type: application/json' | jq
```

Expected output:
```json
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "service_node_pubkey": "YOUR_SERVICE_NODE_PUBLIC_KEY"
  }
}
```

## Registering Multiple Nodes

To register additional nodes:

```bash
# Register sn2
sudo ./arqma-node-setup.sh --register 2 --wallet arYOUR_WALLET_ADDRESS

# Register sn3
sudo ./arqma-node-setup.sh --register 3 --wallet arYOUR_WALLET_ADDRESS
```

Each registration requires:
- Separate 20,000 ARQMA stake
- Can use the same wallet address
- Generates separate registration file (e.g., `arqma-register-sn2.txt`)

## Troubleshooting

### Node Not Synchronized

**Error:** `Node is not synchronized. Wait for sync to complete and try again.`

**Solution:**
```bash
# Check sync status
journalctl -fu sn1.service

# Wait until you see:
# "Synced XXX/XXX"
```

### Storage Server Not Detected

**Warning:** `No storage server ping detected in recent logs`

**Possible causes:**
1. Storage service not running
   ```bash
   systemctl status st1.service
   systemctl start st1.service
   ```

2. Node just started (needs time to establish connection)
   - Wait 5-10 minutes
   - Try registration again

3. Storage server not properly configured
   ```bash
   journalctl -u st1.service -n 50
   ```

### Service Not Active

**Error:** `Service sn1.service is not active. Start it first`

**Solution:**
```bash
sudo systemctl start sn1.service
sudo systemctl status sn1.service
```

### RPC Connection Failed

**Error:** `prepare_registration failed`

**Possible causes:**
1. Node not fully synced yet
2. RPC port not accessible
3. Node crashed/restarting

**Solution:**
```bash
# Check if node is running
systemctl status sn1.service

# Check RPC port (should be listening)
ss -tlnp | grep 10002

# Check recent logs for errors
journalctl -u sn1.service -n 100
```

### Invalid Wallet Address

**Warning:** `Wallet address format seems invalid`

**Requirements:**
- Must start with `ar`
- Approximately 95+ characters long
- Only alphanumeric characters

**Example valid address:**
```
ar4ABC123def456GHI789jkl012MNO345pqr678STU901vwx234YZA567bcd890efg123hij456klm789nop012qrs345tuv678wxy901z
```

### Registration Command Failed in Wallet

**Error in wallet:** `Failed to register service node`

**Possible causes:**
1. Insufficient balance (need 20,000 ARQMA + fee)
2. Node not synchronized when command was generated
3. Network issues
4. Node keys changed (node was restarted/reset)

**Solution:**
1. Check wallet balance: `balance`
2. Generate fresh registration command
3. Ensure node stayed online during registration

## Important Notes

### Security

- **Never share your registration file publicly**
- Contains node-specific cryptographic keys
- Keep backups of wallet keys, not registration commands

### Staking

- **20,000 ARQMA locked per node**
- Funds remain locked while node is active
- Can deregister to unlock funds (subject to unlock schedule)

### Maintenance

- Keep node synchronized and online
- Missing uptime requirements may result in deregistration
- Monitor node health regularly:
  ```bash
  systemctl status sn1.service st1.service
  ```

### Multiple Operators

If running multiple nodes:
- Each needs separate registration
- Can use same wallet for all nodes
- Total stake = 20,000 ARQMA × number of nodes

## Advanced Usage

### Non-Interactive Registration

For scripts/automation:

```bash
# Provide wallet address via flag
sudo ./arqma-node-setup.sh --register 1 --wallet arYOUR_WALLET_ADDRESS
```

### Custom Operator Cut

The script uses 0% operator cut by default. To use a custom cut, you'll need to:

1. Modify the `generate_registration_command` function
2. Change the `operator_cut` parameter in the RPC call
3. Or manually call `prepare_registration` with custom parameters

### Registration with Contributors

The script supports single contributor (your wallet) by default. For multiple contributors:

1. Generate registration command with script
2. Manually modify the command before pasting to wallet
3. Or use wallet CLI's registration helper directly

## Getting Help

If you encounter issues:

1. Check logs:
   ```bash
   journalctl -u sn1.service -n 200
   journalctl -u st1.service -n 200
   ```

2. Verify node configuration:
   ```bash
   sudo ./arqma-node-setup.sh --report-existing
   ```

3. Check dashboard:
   ```bash
   sudo ./arqma-node-setup.sh
   ```

4. Community support:
   - Discord: [Arqma Discord](https://discord.gg/arqma)
   - Forum: [Arqma Forum](https://forum.arqma.com)
   - GitHub: [Issues](https://github.com/ArqTras/snode-script/issues)

## Related Documentation

- [README.md](README.md) - Main documentation
- [INSTALL.md](INSTALL.md) - Installation guide
- [EXAMPLES.md](EXAMPLES.md) - Usage examples
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contributing guidelines
