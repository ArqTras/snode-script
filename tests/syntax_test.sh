#!/bin/bash
# Syntax test for arqma-node-setup.sh script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/arqma-node-setup.sh"

echo "=== Bash Syntax Test ==="
echo "Script: $SCRIPT_PATH"
echo ""

# Test 1: File exists
if [[ ! -f "$SCRIPT_PATH" ]]; then
    echo "❌ ERROR: File does not exist: $SCRIPT_PATH"
    exit 1
fi
echo "✓ File exists"

# Test 2: Has execute permissions
if [[ ! -x "$SCRIPT_PATH" ]]; then
    echo "⚠ WARNING: Missing execute permissions"
    chmod +x "$SCRIPT_PATH"
    echo "  Fixed: chmod +x"
fi
echo "✓ Execute permissions: OK"

# Test 3: Bash syntax
echo ""
echo "Checking syntax (bash -n)..."
if bash -n "$SCRIPT_PATH"; then
    echo "✓ Bash syntax: OK"
else
    echo "❌ ERROR: Invalid bash syntax"
    exit 1
fi

# Test 4: Shebang
echo ""
echo "Checking shebang..."
SHEBANG=$(head -n1 "$SCRIPT_PATH")
if [[ "$SHEBANG" == "#!/bin/bash" ]] || [[ "$SHEBANG" == "#!/usr/bin/env bash" ]]; then
    echo "✓ Shebang: OK ($SHEBANG)"
else
    echo "⚠ WARNING: Non-standard shebang: $SHEBANG"
fi

# Test 5: set -euo pipefail
echo ""
echo "Checking safe bash options..."
if grep -q "set -euo pipefail" "$SCRIPT_PATH"; then
    echo "✓ Security options (set -euo pipefail): OK"
else
    echo "⚠ WARNING: Missing 'set -euo pipefail'"
fi

# Test 6: Shellcheck (if available)
echo ""
if command -v shellcheck >/dev/null 2>&1; then
    echo "Running shellcheck..."
    if shellcheck -x "$SCRIPT_PATH"; then
        echo "✓ Shellcheck: PASSED"
    else
        echo "⚠ Shellcheck found warnings (non-blocking)"
    fi
else
    echo "ℹ Shellcheck not available (skip)"
fi

# Test 7: Help function
echo ""
echo "Testing --help function..."
if "$SCRIPT_PATH" --help >/dev/null 2>&1; then
    echo "✓ Option --help: OK"
else
    echo "❌ ERROR: Option --help does not work"
    exit 1
fi

# Test 8: Core functions exist
echo ""
echo "Checking for key functions..."
REQUIRED_FUNCTIONS=(
    "show_help"
    "die"
    "report_existing"
    "run_add_mode"
    "ensure_users_and_dirs"
    "generate_services_for_new_batch"
    "run_update_mode"
    "run_dashboard"
    "run_register_mode"
    "check_sn_synced"
    "check_storage_ping"
)

MISSING=()
for func in "${REQUIRED_FUNCTIONS[@]}"; do
    if grep -q "^${func}()" "$SCRIPT_PATH" || grep -q "^function ${func}" "$SCRIPT_PATH"; then
        echo "  ✓ $func"
    else
        echo "  ❌ Missing function: $func"
        MISSING+=("$func")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo ""
    echo "❌ Missing functions: ${MISSING[*]}"
    exit 1
fi

# Summary
echo ""
echo "================================="
echo "✓ All tests passed successfully!"
echo "================================="
exit 0
