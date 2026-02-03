# Contributing Guide

Thank you for your interest in contributing to the Arqma Node Setup Script project!

## How to Help

### Reporting Bugs

If you find a bug, create an issue on GitHub containing:

1. **Problem description** - what happened?
2. **Environment**:
   - Linux distribution and version
   - Bash version: `bash --version`
   - Command that caused the error
3. **Logs**: 
   - Script output
   - Systemd logs: `journalctl -u snX.service`
4. **Reproduction steps**
5. **Expected behavior**

### Proposing New Features

Before starting work on a new feature:

1. Check if the issue doesn't already exist
2. Create a new issue with description:
   - What problem does it solve?
   - Usage example
   - Alternative solutions

### Pull Requests

#### Before Submitting PR

1. **Fork** the repository
2. **Create branch**: `git checkout -b feature/feature-name`
3. **Test** changes on clean Ubuntu/Debian
4. **Check syntax**: `bash -n arqma-node-setup.sh`
5. **Shellcheck** (if available): `shellcheck arqma-node-setup.sh`

#### Code Standards

**Bash Style Guide:**

```bash
# Use set -euo pipefail at the beginning
set -euo pipefail

# Variable names: UPPER_CASE for constants, lower_case for variables
readonly CONST_VALUE="value"
local variable_name="value"

# Always quote variables
echo "$variable_name"
[[ -n "$var" ]] && echo "exists"

# Use [[ ]] instead of [ ]
if [[ "$var" == "value" ]]; then
    echo "match"
fi

# Check exit status
if command -v foo >/dev/null 2>&1; then
    echo "foo exists"
fi

# Functions: snake_case
my_function() {
    local param="$1"
    echo "$param"
}

# Use 'local' for local variables
function_with_locals() {
    local file="$1"
    local result
    result=$(process "$file")
    echo "$result"
}

# Comments for complex sections
# ---------------- Section: Helper functions ----------------
```

**Security:**

- DO NOT commit keys, certificates, passwords
- Validate user input
- Use `--` in commands with parameters: `rm -rf -- "$dir"`
- Never use `eval` with user input
- Validate paths before file operations

**Documentation:**

- Add comments to complicated sections
- Update README.md for new features
- Add usage examples
- Document new CLI parameters

#### Commit Message Structure

```
type: Short description (max 50 characters)

Longer description if needed. Explain:
- What was changed
- Why the change was needed
- What are the side effects

Fixes #123
```

**Commit types:**
- `feat:` - new feature
- `fix:` - bug fix
- `docs:` - documentation only
- `style:` - formatting, missing semicolons (no code changes)
- `refactor:` - refactoring (no functionality changes)
- `test:` - adding or fixing tests
- `chore:` - maintenance (update dependencies, etc.)

**Examples:**

```
feat: add support for Rocky Linux

Extend compatibility to Rocky Linux 8+.
Added distribution detection and appropriate package manager.

Fixes #42
```

```
fix: fix seeding error with multiple nodes

Problem occurred when seeding more than 5 nodes
simultaneously - missing timeout for rsync operations.

Added configurable timeout (default: 600s).

Fixes #67
```

#### Review Process

1. Creating PR triggers automatic tests
2. Maintainers will review the code
3. Changes may be required
4. After approval, PR will be merged

## Testing

### Test Environment

We recommend testing on:
- Ubuntu 20.04 LTS
- Ubuntu 22.04 LTS
- Debian 11
- Debian 12

### Basic Tests

```bash
# Syntax test
bash -n arqma-node-setup.sh

# Help option test
./arqma-node-setup.sh --help

# Dry-run test (TODO: to be implemented)
./arqma-node-setup.sh --dry-run --pairs 2

# Shellcheck (if available)
shellcheck -x arqma-node-setup.sh
```

### Functional Tests

Test on clean VPS/VM:

```bash
# Fresh installation test
sudo ./arqma-node-setup.sh

# Reporting test (requires existing nodes)
sudo ./arqma-node-setup.sh --report-existing

# Adding nodes test
sudo ./arqma-node-setup.sh --add-pairs 1 --seed-from 1
```

### Checklist before PR

- [ ] Code passes `bash -n`
- [ ] Code passes shellcheck (if available)
- [ ] Functionality tested on Ubuntu/Debian
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] No sensitive data in commits
- [ ] PR has clear description of changes

## Project Structure

```
snode-script/
├── arqma-node-setup.sh    # Main script
├── README.md              # Full documentation
├── INSTALL.md             # Quick start
├── CONTRIBUTING.md        # This file
├── LICENSE                # MIT License
├── .gitignore            # Ignored files
└── tests/                 # Tests (TODO)
    ├── syntax_test.sh
    └── integration_test.sh
```

## Communication Style

- Be kind and constructive
- Respect others' time
- Ask questions if something is unclear
- Don't be afraid to ask for help

## Resources

- [Bash Style Guide (Google)](https://google.github.io/styleguide/shellguide.html)
- [ShellCheck Wiki](https://github.com/koalaman/shellcheck/wiki)
- [Advanced Bash-Scripting Guide](https://tldp.org/LDP/abs/html/)

## Contact

- GitHub Issues: Technical questions and bugs
- Discord: General questions and discussions
- Email: dev@arqma.com (for sensitive matters)

## License

By contributing to this project, you agree to the MIT license.

---

Thank you for contributing to the Arqma project! 🚀
