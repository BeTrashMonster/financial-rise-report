# WSL Setup Guide for Financial RISE Project

## Why WSL?

Vitest has known issues on Windows/PowerShell where tests hang indefinitely. WSL (Windows Subsystem for Linux) provides a native Linux environment that runs tests reliably.

## Quick Start

### Step 1: Install WSL (One-time setup)

**Run PowerShell as Administrator:**

1. Press `Win + X`
2. Select "Windows PowerShell (Admin)" or "Terminal (Admin)"
3. Navigate to project: `cd C:\Users\Admin\src`
4. Run: `.\setup-wsl.ps1`
5. Your computer will restart

**After restart:**

- Ubuntu will launch automatically
- Create a username (lowercase, no spaces, e.g., "admin")
- Create a password (you won't see it as you type - this is normal)
- Wait for installation to complete

### Step 2: Set Up Project in WSL

**Open Ubuntu terminal:**

1. Search for "Ubuntu" in Start menu, or
2. Type `wsl` in PowerShell

**Run the setup script:**

```bash
cd /mnt/c/Users/Admin/src
bash wsl-project-setup.sh
```

This script will:
- Update Ubuntu packages
- Install Node.js 20 LTS
- Install development tools (git, build-essential)
- Install project dependencies
- Run tests to verify everything works

### Step 3: Daily Workflow

**Option A: Use WSL Terminal**

1. Open Ubuntu from Start menu (or type `wsl` in PowerShell)
2. Navigate to project: `cd /mnt/c/Users/Admin/src/financial-rise-frontend`
3. Run commands: `npm test`, `npm run dev`, etc.

**Option B: Use VS Code with WSL**

1. Install "WSL" extension in VS Code
2. Open VS Code
3. Press `Ctrl+Shift+P`
4. Type "WSL: Open Folder in WSL"
5. Select `C:\Users\Admin\src\financial-rise-frontend`
6. Use the integrated terminal (it will automatically be in WSL)

## Common Commands

```bash
# Navigate to project (from anywhere in WSL)
cd /mnt/c/Users/Admin/src/financial-rise-frontend

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Start development server
npm run dev

# Type check
npm run type-check

# Lint code
npm run lint
```

## Pro Tips

### Create an Alias for Quick Navigation

Add this to your `~/.bashrc`:

```bash
echo "alias fr='cd /mnt/c/Users/Admin/src/financial-rise-frontend'" >> ~/.bashrc
source ~/.bashrc
```

Now you can type `fr` from anywhere to jump to your project!

### Access Windows Files from WSL

Windows drives are mounted at `/mnt/`:
- `C:\` drive → `/mnt/c/`
- `D:\` drive → `/mnt/d/`

### Access WSL Files from Windows

WSL filesystem is accessible in Windows Explorer at:
```
\\wsl$\Ubuntu-22.04\home\<your-username>\
```

## Troubleshooting

### "wsl: command not found"

WSL is not installed. Run `setup-wsl.ps1` as Administrator.

### Tests still hanging

1. Make sure you're running tests IN WSL, not Windows PowerShell
2. Verify you're in WSL by running: `uname -a` (should show "Linux")
3. Reinstall dependencies in WSL: `rm -rf node_modules package-lock.json && npm install`

### Port already in use (dev server)

Kill processes using the port:
```bash
lsof -ti:5173 | xargs kill -9
```

### Performance issues

Edit `C:\Users\Admin\.wslconfig`:
```ini
[wsl2]
memory=4GB
processors=4
```

Then restart WSL: `wsl --shutdown` in PowerShell

## Verifying WSL is Working

Run this command in WSL:
```bash
uname -a
```

You should see output containing "Linux" - this confirms you're in WSL!

In Windows PowerShell, you'd see "Windows" in the output.

## Need Help?

- WSL Documentation: https://docs.microsoft.com/en-us/windows/wsl/
- Ubuntu on WSL: https://ubuntu.com/wsl
- VS Code WSL Extension: https://code.visualstudio.com/docs/remote/wsl
