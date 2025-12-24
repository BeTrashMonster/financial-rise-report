# Quick Fix for WSL Test Setup

The I/O errors you're seeing are because Windows executables (.exe, .node files) can't be deleted from WSL when they're locked.

## ✅ Solution: Use the Improved Script (Version 2)

Run these commands in your WSL terminal:

```bash
cd /mnt/c/Users/Admin/src

# Make the new script executable
chmod +x fix-and-run-tests-wsl-v2.sh

# Run the improved version
./fix-and-run-tests-wsl-v2.sh
```

## What's Different in V2?

The new script handles Windows binary locking by:
1. ✅ Moving locked files to a temporary folder instead of deleting them
2. ✅ Installing fresh dependencies with `--force` flag
3. ✅ Cleaning up old files in the background after install completes
4. ✅ Better error handling and logging

This avoids the I/O errors you encountered.

---

## Alternative: Manual Fix (If Script Still Has Issues)

If the script still encounters problems, you can fix it manually:

### Backend Setup (Works Fine)
```bash
cd /mnt/c/Users/Admin/src/financial-rise-backend

# The backend setup already worked, but if you need to redo it:
npm install
npm test
```

### Frontend Fix (Manual)
```bash
cd /mnt/c/Users/Admin/src/financial-rise-frontend

# Just delete package-lock.json (no need to delete node_modules)
rm -f package-lock.json

# Install fresh - npm will overwrite the Windows binaries with Linux ones
npm install --force

# Then run tests
npm test
```

The `--force` flag tells npm to reinstall everything, replacing Windows binaries with Linux ones, even if node_modules exists.

---

## Why This Happens

WSL (Windows Subsystem for Linux) can read Windows files, but:
- Windows .exe and .node files are locked by Windows file system
- WSL can't delete them directly
- Solution: Install over them, or move them instead of deleting

The improved script handles this automatically!
