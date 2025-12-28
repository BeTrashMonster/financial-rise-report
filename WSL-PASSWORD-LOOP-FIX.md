# WSL Password Loop - Issue Fixed

**Date:** December 28, 2025  
**Issue:** WSL kept asking for password repeatedly

## Problem Diagnosed

Your WSL installation did not have a default user configured in `/etc/wsl.conf`. This caused WSL to potentially prompt for authentication repeatedly, especially when launching or when certain operations required privilege escalation.

**WSL User:** betrashmonster  
**Account Status:** Active, password set, not locked

## Fixes Applied

### 1. Set Default User Configuration
Created/updated `/etc/wsl.conf` with:
```ini
[boot]
systemd=true

[user]
default=betrashmonster
```

### 2. Reset Failed Login Counters
Cleared any potential failed login attempts (if faillock was configured).

### 3. Restarted WSL
WSL was shut down and restarted to apply the configuration changes.

## Verification

The default user is now correctly set:
```bash
$ wsl -e whoami
betrashmonster
```

## What You Should Do Next

### 1. Close and Reopen Your WSL Terminal
- Close any open WSL/Ubuntu terminals
- Open a new Windows Terminal or WSL window
- You should now log in directly as "betrashmonster" without password prompts

### 2. If You Still Get Password Prompts
The password loop might be from:

**A. Windows Terminal Profile**
If using Windows Terminal, check your Ubuntu profile settings:
1. Open Windows Terminal Settings (Ctrl+,)
2. Find your Ubuntu-22.04 profile
3. Check if "Run this profile as Administrator" is enabled - disable it if not needed

**B. sudo Password Prompts**
If the prompt appears when running commands, it might be asking for sudo password:
- This is normal for commands requiring elevated privileges
- Enter your Linux password (same as you set during WSL setup)
- You can configure sudo to not require password (not recommended for security):
  ```bash
  sudo visudo
  # Add: betrashmonster ALL=(ALL) NOPASSWD: ALL
  ```

**C. Windows Credential Manager**
Clear stored WSL credentials:
1. Open "Credential Manager" in Windows
2. Go to "Windows Credentials"
3. Look for any WSL or Ubuntu entries
4. Remove them
5. Restart WSL

### 3. If Issue Persists
Try these additional steps:

**Reset to Root and Recreate User Password:**
```powershell
# In PowerShell (Windows)
wsl -u root
```

Then in WSL:
```bash
# Reset your password
passwd betrashmonster

# Verify account status
passwd -S betrashmonster
```

**Check PAM Configuration:**
```bash
# Check if common-auth has issues
sudo cat /etc/pam.d/common-auth
```

Look for any "pam_faillock" or authentication modules that might be causing loops.

## Current Status

✅ Default user configured  
✅ Account status verified (active)  
✅ Failed login counters cleared  
✅ WSL restarted  
✅ Configuration applied

## Quick Test Commands

Run these in Windows Terminal to verify:

```powershell
# Should show: betrashmonster
wsl -e whoami

# Should work without password prompt
wsl -e ls ~

# Should work
wsl -e pwd
```

## If You Need to Run as Root

```powershell
wsl -u root
```

## Additional Information

- Your WSL distribution: Ubuntu-22.04
- WSL Version: 2
- Default user: betrashmonster
- Configuration file: /etc/wsl.conf
