
# Invoke-Enum.ps1

**Advanced Enumeration for Privilege Escalation in Windows**

## Overview

`Invoke-Enum.ps1` is an advanced tool written in PowerShell that allows cybersecurity analysts to identify potential privilege escalation vectors on Windows systems. The script provides structured, secure, and fully Spanish-language output, with a professional approach for auditing, red teaming, or defensive analysis environments.

---

## Features

- Detection of installed security patches
- Enumeration of sensitive privileges of the current user with `whoami /priv`
- Detection of privileged tokens (`SeImpersonate`, `SeAssignPrimaryToken`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeTcbPrivilege`, `SeManageVolumePrivilege`, `SeCreateTokenPrivilege`)
- Credential extraction:
- AutoLogon keys (`DefaultUserName`, `DefaultPassword`)
- Credentials saved in `cmdkey`
- `Groups.xml` files with `cpassword`
- `unattend.xml`, `sysprep.xml` files `autounattend.xml`
- Unquoted Service Paths (Unquoted Service Paths)
- Detection of dangerous configurations such as `AlwaysInstallElevated`
- Analysis of `PATH` paths with `Write`, `Modify`, or `FullControl` permissions
- Review of automatic execution keys (`Run` from HKCU and HKLM)
- Detection of scheduled tasks outside of Microsoft and their associated executables
- Association of open ports with services and processes
- Deep disk scan:
- `.exe` executables with `FullControl` for `Users` or `Everyone`
- `.ps1`, `.bat`, `.dll`, `.vbs` files with write permissions
- Detection of services and their binary versions to search for CVEs
- Enumeration of installed third-party applications
- Collection of sensitive files:
- `.pfx`, `.pem`, `.sql`, `.config`, `.bak`, `.rdp`, `.key`, `.ini`, `.kdbx`, `.ovpn`, etc.
- Verification and location of `SAM` and `SYSTEM` hives on disk
- Analysis of system information (OS, hardware, users, groups)
- Evaluation of UAC (User Account Control) settings
- Search for DPAPI credentials in registry and files
- Scanning of extended network information (IP configuration, routing table)
- Detection of PowerShell history and sensitive commands
---

## How to use

```powershell
powershell.exe -ep bypass -File .\Invoke-Enum.ps1
```

Or run in memory:

```powershell
iex (Get-Content .\Invoke-Enum.ps1 -Raw)
```

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/ed8b017c-2f3c-4c27-94bd-f23b53a0ca45" style="max-width: 1000px; width: 100%; height: auto;" />
</p>

<br>

<p align="center">
  <img src="https://github.com/user-attachments/assets/ed38a1c9-9b28-4fa8-82c7-e31f7351dda5" style="max-width: 1000px; width: 100%; height: auto;" />
</p>

<br>

<p align="center">
  <img src="https://github.com/user-attachments/assets/245a8c51-0135-4c51-966a-4ab62693d25d" style="max-width: 1000px; width: 100%; height: auto;" />
</p>

<br>

<p align="center">
  <img src="https://github.com/user-attachments/assets/8da0050d-50ba-4665-8d40-cef46a6b6a3b" style="max-width: 1000px; width: 100%; height: auto;" />
</p>



## Requirements

- PowerShell 5.0 or higher
- Standard user permissions (no administrative privileges required)
- Compatible with: Windows 7, 10, 11, Server 2012/2016/2019
---
