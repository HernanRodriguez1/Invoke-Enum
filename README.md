
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

<img width="1384" height="865" alt="1" src="https://github.com/user-attachments/assets/03abfa4d-646d-4d9e-bc65-1ef16dc05485" /><br>

<img width="1877" height="864" alt="2" src="https://github.com/user-attachments/assets/8d7ac0e5-11c8-48c7-99fb-20bfc7b5a649" /><br>

<img width="1210" height="762" alt="3" src="https://github.com/user-attachments/assets/63c1c7fb-61af-41ba-aa52-4c9d5bfb318d" /><br>

<img width="1122" height="852" alt="4" src="https://github.com/user-attachments/assets/d47ce924-1774-406a-b58e-3e82df585219" /><br>

<img width="1145" height="851" alt="5" src="https://github.com/user-attachments/assets/80d7bc27-287c-407b-8776-19ada2720fa9" /><br>

<img width="1030" height="708" alt="6" src="https://github.com/user-attachments/assets/e632fd7f-e477-435e-a134-9828b8aa9438" /><br>


## Requirements

- PowerShell 5.0 or higher
- Standard user permissions (no administrative privileges required)
- Compatible with: Windows 7, 10, 11, Server 2012/2016/2019
---
