
# Invoke-Enum.ps1

**Enumeración avanzada para escalamiento de privilegios en Windows**

## Descripción general

`Invoke-Enum.ps1` es una herramienta avanzada escrita en PowerShell que permite a analistas de ciberseguridad 
identificar posibles vectores de escalamiento de privilegios en sistemas Windows. El script ofrece una salida estructurada, 
segura y completamente en español, con un enfoque profesional para entornos de auditoría, red teaming o análisis defensivo.

---

## Características principales

- Detección de configuraciones peligrosas como `AlwaysInstallElevated`
- Enumeración de privilegios sensibles del usuario actual con `whoami /priv`
- Extracción de credenciales:
  - Claves AutoLogon (`DefaultUserName`, `DefaultPassword`)
  - Credenciales guardadas en `cmdkey`
  - Archivos `Groups.xml` con `cpassword`
  - Archivos `unattend.xml`, `sysprep.xml`, `autounattend.xml`
- Detección de tokens privilegiados (`SeImpersonate`, `SeAssignPrimaryToken`, etc.)
- Análisis de rutas `PATH` con permisos `Write`, `Modify` o `FullControl`
- Revisión de claves de ejecución automática (`Run` de HKCU y HKLM)
- Detección de tareas programadas externas a Microsoft y sus ejecutables asociados
- Asociación de puertos abiertos con servicios y procesos
- Exploración profunda del disco:
  - Ejecutables `.exe` con `FullControl` para `Users` o `Everyone`
  - Archivos `.ps1`, `.bat`, `.dll`, `.vbs` con permisos de escritura
- Detección de servicios y versiones de sus binarios para buscar CVEs
- Enumeración de aplicaciones instaladas de terceros
- Recolección de archivos sensibles:
  - `.pfx`, `.pem`, `.sql`, `.config`, `.bak`, `.rdp`, `.key`, `.ini`, `.kdbx`, `.ovpn`, etc.
- Verificación y localización de hives `SAM` y `SYSTEM` en disco
---

## Modo de uso

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-Enum.ps1
```

O ejecutar en memoria:

```powershell
iex (Get-Content .\Invoke-Enum.ps1 -Raw)
```

---

## Requisitos

- PowerShell 5.0 o superior
- Permisos de usuario estándar (no requiere privilegios administrativos)
- Compatible con: Windows 7, 10, 11, Server 2012/2016/2019

---

## Créditos e inspiración
Desarrollado por y para la comunidad hispanohablante de seguridad ofensiva.
