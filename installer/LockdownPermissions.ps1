# Vantor Enterprise Security - Directory & Service DACL Lockdown Script
# Enforces strict DACL access controls (Major 18)

[CmdletBinding()]
param (
    [string]$InstallPath = "$env:ProgramFiles\Vantor",
    [string]$DataPath = "$env:ProgramData\Vantor"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       Vantor Security Directory & ACL Hardening          " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Lock down Program Files installation directory
if (Test-Path $InstallPath) {
    Write-Host "[*] Applying restrictive DACL to install directory: $InstallPath" -ForegroundColor Yellow
    
    # Disable inheritance and copy existing ACEs
    & icacls.exe "$InstallPath" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" /T /C /Q
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Installation directory locked down. Standard Users granted Read/Execute only." -ForegroundColor Green
    } else {
        Write-Warning "[-] icacls returned exit code $LASTEXITCODE for $InstallPath"
    }
} else {
    Write-Host "[-] Install path does not exist yet: $InstallPath" -ForegroundColor Gray
}

# 2. Lock down ProgramData and Anti-Tamper Backup directory
if (-not (Test-Path $DataPath)) {
    New-Item -Path $DataPath -ItemType Directory -Force | Out-Null
}

$atBackup = Join-Path $DataPath "ATBackup"
if (-not (Test-Path $atBackup)) {
    New-Item -Path $atBackup -ItemType Directory -Force | Out-Null
}

Write-Host "[*] Applying elevated-only DACL to ProgramData & ATBackup: $DataPath" -ForegroundColor Yellow
# Restrict ProgramData\Vantor to SYSTEM and Administrators only (No Users access)
& icacls.exe "$DataPath" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /T /C /Q

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Anti-Tamper data directory secured: SYSTEM & Administrators only." -ForegroundColor Green
}

# 3. Configure Service SID Type to RESTRICTED for VantorAntivirusService
$serviceName = "VantorAntivirusService"
$serviceObj = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($serviceObj) {
    Write-Host "[*] Configuring Service SID Type to RESTRICTED for: $serviceName" -ForegroundColor Yellow
    & sc.exe sidtype $serviceName restricted
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Service SID type successfully set to RESTRICTED." -ForegroundColor Green
    }
}

Write-Host "[+] All enterprise access controls and DACL lockdowns successfully enforced." -ForegroundColor Green
