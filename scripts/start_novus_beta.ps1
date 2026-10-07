# NOVUS - official BETA startup (PORT 5000)
# Usage from repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\start_novus_beta.ps1
#
# Does not disable MFA/RBAC/CSRF/Abuse Guard/CryptoVault.
# Operational target: up to 300 tenants with progressive onboarding.
# See data/production_closure/beta_launch_gate/BETA_OPERATING_LIMITS.md

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Py = "C:\Users\hp\AppData\Local\Python\pythoncore-3.14-64\python.exe"
if (-not (Test-Path $Py)) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Py = $cmd.Source }
}
if (-not $Py) { throw "Python executable not found" }

# --- Required beta profile ---
$env:NOVUS_ENV = "beta"
$env:FLASK_DEBUG = "False"
$env:DEBUG = "False"
$env:PORT = "5000"
if (-not $env:HOST) { $env:HOST = "0.0.0.0" }
$env:NOVUS_ALLOW_LAB_RUNTIME = "False"
$env:NOVUS_ALLOW_QA_SEED = "False"
$env:NOVUS_ENTERPRISE_WARMUP = "False"
if (-not $env:NOVUS_ALLOW_REGISTRATION) { $env:NOVUS_ALLOW_REGISTRATION = "False" }

$EnvFile = Join-Path $Root ".env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $i = $line.IndexOf("=")
        if ($i -lt 1) { return }
        $k = $line.Substring(0, $i).Trim()
        $v = $line.Substring($i + 1).Trim()
        if ($k -in @("NOVUS_ENV", "FLASK_DEBUG", "DEBUG", "PORT")) { return }
        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($k, "Process"))) { return }
        Set-Item -Path ("Env:" + $k) -Value $v
    }
    Write-Host "[beta] Loaded supplemental vars from .env (beta profile locks NOVUS_ENV/FLASK_DEBUG/PORT)"
} else {
    Write-Host "[beta] WARNING: .env missing - copy .env.example to .env and set SECRET_KEY before remote exposure"
}

Write-Host ("[beta] NOVUS_ENV=" + $env:NOVUS_ENV + " PORT=" + $env:PORT + " FLASK_DEBUG=" + $env:FLASK_DEBUG)
Write-Host "[beta] Operational target: up to 300 tenants. Progressive steps 50 100 150 200 250 300. Not a commercial SLA."

$listeners = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
foreach ($procId in $listeners) {
    if ($procId) {
        Write-Host ("[beta] Stopping prior PID " + $procId + " on :5000")
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 2

$stdout = Join-Path $Root "data\production_closure\beta_launch_gate\beta_server_stdout.log"
$stderr = Join-Path $Root "data\production_closure\beta_launch_gate\beta_server_stderr.log"
New-Item -ItemType Directory -Force -Path (Split-Path $stdout) | Out-Null

Start-Process -FilePath $Py -ArgumentList "-u","main.py" -WorkingDirectory $Root `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden

$ok = $false
for ($i = 0; $i -lt 45; $i++) {
    Start-Sleep -Seconds 2
    try {
        $c = (Invoke-WebRequest "http://127.0.0.1:5000/login" -UseBasicParsing -TimeoutSec 5).StatusCode
        if ($c -eq 200) { $ok = $true; break }
    } catch {}
}
if ($ok) {
    Write-Host "[beta] NOVUS is UP on http://127.0.0.1:5000/login"
} else {
    Write-Host ("[beta] START FAILED - check " + $stderr)
    exit 1
}
