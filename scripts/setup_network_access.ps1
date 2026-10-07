# Acceso en red — NOVUS instancia única (puerto 5000)
# Ejecutar en PowerShell como Administrador en el equipo servidor.

$ruleName = "NOVUS MVP TCP 5000"
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existing) {
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5000 `
        -Profile Domain,Private `
        -Description "Permite acceso LAN a la instancia única NOVUS en puerto 5000"
    Write-Host "Regla de firewall creada: $ruleName"
} else {
    Write-Host "Regla de firewall ya existe: $ruleName"
}

Write-Host ""
Write-Host "Configuracion NOVUS para socios (misma instancia):"
Write-Host "  URL LAN:  http://10.196.213.166:5000"
Write-Host "  Host Flask: 0.0.0.0 (todas las interfaces)"
Write-Host "  Puerto: 5000"
Write-Host "  Base de datos: SQLite local en C:\NOVUS (unica)"
Write-Host ""
Write-Host "Requisitos en equipos clientes:"
Write-Host "  - Misma red Wi-Fi/LAN que el servidor"
Write-Host "  - Navegador moderno"
Write-Host "  - Credenciales corporativas NOVUS (login compartido por tenant)"
