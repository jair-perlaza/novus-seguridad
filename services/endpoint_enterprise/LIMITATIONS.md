# Endpoint Enterprise — limitaciones explícitas

## Rootkit kernel propio
**Estado:** NO IMPLEMENTADO  
**Motivo:** Verificar hooks SSDT/IDT/DKOM requiere driver en Ring-0 firmado (EV).  
**Alternativa empresarial:** sensor con minifilter/driver o integración Microsoft Defender for Endpoint / ETW kernel, correlacionado vía Swarm.

## Rootkit Detection Híbrido (Fase 1)
**Estado:** IMPLEMENTADO (user-mode verificable)  
- Cross-view procesos (psutil / WMI / tasklist)
- Servicios SCM vs registro
- Drivers (driverquery + muestra Authenticode)
- Hooks inline / bounds de exportaciones en proceso actual
- ETW/Event Log cuando accesible
- Correlación multi-indicador antes de alertar Swarm  
**No afirma** capacidades Ring-0.

## SSDT
**Estado:** NO IMPLEMENTADO (requiere Ring-0)  
No marcar como implementado en auditoría.

## YARA
**Estado:** IMPLEMENTADO vía `yara-x`.  
Escaneo de archivos + regiones de memoria legibles. Procesos protegidos → AccessDenied documentado.

## Zero-day detector dedicado / ML malware
**Estado:** NO IMPLEMENTADO.  
**Alternativa:** Risk Score comportamental + YARA + heurística + APE.
