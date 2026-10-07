/*
  NOVUS Endpoint Enterprise — reglas YARA baseline (comportamiento / artefactos conocidos).
  No son firmas de AV comercial; reglas abiertas verificables.
*/
rule NOVUS_EICAR_TestFile
{
    meta:
        description = "Cadena EICAR de prueba antivirus (no malware)"
        confidence = "high"
        novus_severity = "info"
        novus_category = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule NOVUS_PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell con -EncodedCommand / -enc (ofuscación frecuente)"
        confidence = "medium"
        novus_severity = "medium"
        novus_category = "lolbin"
    strings:
        $a = "-EncodedCommand" nocase
        $b = " -enc " nocase
        $c = "FromBase64String" nocase
    condition:
        2 of them
}

rule NOVUS_Mimikatz_Strings
{
    meta:
        description = "Cadenas típicas asociadas a Mimikatz (evidencia textual)"
        confidence = "high"
        novus_severity = "critical"
        novus_category = "credential_access"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "mimikatz" nocase
        $c = "privilege::debug" nocase
    condition:
        2 of them
}

rule NOVUS_Reflective_DLL_Stub
{
    meta:
        description = "Indicadores textuales de carga reflectiva / VirtualAlloc RWX"
        confidence = "medium"
        novus_severity = "high"
        novus_category = "injection"
    strings:
        $a = "ReflectiveLoader" nocase
        $b = "VirtualAllocEx" nocase
        $c = "WriteProcessMemory" nocase
        $d = "NtUnmapViewOfSection" nocase
    condition:
        2 of them
}

rule NOVUS_Suspicious_Temp_Script
{
    meta:
        description = "Script PowerShell/JS con rutas TEMP en contenido"
        confidence = "low"
        novus_severity = "low"
        novus_category = "execution"
    strings:
        $a = "\\AppData\\Local\\Temp\\" nocase
        $b = "Invoke-Expression" nocase
        $c = "IEX(" nocase
        $d = "DownloadString" nocase
    condition:
        $a and 1 of ($b, $c, $d)
}
