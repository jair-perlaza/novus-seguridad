/*
  NOVUS Endpoint Enterprise — heurística PE/API keylogging y captura de pantalla.
  Señal observable; no veredicto de malware. Integrado desde especificación Kernel Core.
*/
rule NOVUS_PE_Keylogging_Screencapture_Heuristic
{
    meta:
        description = "Cadenas API Windows asociadas a keylogging/captura — heurística, no confirma malware"
        author = "NOVUS"
        confidence = "low"
        novus_severity = "medium"
        novus_category = "endpoint_heuristic"
    strings:
        $s1 = "GetAsyncKeyState" ascii wide
        $s2 = "GetForegroundWindow" ascii wide
        $s3 = "SetWindowsHookEx" ascii wide
        $s4 = "BitBlt" ascii wide
    condition:
        2 of ($s1, $s2, $s3, $s4)
}
