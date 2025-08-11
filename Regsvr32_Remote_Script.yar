rule Regsvr32_Remote_Script
{
    meta:
        description = "Detect regsvr32 loading a remote script via URL"
        author = "Silas"
        date = "2025-08-11"
        threat = "LOLBin abuse for remote script execution"
    strings:
        $regsvr32 = "regsvr32" nocase
        $url = /https?:\/\/[^\s]+\.sct/ nocase
    condition:
        $regsvr32 and $url
}
