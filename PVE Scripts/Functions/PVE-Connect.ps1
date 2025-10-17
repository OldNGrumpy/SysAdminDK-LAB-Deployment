function PVE-Connect {
    [CmdletBinding(DefaultParameterSetName = 'Auth')]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'Auth')][string]$Authkey,
        [Parameter(Mandatory, ParameterSetName = 'Auth')][string]$Hostaddr,
        [Parameter(ParameterSetName = 'Settings')][switch]$FromSettings
    )

    if ($FromSettings) {
        $PVESettingsFile = Get-ChildItem -Path $MyInvocation.PSScriptRoot -Include PVESettings.ps1 -Recurse -File
        if (!$PVESettingsFile) {
            throw "No settings found"
        }
        . $PVESettingsFile.FullName
        $Authkey = $PVESettings.AuthKey
        $Hostaddr = $PVESettings.Hostaddr
    }

    # HTTP Headers for connection.
    # ------------------------------------------------------------
    $DefaultHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $DefaultHeaders.Add("Authorization", "PVEAPIToken=$AuthKey")
    $DefaultHeaders.Add("Accept", "application/json")


    # Ignore Self Signed Cert.
    # ------------------------------------------------------------
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    # Proxmox API address.
    # ------------------------------------------------------------
    $DefaultProxmoxAPI = "https://$($HostAddr):8006/api2/json"

    return @( [PSCustomObject]@{ PVEAPI  = $DefaultProxmoxAPI; Headers = $DefaultHeaders } )

}

