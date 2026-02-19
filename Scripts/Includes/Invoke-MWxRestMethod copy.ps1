function Invoke-MWxRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [ValidateSet("Post", "Get", "Default", "Delete", "Get", "Head", "Merge", "Options", "Patch", "Post", "Put", "Trace")]
        [string]$Method, 
        $Headers = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]"),
        [string]$APIToken,
        [string]$Body,
        [string]$ContentType
    )
    
    begin {
        $Arguments = @{}
        $UriBase = $ProxmoxInfo.APIbase
        if ($UriBase.EndsWith('/')) {
            
        }
        if ($Uri.StartsWith('/') -or $Uri.StartsWith('http') -eq $false) {
            $Uri = ("/$Uri").Replace('//','/')
            $Uri = "$($ProxmoxInfo.APIbase)$Uri"
        }
        $Arguments.Add("Uri", $Uri)
        $Arguments.Add("Method", $Method)
        if ($PSVersionTable.PSVersion -gt "7.3") {
            $Arguments.Add("SkipCertificateCheck", $true)
        }
        else {
            Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    }
    
    process {
        if ($Headers.Count -gt 0) {
            if (-not $headers.ContainsKey('Authorization')) {
                $headers.Add('Authorization', "PVEAPIToken $APIToken")
            }
        }
        if ([string]::IsNullOrEmpty($APIToken) -eq $false -and $headers.ContainsKey('Authorization') -eq $false) {
            $headers.Add('Authorization', "PVEAPIToken $APIToken")
        }
        elseif ($headers.ContainsKey('Authorization') -eq $false) {
            $headers = Get-MWxProxmoxHeaders
        }

        if ([string]::IsNullOrEmpty($Body) -eq $false) {
            $headers.Add('Body', $Body)
        }
        if ([string]::IsNullOrEmpty($ContentType) -eq $false) {
            $headers.Add('ContentType', $ContentType)
        }

        $Arguments.Add("Headers", $headers)
        try {
            $retVal = Invoke-RestMethod @Arguments
        }
        catch {
            Write-Error $_.Exception.Message
            Write-Error $_.Exception.StackTrace
            $retVal = $null
        }

    }
    
    end {
        return $retVal
    }
}
# Invoke-MWxRestMethod -Uri "nodes/proxmox1/storage" -Method Get -Verbose
# (Invoke-MWxRestMethod -Uri "https://$ProxmoxHost/api2/json/cluster/nextid" -Method Get).data
