function Invoke-MWxRestMethod {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$false)]
        [string]$Method = 'Get',
        
        [Parameter(Mandatory=$false)]
        [object]$Body,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory=$false)]
        [switch]$CertificateCheck,
        
        [Parameter(Mandatory=$false)]
        [switch]$CheckHeaders
    )
    
    $params = @{
        Uri    = $Uri
        Method = $Method
    }
    
    if ($Body) {
        $params['Body'] = $Body
    }
    
    if ($Headers) {
        $params['Headers'] = $Headers
    }
    
    # Handle certificate check based on PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        if ($CertificateCheck) {
            $params['SkipCertificateCheck'] = $false
        } else {
            $params['SkipCertificateCheck'] = $true
        }
        if ($CheckHeaders) {
            $params['SkipHeaderValidation'] = $false
        } else {
            $params['SkipHeaderValidation'] = $true
        }
    } else {
        # PowerShell 5.1 workaround
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
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if ($ForceCertificateCheck) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $false }
        }
        else {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        if ($CheckHeaders) {
            # No direct equivalent in 5.1, so we skip this part
        }
    }     
    
    try {
        Invoke-RestMethod @params
    } catch {
        Write-Error "Failed to invoke REST method: $_"
        throw
    }
}