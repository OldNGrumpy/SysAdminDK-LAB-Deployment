<#

    Create required servers for the FABRIC Domain.

    Tier 0 (10 Servers)
    3 x Active Directory Domain Controllers
    1 x Active Directory Certificate Authority
    2 x Entra Connect Sync
    2 x Entra Password Protection Proxy

    2 x Management server

    Tier 1 (24 Servers)
    2 x Remote Desktop Gateways
    2 x Radius Servers (MFA)
    2 x Entra Application Proxy / App Gateway

    2 x DHCP Servers
    2 x RRAS Servers (Always On VPN)
    2 x NPAS Servers (Always On VPN)

    2 x File Servers
    1 x DFS Server

    2 x Management server
    1 x Limited Management server

    2 x Remote Desktop Connection Broker Database Servers
    2 x Remote Desktop Connection Broker Servers
    2 x Remote Desktop Licensing Servers

    Optional Tier 2 (3 Servers)
    2 x Management server
    1 x Limited Management server


    Optional Tier Endpoint (9) (3 Servers)
    2 x Management server
    1 x Limited Management server

#>

$DefaultUser = "Administrator"
$DefaultPass = "Password,2025!"
$DomainFQDN = "lab25.lostinazure.com"
$DomainSubnet = "172.16.125"

# Find the Functions folder
# ------------------------------------------------------------
while (!(Test-Path -Path ".\Functions")) {
    $ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
    if ((Test-Path -Path "$ScriptDir\Functions")) {
        Set-Location -Path $ScriptDir
        exit
    }
    else {
        $FileLocations = @()
        Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and -not [string]::IsNullOrEmpty($_.DriveLetter) } |
            Sort-Object -Property DriveLetter -Descending |
            ForEach-Object {
                $Path = "$($_.DriveLetter):\"
                try {
                    $FileLocations += (Get-ChildItem -Path $Path -Include "PVE-Connect.ps1" -Recurse -ErrorAction SilentlyContinue).FullName | Split-Path -Parent -ErrorAction Stop
                }
                catch {
                    # Ignore errors
                }
            }
        if ($FileLocations.Count -gt 1) {
            $FunctionsFolder = $FileLocations | Out-GridView -Title "Select the Functions folder" -OutputMode Single
        }
        else {
            $FunctionsFolder = $FileLocations
        }
        Set-Location -Path (Split-Path -Parent $FunctionsFolder)
    }
}


# Import my PVE modules
# ------------------------------------------------------------
Get-ChildItem -Path ".\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }


# Connect to PVE Cluster
# ------------------------------------------------------------
#$PVEConnect = PVE-Connect -Authkey "root@pam!Powershell=16dcf2b5-1ca1-41cd-9e97-3c1d3d308ec0" -Hostaddr "10.36.1.27"
$PVEConnect = PVE-Connect -FromSettings

# Get the Deployment server info
# ------------------------------------------------------------
$MasterServer = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "22-TEST1"


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterServer.Node -ForceNode $MasterServer.Node


#.\New-PVEServer.ps1 -NewVMFQDN "ADDS-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).11" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -NoCreateVM
#"Wait for AD"
#pause
.\New-PVEServer.ps1 -NewVMFQDN "ADCA-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).16" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation -NoCreateVM
Start-Sleep -Seconds 120
#.\New-PVEServer.ps1 -NewVMFQDN "ADCA-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).17" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "AADC-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).18" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
Start-Sleep -Seconds 120
#.\New-PVEServer.ps1 -NewVMFQDN "AADC-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).19" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "AAPP-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).21" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "AAPP-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).22" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
.\New-PVEServer.ps1 -NewVMFQDN "MGMT-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).23" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
Start-Sleep -Seconds 120
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).24" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 8 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

.\New-PVEServer.ps1 -NewVMFQDN "RDGW-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).31" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RDGW-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).32" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "AMFA-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).33" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "AMFA-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).34" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MEAP-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).35" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MEAP-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).36" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RDDB-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).37" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RDDB-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).38" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RDCB-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).39" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RDCB-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).40" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RDLI-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).41" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RDLI-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).42" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

#.\New-PVEServer.ps1 -NewVMFQDN "DHCP-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).44" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "DHCP-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).45" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "NPAS-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).46" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "NPAS-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).47" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RRAS-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).48" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "RRAS-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).49" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

#.\New-PVEServer.ps1 -NewVMFQDN "DFSR-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).51" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "FILE-02.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).52" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "FILE-01.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).53" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-11.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).55" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-12.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).56" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-19.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).57" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-21.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).63" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-22.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).64" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-29.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).65" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation

#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-91.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).67" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-92.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).68" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
#.\New-PVEServer.ps1 -NewVMFQDN "MGMT-99.$DomainFQDN" -TemplateName "2025-Template" -NewVmIp "$($DomainSubnet).69" -LocalUsername $DefaultUser -LocalPassword $DefaultPass -VMMemory 4 -VMCores 2 -OSDisk 50 -DefaultConnection $PVEConnect -DefaultLocation $PVELocation
