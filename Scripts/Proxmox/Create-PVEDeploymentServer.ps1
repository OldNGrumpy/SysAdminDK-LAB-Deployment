<# 

    Create Deployment server.
    4 vCpu
    8Gb Ram
    50Gb OS Drive
    100GB Data Drive


    Download Server 2025 Eval.
    https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso

    Download Server 2022 Eval.
    https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso

    Download VirtIO Drivers.
    https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso
    

    Do the Windows Installation.


    When Done, Download required scripts from Git...
    MS-Fabric\* -> D:\*

    And Extract/Copy content from the ISO drives.

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]
    $VMName = "DEPL00",
    [Parameter(Mandatory=$false)]
    [string]
    $RootPath = "C:\Mats\GitHub\SysAdminDK-LAB-Deployment\Scripts\Proxmox",
    [string]$IsoFileName = "en-us_windows_server_2025_updated_jan_2026_x64_dvd_5cf90374.iso" 
)

Write-Verbose "Using INCLUDES from: $(Split-Path -Path $RootPath -Parent)\Includes"

# Import PVE modules
# ------------------------------------------------------------
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -Confirm:$false
Get-ChildItem -Path "$RootPath\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }

# dot-source includes
Get-ChildItem -Path "$(Split-Path -Path $RootPath -Parent)\Includes" | ForEach-Object {
    Write-Verbose "Dot-sourcing $($_.FullName)"
    . $_.FullName
}

# Connect to PVE Cluster
# ------------------------------------------------------------
$PVESecret = Get-Content "$RootPath\PVE-Secret.json" | Convertfrom-Json
$PVEConnect = PVE-Connect -Authkey "$($PVESecret.User)!$($PVESecret.TokenID)=$($PVESecret.Token)" -Hostaddr $($PVESecret.Host)


# Get information required to create the template (VM)
# ------------------------------------------------------------
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterID.Node
$MasterID = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "LAB-Deploy"
$ISOStorage = ((Invoke-MWxRestMethod -SkipHeaderValidation -SkipCertificateCheck -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage" -Headers $($PVEConnect.Headers) -Method Get).data | Where {$_.content -like "*iso*"}).storage

if ($ISOStorage.Count -gt 1) {
    $ISOStorage = $ISOStorage | Out-GridView -Title "Select ISOStorage for the new VM" -OutputMode Single
}

# Download Windows Server 2025 EVAL Iso
# ------------------------------------------------------------
$DownloadBody = "content=iso"
$DownloadBody += "&node=$($PVELocation.name)"
$DownloadBody += "&url=$([uri]::EscapeDataString("https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"))"
$DownloadBody += "&filename=$([uri]::EscapeDataString("Server2025.iso"))"

#$2025Result = Invoke-MWxRestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage/$ISOStorage/download-url" -Headers $($PVEConnect.Headers) -Body $DownloadBody


# Download VirtIO Windows Drivers.
# ------------------------------------------------------------
$DownloadBody += "&node=$($PVELocation.name)"
$DownloadBody += "&url=$([uri]::EscapeDataString("https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso"))"
$DownloadBody += "&filename=$([uri]::EscapeDataString("virtio-win.iso"))"

#$DriverResult = Invoke-RestMethod -Method POST -SkipHeaderValidation -SkipCertificateCheck -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage/$ISOStorage/download-url" -Headers $($PVEConnect.Headers) -Body $DownloadBody


# Wait all 3 downloads.
# ------------------------------------------------------------
#Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $2022Result.data
#Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $2025Result.data
#Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $DriverResult.data

# Next avalible High VMID
# ------------------------------------------------------------
$VMID = Get-PVENextID -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $($PVEConnect.Headers)


# Default Deployent Sever Configuration
# ------------------------------------------------------------
$Body = "node=$($PVELocation.Name)"
$Body += "&vmid=$VMID"
$Body += "&name=fsddfsdfa"
$Body += "&bios=ovmf"
$Body += "&cpu=host"
$Body += "&ostype=win11"
$Body += "&machine=pc-q35-9.0"
$Body += "&tpmstate0=$([uri]::EscapeDataString("$($PVELocation.storage):1,size=4M,version=v2.0"))"
$Body += "&efidisk0=$([uri]::EscapeDataString("$($PVELocation.storage):1,efitype=4m,format=raw,pre-enrolled-keys=1"))"
$Body += "&net0=$([uri]::EscapeDataString("virtio,bridge=$($PVELocation.Interface),firewall=1"))"
$Body += "&boot=$([uri]::EscapeDataString("order=scsi0;ide2"))"
$Body += "&scsihw=virtio-scsi-single"
$Body += "&memory=8192"
$Body += "&balloon=2048"
$Body += "&cores=4"
$Body += "&scsi0=$([uri]::EscapeDataString("$($PVELocation.storage):50,ssd=on,format=raw"))"
$Body += "&scsi1=$([uri]::EscapeDataString("$($PVELocation.storage):100,format=raw"))"
$Body += "&ide0=$([uri]::EscapeDataString("$($ISOStorage):iso/virtio-win.iso,media=cdrom"))"
$Body += "&ide2=$([uri]::EscapeDataString("$($ISOStorage):iso/$IsoFileName,media=cdrom"))"


# Create the Template VM
# ------------------------------------------------------------
$VMCreate = Invoke-MWxRestMethod -SkipHeaderValidation -SkipCertificateCheck -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.Name)/qemu/" -Body $Body -Method POST -Headers $($PVEConnect.Headers)
Pause
Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.Name) -taskid $VMCreate.data


# Start new server
# ------------------------------------------------------------
$null = Invoke-MWxRestMethod -SkipHeaderValidation -SkipCertificateCheck -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/status/start" -Headers $($PVEConnect.Headers) -Method POST
