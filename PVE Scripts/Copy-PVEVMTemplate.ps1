<#

    Get required PROXMOX data

#>

Get-ChildItem -Path ".\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }

$PVEConnect = PVE-Connect -FromSettings
$PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers


# Find all templates
# ------------------------------------------------------------
$Templates = Get-PVETemplates -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers


foreach ($Template in $Templates) {

    # Clone and migrate to partner node(s)
    # ------------------------------------------------------------
    $CopyLocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ExcludeNode $($PVELocation.name)

    $NextTemplateID = Get-Random -Minimum 99999989 -Maximum 99999999

    $CloneTemplate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$($Template.VmID)/clone" -Body "newid=$NextTemplateID&name=$($Template.Name)&full=1" -Method POST -Headers $PVEConnect.Headers
    Start-PVEWait -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $($PVELocation.name) -Taskid $CloneTemplate.data

    Move-PVEVM -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -SourceNode $Template.Node -TargetNode $CopyLocation.Name -VMID $NextTemplateID -Targetstorage $CopyLocation.Storage # -Wait

    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($CopyLocation.Name)/qemu/$NextTemplateID/template" -Method POST -Headers $($PVEConnect.Headers)


}