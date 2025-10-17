    param (
        [cmdletbinding()]
        [Parameter(ValueFromPipeline)]
        [string]$NewVMFQDN,
        [string]$MachineOU,
        [string]$DomainJoin,
        [string]$NewVmIp,
        [string]$LocalUsername,
        [string]$LocalPassword,
        [int]$VMMemory,
        [int]$VMCores,
        [string]$OSDisk,
        [string]$TemplateName,
        [object]$DefaultConnection,
        [object]$DefaultLocation,
        [switch]$Start,
        [switch]$NoCreateVM
    )

    <#

        1. User/script picks target node, storage, and network.

        3. Clone template → new VM.

        4. If required, migrate the VM to the requested node/storage.

        5. Boot....

    #>

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

    Get-ChildItem -Path ".\Functions" | ForEach-Object { Import-Module -Name $_.FullName -Force }

    # Extract Info of the VM created.
    # ------------------------------------------------------------
    $VMName = $(($NewVMFQDN -split("\."))[0])
    $VMID = (($($NewVmIp -Split("\."))[1]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[2]).PadLeft(2,"0")) + (($($NewVmIp -Split("\."))[3]).PadLeft(3,"0"))
    $VmDomain = $(($NewVMFQDN -split("\."))[1..99]) -join(".")
    $IPGateway = "$(($($NewVmIp -Split("\."))[0..2]) -join(".")).1"

    # Define DNS servers
    # ------------------------------------------------------------
    if ($NewVMFQDN -Like "*ADDS-01") {
        $DNSServers = @("192.168.2.1", "127.0.0.1")
    } else {
        $DNSServers = @(
            "$(($NewVmIp -split("\."))[0..2] -join(".")).11",
            "$(($NewVmIp -split("\."))[0..2] -join(".")).12"
        )
    }

    <#

        Default PROXMOX data

    #>
    Write-Verbose "Script begin: $(Get-Date)"

    ## Include Proxmox Connect script.
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    Get-ChildItem -Path "D:\PVE Scripts\Functions" | ForEach-Object { Import-Module -Name $_.FullName -force -Verbose:$false }


    if (!($DefaultConnection)) {
        $PVEConnect = PVE-Connect -FromSettings
    } else {
        $PVEConnect = $DefaultConnection
    }

    if ($null -eq $VMID) {
        $VMID = Get-PVENextID -ProxmoxAPI
    }


    # Get the Deployment server info
    # ------------------------------------------------------------
    If (!($DefaultLocation)) {
        $MasterID = Get-PVEServerID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -ServerName "22-TEST1"
    }




    if (!($DefaultLocation)) {
        $PVELocation = Get-PVELocation -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -IncludeNode $MasterServer.Node
    } else {
        $PVELocation = $DefaultLocation
    }

    <#

        Verify Deployment and Template is on same NODE

    #>

    # Find all templates
    # ------------------------------------------------------------
    If (!($DefaultLocation)) {
	    $Templates = Get-PVETemplates -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers | Where {$_.node -eq $MasterServer.Node}
    } else {
	    $Templates = Get-PVETemplates -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers | Where {$_.node -eq $PVELocation.Name}
    }


    # Select the template to use.
    # ------------------------------------------------------------
    if ($TemplateName) {
        $Templates = $Templates | Where {$_.Name -eq $TemplateName}
    }
    if ($Templates.Count -gt 1) {
        # Stupid OutGridview thinks the VMID is a number that need a thousands separator!
        $SelectedVMTemplate = $Templates | Select-Object @{Name="VmID"; Expression={ "$($_.vmid)"}},name,Node | Out-GridView -Title "Select VM template to use" -OutputMode Single
    } else {
        $SelectedVMTemplate = $Templates
    }

    # If NO template, FAIL
    # ------------------------------------------------------------
    if (!($SelectedVMTemplate)) {
        Throw "No VM Template found or selected"
    }



    # Verify and Move Template if required.
    # ------------------------------------------------------------
    If ($MasterServer.Node -ne $SelectedVMTemplate.Node) {

    #    # Move Template..
    #    # ------------------------------------------------------------
    #    #Move-PVEVM -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -SourceNode $SelectedVMTemplate.Node -TargetNode $MasterServer.Node -VMID $SelectedVMTemplate.VmID -Wait

    # Switch to template on same node..

    }

    <#

        Create VM

    #>

    $AllVMIDs = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/cluster/resources?type=vm" -Headers $PVEConnect.Headers -Verbose:$false).data | Select-Object vmid, name
    if ($NoCreateVM) {
        Write-Warning "Ignoring VMid check!"
    }
    else {
        if ($AllVMIDs.vmid -contains $VMID) {
            throw "VMID already in use."

        }
    }

    # Configure and create VM
    # ------------------------------------------------------------
    Write-Verbose "Proxmox: Create new VM: $VMName"


    if ($NoCreateVM) {
        Write-Information "Skipping creating VM"
    }
    else {
        # Clone Template
        # ------------------------------------------------------------
            $VMCreate = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$($SelectedVMTemplate.VmID)/clone" -Body "newid=$VMID&name=$NewVMFQDN&full=1&storage=$($PVELocation.storage)" -Method Post -Headers $PVEConnect.Headers -Verbose:$false

        # Wait for clone...
        # ------------------------------------------------------------
        Start-PVEWait -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $PVEConnect.Headers -node $($PVELocation.name) -taskid $VMCreate.data


        # Add Cloud Init drive, with bare minimum data.
        # ------------------------------------------------------------
        #$Body = "node=$($PVELocation.name)"
        #$Body += "&ide2=$($PVELocation.Storage):cloudinit"
        #$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers


        # Set bare minimum data in Cloud Init.
        # ------------------------------------------------------------
        #$Body = "node=$($PVELocation.name)"
        #$Body += "&citype=configdrive2"
        #$Body += "&ciuser=$LocalUsername"
        #$Body += "&cipassword=$LocalPassword"
        #$Body += "&searchdomain=$VmDomain"
        #$Body += "&nameserver=$DNSServers"
        #$Body += "&ipconfig0=$([uri]::EscapeDataString("ip=$NewVmIp/24,gw=$IPGateway"))"
        #
        #$null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers
        #
        #$null = Invoke-RestMethod -Method PUT -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/cloudinit" -Headers $PVEConnect.Headers
    }

    # Create AutoUnattend media, and add required scripts.
    # ------------------------------------------------------------
    If (Test-Path -Path "D:\$NewVMFQDN") {
        Remove-Item -Path "D:\$NewVMFQDN" -Recurse -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
    }
    If (Test-Path -Path "D:\$NewVMFQDN.iso") {
        Remove-Item -Path "D:\$NewVMFQDN.iso" -Force -ErrorAction Stop
    }
    New-Item -Path "D:\$NewVMFQDN" -ItemType Directory | Out-Null
    Start-Sleep -Seconds 1

    $rc = $null
    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT")) {
        $rc = New-Item -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT" -ItemType Directory -Force
        Start-Sleep -Seconds 1
        if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT")) {
            "D:\$NewVMFQDN\OPENSTACK\CONTENT is missing"
        }
    }

    $NetworkData = @()
    $NetworkData += "auto eth0`r`n"
    $NetworkData += "iface eth0 inet static`r`n"
    $NetworkData += "        address $NewVmIp`r`n"
    $NetworkData += "        netmask 255.255.255.0`r`n"
    $NetworkData += "        gateway $IPGateway`r`n"
    $NetworkData += "        dns-nameservers $($DNSServers -join(" "))`r`n"

    $NetworkData | Out-File -FilePath "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000" -Encoding utf8 -Force
    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000")) {
        "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000 is missing"
    }

    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\LATEST")) {
        New-Item -Path "D:\$NewVMFQDN\OPENSTACK\LATEST" -ItemType Directory -Force | Out-Null
        Start-Sleep -Seconds 1
        if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000")) {
            "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000 is missing"
        }
    }

    $HostConfig = @()
    $HostConfig += "#cloud-config"
    $HostConfig += "hostname: $VMName"
    $HostConfig += "manage_etc_hosts: true"
    $HostConfig += "fqdn: $NewVMFQDN"
    $HostConfig += "user: $LocalUsername"
    $HostConfig += "password: $LocalPassword"
    $HostConfig += "chpasswd:"
    $HostConfig += "  expire: False"
    $HostConfig += "users:"
    $HostConfig += "  - default"
    $HostConfig += "package_upgrade: true"
    if ($MachineOU) {
        $HostConfig += "MachineOU: $MachineOU"
    }
    if ($DomainJoin) {
        $HostConfig += "DomainJoin: $DomainJoin"
    }
    $HostConfig | Out-File -FilePath "D:\$NewVMFQDN\OPENSTACK\LATEST\USER_DATA" -Encoding utf8 -Force
    if (!(Test-Path -Path "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000")) {
        "D:\$NewVMFQDN\OPENSTACK\CONTENT\0000 is missing"
    }

    if (!(Test-Path -Path "D:\$NewVMFQDN\Windows DSC")) {
        New-Item -Path "D:\$NewVMFQDN\Windows DSC" -ItemType Directory | Out-Null
        Start-Sleep -Seconds 1
        if (!(Test-Path -Path "D:\$NewVMFQDN\Windows DSC")) {
            "D:\$NewVMFQDN\Windows DSC is missing"
        }
    }
    Copy-Item -Path "D:\Server Roles" -Destination "D:\$NewVMFQDN\Windows DSC" -Recurse | Out-Null
    if ((Get-ChildItem -Path "D:\Server Roles" -Recurse).Count -gt (Get-ChildItem -Path "D:\$NewVMFQDN\Windows DSC" -Recurse).Count) {
        "D:\$NewVMFQDN\Windows DSC mismatch"
    }

    if ($VMName -eq "ADDS-01") {
        Copy-Item -Path "D:\TS-Data\ADTiering.zip" -Destination "D:\$NewVMFQDN" -Force
    }

    New-ISOFileFromFolder -FilePath "D:\$NewVMFQDN" -Name "Unattend Media" -ResultFullFileName "D:\$NewVMFQDN.iso"

    Start-Sleep -Seconds 2
    Remove-Item -Path "D:\$NewVMFQDN" -Recurse -Force

    # Upload ISO.
    $ISOStorage = ((Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/storage" -Headers $PVEConnect.Headers -Verbose:$false).data | Where {$_.content -like "*iso*"} | Sort-Object -Property avail -Descending | Select-Object -First 1).storage
    $null = Upload-PVEISO -ProxmoxAPI $($PVEConnect.PVEAPI) -Headers $($PVEConnect.Headers) -Node $($PVELocation.name) -Storage $ISOStorage -IsoPath "D:\$NewVMFQDN.iso"

    # Add Iso to NewVM
    $Body = "node=$($PVELocation.name)"
    $Body += "&ide2=$([uri]::EscapeDataString("$($ISOStorage):iso/$NewVMFQDN.iso,media=cdrom"))"
    $null = Invoke-RestMethod -Method POST -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Headers $PVEConnect.Headers -Verbose:$false


    # Modify Boot sequence.
    $Body = "boot=$([uri]::EscapeDataString("order=scsi0"))"
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $Body -Method POST -Headers $PVEConnect.Headers -Verbose:$false



    <# 

        Modify New VM depending on selections..

    #>


    # Change Disk size, amount memory and cpu if needed
    # ------------------------------------------------------------
    Write-Verbose "Proxmox: Change VM configuration"
    $VMStatus = (Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Headers $PVEConnect.Headers -Verbose:$false).data


    if ($VMStatus.cores -ne $VMCores) {
        Write-Verbose "Proxmox: Update CPU Cores"

        $body = "cores=$VMCores"
        $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $PVEConnect.Headers -Verbose:$false

    }


    if ([math]::Round($($VMMemory * 1KB)) -ne $VMStatus.memory) {
        Write-Verbose "Proxmox: Update Memory size"

        $body = "memory=$($VMMemory*1KB)"
        $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body $body -Method Post -Headers $PVEConnect.Headers -Verbose:$false

    }

    # Calculate if OSDisk size differs, and change if needed.
    # ------------------------------------------------------------
    $OSDiskSize = ($VMStatus.((($VMStatus.boot -split("="))[-1] -split(";"))[0]) -split("="))[-1]+"b"
    $SizeDiff = [math]::round($OSDisk - $OSDiskSize) / 1Gb


    if ($SizeDiff -gt 0) {
        Write-Verbose "Proxmox: Update Disk size"

        $body = "disk=$($CurrentOSDisk.name)&size=$($OSDisk.ToLower().replace("gb","G"))"
        $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/resize" -Body $body -Method Put -Headers $PVEConnect.Headers -Verbose:$false

    }



    <#

        Add Extra Disks depending on server type.

    #>


    if ($VmDomain -ne "Workgroup") {

            switch ($VMName) {
            {$_ -like "ADDS-*"} {

                # Add 100Gb Backup Drive to All Domain Controllers.
                # ------------------------------------------------------------
                $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $PVELocation.name -VMID $VMID

                $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):100"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
                $VMDiskCount++

            }
            {$_ -like "File-0*" -or $_ -like "*RDDB-*" -or $_ -like "*ADDS-*"} {
            
                # Add 10Gb Log Drive and 100Gb Data Drive to File Cluster and SQL Cluster
                # ------------------------------------------------------------
                $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $PVELocation.name -VMID $VMID

                $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):20"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
                $VMDiskCount++

                $DiskId = Get-PVENextDiskID -ProxmoxAPI $PVEConnect.PVEAPI -Headers $PVEConnect.Headers -Node $PVELocation.name -VMID $VMID

                $Null = Invoke-WebRequest -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/config" -Body "$DiskId=$([uri]::EscapeDataString("$($PVELocation.Storage):100"))" -Method Post -Headers $PVEConnect.Headers -Verbose:$false
                $VMDiskCount++

            }
        }
    }


    # Start new server
    # ------------------------------------------------------------
    $null = Invoke-RestMethod -Uri "$($PVEConnect.PVEAPI)/nodes/$($PVELocation.name)/qemu/$VMID/status/start" -Headers $PVEConnect.Headers -Method POST -Verbose:$false

    Write-Verbose "Script end: $(Get-Date)"

<#

$Location = [pscustomobject]@{
    Name = 'proxmox1'
    Storage = 'NVME1'
    Interface = 'deployment'

}
New-PVEServer -NewVMFQDN "L25-ADDS-01.lab25.lostinazure.com" `
    -NewVmIp "172.16.125.11" `
    -LocalUsername "administrator" `
    -LocalPassword "Password,2025!" `
    -VMMemory 4 `
    -VMCores 4 `
    -OSDisk 80 `
    -TemplateName "2025-Template" `
    -DefaultLocation $Location `
    -Verbose
#>