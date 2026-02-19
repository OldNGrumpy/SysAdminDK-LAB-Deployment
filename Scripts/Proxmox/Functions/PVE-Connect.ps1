<#

    Connecto to PVE cluster.

#>
function PVE-Connect {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][string]$Authkey,
        [Parameter(Mandatory)][string]$Hostaddr
    )


    # HTTP Headers for connection.
    # ------------------------------------------------------------
    $DefaultHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $DefaultHeaders.Add("Authorization", "PVEAPIToken=$AuthKey")
    $DefaultHeaders.Add("Accept", "application/json")

    # Proxmox API address.
    # ------------------------------------------------------------
    $DefaultProxmoxAPI = "https://$($HostAddr):8006/api2/json"

    return @( [PSCustomObject]@{ PVEAPI  = $DefaultProxmoxAPI; Headers = $DefaultHeaders } )

}

