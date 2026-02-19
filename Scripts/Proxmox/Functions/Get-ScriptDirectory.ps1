function Get-ScriptDirectory {
    $dir = ""
    if ($psise) {
        $dir = Split-Path $psise.CurrentFile.FullPath
    }
    else {
        $dir = $global:PSScriptRoot
    }
    if (-not $dir) {
        $dir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\')
    }
    return $dir   
}