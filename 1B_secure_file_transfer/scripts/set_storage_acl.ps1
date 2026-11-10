param(
    [Parameter(Mandatory = $true)][string]$StoragePath,
    [Parameter(Mandatory = $true)][string]$ServiceAccount
)

$ErrorActionPreference = "Stop"
$resolvedStorage = [System.IO.Path]::GetFullPath($StoragePath)
New-Item -ItemType Directory -Path $resolvedStorage -Force | Out-Null
& icacls.exe $resolvedStorage /inheritance:r
if ($LASTEXITCODE -ne 0) { throw "Could not disable inherited permissions on storage." }
& icacls.exe $resolvedStorage /grant:r `
    "$($ServiceAccount):(OI)(CI)M" `
    "SYSTEM:(OI)(CI)F" `
    "BUILTIN\Administrators:(OI)(CI)F" /T /C
if ($LASTEXITCODE -ne 0) { throw "Could not apply storage permissions." }
Write-Host "Storage permissions now allow only the service account, SYSTEM and Administrators."
