param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot 'artifacts' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
& (Join-Path $projectRoot 'build.ps1')
$stagePath = Join-Path $OutputDirectory ('package-' + [Guid]::NewGuid().ToString('N'))
$packageRoot = Join-Path $stagePath 'ClaudePreflight'
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
$files = @(
    'ClaudePreflight.exe', 'ClaudePreflight.cs', 'BrowserChecks.cs', 'BrowserProbe.html',
    'app.manifest', 'build.ps1', 'claude.ico', 'Microsoft.Web.WebView2.Core.dll',
    'Microsoft.Web.WebView2.WinForms.dll', 'WebView2Loader.dll', 'WebView2-LICENSE.txt', 'README.md'
)
foreach ($file in $files) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $file) -Destination $packageRoot
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs') -Destination $packageRoot -Recurse
Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts') -Destination $packageRoot -Recurse
$zipPath = Join-Path $OutputDirectory 'ClaudePreflight-Windows.zip'
Compress-Archive -LiteralPath $packageRoot -DestinationPath $zipPath -Force
$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'SHA256SUMS.txt'), "$hash  ClaudePreflight-Windows.zip`n")
Write-Output $zipPath
Write-Output "SHA256 $hash"
