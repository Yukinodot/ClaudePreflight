$ErrorActionPreference = 'Stop'
$compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compilerPath)) { throw '.NET Framework compiler was not found.' }
Push-Location $PSScriptRoot
try {
    & $compilerPath /nologo /target:winexe /platform:x64 /optimize+ /utf8output /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /reference:Microsoft.Web.WebView2.Core.dll /reference:Microsoft.Web.WebView2.WinForms.dll /win32manifest:app.manifest /win32icon:claude.ico /out:ClaudePreflight.exe ClaudePreflight.cs BrowserChecks.cs
    if ($LASTEXITCODE -ne 0) { throw 'Compilation failed.' }
} finally { Pop-Location }
