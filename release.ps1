param(
    [Parameter(Mandatory)]
    [string]$Version
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^v\d+\.\d+\.\d+$') {
    throw "版本必須為 v主版.次版.修正版，例如 v1.2.1。"
}

$root = $PSScriptRoot
$dist = Join-Path $env:TEMP "password-gui-release-dist"
$work = Join-Path $env:TEMP "password-gui-release-build"
$release = Join-Path $root "release"

Remove-Item -LiteralPath $dist -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $release -Recurse -Force -ErrorAction SilentlyContinue

Push-Location $root
try {
    py -3.10 -m pip install pyinstaller
    py -3.10 -m unittest
    py -3.10 -m PyInstaller --noconfirm --clean --distpath $dist --workpath $work "build\密碼工具GUI.spec"

    $exe = @(Get-ChildItem -LiteralPath $dist -Filter *.exe)
    if ($exe.Count -ne 1 -or $exe[0].Length -ge 40MB) {
        throw "執行檔未產生、數量錯誤或超過 40 MB。"
    }

    New-Item -ItemType Directory -Force $release | Out-Null
    Copy-Item $exe[0].FullName (Join-Path $release "PasswordToolsGUI.exe")
    $hash = Get-FileHash (Join-Path $release "PasswordToolsGUI.exe") -Algorithm SHA256
    "$($hash.Hash)  PasswordToolsGUI.exe" | Set-Content (Join-Path $release "SHA256SUMS.txt") -Encoding ascii
    Compress-Archive -Force -Path (Join-Path $release "PasswordToolsGUI.exe"), (Join-Path $release "SHA256SUMS.txt") -DestinationPath (Join-Path $release "PasswordToolsGUI-$Version.zip")
}
finally {
    Pop-Location
}
