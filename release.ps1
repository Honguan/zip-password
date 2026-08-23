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
$verify = Join-Path $env:TEMP "password-gui-release-verify"
$release = Join-Path $root "release"
$pyInstallerVersion = "6.14.1"
$pyInstallerHooksVersion = "2026.6"

Remove-Item -LiteralPath $dist -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $verify -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $release -Recurse -Force -ErrorAction SilentlyContinue

Push-Location $root
try {
    py -3.10 -m pip install "pyinstaller==$pyInstallerVersion" "pyinstaller-hooks-contrib==$pyInstallerHooksVersion"
    py -3.10 -m unittest
    py -3.10 -m PyInstaller --noconfirm --clean --distpath $dist --workpath $work "build\密碼工具GUI.spec"

    $exe = @(Get-ChildItem -LiteralPath $dist -Filter *.exe -File)
    if ($exe.Count -ne 1 -or $exe[0].Length -lt 1MB -or $exe[0].Length -ge 40MB) {
        throw "執行檔未產生、數量錯誤或超過 40 MB。"
    }

    New-Item -ItemType Directory -Force $release | Out-Null
    $releaseExe = Join-Path $release "PasswordToolsGUI.exe"
    $sumsPath = Join-Path $release "SHA256SUMS.txt"
    $zipPath = Join-Path $release "PasswordToolsGUI-$Version.zip"
    Copy-Item $exe[0].FullName $releaseExe

    $stream = [System.IO.File]::OpenRead($releaseExe)
    try {
        if ($stream.ReadByte() -ne 0x4D -or $stream.ReadByte() -ne 0x5A) {
            throw "執行檔缺少 Windows PE MZ 標頭。"
        }
    }
    finally {
        $stream.Dispose()
    }
    py -3.10 -m PyInstaller.utils.cliutils.archive_viewer --list --brief $releaseExe | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller 封裝內容無法讀取。"
    }

    $hash = Get-FileHash $releaseExe -Algorithm SHA256
    "$($hash.Hash)  PasswordToolsGUI.exe" | Set-Content $sumsPath -Encoding ascii
    Compress-Archive -Force -Path $releaseExe, $sumsPath -DestinationPath $zipPath

    $releaseNames = @((Get-ChildItem -LiteralPath $release -File).Name | Sort-Object)
    $expectedReleaseNames = @("PasswordToolsGUI-$Version.zip", "PasswordToolsGUI.exe", "SHA256SUMS.txt") | Sort-Object
    if (Compare-Object $releaseNames $expectedReleaseNames) {
        throw "發佈目錄的檔名或數量不正確。"
    }

    Expand-Archive -LiteralPath $zipPath -DestinationPath $verify
    $zipNames = @((Get-ChildItem -LiteralPath $verify -File).Name | Sort-Object)
    if (Compare-Object $zipNames @("PasswordToolsGUI.exe", "SHA256SUMS.txt")) {
        throw "ZIP 內容的檔名或數量不正確。"
    }
    $zipHash = Get-FileHash (Join-Path $verify "PasswordToolsGUI.exe") -Algorithm SHA256
    $zipSums = (Get-Content -LiteralPath (Join-Path $verify "SHA256SUMS.txt") -Raw).Trim()
    if ($zipHash.Hash -ne $hash.Hash -or $zipSums -ne "$($hash.Hash)  PasswordToolsGUI.exe") {
        throw "ZIP、EXE 與 SHA256SUMS.txt 的雜湊不一致。"
    }
}
finally {
    Remove-Item -LiteralPath $verify -Recurse -Force -ErrorAction SilentlyContinue
    Pop-Location
}
