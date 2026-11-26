[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConnectorExe,
    [Parameter(Mandatory)][string]$Destination,
    [string]$DownloadDirectory,
    [string]$NsisDestination
)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $project
$license = Join-Path $repoRoot 'LICENSE'
$notices = Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md'
$connector = Get-Item -LiteralPath $ConnectorExe
if ($connector.PSIsContainer -or $connector.Extension -ne '.exe') {
    throw 'ConnectorExe must be a built Windows executable.'
}
$destinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
if (Test-Path -LiteralPath $destinationPath) { throw 'Destination already exists.' }
if ($NsisDestination) {
    $nsisPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($NsisDestination)
    if ([IO.Path]::GetExtension($nsisPath) -ne '.exe') { throw 'NSIS destination must end in .exe.' }
    if (Test-Path -LiteralPath $nsisPath) { throw 'NSIS destination already exists.' }
}
$cleanupDownload = $false
if (-not $DownloadDirectory) {
    $DownloadDirectory = Join-Path ([IO.Path]::GetTempPath()) ('muse-voidtools-' + [Guid]::NewGuid().ToString('N'))
    $cleanupDownload = $true
}
$downloadPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DownloadDirectory)
$null = [IO.Directory]::CreateDirectory($downloadPath)

function Get-VerifiedArchive([string]$Name, [string]$Sha256) {
    $file = Join-Path $downloadPath $Name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Invoke-WebRequest -Uri "https://www.voidtools.com/$Name" -OutFile $file
    }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $Sha256) {
        throw "SHA256 verification failed for $Name."
    }
    $file
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ('muse-portable-stage-' + [Guid]::NewGuid().ToString('N'))
$nsisTarget = $null
try {
    $engine = Get-VerifiedArchive 'Everything-1.4.1.1032.x64.zip' '698df475ec44e638f66f1b6a32d28fea613cec78d3b6310e6abe53431eeb940c'
    $client = Get-VerifiedArchive 'ES-1.1.1.40.x64.zip' 'A4E0F429C03F7B768CF777AD25A55C10C1B82FF06D5CAE4AC52925B7B19B16EC'
    $vendor = Join-Path $stage 'everything'
    $null = [IO.Directory]::CreateDirectory($vendor)
    Expand-Archive -LiteralPath $engine -DestinationPath $vendor
    Expand-Archive -LiteralPath $client -DestinationPath $vendor
    foreach ($binary in @('Everything.exe', 'es.exe')) {
        $signature = Get-AuthenticodeSignature -FilePath (Join-Path $vendor $binary)
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|, )O=voidtools PTY LTD(?:,|$)') {
            throw "Publisher verification failed for $binary."
        }
    }
    Invoke-WebRequest -Uri 'https://www.voidtools.com/License.txt' -OutFile (Join-Path $vendor 'Everything-License.txt')
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/voidtools/ES/main/LICENSE' -OutFile (Join-Path $vendor 'ES-License.txt')
    Copy-Item -LiteralPath $connector.FullName -Destination (Join-Path $stage 'muse-connector.exe')

    if ($NsisDestination) {
        $tauri = Join-Path $project 'src-tauri'
        $targetRelative = 'target/muse-nsis-' + [Guid]::NewGuid().ToString('N')
        $nsisTarget = Join-Path $tauri $targetRelative
        $null = [IO.Directory]::CreateDirectory($nsisTarget)
        Copy-Item -LiteralPath $vendor -Destination $nsisTarget -Recurse
        $resources = @{}
        Get-ChildItem -LiteralPath $vendor -File | ForEach-Object {
            $resources["$targetRelative/everything/$($_.Name)"] = "everything/$($_.Name)"
        }
        Copy-Item -LiteralPath $license -Destination $nsisTarget
        $resources["$targetRelative/LICENSE"] = 'LICENSE'
        Copy-Item -LiteralPath $notices -Destination $nsisTarget
        $resources["$targetRelative/THIRD_PARTY_NOTICES.md"] = 'THIRD_PARTY_NOTICES.md'
        $release = Join-Path $nsisTarget 'release'
        $null = [IO.Directory]::CreateDirectory($release)
        Copy-Item -LiteralPath $connector.FullName -Destination (Join-Path $release 'muse-connector.exe')
        $bundleConfig = Join-Path $nsisTarget 'resources.json'
        [IO.File]::WriteAllText($bundleConfig, (@{ bundle = @{ resources = $resources } } | ConvertTo-Json -Depth 4))
        $toolPaths = Get-Command cargo.exe,pnpm.cmd,node.exe | ForEach-Object { Split-Path -Parent $_.Source }
        $previousTarget = $env:CARGO_TARGET_DIR
        $previousPath = $env:Path
        try {
            $env:CARGO_TARGET_DIR = $nsisTarget
            $env:Path = (($toolPaths | Select-Object -Unique) -join ';') + ';' + $previousPath
            pnpm -C $project tauri bundle --bundles nsis --config $bundleConfig --ci
            if ($LASTEXITCODE -ne 0) { throw 'NSIS bundling failed.' }
            $installer = @(Get-ChildItem -LiteralPath (Join-Path $release 'bundle/nsis') -Filter '*.exe' -File)
            if ($installer.Count -ne 1) { throw 'Expected one NSIS installer.' }
            if (Test-Path -LiteralPath $nsisPath) { throw 'NSIS destination already exists.' }
            $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $nsisPath))
            Copy-Item -LiteralPath $installer[0].FullName -Destination $nsisPath
        } finally {
            $env:CARGO_TARGET_DIR = $previousTarget
            $env:Path = $previousPath
        }
    }

    if (Test-Path -LiteralPath $destinationPath) { throw 'Destination already exists.' }
    $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $destinationPath))
    $null = [IO.Directory]::CreateDirectory($destinationPath)
    Copy-Item -LiteralPath (Join-Path $stage 'muse-connector.exe') -Destination $destinationPath
    Copy-Item -LiteralPath $vendor -Destination $destinationPath -Recurse
    Copy-Item -LiteralPath $license -Destination $destinationPath
    Copy-Item -LiteralPath $notices -Destination $destinationPath
    Get-Item -LiteralPath $destinationPath
} finally {
    foreach ($cleanupPath in @($stage, $nsisTarget, $(if ($cleanupDownload) { $downloadPath }))) {
        if ($cleanupPath -and (Test-Path -LiteralPath $cleanupPath)) {
            Remove-Item -LiteralPath $cleanupPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
