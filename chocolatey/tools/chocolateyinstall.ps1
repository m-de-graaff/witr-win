$ErrorActionPreference = 'Stop'

$packageName = 'witr-win'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$version = '0.2.1'
$url = "https://github.com/m-de-graaff/witr-win/releases/download/v$version/witr-win.exe"
$checksumUrl = "https://github.com/m-de-graaff/witr-win/releases/download/v$version/witr-win.exe.sha256"

# Download and parse SHA256 checksum
try {
    $checksumResponse = Invoke-WebRequest -Uri $checksumUrl -UseBasicParsing
    $checksum = ($checksumResponse.Content -split '\s+')[0]
} catch {
    Write-Warning "Failed to fetch checksum from $checksumUrl. Proceeding without verification."
    $checksum = ''
}

$packageArgs = @{
    packageName   = $packageName
    unzipLocation = $toolsDir
    fileType      = 'exe'
    url           = $url
    checksum      = $checksum
    checksumType  = 'sha256'
}

if ($checksum) {
    Install-ChocolateyPackage @packageArgs
} else {
    # Fallback without checksum verification
    $packageArgs.Remove('checksum')
    $packageArgs.Remove('checksumType')
    Install-ChocolateyPackage @packageArgs
}


