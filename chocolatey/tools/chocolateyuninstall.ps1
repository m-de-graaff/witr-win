$ErrorActionPreference = 'Stop'

$packageName = 'witr-win'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

Remove-Item "$toolsDir\witr-win.exe" -ErrorAction SilentlyContinue

