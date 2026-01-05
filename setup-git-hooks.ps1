# Setup script for git hooks on Windows
# This script sets up pre-commit and pre-push hooks for witr-win

Write-Host "Setting up git hooks..." -ForegroundColor Cyan

$hooksDir = ".git\hooks"

if (-not (Test-Path $hooksDir)) {
    Write-Host "Creating .git\hooks directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null
}

# Get the absolute path to the PowerShell script (convert to forward slashes for shell scripts)
$repoRoot = (Get-Location).Path -replace '\\', '/'
$preCommitPs1 = "$repoRoot/.git/hooks/pre-commit.ps1"
$prePushPs1 = "$repoRoot/.git/hooks/pre-push.ps1"

# Find PowerShell executable (try pwsh first, then powershell)
$pwshExe = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { 
    "pwsh.exe" 
} else { 
    "powershell.exe" 
}

# Create shell script wrapper for pre-commit (works with Git Bash and Git for Windows)
Write-Host "Installing pre-commit hook..." -ForegroundColor Cyan
$preCommitWrapper = @"
#!/bin/sh
# Wrapper script to run PowerShell pre-commit hook
cd "$repoRoot"
exec "$pwshExe" -NoProfile -ExecutionPolicy Bypass -File "$preCommitPs1"
"@
# Write with Unix line endings (LF only) for shell scripts
$preCommitWrapper = $preCommitWrapper -replace "`r`n", "`n"
[System.IO.File]::WriteAllText("$hooksDir\pre-commit", $preCommitWrapper, [System.Text.UTF8Encoding]::new($false))
# Make it executable (for Git Bash)
if (Get-Command git -ErrorAction SilentlyContinue) {
    git update-index --chmod=+x "$hooksDir\pre-commit" 2>$null
}

# Create shell script wrapper for pre-push
Write-Host "Installing pre-push hook..." -ForegroundColor Cyan
$prePushWrapper = @"
#!/bin/sh
# Wrapper script to run PowerShell pre-push hook
cd "$repoRoot"
exec "$pwshExe" -NoProfile -ExecutionPolicy Bypass -File "$prePushPs1"
"@
# Write with Unix line endings (LF only) for shell scripts
$prePushWrapper = $prePushWrapper -replace "`r`n", "`n"
[System.IO.File]::WriteAllText("$hooksDir\pre-push", $prePushWrapper, [System.Text.UTF8Encoding]::new($false))
# Make it executable (for Git Bash)
if (Get-Command git -ErrorAction SilentlyContinue) {
    git update-index --chmod=+x "$hooksDir\pre-push" 2>$null
}

Write-Host "✅ Git hooks installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "The following checks will run automatically:" -ForegroundColor Cyan
Write-Host "  - Pre-commit: cargo fmt --all --check and cargo clippy" -ForegroundColor White
Write-Host "  - Pre-push: cargo test" -ForegroundColor White
Write-Host ""
Write-Host "To skip hooks temporarily, use:" -ForegroundColor Yellow
Write-Host "  git commit --no-verify" -ForegroundColor White
Write-Host "  git push --no-verify" -ForegroundColor White

