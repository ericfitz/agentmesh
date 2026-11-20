# job.ps1: the guest side of scripts/windows-test.sh (local CI spec section 3).
# Runs inside the Windows test VM as the unelevated user `test`, started by
# vmrun as: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command
#   "& 'C:\amt\job.ps1' *> 'C:\amt\job.out'"
# Writes, under -Out: results.txt (ASCII; `STEP <name> PASS|FAIL` lines, `FAILED
# <test>` lines, and `GOMODCACHE-MISS` when the baseline's module cache lacks the
# first module go.sum names) and one <step>.log per step; then zips the logs to
# C:\amt\logs.zip. Every step runs even after a failure. Windows PowerShell 5.1
# compatible.
param(
    [string]$Src = 'C:\amt\src',
    [string]$Out = 'C:\amt\out',
    [string]$Zip = 'C:\amt\src.zip',
    [string]$Logs = 'C:\amt\logs.zip'
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

if (Test-Path -LiteralPath $Out) { Remove-Item -Recurse -Force -LiteralPath $Out }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$results = Join-Path $Out 'results.txt'
New-Item -ItemType File -Force -Path $results | Out-Null

function Add-Result([string]$Line) {
    Add-Content -LiteralPath $results -Value $Line -Encoding ascii
}

if (-not (Test-Path -LiteralPath $Src)) {
    Expand-Archive -LiteralPath $Zip -DestinationPath $Src -Force
}
Set-Location -LiteralPath $Src

# git ls-files and the install harness need a repository; the archive carries none.
if (-not (Test-Path -LiteralPath (Join-Path $Src '.git'))) {
    git init -q
    git config core.autocrlf false
    git add -A
    git -c user.name=amt -c user.email=amt@localhost commit -q -m amt
    if ($LASTEXITCODE -ne 0) { Write-Output 'git setup failed'; }
}

# Staleness probe: the first module go.sum names must be in the module cache.
$firstLine = Get-Content -LiteralPath (Join-Path $Src 'go.sum') -TotalCount 1
if ($firstLine) {
    $parts = $firstLine -split ' '
    $escaped = [regex]::Replace($parts[0], '[A-Z]', { param($m) '!' + $m.Value.ToLower() })
    $cache = Join-Path (go env GOMODCACHE) ('cache\download\' + ($escaped -replace '/', '\') + '\@v')
    if (-not (Test-Path -LiteralPath $cache)) { Add-Result 'GOMODCACHE-MISS' }
}

# Invoke-Step runs a script block, sends its output to <name>.log and records PASS
# when $LASTEXITCODE is 0 afterwards (a block ends with a native command or sets
# $global:LASTEXITCODE itself).
function Invoke-Step([string]$Name, [scriptblock]$Body) {
    $log = Join-Path $Out "$Name.log"
    $global:LASTEXITCODE = 0
    try {
        & $Body *> $log
    } catch {
        $_ | Out-String | Add-Content -LiteralPath $log -Encoding ascii
        $global:LASTEXITCODE = 1
    }
    if ($global:LASTEXITCODE -eq 0) { Add-Result "STEP $Name PASS" } else { Add-Result "STEP $Name FAIL" }
    Set-Location -LiteralPath $Src
}

function Invoke-GoTest {
    $pkgs = @(go list ./... | Where-Object { $_ -notmatch '/internal/conformance' })
    $raw = go test -json @pkgs 2>&1
    $code = $LASTEXITCODE
    $failed = @()
    foreach ($line in $raw) {
        $text = [string]$line
        try { $ev = $text | ConvertFrom-Json } catch { Write-Output $text; continue }
        if ($ev.Output) { Write-Output ($ev.Output.TrimEnd()) }
        if ($ev.Action -eq 'fail' -and $ev.Test) { $failed += $ev.Test }
    }
    foreach ($t in ($failed | Sort-Object -Unique)) { Add-Result "FAILED $t" }
    $global:LASTEXITCODE = $code
}

# The parse check of every tracked .ps1 (what windows.yml runs under both hosts).
$parseScript = Join-Path $Out 'parse-check.ps1'
@'
$bad = 0
foreach ($f in (git ls-files '*.ps1')) {
    $tokens = $null; $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $f).Path, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) { Write-Host "${f}:$($e.Extent.StartLineNumber): $($e.Message)"; $bad++ }
}
if ($bad -gt 0) { exit 1 }
exit 0
'@ | Set-Content -LiteralPath $parseScript -Encoding ascii

$tags = 'awskms,gcpkms,azurekms,hashivault'

$env:GOARCH = 'arm64'
Invoke-Step 'vet-arm64' { go vet ./... }
Invoke-Step 'vet-tags-arm64' { go vet -tags $tags ./... }
Invoke-Step 'go-test-arm64' { Invoke-GoTest }

$env:GOARCH = 'amd64'
Invoke-Step 'vet-amd64' { go vet ./... }
Invoke-Step 'vet-tags-amd64' { go vet -tags $tags ./... }
Invoke-Step 'go-test-amd64' { Invoke-GoTest }
Remove-Item Env:GOARCH

Invoke-Step 'ps1-parse-5' { powershell.exe -NoProfile -ExecutionPolicy Bypass -File $parseScript }
Invoke-Step 'ps1-parse-7' { pwsh.exe -NoProfile -File $parseScript }
Invoke-Step 'install-selftest-5' { powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Src 'release\test-install.ps1') -SelfTest }
Invoke-Step 'install-5' { powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Src 'release\test-install.ps1') }
Invoke-Step 'install-7' { pwsh.exe -NoProfile -File (Join-Path $Src 'release\test-install.ps1') }

if (Test-Path -LiteralPath $Logs) { Remove-Item -Force -LiteralPath $Logs }
Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $Logs -Force
