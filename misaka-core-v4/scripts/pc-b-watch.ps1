# PC-B automated smoke test watcher
# Polls origin/main every 30s, runs smoke tests on new commits
#
# Usage:
#   cd $HOME\MISAKA-CORE-SHARE
#   .\scripts\pc-b-watch.ps1
#
# Stop: Ctrl+C

$ErrorActionPreference = "Continue"
$PollInterval = 30
$RepoRoot = "$env:USERPROFILE\MISAKA-CORE-SHARE"
$LogDir = "$RepoRoot\test-results\pc-b-logs"
$LastCommitFile = "$RepoRoot\.pc-b-last-commit"

# ── MSVC environment ──
$env:PATH = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;$env:PATH"
$env:CC = "cl.exe"
$env:CXX = "cl.exe"
$env:AR = "lib.exe"
$env:VCINSTALLDIR = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\"
$env:VCToolsVersion = "14.44.35207"
$env:WindowsSdkDir = "C:\Program Files (x86)\Windows Kits\10\"
$env:WindowsSDKVersion = "10.0.26100.0\"
$env:LIB = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64"
$env:INCLUDE = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"

function Log-Msg($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] $msg"
}

function Get-TestResult($logFile) {
    $content = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
    if ($content -match "test result: ok\. (\d+) passed; (\d+) failed") {
        return "ok. $($Matches[1]) passed; $($Matches[2]) failed"
    }
    if ($content -match "test result: FAILED\. (\d+) passed; (\d+) failed") {
        return "FAILED. $($Matches[1]) passed; $($Matches[2]) failed"
    }
    if ($content -match "error\[") {
        return "BUILD_ERROR"
    }
    return "UNKNOWN"
}

# ── Init ──
Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$LastProcessed = ""
if (Test-Path $LastCommitFile) {
    $LastProcessed = (Get-Content $LastCommitFile -Raw).Trim()
}

Log-Msg "PC-B watch started (poll=${PollInterval}s, last=$LastProcessed)"

# ── Main loop ──
while ($true) {
    try {
        Set-Location $RepoRoot

        # fetch
        $fetchOut = git fetch origin 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log-Msg "git fetch failed: $fetchOut"
            Start-Sleep -Seconds $PollInterval
            continue
        }

        $RemoteCommit = (git rev-parse origin/main 2>&1).Trim()
        $ShortHash = $RemoteCommit.Substring(0, 7)

        if ($RemoteCommit -eq $LastProcessed) {
            Log-Msg "Waiting... (origin/main=$ShortHash, already tested)"
            Start-Sleep -Seconds $PollInterval
            continue
        }

        Log-Msg "New commit detected: $ShortHash"
        Log-Msg "Pulling..."

        git checkout main 2>&1 | Out-Null
        $pullOut = git pull --rebase origin main 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log-Msg "git pull failed: $pullOut"
            Start-Sleep -Seconds $PollInterval
            continue
        }

        # cargo check
        Log-Msg "Running cargo check --workspace..."
        $checkStart = Get-Date
        $checkOut = cargo check --workspace 2>&1
        $checkEnd = Get-Date
        $checkTime = [int]($checkEnd - $checkStart).TotalSeconds

        $errorCount = ($checkOut | Select-String "^error\[" | Measure-Object).Count
        $warningCount = 0
        $checkOut | Select-String 'generated (\d+) warning' | ForEach-Object {
            $warningCount += [int]$_.Matches[0].Groups[1].Value
        }

        Log-Msg "cargo check: ${errorCount} errors, ${warningCount} warnings (${checkTime}s)"

        if ($errorCount -gt 0) {
            Log-Msg "BUILD FAILED - writing failure report"
            $checkOut | Out-File "$LogDir\check.log" -Encoding utf8

            $report = @"
# PC-B smoke FAILED (build error)
- commit: $RemoteCommit
- date: $((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
- OS: Windows 11 (x86_64-pc-windows-msvc)

## cargo check
- errors: $errorCount
- warnings: $warningCount
- check time: ${checkTime}s

## log
$LogDir\check.log
"@
            $report | Out-File "test-results\pc-b-latest.md" -Encoding utf8

            git add "test-results\pc-b-latest.md" 2>&1 | Out-Null
            git commit -m "test(pc-b): build failed for $ShortHash [skip ci]" 2>&1 | Out-Null
            git push origin main 2>&1 | Out-Null

            $RemoteCommit | Out-File $LastCommitFile
            $LastProcessed = $RemoteCommit
            Start-Sleep -Seconds $PollInterval
            continue
        }

        # smoke tests
        $testCrates = @("misaka-dag", "misaka-simulator", "misaka-test-cluster")
        $results = @{}

        foreach ($crate in $testCrates) {
            Log-Msg "Testing $crate..."
            $testStart = Get-Date

            if ($crate -eq "misaka-test-cluster") {
                cargo test -p $crate 2>&1 | Tee-Object -FilePath "$LogDir\$crate.log" | Out-Null
            } else {
                cargo test -p $crate --lib 2>&1 | Tee-Object -FilePath "$LogDir\$crate.log" | Out-Null
            }

            $testEnd = Get-Date
            $testTime = [int]($testEnd - $testStart).TotalSeconds
            $result = Get-TestResult "$LogDir\$crate.log"

            $results[$crate] = @{
                result = $result
                time = $testTime
            }

            Log-Msg "$crate : $result (${testTime}s)"
        }

        # report
        $totalTime = ($results.Values | ForEach-Object { $_.time } | Measure-Object -Sum).Sum

        $report = @"
# PC-B Phase smoke result
- commit: $RemoteCommit
- date: $((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
- OS: Windows 11 (x86_64-pc-windows-msvc)
- host: $env:COMPUTERNAME

## cargo check
- errors: $errorCount
- warnings: $warningCount
- check time: ${checkTime}s

## smoke test results
| crate | result | wall clock |
|---|---|---|
| misaka-dag | $($results['misaka-dag'].result) | $($results['misaka-dag'].time)s |
| misaka-simulator | $($results['misaka-simulator'].result) | $($results['misaka-simulator'].time)s |
| misaka-test-cluster | $($results['misaka-test-cluster'].result) | $($results['misaka-test-cluster'].time)s |

total smoke wall clock: ${totalTime}s

## verdict
$(if ($results.Values | Where-Object { $_.result -match "^FAILED\." -or $_.result -eq "UNKNOWN" -or $_.result -eq "BUILD_ERROR" }) { "FAIL/INVESTIGATE" } else { "PASS" })

## logs
$LogDir\
"@

        $report | Out-File "test-results\pc-b-latest.md" -Encoding utf8

        # commit + push
        Log-Msg "Committing results..."
        git add "test-results\pc-b-latest.md" 2>&1 | Out-Null
        git commit -m "test(pc-b): smoke for $ShortHash [skip ci]" 2>&1 | Out-Null

        $pushResult = git push origin main 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log-Msg "push failed, retrying with pull --rebase"
            git pull --rebase origin main 2>&1 | Out-Null
            git push origin main 2>&1 | Out-Null
        }

        $RemoteCommit | Out-File $LastCommitFile
        $LastProcessed = $RemoteCommit

        Log-Msg "Cycle complete. Next poll in ${PollInterval}s..."
    } catch {
        Log-Msg "ERROR in cycle: $_"
    }

    Start-Sleep -Seconds $PollInterval
}
