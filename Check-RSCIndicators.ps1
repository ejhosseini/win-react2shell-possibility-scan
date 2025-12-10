<#
.SYNOPSIS
    Heuristic detector for possible React Server Components (RSC) / Next.js usage on a Windows server.

.DESCRIPTION
    This script looks for indicators that a server might be running React Server Components / Next.js,
    which is relevant for assessing exposure to the React2Shell vulnerability (CVE-2025-55182).

    It checks:
      1. Installed JS runtimes / CLI: node, bun, deno, pm2
      2. Running processes: node.exe, bun.exe, deno.exe, pm2.exe (including parent process)
      3. package.json files under common web roots and scans for:
         - next
         - react / react-dom
         - react-server-dom-* (RSC packages)
         - waku (example RSC framework)
         - .next directory
         - app directory (Next.js App Router)
         - next.config.js / .mjs / .ts
         - any occurrences of "react-server-dom" text
      4. Listening ports that commonly indicate Next.js-style apps
      5. Established connections to other servers on those ports

    NOTE:
      - This is heuristic only. It does NOT prove a server is vulnerable or exploited.
      - Use it to find candidate servers / apps for deeper inspection.

.PARAMETER SearchRoots
    Root directories to scan for package.json and RSC / Next indicators.

.PARAMETER NextStylePorts
    Ports often used by Next.js / Node dev or prod servers.

#>

param(
    # Directories where web or app code typically resides
    [string[]]$SearchRoots = @(
        "C:\inetpub",
        "D:\web",
        "D:\sites"
    ),

    # Typical Next.js-style ports (adjust to your environment)
    [int[]]$NextStylePorts = @(3000,3001,3002,3003,4000,4001,8000,8080)
)

Write-Host "=== React Server Components / Next.js - Indicator Check on $env:COMPUTERNAME ===" -ForegroundColor Cyan
Write-Host ""

# --------------------------------------------------------------------
# 1) JS runtimes: Node, Bun, Deno, pm2
# --------------------------------------------------------------------
function Get-JsRuntimeInfo {
    Write-Host "== 1) JS runtimes (Node / Bun / Deno / pm2) - installed and running ==" -ForegroundColor Green

    # Commands to look for in PATH
    $runtimeNames = @("node","bun","deno","pm2")
    $installed = @()
    foreach ($name in $runtimeNames) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            $installed += [PSCustomObject]@{
                Runtime = $name
                Path    = $cmd.Source
            }
        }
    }

    if ($installed.Count -gt 0) {
        Write-Host "Detected runtimes or CLI in PATH:" -ForegroundColor Yellow
        $installed | Format-Table -AutoSize
    } else {
        Write-Host "No runtimes or CLI found in PATH (node, bun, deno, pm2)." -ForegroundColor Yellow
    }

    Write-Host ""

    # Processes plus parent process
    $procNames = @("node.exe","bun.exe","deno.exe","pm2.exe")
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -in $procNames }

    if ($procs) {
        Write-Host "Active runtime or pm2 processes:" -ForegroundColor Yellow
        foreach ($p in $procs) {
            $parent = $null
            try {
                $parent = Get-Process -Id $p.ParentProcessId -ErrorAction SilentlyContinue
            } catch {}

            [PSCustomObject]@{
                Name        = $p.Name
                ProcessId   = $p.ProcessId
                CommandLine = $p.CommandLine
                ParentId    = $p.ParentProcessId
                ParentName  = if ($parent) { $parent.ProcessName } else { $null }
            }
        }
    } else {
        Write-Host "No active node, bun, deno or pm2 processes found." -ForegroundColor Yellow
    }

    Write-Host ""
    return [PSCustomObject]@{
        InstalledRuntimes = $installed
        RuntimeProcesses  = $procs
    }
}

# --------------------------------------------------------------------
# 2) File indicators - package.json, RSC / Next markers
# --------------------------------------------------------------------
function Get-RscFileIndicators {
    param(
        [string[]]$Roots
    )

    Write-Host "== 2) File indicators (package.json, react-server-dom-*, next, .next, app) ==" -ForegroundColor Green

    $results = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) {
            Write-Host "Skipping missing path: $root" -ForegroundColor DarkYellow
            continue
        }

        Write-Host "Searching for package.json under $root ..." -ForegroundColor Cyan

        try {
            $pkgFiles = Get-ChildItem -Path $root -Recurse -Filter "package.json" -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  Could not enumerate $root : $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        foreach ($pkg in $pkgFiles) {
            $json = $null
            try {
                $json = Get-Content $pkg.FullName -Raw | ConvertFrom-Json
            } catch {
                Write-Host "  Warning: could not parse $($pkg.FullName) as JSON." -ForegroundColor DarkYellow
                continue
            }

            $deps = @()
            if ($json.dependencies)    { $deps += $json.dependencies.PSObject.Properties }
            if ($json.devDependencies) { $deps += $json.devDependencies.PSObject.Properties }

            if (-not $deps) { continue }

            $hasNext       = $false
            $nextVersion   = $null
            $hasRsc        = $false
            $rscPackages   = @()
            $hasReact      = $false
            $hasReactDom   = $false

            foreach ($d in $deps) {
                switch -Wildcard ($d.Name) {
                    "next" {
                        $hasNext = $true
                        $nextVersion = $d.Value
                    }
                    "react" {
                        $hasReact = $true
                    }
                    "react-dom" {
                        $hasReactDom = $true
                    }
                    "react-server-dom-*" {
                        $hasRsc = $true
                        $rscPackages += "$($d.Name)=$($d.Value)"
                    }
                    "waku" {
                        # Example of another RSC-capable framework
                        $hasRsc = $true
                        $rscPackages += "$($d.Name)=$($d.Value)"
                    }
                }
            }

            $appRoot      = $pkg.DirectoryName
            $hasNextBuild = Test-Path (Join-Path $appRoot ".next")
            $hasAppDir    = Test-Path (Join-Path $appRoot "app")
            $hasNextCfg   = (Test-Path (Join-Path $appRoot "next.config.js")) -or
                            (Test-Path (Join-Path $appRoot "next.config.mjs")) -or
                            (Test-Path (Join-Path $appRoot "next.config.ts"))

            # Search for "react-server-dom" text within the app root
            $textHit = $null
            try {
                $textHit = Select-String -Path (Join-Path $appRoot "*") -Pattern "react-server-dom" -Recurse -ErrorAction SilentlyContinue |
                           Select-Object -First 1
            } catch {}

            $hasTextRsc = [bool]$textHit

            if ($hasNext -or $hasRsc -or $hasNextBuild -or $hasTextRsc) {
                if ($hasRsc -or $hasTextRsc) {
                    $risk = "High (RSC indication: react-server-dom-* or text hit)"
                } elseif ($hasNextBuild -and $hasNext) {
                    $risk = "Medium (Next and .next - check App Router and versions)"
                } elseif ($hasNext) {
                    $risk = "Needs review (Next dependency present)"
                } else {
                    $risk = "Low indication (React build - likely SPA only)"
                }

                $obj = [PSCustomObject]@{
                    ComputerName   = $env:COMPUTERNAME
                    AppRoot        = $appRoot
                    PackageJson    = $pkg.FullName
                    HasNext        = $hasNext
                    NextVersion    = $nextVersion
                    HasReact       = $hasReact
                    HasReactDom    = $hasReactDom
                    HasRscPackages = $hasRsc
                    RscPackages    = ($rscPackages -join ",")
                    HasNextBuild   = $hasNextBuild
                    HasAppDir      = $hasAppDir
                    HasNextConfig  = $hasNextCfg
                    TextRscHitPath = if ($textHit) { $textHit.Path } else { $null }
                    RiskLevel      = $risk
                }

                $results += $obj
            }
        }
    }

    if ($results.Count -gt 0) {
        Write-Host ""
        Write-Host "Potential RSC or Next.js apps detected:" -ForegroundColor Yellow
        $results |
            Sort-Object RiskLevel, AppRoot |
            Format-Table AppRoot, HasNext, NextVersion, HasRscPackages, RscPackages, HasAppDir, HasNextBuild, RiskLevel -AutoSize
    } else {
        Write-Host "No clear Next or RSC indicators found under the specified roots." -ForegroundColor Yellow
    }

    Write-Host ""
    return $results
}

# --------------------------------------------------------------------
# 3) Local listening ports - Next.js-style ports
# --------------------------------------------------------------------
function Get-NextStyleLocalPorts {
    param(
        [int[]]$Ports
    )

    Write-Host "== 3) Listening ports commonly used by Next.js (heuristic) ==" -ForegroundColor Green

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        Write-Host "Get-NetTCPConnection is not available. Skipping local port analysis." -ForegroundColor Yellow
        return @()
    }

    $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                 Where-Object { $Ports -contains $_.LocalPort }

    if ($listening) {
        $procMap = @{}
        Get-Process | ForEach-Object { $procMap[$_.Id] = $_ }

        $out = foreach ($l in $listening) {
            $proc = $null
            $procMap.TryGetValue($l.OwningProcess, [ref]$proc) | Out-Null

            [PSCustomObject]@{
                LocalAddress = $l.LocalAddress
                LocalPort    = $l.LocalPort
                OwningPid    = $l.OwningProcess
                ProcessName  = if ($proc) { $proc.ProcessName } else { $null }
            }
        }

        Write-Host "Listening on Next-like ports:" -ForegroundColor Yellow
        $out | Sort-Object LocalPort, ProcessName | Format-Table -AutoSize
        Write-Host ""
        return $out
    } else {
        Write-Host "No listeners found on ports: $($Ports -join ', ')." -ForegroundColor Yellow
        Write-Host ""
        return @()
    }
}

# --------------------------------------------------------------------
# 4) Established connections to other servers on Next-like ports
# --------------------------------------------------------------------
function Get-NextStyleRemoteConnections {
    param(
        [int[]]$Ports
    )

    Write-Host "== 4) Established connections to other servers on Next-like ports ==" -ForegroundColor Green

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        Write-Host "Get-NetTCPConnection is not available. Skipping remote connection analysis." -ForegroundColor Yellow
        return @()
    }

    $est = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
           Where-Object {
                $Ports -contains $_.RemotePort -and
                $_.RemoteAddress -notin @("127.0.0.1","::1")
           }

    if ($est) {
        $procMap = @{}
        Get-Process | ForEach-Object { $procMap[$_.Id] = $_ }

        $out = foreach ($c in $est) {
            $proc = $null
            $procMap.TryGetValue($c.OwningProcess, [ref]$proc) | Out-Null

            [PSCustomObject]@{
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                RemoteAddress = $c.RemoteAddress
                RemotePort    = $c.RemotePort
                OwningPid     = $c.OwningProcess
                ProcessName   = if ($proc) { $proc.ProcessName } else { $null }
            }
        }

        Write-Host "Active connections to Next-like ports on remote servers:" -ForegroundColor Yellow
        $out | Sort-Object RemoteAddress, RemotePort | Format-Table -AutoSize
        Write-Host ""
        return $out
    } else {
        Write-Host "No active connections to Next-like ports were found." -ForegroundColor Yellow
        Write-Host ""
        return @()
    }
}

# --------------------------------------------------------------------
# Execute all checks and summarize
# --------------------------------------------------------------------
$runtimeInfo    = Get-JsRuntimeInfo
$fileIndicators = Get-RscFileIndicators -Roots $SearchRoots
$localPorts     = Get-NextStyleLocalPorts -Ports $NextStylePorts
$remoteConns    = Get-NextStyleRemoteConnections -Ports $NextStylePorts

Write-Host "=== Summary (heuristic only) ===" -ForegroundColor Cyan

$hasRuntime = ($runtimeInfo.RuntimeProcesses.Count -gt 0 -or $runtimeInfo.InstalledRuntimes.Count -gt 0)
$hasRscApp  = ($fileIndicators | Where-Object { $_.HasRscPackages -or $_.TextRscHitPath }).Count -gt 0

if ($hasRscApp -or $hasRuntime -or $localPorts.Count -gt 0 -or $remoteConns.Count -gt 0) {
    Write-Host "This server shows indicators of JS runtimes and/or Next / RSC-related code." -ForegroundColor Yellow
    Write-Host "Follow up with version analysis (react-server-dom-* / next) and the application or development team." -ForegroundColor Yellow
} else {
    Write-Host "No obvious indicators that this server runs React Server Components or Next.js." -ForegroundColor Green
    Write-Host "Note: RSC may still exist on other servers (containers, internal backends) that this host talks to indirectly." -ForegroundColor DarkYellow
}

# Return a structured object for further processing if needed
[PSCustomObject]@{
    ComputerName      = $env:COMPUTERNAME
    RuntimeInfo       = $runtimeInfo
    FileIndicators    = $fileIndicators
    LocalPorts        = $localPorts
    RemoteConnections = $remoteConns
}
