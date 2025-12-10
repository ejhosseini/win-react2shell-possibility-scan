<#
.SYNOPSIS
    Heuristic detector for possible React Server Components (RSC) / Next.js usage on a Windows server.

.DESCRIPTION
    This script looks for indicators that a server might be running React Server Components / Next.js,
    which is relevant for assessing exposure to the React2Shell vulnerability (CVE-2025-55182).

    It checks:
      1. Installed JS runtimes / CLI: node, bun, deno, pm2 (via PATH and registry for Node)
      2. Running processes: node.exe, bun.exe, deno.exe, pm2.exe (including parent process)
      3. package.json files under common web roots and scans for:
         - next
         - react / react-dom
         - react-server-dom-* (RSC packages)
         - waku (example RSC framework)
         - .next directory
         - app directory (Next.js App Router)
         - next.config.js / .mjs / .ts
         - occurrences of "react-server-dom"
      4. Listening ports often used by Next.js-style apps
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
    [string[]]$SearchRoots = @(
        "C:\inetpub",
        "D:\web",
        "D:\sites"
    ),
    [int[]]$NextStylePorts = @(3000,3001,3002,3003,4000,4001,8000,8080)
)

Write-Host "=== React Server Components / Next.js - Indicator Check on $env:COMPUTERNAME ===" -ForegroundColor Cyan
Write-Host ""

# --------------------------------------------------------------------
# Helper: get Node.js installations from registry (Apps & Features)
# --------------------------------------------------------------------
function Get-NodeInstallFromRegistry {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $items = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like 'Node.js*' }
    }

    foreach ($i in $items) {
        [PSCustomObject]@{
            DisplayName     = $i.DisplayName
            DisplayVersion  = $i.DisplayVersion
            InstallLocation = $i.InstallLocation
            RegistryKeyPath = $i.PSPath
        }
    }
}

# --------------------------------------------------------------------
# 1) JS runtimes: Node, Bun, Deno, pm2
# --------------------------------------------------------------------
function Get-JsRuntimeInfo {
    Write-Host "== 1) JS runtimes (Node / Bun / Deno / pm2) - installed and running ==" -ForegroundColor Green

    # 1a) Look for CLI in PATH
    $runtimeNames = @("node","bun","deno","pm2")
    $installedCli = @()
    foreach ($name in $runtimeNames) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            $installedCli += [PSCustomObject]@{
                Runtime = $name
                Source  = "PATH"
                Path    = $cmd.Source
            }
        }
    }

    # 1b) Look for Node.js in registry (Apps & Features)
    $nodeReg = Get-NodeInstallFromRegistry
    $installedReg = @()
    foreach ($n in $nodeReg) {
        $installedReg += [PSCustomObject]@{
            Runtime        = "node"
            Source         = "Registry"
            Path           = $n.InstallLocation
            DisplayName    = $n.DisplayName
            DisplayVersion = $n.DisplayVersion
        }
    }

    $installed = $installedCli + $installedReg

    if ($installed.Count -gt 0) {
        Write-Host "Detected runtimes / CLI (PATH and registry):" -ForegroundColor Yellow
        $installed | Format-Table -AutoSize
    } else {
        Write-Host "No runtimes or CLI found (node, bun, deno, pm2) via PATH or registry." -ForegroundColor Yellow
    }

    Write-Host ""

    # 1c) Processes plus parent process
    $procNames = @("node.exe","bun.exe","deno.exe","pm2.exe")
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -in $procNames }

    if ($procs) {
        Write-Host "Active runtime / pm2 processes:" -ForegroundColor Yellow
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
        } | Format-Table -AutoSize
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
                        $hasRsc = $true
                        $rscPackages += "$($d.Name)=$($d.Value)"
                    }
                }
            }

            $appRoot      = $pkg.DirectoryName
            $hasNextBuild = Test-Path (Join-Path $appRoot ".next")
            $hasAppDir    = Test-Path (Join-Path $appRoot "app")
            $hasNextCfg   = (Test-Path (Join-Path $appRoot "next.config.
