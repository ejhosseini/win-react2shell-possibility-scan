param(
    # Kataloger där webb-/app-kod brukar ligga
    [string[]]$SearchRoots = @(
        "C:\inetpub",
        "D:\web",
        "D:\sites"
    ),

    # "Typiska" Next.js-portar (dev/prod): justera efter behov
    [int[]]$NextStylePorts = @(3000,3001,3002,3003,4000,4001,8000,8080)
)

Write-Host "=== React Server Components / Next.js - Indikatorcheck på $env:COMPUTERNAME ===" -ForegroundColor Cyan
Write-Host ""

# -----------------------------
# 1) Kolla JS-runtimes: Node, Bun, Deno, pm2
# -----------------------------
function Get-JsRuntimeInfo {
    Write-Host "== 1) JS-runtimes (Node / Bun / Deno / pm2) – installerade & processer ==" -ForegroundColor Green

    # Kommandon vi vill hitta i PATH
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
        Write-Host "Installerade runtimes/CLI (enligt PATH):" -ForegroundColor Yellow
        $installed | Format-Table -AutoSize
    } else {
        Write-Host "Inga runtimes/CLI hittades via PATH (node/bun/deno/pm2)." -ForegroundColor Yellow
    }

    Write-Host ""

    # Processer + parent process
    $procNames = @("node.exe","bun.exe","deno.exe","pm2.exe")
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -in $procNames }

    if ($procs) {
        Write-Host "Aktiva runtime-/pm2-processer:" -ForegroundColor Yellow
        foreach ($p in $procs) {
            $parent = $null
            try {
                $parent = Get-Process -Id $p.ParentProcessId -ErrorAction SilentlyContinue
            } catch {}

            [PSCustomObject]@{
                Name            = $p.Name
                ProcessId       = $p.ProcessId
                CommandLine     = $p.CommandLine
                ParentId        = $p.ParentProcessId
                ParentName      = if ($parent) { $parent.ProcessName } else { $null }
            }
        } | Format-Table -AutoSize
    } else {
        Write-Host "Inga aktiva node/bun/deno/pm2-processer hittades." -ForegroundColor Yellow
    }

    Write-Host ""
    return [PSCustomObject]@{
        InstalledRuntimes = $installed
        RuntimeProcesses  = $procs
    }
}

# -----------------------------
# 2) Kolla efter RSC/Next-indikatorer i filer
# -----------------------------
function Get-RscFileIndicators {
    param(
        [string[]]$Roots
    )

    Write-Host "== 2) Filindikatorer (package.json, react-server-dom-*, next, .next, app/) ==" -ForegroundColor Green

    $results = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) {
            Write-Host "Hoppar över saknad path: $root" -ForegroundColor DarkYellow
            continue
        }

        Write-Host "Söker package.json under $root ..." -ForegroundColor Cyan

        try {
            $pkgFiles = Get-ChildItem -Path $root -Recurse -Filter "package.json" -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  Kunde inte läsa $root : $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        foreach ($pkg in $pkgFiles) {
            $json = $null
            try {
                $json = Get-Content $pkg.FullName -Raw | ConvertFrom-Json
            } catch {
                Write-Host "  Varning: kunde inte tolka $($pkg.FullName) som JSON." -ForegroundColor DarkYellow
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
                        # Exempel på annat RSC-ramverk
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

            # Sök efter "react-server-dom" i appRoot (snäv scope)
            $textHit = $null
            try {
                $textHit = Select-String -Path (Join-Path $appRoot "*") -Pattern "react-server-dom" -Recurse -ErrorAction SilentlyContinue |
                           Select-Object -First 1
            } catch {}

            $hasTextRsc = [bool]$textHit

            if ($hasNext -or $hasRsc -or $hasNextBuild -or $hasTextRsc) {
                $risk =
                    if ($hasRsc -or $hasTextRsc) {
                        "Hög (RSC-indikation: react-server-dom-* eller textträff)"
                    } elseif ($hasNextBuild -and $hasNext) {
                        "Medel (Next + .next – kolla App Router / versioner)"
                    } elseif ($hasNext) {
                        "Behöver kontroll (Next-dependency)"
                    } else {
                        "Indikation (React-bygge, troligen SPA)"
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
        Write-Host "`nPotentiella RSC/Next-appar hittades:" -ForegroundColor Yellow
        $results |
            Sort-Object RiskLevel, AppRoot |
            Format-Table AppRoot, HasNext, NextVersion, HasRscPackages, RscPackages, HasAppDir, HasNextBuild, RiskLevel -AutoSize
    } else {
        Write-Host "Inga tydliga indikatorer på Next/RSC hittades under angivna rötter." -ForegroundColor Yellow
    }

    Write-Host ""
    return $results
}

# -----------------------------
# 3) Portar: lokala lyssningar på "Next-typiska" portar
# -----------------------------
function Get-NextStyleLocalPorts {
    param(
        [int[]]$Ports
    )

    Write-Host "== 3) Lyssnande portar typiska för Next.js (heuristik) ==" -ForegroundColor Green

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        Write-Host "Get-NetTCPConnection finns inte – hoppar över port-analys." -ForegroundColor Yellow
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
                LocalAddress  = $l.LocalAddress
                LocalPort     = $l.LocalPort
                OwningPid     = $l.OwningProcess
                ProcessName   = if ($proc) { $proc.ProcessName } else { $null }
            }
        }

        Write-Host "Lyssnande 'Next-typiska' portar:" -ForegroundColor Yellow
        $out | Sort-Object LocalPort, ProcessName | Format-Table -AutoSize
        Write-Host ""
        return $out
    } else {
        Write-Host "Inga lyssnande portar på $($Ports -join ', ') hittades." -ForegroundColor Yellow
        Write-Host ""
        return @()
    }
}

# -----------------------------
# 4) Aktiva anslutningar till andra servrar på "Next-portar"
# -----------------------------
function Get-NextStyleRemoteConnections {
    param(
        [int[]]$Ports
    )

    Write-Host "== 4) Befintliga anslutningar mot andra servrar på Next-liknande portar ==" -ForegroundColor Green

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        Write-Host "Get-NetTCPConnection finns inte – hoppar över anslutnings-analys." -ForegroundColor Yellow
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

        Write-Host "Aktiva anslutningar till $($Ports -join ', ') på andra servrar:" -ForegroundColor Yellow
        $out | Sort-Object RemoteAddress, RemotePort | Format-Table -AutoSize
        Write-Host ""
        return $out
    } else {
        Write-Host "Inga aktiva anslutningar mot Next-liknande portar hittades." -ForegroundColor Yellow
        Write-Host ""
        return @()
    }
}

# -----------------------------
# Kör alla steg och samla resultat
# -----------------------------
$runtimeInfo    = Get-JsRuntimeInfo
$fileIndicators = Get-RscFileIndicators -Roots $SearchRoots
$localPorts     = Get-NextStyleLocalPorts -Ports $NextStylePorts
$remoteConns    = Get-NextStyleRemoteConnections -Ports $NextStylePorts

Write-Host "=== Sammanfattning (heuristisk) ===" -ForegroundColor Cyan

$hasRuntime = ($runtimeInfo.RuntimeProcesses.Count -gt 0 -or $runtimeInfo.InstalledRuntimes.Count -gt 0)
$hasRscApp  = ($fileIndicators | Where-Object { $_.HasRscPackages -or $_.TextRscHitPath }).Count -gt 0

if ($hasRscApp -or $hasRuntime -or $localPorts.Count -gt 0 -or $remoteConns.Count -gt 0) {
    Write-Host "Den här servern har indikatorer på JS-runtime och/eller Next/RSC-relaterad kod." -ForegroundColor Yellow
    Write-Host "→ Gå vidare med analys av versioner (react-server-dom-* / next) och prata med dev-teamet." -ForegroundColor Yellow
} else {
    Write-Host "Inga tydliga indikatorer på att den här servern kör React Server Components / Next.js." -ForegroundColor Green
    Write-Host "Observera att RSC kan finnas på andra servrar (containers, interna backends) som den här pratar med indirekt." -ForegroundColor DarkYellow
}

# Returnera ett objekt om man vill jobba vidare i PowerShell
[PSCustomObject]@{
    ComputerName       = $env:COMPUTERNAME
    RuntimeInfo        = $runtimeInfo
    FileIndicators     = $fileIndicators
    LocalPorts         = $localPorts
    RemoteConnections  = $remoteConns
}
