# PHP2Shell hunting pack (CVE-2026-109618 / CVE-2026-109619)

Self-contained: every query, command and script is pasted inline under its row. Nothing needs to be opened from another file.

**Fixed upstream:** PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35. **PHP 8.1 and older: no official fix** (source-only backport branches `PHP-7.4-/8.0-/8.1-CVE-2026-109618-109619` exist; 8.2 reaches EOL on 31 Dec 2026). Distro packages may carry backports, so version strings are unreliable.

## Read this first
- **Verified against Microsoft Learn / primary sources:** table schemas used, Cloud Security Explorer and Recommendations > Vulnerabilities navigation, Syslog/AMA/DCR setup, Custom Text Logs rules, Application Gateway log tables, App Service diagnostic categories, the Sentinel-in-Defender-portal move, EASM filter names, Microsoft's ARG sample for registry findings.
- **Not confirmed:** whether Defender Vulnerability Management, Defender for Cloud or EASM already publish detections for these two CVEs. No MSRC advisory was found. **An empty CVE result does not mean "not vulnerable".** Rows 5, 8 and 9 (version/inventory based) are the safety net.
- **Not run against a tenant.** Run each query once, fix any schema differences, then save it.
- Portal labels change often; where a label is unverified the step says so.
- **Where Sentinel data is queried now:** Sentinel in the Azure portal is retired after 31 Mar 2027. Run Sentinel/Log Analytics tables from **security.microsoft.com > Investigation & response > Hunting > Advanced hunting** (workspace onboarded to the Defender portal, at least Microsoft Sentinel Reader). `DeviceTvm*` and `Device*` tables exist **only** in Defender XDR.

## Index

| # | Part 1 - Build the list of vulnerable assets |
|---|---|
| 1 | [Defender Vulnerability Management (TVM) CVE view](#row-1) |
| 2 | [Defender for Cloud - VMs and running containers](#row-2) |
| 3 | [Resource Graph - App Service runtimes](#row-3) |
| 4 | [Defender for Containers - registry and running images](#row-4) |
| 5 | [MDE software inventory with version check](#row-5) |
| 6 | [Defender EASM - internet-facing assets](#row-6) |
| 7 | [Source-code search + Defender for DevOps](#row-7) |
| 8 | [PHP bundled outside normal packages](#row-8) |
| 9 | [Running vs installed, and mod_php](#row-9) |
| 10 | [nmap / httpx network fingerprint scan (complex, optional)](#row-10) |

| ID | Part 2 - Hunt for exploitation |
|---|---|
| A | [Triage: which hosts matter most](#hunt-a) |
| B | [Web worker spawns shell / downloader](#hunt-b) |
| C | [Syslog crash / OOM / worker churn](#hunt-c) |
| D1 | [App Service HTTP logs](#hunt-d1) |
| D2 | [Application Gateway WAF logs](#hunt-d2) |
| E1 / E2 | [Dropped PHP files; web-worker outbound connections](#hunt-e) |
| F1 | [AKS container logs](#hunt-f1) |
| F2 | [Apache / nginx / php-fpm text logs](#hunt-f2) |
| G | [Mitigate until patched](#hunt-g) |

---

# Part 1 - Build the list of vulnerable assets

<a id="row-1"></a>
## Row 1 - Defender Vulnerability Management (TVM) CVE view
**Finds:** devices MDE already flags for the CVEs.

1. Go to **security.microsoft.com**.
2. Left nav: **Vulnerability management > Weaknesses** (labelled **Vulnerabilities** in some tenants).
3. In the search box type `CVE-2026-109618`, press Enter, open it, open the **Exposed devices** tab, click **Export**.
4. Repeat for `CVE-2026-109619`.
5. If nothing is found, TVM has not published the CVE yet. Use the query below and rows 5, 8 and 9.

Query (**Hunting > Advanced hunting > + New query > paste > Run query**):

```kql
// Devices MDE/TVM already flags as exposed to the PHP2Shell CVEs
// NOTE : DeviceTvm* tables exist ONLY in Defender XDR Advanced hunting (they are not ingested into Sentinel).
// CAVEAT: returns rows only once Microsoft Defender Vulnerability Management has published detection logic for these
//         CVEs. Empty result != safe. Always also run rows 5 and 8.
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2026-109618", "CVE-2026-109619")
| summarize
    CVEs = make_set(CveId),
    Software = make_set(strcat(SoftwareName, " ", SoftwareVersion)),
    RecommendedFix = make_set(RecommendedSecurityUpdate)
    by DeviceId, DeviceName, OSPlatform
| order by DeviceName asc
```

<a id="row-2"></a>
## Row 2 - Defender for Cloud: VMs and running containers
**Finds:** Azure/AWS/GCP VMs and AKS workloads with the CVEs.
**Requires:** Defender CSPM, or Defender for Servers P2 with agentless scanning; Security Reader/Reader.

1. Go to **portal.azure.com**, open **Microsoft Defender for Cloud**.
2. Left menu: **Recommendations**, open the **Vulnerabilities** tab, choose **Flat list**.
3. **Add filter > Resource type** > pick **Virtual machine**, then **Apply**. Repeat with **Container** (running workloads).
4. Open a vulnerability recommendation, open the **Associated CVEs** tab, look for `CVE-2026-109618` / `CVE-2026-109619`.
5. Optional graph view: **Cloud Security Explorer** > choose the resource type > **+** add a vulnerability filter > **Search** > **Download CSV report**. (The exact CVE filter label is unverified.)

<a id="row-3"></a>
## Row 3 - Resource Graph: App Service runtimes
**Finds:** every App Service / Function with a PHP, WordPress or custom-container runtime.

1. Go to **portal.azure.com**, search **Resource Graph Explorer**.
2. Set **Scope** to **Directory** (whole tenant).
3. Paste the query below, click **Run query**, then **Download as CSV**.
4. Limits: App Service exposes only major.minor (e.g. `PHP|8.3`), never the patch level. Microsoft's "Latest" channel was on 8.5.11 at disclosure (watch github.com/Azure/app-service-announcements). Treat every row as in scope until confirmed.
5. If fields come back empty for apps you know exist, run the PowerShell fallback below.

```kql
// RG-01 - Every App Service / Function app whose runtime is PHP, WordPress-on-App-Service or a custom container
// LIMITS:
//  * App Service exposes only major.minor for PHP (e.g. "PHP|8.3" / phpVersion "8.2"), never the patch level.
//  * Custom containers (linuxFxVersion starts with DOCKER|) are YOUR responsibility: take the image to Row 4.
//  * If linuxFxVersion/phpVersion come back empty for apps you know exist, use the PowerShell fallback below this query.
resources
| where type =~ "microsoft.web/sites"
| extend kindStr = tostring(kind)
| extend linuxFx = tostring(properties.siteConfig.linuxFxVersion)
| extend winPhp = tostring(properties.siteConfig.phpVersion)
| extend isLinux = kindStr contains "linux"
| extend isContainer = linuxFx startswith "DOCKER|" or linuxFx startswith "COMPOSE|" or linuxFx startswith "KUBE|"
| extend Runtime = case(
    isContainer, "Custom container",
    linuxFx startswith "PHP|", linuxFx,
    linuxFx startswith "WORDPRESS|", linuxFx,
    isnotempty(winPhp), strcat("Windows PHP ", winPhp),
    "")
| where isnotempty(Runtime)
| extend MajorMinor = extract(@"(\d+\.\d+)", 1, Runtime)
| extend Note = case(
    isContainer, "Inspect the image: Row 4 + Defender for Containers",
    MajorMinor in ("5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"), "EOL branch - no official fix",
    MajorMinor in ("8.2", "8.3", "8.4", "8.5"), "Supported branch - confirm platform patch level (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)",
    "Review")
| project name, resourceGroup, subscriptionId, location, kindStr, Runtime, Note, defaultHostName = tostring(properties.defaultHostName), id
| order by Note asc, name asc
```

PowerShell fallback (terminal; needs `az login`, Reader is enough; writes `appservice-php.csv`):

```powershell
$rows = foreach ($sub in (az account list --query "[].id" -o tsv)) {
    az account set --subscription $sub
    foreach ($app in (az webapp list --query "[].{n:name,g:resourceGroup}" -o json | ConvertFrom-Json)) {
        $cfg = az webapp config show -g $app.g -n $app.n --query "{linux:linuxFxVersion, php:phpVersion}" -o json | ConvertFrom-Json
        if ($cfg.linux -match 'PHP|WORDPRESS|DOCKER' -or $cfg.php) {
            [pscustomobject]@{ Subscription = $sub; ResourceGroup = $app.g; App = $app.n; LinuxFx = $cfg.linux; WindowsPhp = $cfg.php }
        }
    }
}
$rows | Export-Csv -NoTypeInformation appservice-php.csv
$rows | Format-Table -AutoSize
```

<a id="row-4"></a>
## Row 4 - Defender for Containers: registry and running images
**Finds:** ACR/ECR/GAR images and AKS workloads with the CVEs or any PHP finding.
**Requires:** Defender for Containers (or CSPM) with **Registry access**, plus **K8S API access** or the **Defender sensor**. Images not pushed/pulled in 30 days and not running are not rescanned. Runtime scanning does not cover Windows nodes.

1. In **portal.azure.com > Defender for Cloud > Recommendations > Vulnerabilities > Flat list**, **Add filter > Resource type = Container Image** (registry), then repeat with **Container** (running). Open the recommendation, check **Associated CVEs**.
2. For a tenant-wide CSV open **Resource Graph Explorer** (Scope: Directory) and run Query 4a.
3. To list every registry image that contains PHP even without a CVE finding, run Query 4b.
4. For images with zero findings, run the SBOM sweep (4c).

**Query 4a - registry findings that mention the CVEs.** Based on Microsoft's sample (github.com/Azure/Microsoft-Defender-for-Cloud, Kusto/Azure Resource Graph). It does not hard-code the assessment key and matches the CVE text anywhere in the sub-assessment. No rows = no finding, which is not "no PHP".

```kql
securityresources
| where type == "microsoft.security/assessments/subassessments"
| where tostring(properties) has_any ("CVE-2026-109618", "CVE-2026-109619")
| parse id with registryResourceId "/providers/Microsoft.Security/assessments/" assessmentKey "/subassessments/" *
| parse registryResourceId with * "/providers/Microsoft.ContainerRegistry/registries/" registryName
| extend imageDigest = tostring(properties.additionalData.imageDigest),
         repository = tostring(properties.additionalData.repositoryName)
| project health = tostring(properties.status.code),
          severity = tostring(properties.status.severity),
          vulnId = tostring(properties.id),
          displayName = tostring(properties.displayName),
          registryName, repository, imageDigest, resourceGroup, subscriptionId, assessmentKey, registryResourceId
| order by registryName asc, repository asc
```

**Query 4b - registry images with any PHP-related finding** (works even if no detection for the new CVEs exists). A fully patched PHP image with zero findings will not appear; use 4c for that.

```kql
securityresources
| where type == "microsoft.security/assessments/subassessments"
| where tostring(properties.additionalData) matches regex @"(?i)\bphp([\d.]*|[-_][a-z0-9]+)\b|libphp|mod_php"
| parse id with registryResourceId "/providers/Microsoft.Security/assessments/" assessmentKey "/subassessments/" *
| where registryResourceId has "/providers/Microsoft.ContainerRegistry/registries/"
| parse registryResourceId with * "/providers/Microsoft.ContainerRegistry/registries/" registryName
| extend repository = tostring(properties.additionalData.repositoryName),
         imageDigest = tostring(properties.additionalData.imageDigest)
| summarize FindingCount = count(), SampleFindings = make_set(tostring(properties.displayName), 5)
    by registryName, repository, imageDigest, subscriptionId, resourceGroup
| order by FindingCount desc
```

**4c - SBOM sweep** (terminal on a workstation/jump box that can pull from your registry; install [Syft](https://github.com/anchore/syft) and `jq`; replace `MYREGISTRY`):

```bash
# 1. Sign in and list every image in an Azure Container Registry
az login
az acr login -n MYREGISTRY
for repo in $(az acr repository list -n MYREGISTRY -o tsv); do
  for tag in $(az acr repository show-tags -n MYREGISTRY --repository "$repo" -o tsv); do
    echo "MYREGISTRY.azurecr.io/$repo:$tag"
  done
done > images.txt

# 2. Catalog each image and keep PHP packages and PHP binaries
while read img; do
  syft "$img" -o json 2>/dev/null \
  | jq -r --arg i "$img" '.artifacts[] | select(.name|test("^(php|libphp|libapache2-mod-php|mod_php)")) | [$i,.name,.version,.type]|@tsv'
done < images.txt > php-images.tsv
```

For running AKS workloads, build `images.txt` this way instead, then repeat step 2:

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u > images.txt
```

Single-image truth check (runs the binary, so use only on images you trust): `docker run --rm --entrypoint php IMAGE -v`
Caveat: official `php:*` images compile PHP from source, so the version appears as the Syft `binary` entry or in the image tag, not as a distro package.

<a id="row-5"></a>
## Row 5 - MDE software inventory with version check
**Finds:** every PHP package on onboarded devices, classified (mod_php / FPM / CGI / CLI) with VULNERABLE / EOL status.

1. Go to **security.microsoft.com > Investigation & response > Hunting > Advanced hunting**.
2. Click **+ New query**, paste the query below, click **Run query**, then **Export** (CSV).
3. Rows with `VendorPackaged = true` need a changelog/vendor-advisory check before calling them vulnerable (distros backport fixes).

```kql
// Every PHP package MDE inventoried, classified by SAPI role and compared to the fixed versions
// Fixed upstream: 8.5.12, 8.4.27, 8.3.36, 8.2.35. PHP 8.1 and older: no official fix.
// CAVEAT: distro packages may carry backported fixes without changing the upstream number.
let Fixed = datatable(MajorMinor: string, FixedIn: string)
[
    "8.2", "8.2.35",
    "8.3", "8.3.36",
    "8.4", "8.4.27",
    "8.5", "8.5.12"
];
DeviceTvmSoftwareInventory
| where SoftwareName matches regex @"(?i)php"
| extend Ver = extract(@"^(?:\d+:)?(\d+\.\d+\.\d+)", 1, SoftwareVersion)
| extend MajorMinor = extract(@"^(?:\d+:)?(\d+\.\d+)\.", 1, SoftwareVersion)
| extend Role = case(
    SoftwareName matches regex @"(?i)mod[-_]?php|libphp", "mod_php (Apache module) - HIGHEST RISK",
    SoftwareName matches regex @"(?i)fpm", "php-fpm",
    SoftwareName matches regex @"(?i)cgi", "php-cgi",
    SoftwareName matches regex @"(?i)(^|[-_])cli($|[-_])", "php-cli (not web-facing by itself)",
    SoftwareName matches regex @"(?i)phpmyadmin|phpbb|phpunit|phpseclib|phpldapadmin", "PHP application (version is NOT the PHP runtime)",
    "php core / other")
| join kind=leftouter Fixed on MajorMinor
| extend Status = case(
    Role startswith "PHP application", "N/A - application; check the PHP runtime on the same device",
    isempty(Ver), "Unknown version format - review manually",
    isnotempty(FixedIn) and parse_version(Ver) < parse_version(FixedIn), strcat("VULNERABLE - upgrade to ", FixedIn),
    isnotempty(FixedIn), "Upstream version >= fixed",
    parse_version(Ver) < parse_version("8.2.0"), "VULNERABLE (EOL branch) - no official fix; need vendor backport or upstream backport branch",
    "Newer than known branches - review manually")
| extend VendorPackaged = SoftwareVersion matches regex @"(?i)(ubuntu|deb\d|el\d|\.fc\d|~|\+)"
| project DeviceName, OSPlatform, SoftwareName, SoftwareVersion, Role, Status, VendorPackaged, EndOfSupportStatus, DeviceId
| order by Status asc, DeviceName asc
```

<a id="row-6"></a>
## Row 6 - Defender EASM (internet-facing)
**Finds:** public sites running PHP or common PHP apps, including ones you did not know about.

1. Go to **portal.azure.com**, search **Microsoft Defender EASM**, open your workspace.
2. Left menu: **Inventory > Page assets**.
3. **Add filter** (each pass below, combined with these two): **State = Approved Inventory** and **Live = true**. Only Approved Inventory assets are scanned daily.
4. **Pass A:** **Framework Equals PHP**.
5. **Pass B:** **Server Contains** `Apache`, `nginx`, `LiteSpeed`, `Microsoft-IIS` (PHP commonly sits behind these).
6. **Pass C:** **Web Component Name Contains**, one value at a time: `WordPress`, `Drupal`, `Joomla`, `Magento`, `MediaWiki`, `Roundcube`, `phpMyAdmin`, `Nextcloud`, `Laravel`, `Symfony`, `WHMCS`, `cPanel`, `Plesk`, `Moodle`, `TYPO3`, `PrestaShop`, `OpenCart`, `phpBB`, `Matomo`, `SuiteCRM`. Freeform values are case-sensitive, so use **Contains**.
7. Also try **Web Component Name & Version**, and **Affected CVSS Score** >= 9 to see Microsoft-mapped CVEs (a dashboard for these CVEs is not confirmed).
8. Switch to **Inventory > IP addresses**, filter **Banner Matches** `PHP/`.
9. **Export** each result.
10. Limits: external assets only; PHP versions are often hidden (`expose_php=Off`, stripped headers), so absence is not proof of no PHP. Candidate-state assets are not scanned daily; review and approve them.

<a id="row-7"></a>
## Row 7 - Source-code search + Defender for DevOps
**Finds:** repos and pipelines that build PHP images, i.e. who owns the fix.

**Where you type it:** a terminal (PowerShell, bash, Windows Terminal, VS Code terminal), not a portal. One-time setup: install GitHub CLI (https://cli.github.com), run `gh auth login`, choose GitHub.com or your Enterprise host. Replace `YOURORG` with your GitHub organization.

```powershell
# Dockerfiles based on a PHP image
gh search code "FROM php" --owner YOURORG --filename Dockerfile --limit 200 --json repository,path,url

# Dockerfiles that install PHP packages on a generic base image
gh search code "php-fpm" --owner YOURORG --filename Dockerfile --limit 200 --json repository,path,url
gh search code "libapache2-mod-php" --owner YOURORG --limit 200 --json repository,path,url
gh search code "apt-get install php" --owner YOURORG --limit 200 --json repository,path,url

# Docker Hub / WordPress style images and Compose / Kubernetes manifests
gh search code "wordpress" --owner YOURORG --extension yml --limit 200 --json repository,path,url
gh search code "image: php" --owner YOURORG --extension yaml --limit 200 --json repository,path,url

# Any Composer (PHP) project
gh search code "require" --owner YOURORG --filename composer.json --limit 200 --json repository,path,url
```

Add `| ConvertFrom-Json | Select-Object -ExpandProperty repository | Select-Object -ExpandProperty nameWithOwner -Unique` to get only repo names. `gh search code` is rate limited (about 10 requests per minute); wait between commands.

**No terminal?**
- GitHub: go to https://github.com/search?type=code and paste `org:YOURORG "FROM php" path:Dockerfile`.
- Azure DevOps: top-right search box in your organization (needs the free **Code Search** extension from the Marketplace). Search `FROM php`, then use the left filters to limit to Dockerfile.

**Then map to owners:** portal.azure.com > Defender for Cloud > **DevOps security** (code-to-cloud mapping) links a vulnerable registry image or running workload back to its repo and pipeline. Defender for DevOps is not itself a free-text code search.

<a id="row-8"></a>
## Row 8 - PHP bundled outside normal packages
**Finds:** PHP binaries TVM sees on disk (XAMPP, cPanel EasyApache, Plesk, vendor appliances).

1. **security.microsoft.com > Hunting > Advanced hunting > + New query**, paste the query, **Run query**.
2. Also check the NCSC-NL list of PHP-dependent software (github.com/NCSC-NL, folder `software/`) against your product inventory.
3. The table is beta and lists only software TVM already recognises; unrecognised appliances need a vendor advisory.

```kql
// PHP binaries/modules found on disk by MDE software evidence (catches PHP bundled inside other products)
// CAVEAT: DeviceTvmSoftwareEvidenceBeta is a beta table (name/schema may change).
DeviceTvmSoftwareEvidenceBeta
| mv-expand DiskPath = DiskPaths to typeof(string)
| where DiskPath matches regex @"(?i)(libphp[\d.]*\.so|php[\d.]*-?fpm|php[\d.]*-cgi|php-cgi(\.exe)?|php\d*apache2[_\d]*\.dll|php\d+(ts)?\.dll|[\\/]php(\.exe)?$|[\\/]php\d+(\.\d+)?$)"
| summarize
    Paths = make_set(DiskPath, 20),
    SoftwareNames = make_set(SoftwareName),
    SoftwareVersions = make_set(SoftwareVersion)
    by DeviceId
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, DeviceName, OSPlatform) by DeviceId
    | project DeviceId, DeviceName, OSPlatform
  ) on DeviceId
| project DeviceName, OSPlatform, SoftwareNames, SoftwareVersions, Paths, DeviceId
| order by DeviceName asc
```

<a id="row-9"></a>
## Row 9 - Running vs installed, and mod_php vs FPM
**Finds:** which hosts actually run PHP, and which are mod_php (highest risk).

1. **security.microsoft.com > Hunting > Advanced hunting > + New query**, paste the query, **Run query**.
2. Sort by the `Classification` column (1-HIGHEST first), then **Export**.
3. Limits: process events fire only at process start (30-day window) and cannot see inside Apache. mod_php lives inside the Apache process, so "mod_php package installed + Apache running" is a proxy, not proof. An installed module may be disabled (`a2dismod php*`). Windows `php-cgi.exe` exposes its version via `ProcessVersionInfoProductVersion`; Linux does not.

```kql
// Which devices actually RUN PHP, and are they mod_php (highest risk) or php-fpm/php-cgi?
let lookback = 30d;
let ModPhpPackages = DeviceTvmSoftwareInventory
    | where SoftwareName matches regex @"(?i)mod[-_]?php|libapache2-mod-php|libphp"
    | summarize ModPhpPackages = make_set(strcat(SoftwareName, " ", SoftwareVersion)) by DeviceId;
let ApacheRunning = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ ("apache2", "httpd", "httpd.exe", "apache2.exe", "apache.exe")
    | summarize ApacheLastSeen = max(Timestamp), ApachePaths = make_set(FolderPath, 3) by DeviceId, DeviceName;
let PhpWorkersRunning = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName startswith "php-fpm" or FileName startswith "lsphp" or FileName in~ ("php-cgi", "php-cgi.exe", "frankenphp")
    | summarize PhpWorkerBinaries = make_set(FileName), PhpPaths = make_set(FolderPath, 5),
                PhpFileVersions = make_set(ProcessVersionInfoProductVersion), PhpLastSeen = max(Timestamp)
      by DeviceId, DeviceName;
union ApacheRunning, PhpWorkersRunning
| distinct DeviceId, DeviceName
| join kind=leftouter ApacheRunning on DeviceId
| join kind=leftouter PhpWorkersRunning on DeviceId
| join kind=leftouter ModPhpPackages on DeviceId
| project-away DeviceId1, DeviceId2, DeviceId3, DeviceName1, DeviceName2
| extend Classification = case(
    isnotempty(ModPhpPackages) and isnotempty(ApacheLastSeen), "1-HIGHEST: Apache running + mod_php package installed",
    isnotempty(PhpLastSeen), "2-HIGH: php-fpm / php-cgi / lsphp worker running (PHP-FPM needs an app code path to exploit)",
    isnotempty(ModPhpPackages), "3-MEDIUM: mod_php installed, Apache not seen starting in window",
    "4-REVIEW: Apache running, no mod_php package seen (may use FPM on another host, or bundled PHP)")
| project DeviceName, Classification, ModPhpPackages, ApacheLastSeen, PhpWorkerBinaries, PhpPaths, PhpFileVersions, PhpLastSeen, DeviceId
| order by Classification asc, DeviceName asc
```

<a id="row-10"></a>
## Row 10 - nmap / httpx network fingerprint scan (complex, optional)
**Finds:** internal web servers nothing else can see. Validation only; this is a project, not a quick check.

**Why it is the most complex row:** no Microsoft tool fingerprints your internal web servers for PHP. MDE device discovery does not return PHP versions, and Defender EASM sees only the internet-facing side.

1. **Where to run it from:** a dedicated, authorized scan host (Linux VM or jump box) per network zone. A laptop on the corporate LAN only reaches the VLANs it is routed to.
2. **Reachability:** server VLANs, DMZ, OT/lab and cloud VNets are often not routed from user networks or are protected by firewalls/NSGs that block scanners. Expect one scanner per segment (a jump box in each VNet, a VM in each VLAN, or an SSH/VPN pivot) and firewall exceptions for the scanner IPs.
3. **Approvals and noise:** get change approval. IDS/IPS/NDR (Defender for Endpoint network protection, Defender for IoT, WAF) will alert, so allow-list the scanner IPs and tell the SOC.
4. **Limits:** many sites hide PHP (`expose_php = Off`, headers stripped by a reverse proxy). A missing `X-Powered-By: PHP` is not proof of no PHP. Treat output as leads to confirm with MDE/TVM.
5. **Never run the public PHP2Shell exploit/PoC against production** to "verify". It can crash workers.

[httpx](https://github.com/projectdiscovery/httpx) (fast, best for technology detection). `targets.txt` = one CIDR / IP / hostname per line (get ranges from your network team):

```bash
httpx -l targets.txt -ports 80,443,8000,8080,8443,8888 -td -server -title -sc -rl 50 -json -o httpx.json

# keep only PHP-ish hits
jq -r 'select((.tech // [] | join(",")) | test("PHP|WordPress|Drupal|Joomla|Magento|MediaWiki|Roundcube|phpMyAdmin|Nextcloud|Laravel|Symfony|cPanel|Plesk";"i")) | [.url,.webserver,((.tech // [])|join(","))] | @tsv' httpx.json
```

nmap (service detection + HTTP headers):

```bash
nmap -sV --version-light -p 80,443,8000,8080,8443 --script http-headers,http-server-header,http-generator,http-title -iL targets.txt -oA phpscan
grep -iE "X-Powered-By: PHP|PHP/" phpscan.nmap
```

Single-host spot check on Windows (nothing to install):

```powershell
(Invoke-WebRequest https://host.contoso.com -Method Head -UseBasicParsing).Headers['X-Powered-By']
```

---

# Part 2 - Hunt for exploitation

<a id="hunt-a"></a>
## Hunt A - Triage: which hosts matter most
No separate query. Run Row 9 and take `Classification` 1 and 2 hosts, cross-match their hostnames/IPs with the Row 6 EASM export (internet-facing first), then run hunts B, C and E against those hosts first.

<a id="hunt-b"></a>
## Hunt B - Web worker spawns shell / downloader / reverse shell
**Requires:** MDE on the web servers (Linux eBPF telemetry).

1. **security.microsoft.com > Hunting > Advanced hunting > + New query**, paste Query 1, **Run query**, sort by `Severity`.
2. Run Query 2 (baseline) on a noisy server first to build exclusions: legitimate apps spawn children too (git, composer, convert/magick, wkhtmltopdf, sendmail, cron wrappers).
3. Code executing purely inside the PHP worker leaves no process event, so absence is not proof of safety. PHP's `shell_exec`/`system`/`exec`/`passthru`/`popen` run `sh -c --` (dash on Debian/Ubuntu, bash on RHEL).

```kql
// ---- Query 1: detections ----
let WebWorkerRegex = @"(?i)^(php-fpm[\d.]*|php-cgi(\.exe)?|php(\.exe)?|lsphp[\d]*|litespeed|lshttpd|frankenphp|apache2|apache(\.exe)?|httpd(\.exe)?|w3wp\.exe)$";
let Shells = dynamic(["sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh"]);
let Interpreters = dynamic(["python", "python2", "python3", "perl", "ruby", "node", "lua"]);
let Fetchers = dynamic(["curl", "wget", "nc", "ncat", "netcat", "socat", "busybox", "tftp", "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]);
let Recon = dynamic(["whoami", "id", "uname", "hostname", "ifconfig", "ipconfig", "ip", "netstat", "ss", "ps", "env", "cat", "ls", "find", "net.exe", "net1.exe", "systeminfo", "tasklist", "nltest.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName matches regex WebWorkerRegex
| extend Child = tolower(FileName)
| extend Category = case(
    Child in (Shells), "shell",
    Child in (Interpreters), "interpreter",
    Child in (Fetchers), "download/netcat/LOLBin",
    Child in (Recon), "recon",
    "other")
| where Category != "other"
| extend ReverseShellPattern = ProcessCommandLine matches regex @"(?i)(/dev/tcp/|/dev/udp/|mkfifo|fsockopen|bash\s+-i|\bnc(at)?\s+.*-e\b|socat\s+.*exec|python[\d.]*\s+-c\s+.*socket|perl\s+-e\s+.*socket|powershell.*(-enc|-encodedcommand|downloadstring|iex))")
| extend Severity = case(ReverseShellPattern, "HIGH", Category in ("download/netcat/LOLBin", "interpreter"), "MEDIUM", "LOW")
| project Timestamp, DeviceName, Severity, Category, ParentWorker = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, Account = AccountName, ReverseShellPattern, DeviceId, ReportId
| order by Severity asc, Timestamp desc
```

```kql
// ---- Query 2: baseline (run separately; use it to build exclusions for Query 1) ----
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName matches regex @"(?i)^(php-fpm[\d.]*|php-cgi(\.exe)?|lsphp[\d]*|apache2|httpd(\.exe)?|w3wp\.exe)$"
| summarize Executions = count(), Devices = dcount(DeviceId), SampleCmd = take_any(ProcessCommandLine) by InitiatingProcessFileName, FileName
| order by Executions desc
```

<a id="hunt-c"></a>
## Hunt C - Linux Syslog: crash / OOM / worker-churn signals
**Requires:** Syslog flowing from the Linux web servers via Azure Monitor Agent, and a Sentinel workspace onboarded to the Defender portal.

**Step 1 - get Syslog flowing** (otherwise the table is empty):
1. Azure VM: **portal.azure.com > Monitor > Data Collection Rules > Create**. Non-Azure Linux: onboard with Azure Arc first.
2. **Resources** tab: add the Linux web servers (Azure Monitor Agent installs automatically).
3. **Collect and deliver** tab > **Add data source** > data source type **Linux Syslog**. Tick facilities `kern`, `daemon`, `user`, `local0`-`local7`, and set **Minimum log level = Warning**. (kern = segfaults and the OOM killer; daemon = systemd/php-fpm unit messages; localN/user = apps configured to use syslog.)
4. Destination: **Azure Monitor Logs** > your Sentinel workspace > **Save**.
5. Verify: workspace > **Logs > Tables > Virtual machines** > click **Run** beside **Syslog**.

**Step 2 - run the query:** **security.microsoft.com > Investigation & response > Hunting > Advanced hunting**, paste Query 1, **Run query**. (Fallback: portal.azure.com > Log Analytics workspace > Logs.) If both a time-range dropdown and a `TimeGenerated` filter are present, the dropdown wins.

**Important limit:** Apache and php-fpm write their own error logs by default (`/var/log/apache2/error.log`, `/var/log/php*-fpm.log`), not to syslog. Kernel segfault/OOM lines do reach Syslog. Apache/PHP lines reach Syslog only if you set `ErrorLog syslog:local7` (Apache), `error_log = syslog` (php.ini) or `error_log = syslog` (php-fpm.conf). Otherwise use Hunt F2.

```kql
// ---- Query 1: signals ----
Syslog
| where TimeGenerated > ago(14d)
| extend Signal = case(
    SyslogMessage matches regex @"(?i)segfault at .+ in (libphp[\d.]*\.so|php-fpm[\d.]*|php-cgi|php[\d.]*|apache2|httpd)", "kernel segfault in PHP/Apache",
    SyslogMessage matches regex @"(?i)Out of memory: Killed process \d+ \((php-fpm[\d.]*|php-cgi|php[\d.]*|apache2|httpd|lsphp[\d]*)\)", "OOM killer killed PHP/Apache worker",
    SyslogMessage matches regex @"(?i)child pid \d+ exit signal", "Apache child exited on signal",
    SyslogMessage matches regex @"(?i)child \d+ exited on signal \d+", "php-fpm child exited on signal",
    SyslogMessage matches regex @"(?i)child \d+ exited with code (255|\d+) after [\d.]+ seconds from start", "php-fpm child exited right after start",
    SyslogMessage matches regex @"(?i)Allowed memory size of \d+ bytes exhausted", "PHP memory_limit exhausted",
    SyslogMessage matches regex @"(?i)Maximum execution time of \d+ seconds? exceeded", "PHP max_execution_time exceeded",
    "")
| where isnotempty(Signal)
| summarize Events = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Sample = take_any(substring(SyslogMessage, 0, 300))
    by Computer, Signal, bin(TimeGenerated, 1h)
| order by Events desc
```

```kql
// ---- Query 2: bursts (many worker deaths in 10 minutes on one host = exploitation or heavy abuse) ----
Syslog
| where TimeGenerated > ago(14d)
| where SyslogMessage matches regex @"(?i)(segfault at .+ in (libphp|php|apache2|httpd)|child pid \d+ exit signal|child \d+ exited on signal|Out of memory: Killed process \d+ \((php|apache2|httpd))"
| summarize Events = count(), Sample = take_any(substring(SyslogMessage, 0, 300)) by Computer, bin(TimeGenerated, 10m)
| where Events >= 5
| order by Events desc
```

<a id="hunt-d1"></a>
## Hunt D1 - Azure App Service HTTP logs
**Requires:** diagnostic setting for **App Service HTTP Logs**.

**Step 1 - enable logging (per app):**
1. **portal.azure.com > App Services > your app > Monitoring > Diagnostic settings > Add diagnostic setting**.
2. Tick **App Service HTTP Logs** (table `AppServiceHTTPLogs`).
3. Destination: **Send to Log Analytics workspace** > your Sentinel workspace > **Save**. (To enforce at scale, use the Azure Policy "Deploy Diagnostic Settings for App Service to Log Analytics workspace".)

**Step 2:** **security.microsoft.com > Hunting > Advanced hunting**, paste Query 1, **Run query**.

**Limits:** `AppServiceHTTPLogs` has no Content-Type, no request body detail and no response Set-Cookie. Multipart cannot be identified directly (heuristic: POST + large request + 5xx bursts), the oversized `PHPSESSID` response cookie (Wiz memory-disclosure signal) cannot be seen, and the `Cookie` column is the request cookie only. Treat hits as leads to correlate with WAF logs (D2) and the app's own error log. `CsBytes` = request bytes received, `ScBytes` = response bytes sent.

```kql
// ---- Query 1: POST bursts producing server errors, per client IP ----
AppServiceHTTPLogs
| where TimeGenerated > ago(14d)
| where CsMethod == "POST"
| summarize
    Posts = count(),
    Err5xx = countif(ScStatus >= 500),
    MaxRequestBytes = max(CsBytes),
    MedianRequestBytes = percentile(CsBytes, 50),
    Uris = make_set(CsUriStem, 5),
    Hosts = make_set(CsHost, 3),
    UserAgents = make_set(UserAgent, 3)
  by CIp, bin(TimeGenerated, 5m)
| where Err5xx >= 5 and MaxRequestBytes > 100000
| order by Err5xx desc
```

```kql
// ---- Query 2: pairs of POSTs from one IP within 10s where the second carries a session cookie (upload-progress trigger shape) ----
AppServiceHTTPLogs
| where TimeGenerated > ago(14d) and CsMethod == "POST"
| extend HasSession = Cookie has "PHPSESSID"
| summarize Posts = count(), WithSession = countif(HasSession), Err5xx = countif(ScStatus >= 500), Uris = make_set(CsUriStem, 5)
    by CIp, CsHost, bin(TimeGenerated, 10s)
| where Posts >= 2 and WithSession >= 1 and Err5xx >= 1
| order by TimeGenerated desc
```

```kql
// ---- Query 3: unusually large request cookies (client replaying a bloated PHPSESSID) ----
AppServiceHTTPLogs
| where TimeGenerated > ago(14d)
| extend CookieLen = strlen(Cookie)
| where CookieLen > 1000
| summarize Requests = count(), MaxCookieLen = max(CookieLen), Uris = make_set(CsUriStem, 5) by CIp, CsHost
| order by MaxCookieLen desc
```

<a id="hunt-d2"></a>
## Hunt D2 - Application Gateway (WAF) logs
**Requires:** Access and Firewall logs in **Resource specific** mode.

**Step 1:** **portal.azure.com > Application gateways > your gateway > Monitoring > Diagnostic settings > Add diagnostic setting**. Tick **Application Gateway Access Log** and **Application Gateway Firewall Log**. Destination: Log Analytics workspace, and choose **Resource specific** (tables `AGWAccessLogs` / `AGWFirewallLogs`). With the legacy "Azure diagnostics" destination the data lands in `AzureDiagnostics` with `*_s`/`*_d` columns and these queries will not run.

**Step 2:** **security.microsoft.com > Hunting > Advanced hunting**, paste a query, **Run query**.

**Limit:** no evidence (unverified) of a dedicated Azure WAF managed rule for these CVEs; the signals are generic. Request body content is not logged by Azure WAF. Front Door WAF tables were not verified. Rule IDs 200002 (body parse failure) and 200003 (multipart strict validation) are OWASP CRS IDs; confirm them in your ruleset version.

```kql
// ---- Query 1: POST bursts that cause backend 5xx (large bodies + failures) per client ----
AGWAccessLogs
| where TimeGenerated > ago(14d)
| where HttpMethod == "POST"
| summarize
    Posts = count(),
    Backend5xx = countif(ServerStatus >= 500),
    MaxReceivedBytes = max(ReceivedBytes),
    Uris = make_set(RequestUri, 5),
    Hosts = make_set(Host, 3),
    WafModes = make_set(WafMode)
  by ClientIp, bin(TimeGenerated, 5m)
| where Backend5xx >= 5 and MaxReceivedBytes > 100000
| order by Backend5xx desc
```

```kql
// ---- Query 2: WAF events that mention multipart / body-parsing problems ----
AGWFirewallLogs
| where TimeGenerated > ago(14d)
| where RuleId in ("200002", "200003") or Message has "ultipart" or DetailedMessage has "ultipart"
| summarize Hits = count(), Actions = make_set(Action), Rules = make_set(RuleId), Uris = make_set(RequestUri, 5) by ClientIp, bin(TimeGenerated, 10m)
| order by Hits desc
```

```kql
// ---- Query 3: join the two on TransactionId to see which flagged requests also hurt the backend ----
AGWFirewallLogs
| where TimeGenerated > ago(14d)
| where RuleId in ("200002", "200003") or Message has "ultipart"
| project TransactionId, RuleId, Message, WafAction = Action
| join kind=inner (AGWAccessLogs | where TimeGenerated > ago(14d) | project TransactionId, ClientIp, Host, RequestUri, HttpMethod, HttpStatus, ServerStatus, ReceivedBytes) on TransactionId
| order by ServerStatus desc
```

<a id="hunt-e"></a>
## Hunt E1 / E2 - Dropped PHP files; web-worker outbound connections
**Requires:** MDE. Both run in **security.microsoft.com > Hunting > Advanced hunting > + New query**.

**E1 - PHP files written by web workers or dropped in temp locations.** Huntress saw PHP write temporary PHP files, execute them, then delete them (marker string `!notwrtbl!`). File content cannot be searched here, so the query hunts on the file events and the delete that follows. Look at `DeletedWithin10Min = true`. Expect CMS-update noise under `*/wp-content/upgrade/*`, `*/wp-content/plugins/*`, `*/sites/default/files/php/*`, `vendor/` and `cache/`.

```kql
let WebWorkerRegex = @"(?i)^(php-fpm[\d.]*|php-cgi(\.exe)?|php(\.exe)?|lsphp[\d]*|litespeed|lshttpd|frankenphp|apache2|apache(\.exe)?|httpd(\.exe)?|w3wp\.exe)$";
let PhpExt = @"(?i)\.(php[3-8]?|phtml|pht|phar|inc)$";
let Created = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FileName matches regex PhpExt
    | where InitiatingProcessFileName matches regex WebWorkerRegex
         or FolderPath matches regex @"(?i)^(/tmp/|/var/tmp/|/dev/shm/|.*\\temp\\|.*\\appdata\\local\\temp\\)"
    | project CreateTime = Timestamp, DeviceId, DeviceName, FolderPath, FileName, SHA1, Writer = InitiatingProcessFileName, WriterCmd = InitiatingProcessCommandLine;
let Deleted = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileDeleted"
    | where FileName matches regex PhpExt
    | project DeleteTime = Timestamp, DeviceId, FolderPath, FileName;
Created
| join kind=leftouter Deleted on DeviceId, FolderPath, FileName
| extend DeletedWithin10Min = isnotnull(DeleteTime) and DeleteTime between (CreateTime .. (CreateTime + 10m))
| summarize arg_max(toint(DeletedWithin10Min), *) by DeviceId, FolderPath, FileName, CreateTime
| project CreateTime, DeviceName, FolderPath, FileName, Writer, WriterCmd, DeletedWithin10Min, SHA1
| order by DeletedWithin10Min desc, CreateTime desc
```

**E2 - outbound connections by web workers, or by shells/downloaders whose parent is a web worker.** Reverse shells and payload downloads after RCE. PHP legitimately calls APIs on 443/80 and databases on private IPs, so Part A excludes those; Part B (child of a web worker) is high signal on any port.

```kql
let WebWorkerRegex = @"(?i)^(php-fpm[\d.]*|php-cgi(\.exe)?|php(\.exe)?|lsphp[\d]*|litespeed|lshttpd|frankenphp|apache2|apache(\.exe)?|httpd(\.exe)?|w3wp\.exe)$";
let ChildTools = dynamic(["sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "curl", "wget", "nc", "ncat", "netcat", "socat", "cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt", "ConnectionFailed")
| where RemoteIPType == "Public"
| extend PartA_WorkerDirect = InitiatingProcessFileName matches regex WebWorkerRegex and RemotePort !in (80, 443, 53, 25, 465, 587)
| extend PartB_ChildOfWorker = tolower(InitiatingProcessFileName) in (ChildTools) and InitiatingProcessParentFileName matches regex WebWorkerRegex
| where PartA_WorkerDirect or PartB_ChildOfWorker
| project Timestamp, DeviceName, Signal = iff(PartB_ChildOfWorker, "B: shell/tool spawned by web worker", "A: web worker direct to unusual public port"),
          Process = InitiatingProcessFileName, ProcessCmd = InitiatingProcessCommandLine, Parent = InitiatingProcessParentFileName,
          RemoteIP, RemotePort, RemoteUrl, ActionType, DeviceId, ReportId
| order by Signal asc, Timestamp desc
```

<a id="hunt-f1"></a>
## Hunt F1 - AKS container logs (ContainerLogV2)
**Requires:** Container Insights with the ContainerLogV2 schema.

**Step 1:** **portal.azure.com > Kubernetes services > your cluster > Monitoring > Insights > Monitor Settings** (or **Configure monitoring**) > enable Container Insights > **Logs schema = ContainerLogV2**.
**Step 2:** **security.microsoft.com > Hunting > Advanced hunting** (or cluster > Monitoring > Logs), paste the query, **Run query**.

PHP images write errors to stderr, which lands here only if the app logs to stderr (php-fpm: `catch_workers_output = yes`, `error_log = /proc/self/fd/2`; Apache images already log to stderr). `LogMessage` is dynamic, so the query uses `tostring()`.

```kql
ContainerLogV2
| where TimeGenerated > ago(14d)
| extend Msg = tostring(LogMessage)
| extend Signal = case(
    Msg matches regex @"(?i)Allowed memory size of \d+ bytes exhausted", "PHP memory_limit exhausted",
    Msg matches regex @"(?i)Out of memory \(allocated", "PHP out of memory",
    Msg matches regex @"(?i)Maximum execution time of \d+ seconds? exceeded", "PHP max_execution_time exceeded",
    Msg matches regex @"(?i)child \d+ exited on signal \d+", "php-fpm child exited on signal",
    Msg matches regex @"(?i)child \d+ exited with code \d+ after [\d.]+ seconds from start", "php-fpm child exited right after start",
    Msg matches regex @"(?i)child pid \d+ exit signal", "Apache child exited on signal",
    Msg matches regex @"(?i)PHP (Fatal error|Warning|Deprecated).*(upload_progress|session)", "PHP session/upload_progress diagnostic",
    "")
| where isnotempty(Signal)
| summarize Events = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Sample = take_any(substring(Msg, 0, 300)), Containers = make_set(ContainerName, 5)
    by PodNamespace, PodName, Signal, bin(TimeGenerated, 1h)
| order by Events desc
```

<a id="hunt-f2"></a>
## Hunt F2 - Apache / nginx / php-fpm text logs (Custom Text Logs DCR)
**Use when** error logs do not reach Syslog, or to add the HTTP fields the platform logs lack (Content-Type, Transfer-Encoding, request length, oversized Set-Cookie).

**Step 1 - create the destination tables** (they must exist before the DCR is saved): **portal.azure.com > Log Analytics workspaces > your workspace > Settings > Tables > Create > New custom log (DCR-based)**. Names: `WebErrorLog_CL` and `WebAccessLog_CL`. Minimum columns: `TimeGenerated` (datetime) and `RawData` (string).

**Step 2 - Data Collection Rule:** **Monitor > Data Collection Rules > Create**, add the Linux servers (needs Azure Monitor Agent; Azure Arc for non-Azure), **Collect and deliver > Add data source > Custom Text Logs**.
- File patterns (wildcards allowed only in the file name and the first-level folder above it):
  - error log: `/var/log/apache2/error.log`, `/var/log/httpd/error_log`, `/var/log/php*-fpm.log`, `/var/log/nginx/error.log` into `WebErrorLog_CL`
  - access log: `/var/log/nginx/phpwatch.log`, `/var/log/apache2/phpwatch.log` into `WebAccessLog_CL`
- Record delimiter: **TimeStamp**, time format `YYYY-MM-DD HH:MM:SS` for the access-log lines below. Native Apache/PHP timestamp formats are not in the supported list, so those files fall back to one record per line (fine).
- Destination: Azure Monitor Logs > your workspace. Files must be ASCII/UTF-8 and append-only; keep 10 or fewer monitored directories.

**Step 3 - add a dedicated access-log format:**

nginx (inside `http { }` in `/etc/nginx/nginx.conf`), then `nginx -t && systemctl reload nginx`:

```nginx
map $sent_http_set_cookie $bigcookie { default 0; "~^.{200,}$" 1; }   # flags oversized Set-Cookie WITHOUT logging session IDs
log_format phpwatch '$time_iso8601|$remote_addr|$request_method|$uri|$status|$request_length|$content_type|$http_transfer_encoding|$bigcookie';
access_log /var/log/nginx/phpwatch.log phpwatch;
```

Apache (needs `mod_logio` for `%I`), then `apachectl configtest && systemctl reload apache2`:

```apache
LogFormat "%{%Y-%m-%d %H:%M:%S}t|%a|%m|%U|%>s|%I|%{Content-Type}i|%{Transfer-Encoding}i|-" phpwatch
CustomLog /var/log/apache2/phpwatch.log phpwatch
```

Apache cannot cheaply flag an oversized Set-Cookie, so its last field stays `-`. The nginx timestamp is ISO 8601; if it does not parse you still get ingestion time as `TimeGenerated`.

**Step 4 - run:** **security.microsoft.com > Hunting > Advanced hunting** (or workspace > Logs).

```kql
// ---- Query 1: error-log signals ----
WebErrorLog_CL
| where TimeGenerated > ago(14d)
| where RawData matches regex @"(?i)(Allowed memory size of \d+ bytes exhausted|Out of memory \(allocated|child \d+ exited on signal|child \d+ exited with code \d+ after [\d.]+ seconds from start|child pid \d+ exit signal|Maximum execution time of \d+ seconds? exceeded)"
| summarize Events = count(), Sample = take_any(substring(RawData, 0, 300)) by bin(TimeGenerated, 1h)
| order by Events desc
```

```kql
// ---- Query 2: access-log fields: chunked/multipart POST failures and oversized Set-Cookie (run once the access log has data) ----
WebAccessLog_CL
| where TimeGenerated > ago(14d)
| parse RawData with Ts "|" ClientIp "|" Method "|" Uri "|" Status:int "|" RequestLen:long "|" ContentType "|" TransferEncoding "|" BigCookie
| extend IsMultipart = ContentType has "multipart/form-data", IsChunked = TransferEncoding has "chunked"
| summarize Requests = count(),
            MultipartErrors = countif(IsMultipart and Status >= 500),
            ChunkedMultipart = countif(IsMultipart and IsChunked),
            BigSetCookie = countif(BigCookie == "1"),
            MaxRequestLen = max(RequestLen)
    by ClientIp, bin(TimeGenerated, 10m)
| where MultipartErrors >= 3 or ChunkedMultipart >= 1 or BigSetCookie >= 1
| order by MultipartErrors desc, BigSetCookie desc
```

<a id="hunt-g"></a>
## Hunt G - Mitigate until patched
**Only patching fixes this.** PHP states there is no complete generic mitigation. Sources: php.net announcement and GitHub advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp.

> Config changes require restarting **every** PHP worker (FPM and Apache). Set them in php.ini, the FPM pool or the server config, **not** via `ini_set()` and **not** via `.user.ini`.

**CVE-2026-109619 (session upload-progress)**

| File / location | Setting |
|---|---|
| php.ini (e.g. `/etc/php/8.3/fpm/php.ini`, `/etc/php/8.3/apache2/php.ini`, `/etc/php.ini`) | `session.upload_progress.enabled = 0` |
| FPM pool (e.g. `/etc/php/8.3/fpm/pool.d/www.conf`) | `php_admin_flag[session.upload_progress.enabled] = off` |
| Apache mod_php (vhost or `apache2.conf`) | `php_admin_flag session.upload_progress.enabled off` |
| PHP 8.5 only, php.ini | `fatal_error_backtraces = 0` |

Also remove invalid/deprecated INI directives that emit diagnostics before request init. `pm.max_requests = 1` is an option only if performance allows. Hiding errors (`display_errors`, `error_reporting`, `@`) does **not** help.

**CVE-2026-109618 (multipart memory exhaustion)**

| File / location | Setting |
|---|---|
| FPM pool | `php_admin_value[memory_limit] = -1` (php_admin_* so apps cannot override it) |
| Apache mod_php | `php_admin_value memory_limit -1` |
| php.ini | `post_max_size = 8M` (no uploads) or `32M` (uploads needed); keep `upload_max_filesize` smaller; reduce `max_input_nesting_level` |
| Reverse proxy / WAF | Cap decoded body size, number of fields, multipart parts, header count and nesting depth. Must also cover requests with no Content-Length (chunked HTTP/1.1, HTTP/2, decompressed bodies). Block multipart entirely on routes that do not use uploads. |
| Container / cgroup | Memory limit as an availability boundary only, ideally killing one worker, not the whole service |

**Do NOT** use `RLIMIT_AS` or `RLIMIT_DATA` (makes `mmap` fail and triggers the vulnerable path).

**Restart and verify (Linux):**

```bash
# Debian/Ubuntu
sudo systemctl restart php8.3-fpm apache2        # whichever you run
# RHEL family
sudo systemctl restart php-fpm httpd

# Verify the values the FPM/Apache workers will actually use (NOT plain `php -i`, which reads the CLI ini)
php-fpm8.3 -i | grep -E "session.upload_progress.enabled|memory_limit|post_max_size"     # FPM
php-fpm8.3 -tt 2>&1 | grep -E "memory_limit|upload_progress"                              # pool-level admin values
```

For mod_php, create a throwaway `phpinfo()` file only on an internal, access-restricted host and delete it immediately after reading it.

**Logging audit (to find past attempts):** during an isolated audit window set in startup config `log_errors = On`, a working `error_log = /var/log/php_errors.log`, `error_reporting = E_ALL`. Review for warnings, deprecations, fatals and "Maximum execution time exceeded". Absence of errors is not proof of safety.

**Cloudflare (if you front sites with it)**
- Free Managed Ruleset ID `77454fe2d30c4220b5701f6fdfb893ba`
- Paid Managed Ruleset ID `efb7b8c949ac4650a09736fc376e9aee` (includes "Generic Rules - Anomalous Execution 1-7")
- Managed Response Firewall rule `afffe22785674c80a31875c848d2242a` (full-transaction detection)
- Review hits: Cloudflare dashboard > **Security > Security Analytics > Events**, filter by those rule IDs.

**Azure:** no dedicated Azure WAF rule for these CVEs was found (unverified; confirm with Microsoft). App Service platform images: Microsoft's "Latest" channel was on 8.5.11 at disclosure; follow github.com/Azure/app-service-announcements. Custom containers must be rebuilt by you on a fixed PHP version.

**Open-source runtime detection:** Florian Roth's `process-watcher` (eBPF; Linux amd64/arm64; kernel 5.15+ with BTF; run on the host) can observe or kill PHP workers spawning shells. It has observe-only and kill rule configs; start in observe mode.

---

## Suggested run order
1. Rows 1, 5, 8, 9 (MDE-onboarded estate). 2. Rows 2, 3, 4 (cloud). 3. Row 6 (external). 4. Hunts B, E and C in parallel on Row 9 class 1-2 hosts. 5. Hunts D1, D2, F1, F2 where the log source exists. 6. Row 7 to find owners. 7. Row 10 only for gaps. 8. Apply Hunt G to the highest-risk hosts while patches roll out.
