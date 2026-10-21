# PHP2Shell Hunting Pack (CVE-2026-109618 / CVE-2026-109619)

Top 10 ways to find vulnerable PHP assets for Microsoft customers, sorted from easiest to most complex, plus hunts for attempted or successful exploitation. Every row links to a copy-paste-ready query or runbook in this repo.

> **Background:** [PHP2Shell: AI uncovers critical RCE vulnerabilities affecting 70% of the Internet (Wiz)](https://www.wiz.io/blog/php2shell-php-rce)
> **Fixed upstream:** PHP **8.5.12, 8.4.27, 8.3.36, 8.2.35**. **PHP 8.1 and older: no official fix.** Distro packages may carry backports, so version strings alone are unreliable.

## Read this first

- **Not confirmed:** whether Defender Vulnerability Management (TVM), Defender for Cloud or EASM already publish detections for these CVEs. **An empty CVE result does not mean "not vulnerable".** Rows 5, 8 and 9 (inventory/version based) are the safety net.
- **Queries were not run against a live tenant.** Run each once, fix any schema differences, then save it.
- Portal menu labels change often. Where a label is unverified, the step says so.
- **Sentinel data is now queried in the Defender portal:** *security.microsoft.com > Investigation & response > Hunting > Advanced hunting* (workspace onboarded to the Defender portal, at least Microsoft Sentinel Reader). `DeviceTvm*` and `Device*` tables exist only in Defender XDR.
- Do **not** run the public PoC for this exploit against production systems.

## Repository layout

| Path | Contents |
|---|---|
| [`docs/detailed-guide.md`](docs/detailed-guide.md) | Full walkthrough with every query and command inline |
| [`docs/mitigations.md`](docs/mitigations.md) | Hunt G: php.ini / FPM / Apache / proxy mitigations until patched |
| [`docs/github-code-search.md`](docs/github-code-search.md) | Find repos that build PHP images (Row 7) |
| [`docs/container-sbom-sweep.md`](docs/container-sbom-sweep.md) | Syft + jq image sweep (Row 4c) |
| [`docs/network-fingerprint-scan.md`](docs/network-fingerprint-scan.md) | nmap / httpx scanning guidance (Row 10) |
| [`queries/defender-xdr/`](queries/defender-xdr) | Defender XDR Advanced hunting KQL |
| [`queries/sentinel-log-analytics/`](queries/sentinel-log-analytics) | Sentinel / Log Analytics KQL, with log-source setup in each header |
| [`queries/resource-graph/`](queries/resource-graph) | Azure Resource Graph KQL |
| [`scripts/`](scripts) | PowerShell helpers |

---

## Table 1: Build the list of vulnerable assets

| **#** | **Approach** | **How to run it** |
| --- | --- | --- |
| 1 | **Defender TVM** CVE view | 1. Go to security.microsoft.com<br>2. Open **Vulnerability management > Weaknesses**<br>3. Search `CVE-2026-109618`, open it, then the **Exposed devices** tab, then **Export**<br>4. Repeat for `CVE-2026-109619`<br>5. If the CVE isn't listed, run [row01-tvm-cve-exposure.kql](queries/defender-xdr/row01-tvm-cve-exposure.kql) in **Hunting > Advanced hunting**, or use rows 5, 8 and 9 |
| 2 | **Defender for Cloud**: VMs and running containers | 1. Go to portal.azure.com, then **Microsoft Defender for Cloud > Recommendations**<br>2. Open the **Vulnerabilities** tab and choose **Flat list**<br>3. **Add filter > Resource type** = *Virtual machine*, then repeat with *Container*<br>4. Open a recommendation, then **Associated CVEs**, and look for the two CVEs<br>5. Optionally use **Cloud Security Explorer** and **Download CSV** (the CVE filter label is unverified)<br>6. Needs Defender CSPM or Defender for Servers P2 with agentless scanning |
| 3 | **Resource Graph**: App Service runtimes | 1. Go to portal.azure.com, then **Resource Graph Explorer**<br>2. Set **Scope = Directory**<br>3. Paste [row03-appservice-php-runtimes.kql](queries/resource-graph/row03-appservice-php-runtimes.kql), click **Run query**, then **Download as CSV**<br>4. App Service exposes only major.minor, so treat every PHP app as in scope until Microsoft confirms patched images<br>5. If fields come back empty, run [appservice-php-config.ps1](scripts/appservice-php-config.ps1)<br>6. The filter only matches known PHP runtimes. Also run the commented **Query 2** in the same file for a distinct list of every runtime across all apps, and review it for other PHP-based stacks |
| 4 | **Defender for Containers**: registry and running images | 1. In **Defender for Cloud > Recommendations > Vulnerabilities > Flat list**, add **Resource type = Container Image** (registry), then **Container** (running)<br>2. Check **Associated CVEs**<br>3. For a tenant-wide CSV, run [row04a-acr-subassessments-cve.kql](queries/resource-graph/row04a-acr-subassessments-cve.kql) in Resource Graph Explorer<br>4. To list every image with any PHP finding, run [row04b-acr-images-with-php-findings.kql](queries/resource-graph/row04b-acr-images-with-php-findings.kql)<br>5. For images with zero findings, use the [SBOM sweep](docs/container-sbom-sweep.md)<br>6. Needs registry access plus K8S API access or the Defender sensor |
| 5 | **MDE software inventory** (version vs fixed) | 1. Go to security.microsoft.com, then **Investigation & response > Hunting > Advanced hunting**<br>2. Click **+ New query** and paste [row05-php-inventory-version-check.kql](queries/defender-xdr/row05-php-inventory-version-check.kql)<br>3. Click **Run query**, then **Export**<br>4. Rows with `VendorPackaged = true` need a vendor changelog check, because distros backport fixes<br>5. The product list is **not exhaustive**. Also run the commented **Query 2** (distinct PHP-named software) and **Query 3** (distinct software on hosts that run a web server, which catches WordPress/Drupal-style apps without "php" in the name) in the same file and review them by hand |
| 6 | **Defender EASM** (internet-facing) | 1. Go to portal.azure.com, open **Microsoft Defender EASM**, then your workspace, then **Inventory > Page assets**<br>2. Filter **State = Approved Inventory** and **Live = true**<br>3. Pass A: **Framework Equals PHP**<br>4. Pass B: **Server Contains** Apache, nginx, LiteSpeed, Microsoft-IIS<br>5. Pass C: **Web Component Name Contains** WordPress, Drupal, Joomla, Magento, MediaWiki, Roundcube, phpMyAdmin, Nextcloud, Laravel, Symfony, WHMCS, cPanel, Plesk, Moodle, TYPO3, PrestaShop, OpenCart, phpBB, Matomo, SuiteCRM (case-sensitive, so use *Contains*)<br>6. On **IP addresses**, filter **Banner Matches** `PHP/`<br>7. Export each result<br>8. These lists are **not exhaustive**. Build a distinct list too: clear the Pass A-C filters (keep only **State = Approved Inventory** and **Live = true**), **Export** the page assets, then list the distinct values of the web component / framework / server columns (Excel: **Data > Remove Duplicates** or a PivotTable; PowerShell: `Import-Csv .\easm.csv \| Select-Object -ExpandProperty '<exact column header>' -Unique`). Review it for other PHP-based products and re-run Pass C with them<br>9. Limits: external assets only, and PHP versions are often hidden |
| 7 | **Code search + Defender for DevOps** (find owners) | 1. Open a terminal and run `gh auth login` once<br>2. Run `gh search code "FROM php" --owner YOURORG --filename Dockerfile --limit 200 --json repository,path,url`<br>3. Run the other searches in [github-code-search.md](docs/github-code-search.md)<br>4. Without a terminal, go to github.com/search?type=code and enter `org:YOURORG "FROM php" path:Dockerfile`. Azure DevOps uses the top-right search box and needs the Code Search extension<br>5. Then use **Defender for Cloud > DevOps security** to map an image back to its repo and pipeline. It doesn't do free-text search<br>6. The keyword searches are not exhaustive; the `composer.json` search is the most general. Also list the distinct repositories returned (see [github-code-search.md](docs/github-code-search.md)) and review them for other PHP stacks |
| 8 | **Bundled PHP** (XAMPP, cPanel, Plesk, appliances) | 1. In Advanced hunting, paste [row08-php-binaries-on-disk.kql](queries/defender-xdr/row08-php-binaries-on-disk.kql) and **Run query**<br>2. Then paste [row08-ncsc-products-in-inventory.kql](queries/defender-xdr/row08-ncsc-products-in-inventory.kql) and **Run query**. It matches the [NCSC-NL php2shell software list](https://github.com/NCSC-NL/php2shell/tree/main/software) of PHP-dependent products (refreshed daily into [data/](data/)) against your MDE software inventory. Sort by Priority; results are leads, since most NCSC entries are "Investigation". If your tenant blocks `externaldata`, generate an offline copy with [ncsc-inventory-to-csv.ps1](scripts/ncsc-inventory-to-csv.ps1) `-KqlFile`<br>3. The table is beta and covers only software TVM recognises |
| 9 | **Running vs installed, and mod_php** | 1. In Advanced hunting, paste [row09-running-php-vs-mod-php.kql](queries/defender-xdr/row09-running-php-vs-mod-php.kql) (complete, no joins to write)<br>2. **Run query** and sort by `Classification`, where 1 is highest risk<br>3. **Export**<br>4. mod_php can't be proven from process events. "mod_php package installed and Apache running" is a proxy<br>5. The process-name lists are **not exhaustive**. Also run the commented **Query 2** (distinct processes mentioning PHP) and **Query 3** (distinct processes accepting inbound web traffic) in the same file, review the results, and add any new names to `WebWorkerRegex` in Hunts B, E1 and E2 |
| 10 | **nmap / httpx scan** (complex, optional) | 1. Read [network-fingerprint-scan.md](docs/network-fingerprint-scan.md) first<br>2. Place one authorized scanner per network zone (VLAN, DMZ, VNet)<br>3. Confirm routing and firewall/NSG reach to each segment, and request exceptions for the scanner IPs<br>4. Get change approval and warn the SOC<br>5. Run the httpx/nmap commands from that file<br>6. A missing `X-Powered-By` is not proof of no PHP, so validate hits with MDE<br>7. The technology filter is not exhaustive: also list the distinct technologies and web servers found (`jq -r '.tech[]?' httpx.json \| sort \| uniq -c \| sort -rn`) and review them |

---

## Table 2: Hunt for exploitation

All hunts run in **security.microsoft.com > Investigation & response > Hunting > Advanced hunting > + New query** unless noted. Hunt A is the triage step (run row 9, take `Classification` 1 and 2 hosts, then cross-match with the EASM export from row 6 and hunt those hosts first).

| **ID** | **Hunt** | **Prerequisite** | **How to run it** |
| --- | --- | --- | --- |
| B | Web worker spawns shell or downloader | MDE on the web servers (Linux eBPF telemetry) | 1. In Advanced hunting, paste Query 1 from [huntB-web-worker-spawns-shell.kql](queries/defender-xdr/huntB-web-worker-spawns-shell.kql) and **Run query**<br>2. Sort by `Severity`<br>3. Run the baseline Query 2 (at the bottom of the file) first on noisy servers to build exclusions (git, composer, ImageMagick, mail are normal)<br>4. Code running purely inside the worker leaves no process event, so absence is not proof of safety |
| C | Syslog segfaults, OOM kills, worker churn | Linux Syslog via Azure Monitor Agent and a Data Collection Rule (DCR) | 1. Follow the setup at the top of [huntC-syslog-crash-oom.kql](queries/sentinel-log-analytics/huntC-syslog-crash-oom.kql) (**Monitor > Data Collection Rules > Create**, data source **Linux Syslog**, facilities kern/daemon/user/local0-7, minimum level Warning)<br>2. Verify data is arriving (allow 10-15 minutes after creating the DCR): in **security.microsoft.com > Investigation & response > Hunting > Advanced hunting**, run `Syslog \| where TimeGenerated > ago(1h) \| summarize Events = count() by Computer, Facility, SeverityLevel`. Rows for your web servers mean collection works; no rows means check the DCR **Resources** tab and the Azure Monitor Agent on the server (alternative: Azure portal > your Log Analytics workspace > **Logs > Tables > Virtual machines**, hover **Syslog**, click **Run**)<br>3. In the **Defender portal's Advanced hunting** (not the retired Sentinel Logs), paste Query 1 and **Run query**<br>4. Apache and php-fpm error logs reach Syslog only if configured to; otherwise use F2 |
| D1 | App Service HTTP logs | Diagnostic setting for **App Service HTTP Logs** | 1. **portal.azure.com > App Services > your app > Monitoring > Diagnostic settings > Add diagnostic setting**, tick **App Service HTTP Logs**, send to your Log Analytics workspace, **Save**<br>2. In Advanced hunting, paste [huntD1-appservice-http.kql](queries/sentinel-log-analytics/huntD1-appservice-http.kql) and **Run query**<br>3. Results are leads only: the table has no Content-Type and no response cookie |
| D2 | App Gateway WAF logs | Access and Firewall logs in **Resource specific** mode | 1. **portal.azure.com > Application gateways > your gateway > Monitoring > Diagnostic settings**, tick **Access Log** and **Firewall Log**, destination Log Analytics, choose **Resource specific**<br>2. In Advanced hunting, paste [huntD2-appgw-waf.kql](queries/sentinel-log-analytics/huntD2-appgw-waf.kql) and **Run query**<br>3. Rule IDs 200002 / 200003 are OWASP CRS IDs; confirm them in your ruleset version |
| E1 / E2 | Dropped PHP files; web-worker outbound connections | MDE | 1. Paste [huntE1-php-file-drops.kql](queries/defender-xdr/huntE1-php-file-drops.kql), **Run query**, and look at `DeletedWithin10Min = true` (expect CMS-update noise)<br>2. Paste [huntE2-web-worker-network.kql](queries/defender-xdr/huntE2-web-worker-network.kql) and **Run query**<br>3. Part B of E2 (a shell or tool whose parent is a web worker) is high signal on any port |
| F1 | AKS container logs | Container Insights with **ContainerLogV2** | 1. **portal.azure.com > Kubernetes services > your cluster > Monitoring > Insights**, enable Container Insights with schema **ContainerLogV2**<br>2. In Advanced hunting, paste [huntF1-aks-containerlogv2.kql](queries/sentinel-log-analytics/huntF1-aks-containerlogv2.kql) and **Run query**<br>3. php-fpm needs `catch_workers_output = yes` for errors to reach container logs |
| F2 | Apache / nginx / php-fpm text logs | Custom Text Logs DCR on the Linux servers | 1. Follow steps 1 to 3 in [huntF2-apache-nginx-textlogs.kql](queries/sentinel-log-analytics/huntF2-apache-nginx-textlogs.kql) (create `WebErrorLog_CL` / `WebAccessLog_CL`, create the DCR, add the `phpwatch` log format that records Content-Type, Transfer-Encoding and request length)<br>2. In Advanced hunting, paste Query 1 (and Query 2 once the access log has data), then **Run query** |
| G | Mitigate until patched | Admin access to servers and WAF | 1. Follow [mitigations.md](docs/mitigations.md)<br>2. Set `session.upload_progress.enabled=0` and `memory_limit=-1` via `php_admin_value`<br>3. Set a low `post_max_size`<br>4. On PHP 8.5, set `fatal_error_backtraces=0`<br>5. Set these in php.ini, the FPM pool or server config, **not** `ini_set` or `.user.ini`<br>6. Restart all PHP workers<br>7. Never use `RLIMIT_AS` or `RLIMIT_DATA` |

## Suggested run order

1. Rows 1, 5, 8, 9 (MDE-onboarded estate)
2. Rows 2, 3, 4 (cloud)
3. Row 6 (external exposure)
4. Hunts B, E and C in parallel on row 9 class 1-2 hosts
5. Hunts D1, D2, F1, F2 where the log source exists
6. Row 7 to find owners
7. Row 10 only for gaps
8. Apply Hunt G to the highest-risk hosts while patches roll out

The same content with every query, command and config snippet inline is in [`docs/detailed-guide.md`](docs/detailed-guide.md).

## Sources

- [Wiz: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
- [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell): the Dutch National Cyber Security Centre's operational repository for these CVEs. Its PHP-dependent software inventory (`software/spdx/PHP_Downstream_Inventory.spdx3.json`, EUPL-1.2) is the source of [`data/ncsc-php-products.csv`](data/ncsc-php-products.csv), which is derived from it and refreshed daily. NCSC-NL gives no guarantee of completeness or accuracy; see [`data/README.md`](data/README.md)
- php.net announcement and GitHub advisories GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp
- Microsoft Learn: Advanced hunting schema, Defender for Containers / CSPM, Defender EASM, Azure Monitor Agent Syslog and Custom Text Logs, Azure Resource Graph

## Disclaimer

Provided as-is without warranty. Queries are untested against a live tenant and may need schema adjustments. Always validate findings and test mitigations in non-production first.
