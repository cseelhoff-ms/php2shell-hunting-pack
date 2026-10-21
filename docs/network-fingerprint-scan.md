# Optional: network fingerprint scan for PHP web servers (validation only; this is a project, not a quick check)

## Why this is the most complex row
No Microsoft tool fingerprints your INTERNAL web servers for PHP. MDE device discovery does not return PHP versions and Defender EASM
only sees the internet-facing side. An nmap/httpx sweep is the only generic way to enumerate internal web servers, and it has real prerequisites:

1. **Where to run it from.** A dedicated, authorized scan host (Linux VM or jump box) per network zone. A laptop on the corporate LAN only reaches the VLANs it is routed to.
2. **Reachability.** Server VLANs, DMZ, OT/lab and cloud VNets are often NOT routed from user networks, or are protected by firewalls/NSGs that block scanners.
   Expect to place one scanner per segment (jump box in each VNet, a VM in each VLAN, or an SSH/VPN pivot) and to request firewall exceptions for the scanner IPs.
3. **Approvals and noise.** Get change approval. IDS/IPS/NDR (Defender for Endpoint network protection, Defender for IoT, WAF) will alert on scans, so allow-list the scanner IPs and tell the SOC.
4. **Limits of the result.** Many sites hide PHP (`expose_php = Off`, headers stripped by a reverse proxy). A missing `X-Powered-By: PHP` is NOT proof of no PHP. Treat output as leads to confirm with MDE/TVM.
5. **Never run the public PHP2Shell exploit/PoC against production to "verify".** It can crash workers.

## Commands (run from the scan host terminal)

httpx (https://github.com/projectdiscovery/httpx) - fast and best for technology detection:
```bash
# targets.txt = one CIDR / IP / hostname per line (get the ranges from your network team)
httpx -l targets.txt -ports 80,443,8000,8080,8443,8888 -td -server -title -sc -rl 50 -json -o httpx.json

# keep only PHP-ish hits
jq -r 'select((.tech // [] | join(",")) | test("PHP|WordPress|Drupal|Joomla|Magento|MediaWiki|Roundcube|phpMyAdmin|Nextcloud|Laravel|Symfony|cPanel|Plesk";"i")) | [.url,.webserver,((.tech // [])|join(","))] | @tsv' httpx.json
```

nmap (service detection + HTTP headers):
```bash
nmap -sV --version-light -p 80,443,8000,8080,8443 --script http-headers,http-server-header,http-generator,http-title -iL targets.txt -oA phpscan
grep -iE "X-Powered-By: PHP|PHP/" phpscan.nmap
```

PowerShell on Windows (single host spot-check, no tools to install):
```powershell
(Invoke-WebRequest https://host.contoso.com -Method Head -UseBasicParsing).Headers['X-Powered-By']
```
