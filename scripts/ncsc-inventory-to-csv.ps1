# Converts the NCSC-NL php2shell SPDX 3 inventory into data/ncsc-php-products.csv (one row per product keyword).
# Source: https://github.com/NCSC-NL/php2shell (EUPL-1.2). Needs only PowerShell 7 and internet access.
# Usage: pwsh ./scripts/ncsc-inventory-to-csv.ps1 [-OutFile data/ncsc-php-products.csv] [-KqlFile ncsc-offline.kql]
# -KqlFile also writes an offline copy of queries/defender-xdr/row08-ncsc-products-in-inventory.kql with the list inlined (no externaldata needed).
param(
    [string]$Url = 'https://raw.githubusercontent.com/NCSC-NL/php2shell/main/software/spdx/PHP_Downstream_Inventory.spdx3.json',
    [string]$OutFile = (Join-Path $PSScriptRoot '..\data\ncsc-php-products.csv'),
    [string]$KqlFile
)
$ErrorActionPreference = 'Stop'
$graph = (Invoke-RestMethod -Uri $Url -MaximumRetryCount 3 -RetryIntervalSec 5).'@graph'

$orgs = @{}
$graph | Where-Object type -eq 'Organization' | ForEach-Object { $orgs[$_.spdxId] = $_.name }

# package id -> CVE -> status, from the VEX relationships
$statusMap = @{ affects = 'Vulnerable'; fixedIn = 'Fix'; doesNotAffect = 'Not vuln'; underInvestigationFor = 'Investigation' }
$status = @{}; $vexNote = @{}
foreach ($v in ($graph | Where-Object { $_.type -like 'security_Vex*' })) {
    $cve = $v.from -replace '.*:', ''
    foreach ($pkg in $v.to) {
        $status["$pkg|$cve"] = $statusMap[$v.relationshipType]
        $vexNote[$pkg] = (@($v.security_statusNotes, $v.security_actionStatement) | Where-Object { $_ }) -join ' '
    }
}

# PHP-internal components cannot be matched against installed software
$skipCategories = 'PHP bundled modules', 'PHP external extensions', 'PHP core', 'Runtime interfaces'
$stop = '\s+(PHP\b|web\b|hosted|management|for\b|on\b|with\b|and\b)|\s+[-–/(]\s*'

function Get-Keywords($product, $aliases) {
    $cut = ($product -split $stop, 2)[0] -replace '\s+\d+(\.[\dx]+)*(\.x)?$', ''
    $all = @($cut) + ($aliases -split ',\s*') | ForEach-Object { $_.Trim() } |
        Where-Object { $_.Length -ge 5 -and $_ -notmatch '[:/]' -and $_ -cnotmatch '^[a-z]+$' } | Sort-Object -Unique
    $all
}

$rows = foreach ($p in ($graph | Where-Object type -eq 'software_Package')) {
    $category = [regex]::Match($p.comment, 'Category: (.*)').Groups[1].Value.Trim()
    if ($category -in $skipCategories) { continue }
    $aliases = [regex]::Match($p.comment, 'Aliases: (.*)').Groups[1].Value
    $links = @($p.externalRef | Where-Object { $_.externalRefType -ne 'securityAdvisory' } | ForEach-Object { $_.locator } | Select-Object -First 2) -join ' '
    $note = $vexNote[$p.spdxId]; if ($note.Length -gt 250) { $note = $note.Substring(0, 250) }
    foreach ($k in (Get-Keywords $p.name $aliases)) {
        [pscustomobject]@{
            Keyword       = $k
            Supplier      = $orgs[$p.suppliedBy]
            Product       = $p.name
            Category      = $category
            Version       = $p.software_packageVersion
            Status109618  = $status["$($p.spdxId)|CVE-2026-109618"]
            Status109619  = $status["$($p.spdxId)|CVE-2026-109619"]
            Notes         = ($note -replace '[\r\n]+', ' ')
            Source        = $links
        }
    }
}
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
$rows | Sort-Object Keyword, Product | Export-Csv -NoTypeInformation -Encoding utf8 -Path $OutFile
"Wrote $(@($rows).Count) rows to $OutFile"

# Offline copy of the row 8 query: same body, with the list inlined as a datatable instead of externaldata
if ($KqlFile) {
    $q = Get-Content (Join-Path $PSScriptRoot '..\queries\defender-xdr\row08-ncsc-products-in-inventory.kql') -Raw
    $esc = { param($s) '"' + (($s -as [string]) -replace '\\', '\\' -replace '"', '\"') + '"' }
    $lines = $rows | Sort-Object Keyword, Product | ForEach-Object {
        '    ' + ((@($_.Keyword, $_.Supplier, $_.Product, $_.Category, $_.Version, $_.Status109618, $_.Status109619, '', '') | ForEach-Object { & $esc $_ }) -join ', ') + ','
    }
    $dt = "let Ncsc = datatable(Keyword:string, Supplier:string, Product:string, Category:string, Version:string, Status109618:string, Status109619:string, Notes:string, Source:string) [`n" + ($lines -join "`n") + "`n];"
    $q = [regex]::Replace($q, '(?s)// BEGIN-NCSC-SOURCE.*?// END-NCSC-SOURCE', { param($m) $dt })
    Set-Content -Path $KqlFile -Value $q -Encoding utf8
    "Wrote offline query to $KqlFile"
}
