# Lists PHP runtime settings for every App Service in every subscription you can read. fallback for queries/resource-graph/row03 when
# siteConfig fields come back empty. Requires: az login (Reader is enough). Output: appservice-php.csv
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
# The filter above is not exhaustive (it only keeps PHP/WORDPRESS/DOCKER runtimes). Distinct runtimes of the matched apps are below;
# for the distinct runtimes of ALL apps, run Query 2 in queries/resource-graph/row03-appservice-php-runtimes.kql.
$rows | Group-Object LinuxFx, WindowsPhp | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize
