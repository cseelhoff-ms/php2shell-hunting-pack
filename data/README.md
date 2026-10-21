# data

`ncsc-php-products.csv` is generated from the NCSC-NL php2shell inventory (https://github.com/NCSC-NL/php2shell, licensed EUPL-1.2; source of truth is `software/spdx/PHP_Downstream_Inventory.spdx3.json`). It is regenerated daily by `.github/workflows/refresh-ncsc-inventory.yml` using `scripts/ncsc-inventory-to-csv.ps1`. Do not edit it by hand.

One row per match keyword (a product can have several). Columns: Keyword, Supplier, Product, Category, Version, Status109618, Status109619, Notes, Source. Status values are NCSC's: Investigation, Vulnerable, Fix, Workaround, Not vuln.

NCSC states that the inventory is not guaranteed complete or accurate and that most entries are investigation leads. Custom PHP applications are not listed.
