# Hunt G - Official partial mitigations and logging audit (PHP2Shell, CVE-2026-109618 / CVE-2026-109619)

**Only patching fixes this.** PHP states there is no complete generic mitigation. Fixed: 8.5.12, 8.4.27, 8.3.36, 8.2.35.
8.1 and older have no official fix (source-only backport branches `PHP-7.4-/8.0-/8.1-CVE-2026-109618-109619` exist; 8.2 is EOL 31 Dec 2026).
Apply the steps below to reduce exposure until you can patch. Sources: php.net announcement and GitHub advisories GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp.

> Config changes require restarting EVERY PHP worker (FPM and Apache). Set them in php.ini, the FPM pool or the server config.
> NOT via `ini_set()` and NOT via `.user.ini`.

## CVE-2026-109619 (session upload-progress)
| File / location | Setting |
|---|---|
| php.ini (e.g. `/etc/php/8.3/fpm/php.ini`, `/etc/php/8.3/apache2/php.ini`, `/etc/php.ini`) | `session.upload_progress.enabled = 0` |
| FPM pool (e.g. `/etc/php/8.3/fpm/pool.d/www.conf`) | `php_admin_flag[session.upload_progress.enabled] = off` |
| Apache mod_php (vhost or `apache2.conf`) | `php_admin_flag session.upload_progress.enabled off` |
| PHP 8.5 only, php.ini | `fatal_error_backtraces = 0` |

Also remove invalid/deprecated INI directives that emit diagnostics before request init. `pm.max_requests = 1` is an option only if performance allows.
Hiding errors (`display_errors`, `error_reporting`, `@`) does NOT help.

## CVE-2026-109618 (multipart memory exhaustion)
| File / location | Setting |
|---|---|
| FPM pool | `php_admin_value[memory_limit] = -1` (set with php_admin_* so apps cannot override it) |
| Apache mod_php | `php_admin_value memory_limit -1` |
| php.ini | `post_max_size = 8M` (no uploads) or `32M` (uploads needed); keep `upload_max_filesize` smaller; reduce `max_input_nesting_level` |
| Reverse proxy / WAF | Cap decoded body size, number of fields, multipart parts, header count and nesting depth. Must also cover requests with no Content-Length (chunked HTTP/1.1, HTTP/2, decompressed bodies). Block multipart entirely on routes that do not use uploads. |
| Container / cgroup | Memory limit as an availability boundary only, ideally killing one worker, not the whole service |

**Do NOT** use `RLIMIT_AS` or `RLIMIT_DATA` (makes `mmap` fail and triggers the vulnerable path).

## Restart and verify (Linux)
```bash
# Debian/Ubuntu
sudo systemctl restart php8.3-fpm apache2        # whichever you run
# RHEL family
sudo systemctl restart php-fpm httpd

# Verify the values the FPM/Apache workers will actually use (NOT plain `php -i`, which reads the CLI ini)
php-fpm8.3 -i | grep -E "session.upload_progress.enabled|memory_limit|post_max_size"     # FPM
php-fpm8.3 -tt 2>&1 | grep -E "memory_limit|upload_progress"                              # pool-level admin values
```
mod_php: create a throwaway `phpinfo()` file only on an internal, access-restricted host; delete it immediately after reading it.

## Logging audit (to find past attempts)
During an isolated audit window set in startup config: `log_errors = On`, a working `error_log = /var/log/php_errors.log`, `error_reporting = E_ALL`.
Review for warnings, deprecations, fatals and "Maximum execution time exceeded". Absence of errors is not proof of safety.

## Cloudflare (if you front sites with it)
- Free Managed Ruleset ID `77454fe2d30c4220b5701f6fdfb893ba`
- Paid Managed Ruleset ID `efb7b8c949ac4650a09736fc376e9aee` (includes "Generic Rules - Anomalous Execution 1-7")
- Managed Response Firewall rule `afffe22785674c80a31875c848d2242a` (full-transaction detection)
- Review hits: Cloudflare dashboard > Security > Security Analytics > Events, filter by those rule IDs.

## Azure
No dedicated Azure WAF rule for these CVEs was found (unverified; confirm with Microsoft). App Service platform images: Microsoft's "Latest" channel was on 8.5.11 at disclosure; follow github.com/Azure/app-service-announcements. Custom containers must be rebuilt by you on a fixed PHP version.

## Open-source runtime detection
Florian Roth's `process-watcher` (eBPF, Linux amd64/arm64, kernel 5.15+ with BTF, run on the host) can observe or kill PHP workers spawning shells. It has observe-only and kill rule configs; start in observe mode.
