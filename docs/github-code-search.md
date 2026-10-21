# Find repos that build or deploy PHP (Dockerfiles, compose, k8s manifests, composer projects)

## Where you type it
These run in a **terminal** (PowerShell, bash, Windows Terminal, VS Code terminal), not in a portal.
One-time setup: install GitHub CLI (https://cli.github.com), then run `gh auth login` and choose GitHub.com or your Enterprise host.
Replace `YOURORG` with your GitHub organization name.

## Commands (copy/paste one at a time)

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

Add `| ConvertFrom-Json | Select-Object -ExpandProperty repository | Select-Object -ExpandProperty nameWithOwner -Unique` to get just repo names.
`gh search code` has an API rate limit (about 10 requests per minute); wait between commands.

## No terminal? Use the browser
- GitHub: go to https://github.com/search?type=code, then paste: `org:YOURORG "FROM php" path:Dockerfile`
- Azure DevOps: top-right search box in your organization (requires the free **Code Search** extension from the Marketplace). Search `FROM php` then use the left filters to limit to Dockerfile.

## What this does and does not do
Finds the source of truth so you can rebuild images on fixed PHP versions. Defender for DevOps (code-to-cloud mapping) then tells you
which registry image or running workload came from which repo/pipeline so you can find the owner. It is not itself a free-text search tool.
