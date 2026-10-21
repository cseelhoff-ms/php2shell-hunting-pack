# Image SBOM sweep: find PHP inside container images that Defender has no finding for

Use when RG-03 / Defender recommendations are empty (no CVE detection published yet, or the image has zero findings).
Run from a terminal on a workstation or jump box that can pull from your registry. Install Syft (https://github.com/anchore/syft) and jq.

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

Running AKS workloads (images actually deployed):

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u > images.txt
```
then repeat step 2.

Quick single-image truth check (runs the binary, so only use on images you trust): `docker run --rm --entrypoint php IMAGE -v`

Caveats: official `php:*` images compile PHP from source, so the version appears as the Syft `binary` entry or in the image tag, not as a distro package.
