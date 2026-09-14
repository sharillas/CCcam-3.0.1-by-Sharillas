#!/bin/bash
# Gera um feed opkg (índice Packages) a partir de uma release do GitHub.
#
# Uso:
#   ./tools/make_opkg_feed.sh <tag> <pasta_de_saida>
#   ex.: ./tools/make_opkg_feed.sh v3.0.2 feed/
#
# O resultado pode ser servido por qualquer HTTP estático (GitHub Pages,
# nginx, apache...) e as boxes instalam/atualizam com:
#   echo "src/gz cccam3 http://<host>/<feed>" > /etc/opkg/cccam3-feed.conf
#   opkg update
#   opkg install enigma2-plugin-softcams-cccam3
#
set -e

TAG="${1:?uso: $0 <tag> <pasta>}"
OUT="${2:?uso: $0 <tag> <pasta>}"
REPO="sharillas/CCcam-3.0.1-by-Sharillas"
API="https://api.github.com/repos/$REPO/releases/tags/$TAG"

mkdir -p "$OUT"
rm -f "$OUT/Packages" "$OUT/Packages.gz"

echo ">> A procurar a release $TAG..."
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo "ERRO: precisa de curl ou wget"
    exit 1
fi

dl() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

# Lista os assets .ipk da release e descarrega-os
dl "$API" "/tmp/cccam3-release.json"
grep -o '"browser_download_url": *"[^"]*\.ipk"' /tmp/cccam3-release.json | \
    sed 's/.*"browser_download_url": *"//;s/"$//' | while read -r url; do
    name=$(basename "$url")
    echo ">> $name"
    dl "$url" "$OUT/$name"

    size=$(stat -c%s "$OUT/$name")
    md5=$(md5sum "$OUT/$name" | awk '{print $1}')
    {
        echo "Package: $(echo "$name" | sed 's/_[^_]*$//')"
        echo "Version: ${TAG#v}"
        echo "Architecture: all"
        echo "Filename: $name"
        echo "Size: $size"
        echo "MD5Sum: $md5"
        echo "Description: CCcam3 - servidor de cardsharing (binários estáticos)"
        echo ""
    } >> "$OUT/Packages"
done

gzip -9 -c "$OUT/Packages" > "$OUT/Packages.gz"

echo ">> Feed gerado em $OUT (Packages + Packages.gz)"
