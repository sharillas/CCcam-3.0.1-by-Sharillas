#!/bin/bash
# Script para fazer upload do projeto local para a VPS e compilar
# Uso: ./build_cccam3_upload.sh <ip_vps> [usuario] [caminho]

set -e

# --- Cores ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Parâmetros ---
VPS_IP="${1:-}"
VPS_USER="${2:-root}"
VPS_PATH="${3:-/root/cccam3}"

if [ -z "$VPS_IP" ]; then
    echo -e "${RED}❌ Uso: $0 <ip_vps> [usuario] [caminho]${NC}"
    exit 1
fi

echo -e "${GREEN}🚀 A enviar projeto para $VPS_IP...${NC}"

# Criar pacote local
tar -czf cccam3_upload.tar.gz --exclude='cccam3_upload.tar.gz' --exclude='.git' --exclude='obj' --exclude='bin' .

# Enviar para VPS
scp cccam3_upload.tar.gz ${VPS_USER}@${VPS_IP}:${VPS_PATH}/

# Extrair e compilar
ssh ${VPS_USER}@${VPS_IP} << EOF
    cd ${VPS_PATH}
    tar -xzf cccam3_upload.tar.gz
    rm -f cccam3_upload.tar.gz
    chmod +x build_release.sh
    ./build_release.sh
EOF

# Limpar
rm -f cccam3_upload.tar.gz

echo -e "${GREEN}✅ Concluído!${NC}"
