#!/bin/bash
# Script para empacotar, transferir e compilar o CCcam3 numa VPS Linux
# Uso: ./deploy_to_vps.sh <ip_vps> [usuario] [caminho_destino]

set -e

# --- Cores para output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Configuração ---
VERSION="3.0.1"
PROJECT_NAME="CCcam3"
PACKAGE_NAME="${PROJECT_NAME}-v${VERSION}"

# --- Parâmetros ---
VPS_IP="${1:-}"
VPS_USER="${2:-root}"
VPS_PATH="${3:-/root/${PROJECT_NAME}}"
VPS_RELEASE_PATH="${VPS_PATH}/release"

# --- Verificação de parâmetros ---
if [ -z "$VPS_IP" ]; then
    echo -e "${RED}❌ Erro: IP da VPS não fornecido!${NC}"
    echo ""
    echo -e "${YELLOW}Uso:${NC}"
    echo "  ./deploy_to_vps.sh <ip_vps> [usuario] [caminho_destino]"
    echo ""
    echo -e "${YELLOW}Exemplo:${NC}"
    echo "  ./deploy_to_vps.sh 192.168.1.100"
    echo "  ./deploy_to_vps.sh 192.168.1.100 root /opt/cccam3"
    echo ""
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🚀 CCcam3 - Deploy para VPS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}📋 Configuração:${NC}"
echo -e "   VPS IP: ${GREEN}${VPS_IP}${NC}"
echo -e "   Usuário: ${GREEN}${VPS_USER}${NC}"
echo -e "   Destino: ${GREEN}${VPS_PATH}${NC}"
echo ""

# --- 1. Verificar conexão SSH ---
echo -e "${YELLOW}🔍 A verificar conexão SSH com a VPS...${NC}"
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes ${VPS_USER}@${VPS_IP} "echo OK" 2>/dev/null | grep -q OK; then
    echo -e "${RED}❌ Não foi possível ligar à VPS via SSH.${NC}"
    echo -e "${YELLOW}   Verifique se:${NC}"
    echo -e "   1. O IP está correto"
    echo -e "   2. A VPS está ligada"
    echo -e "   3. A chave SSH está configurada"
    echo -e "   4. O firewall permite SSH (porta 22)"
    echo ""
    exit 1
fi
echo -e "${GREEN}✅ Conexão SSH OK${NC}"
echo ""

# --- 2. Criar pacote local ---
echo -e "${YELLOW}📦 A criar pacote local do projeto...${NC}"

# Criar diretório temporário
TEMP_DIR=$(mktemp -d)
PACKAGE_DIR="${TEMP_DIR}/${PACKAGE_NAME}"

# Criar estrutura de diretórios
mkdir -p ${PACKAGE_DIR}/src
mkdir -p ${PACKAGE_DIR}/include
mkdir -p ${PACKAGE_DIR}/conf
mkdir -p ${PACKAGE_DIR}/docs
mkdir -p ${PACKAGE_DIR}/scripts

# --- Copiar ficheiros fonte ---
echo -e "   📂 A copiar código fonte..."

# Core
cp -r src/core ${PACKAGE_DIR}/src/
cp -r src/network ${PACKAGE_DIR}/src/
cp -r src/hardware ${PACKAGE_DIR}/src/
cp -r src/CCshare ${PACKAGE_DIR}/src/
cp -r src/api ${PACKAGE_DIR}/src/

# Includes
cp -r include/* ${PACKAGE_DIR}/include/

# Configuração
cp -r conf/* ${PACKAGE_DIR}/conf/

# Documentação
cp docs/* ${PACKAGE_DIR}/docs/ 2>/dev/null || true

# Scripts
cp build_release.sh ${PACKAGE_DIR}/scripts/ 2>/dev/null || true

# Ficheiros raiz
cp Makefile ${PACKAGE_DIR}/
cp README.md ${PACKAGE_DIR}/ 2>/dev/null || true
cp LICENSE ${PACKAGE_DIR}/ 2>/dev/null || true

# Criar ficheiro de versão
cat > ${PACKAGE_DIR}/VERSION << EOF
CCcam3 - Versão ${VERSION}
Data: $(date +%Y-%m-%d)
Build: $(date +%Y%m%d%H%M%S)
EOF

# Criar script de compilação remota
cat > ${PACKAGE_DIR}/scripts/build_all.sh << 'EOF'
#!/bin/bash
# Script para compilar CCcam3 para todas as arquiteturas na VPS

set -e

VERSION="3.0.1"
RELEASE_DIR="CCcam3-v${VERSION}"
BIN_DIR="${RELEASE_DIR}/bin"
CONF_DIR="${RELEASE_DIR}/conf"
DOCS_DIR="${RELEASE_DIR}/docs"

echo "🚀 A compilar CCcam3 para todas as arquiteturas..."

# Criar diretórios
mkdir -p ${BIN_DIR}
mkdir -p ${CONF_DIR}
mkdir -p ${DOCS_DIR}

# --- Verificar dependências ---
echo "🔍 A verificar dependências..."

# GCC
if ! command -v gcc &> /dev/null; then
    echo "📦 A instalar GCC..."
    apt-get update -qq && apt-get install -y -qq gcc make libssl-dev
fi

# Cross-compile tools
if ! command -v arm-linux-gnueabihf-gcc &> /dev/null; then
    echo "📦 A instalar ferramentas cross-compile..."
    apt-get install -y -qq gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu gcc-mipsel-linux-gnu
fi

# --- Compilar para x86_64 ---
echo ""
echo "📦 A compilar para x86_64..."
make clean
make CC=gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -m64"
cp bin/cccam3 ${BIN_DIR}/cccam3-x86_64
make clean

# --- Compilar para ARMv7 ---
echo ""
echo "📦 A compilar para ARMv7..."
if command -v arm-linux-gnueabihf-gcc &> /dev/null; then
    make CC=arm-linux-gnueabihf-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -march=armv7-a -mfpu=neon"
    cp bin/cccam3 ${BIN_DIR}/cccam3-armv7
    make clean
else
    echo "⚠️  arm-linux-gnueabihf-gcc não encontrado. A saltar ARMv7."
fi

# --- Compilar para ARMv8 ---
echo ""
echo "📦 A compilar para ARMv8..."
if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    make CC=aarch64-linux-gnu-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -march=armv8-a"
    cp bin/cccam3 ${BIN_DIR}/cccam3-armv8
    make clean
else
    echo "⚠️  aarch64-linux-gnu-gcc não encontrado. A saltar ARMv8."
fi

# --- Compilar para MIPS ---
echo ""
echo "📦 A compilar para MIPS..."
if command -v mipsel-linux-gcc &> /dev/null; then
    make CC=mipsel-linux-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -march=mips32"
    cp bin/cccam3 ${BIN_DIR}/cccam3-mips
    make clean
else
    echo "⚠️  mipsel-linux-gcc não encontrado. A saltar MIPS."
fi

# --- Copiar ficheiros de configuração ---
echo ""
echo "📄 A copiar ficheiros de configuração..."
cp conf/cccam3.conf ${CONF_DIR}/
cp conf/cccam3.users ${CONF_DIR}/
cp conf/cccam3.readers ${CONF_DIR}/

# --- Copiar documentação ---
echo "📚 A copiar documentação..."
cp docs/API.md ${DOCS_DIR}/ 2>/dev/null || true
cp docs/INSTALL.md ${DOCS_DIR}/ 2>/dev/null || true

# --- Copiar README ---
cp README.md ${RELEASE_DIR}/ 2>/dev/null || true
cp LICENSE ${RELEASE_DIR}/ 2>/dev/null || true

# --- Criar ficheiro de versão ---
cat > ${RELEASE_DIR}/VERSION << EOV
CCcam3 - Versão ${VERSION}
Data: $(date +%Y-%m-%d)
Plataformas: x86_64, ARMv7, ARMv8, MIPS
EOV

# --- Criar RELEASE_README.md ---
cat > ${RELEASE_DIR}/RELEASE_README.md << 'EOR'
# CCcam3 v3.0.1 - Release

## 📦 Conteúdo

### Binários
| Arquitetura | Ficheiro |
|:---|:---|
| x86_64 | `bin/cccam3-x86_64` |
| ARMv7 | `bin/cccam3-armv7` |
| ARMv8 | `bin/cccam3-armv8` |
| MIPS | `bin/cccam3-mips` |

## 🚀 Instalação

```bash
chmod +x bin/cccam3-*
./bin/cccam3-x86_64 -c conf/cccam3.conf
```
