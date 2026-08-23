#!/bin/bash
# Script único para clonar/atualizar o CCcam3 e compilar a release
# Uso: ./build_cccam3_release.sh [branch]

set -e

# --- Cores para output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Configuração ---
REPO_URL="https://github.com/sharillas/CCcam-3.0.1-by-Sharillas.git"  # <-- ALTERAR PARA O SEU REPO
BRANCH="${1:-main}"
PROJECT_DIR="cccam3"
BUILD_SCRIPT="scripts/build_release.sh"

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🚀 CCcam3 - Build Release${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# --- Verificar se o Git está instalado ---
if ! command -v git &> /dev/null; then
    echo -e "${YELLOW}📦 Git não encontrado. A instalar...${NC}"
    apt-get update -qq && apt-get install -y -qq git
fi

# --- Verificar se o diretório já existe ---
if [ -d "$PROJECT_DIR" ]; then
    echo -e "${YELLOW}📂 Projeto já existe. A atualizar...${NC}"
    cd $PROJECT_DIR
    git pull origin $BRANCH
    cd ..
else
    echo -e "${YELLOW}📦 A clonar o repositório...${NC}"
    git clone $REPO_URL $PROJECT_DIR
fi

echo ""

# --- Entrar no diretório do projeto ---
cd $PROJECT_DIR

# --- Verificar se o script de build existe ---
if [ ! -f "$BUILD_SCRIPT" ]; then
    echo -e "${RED}❌ Script de build não encontrado: $BUILD_SCRIPT${NC}"
    echo -e "${YELLOW}   A criar script de build padrão...${NC}"
    
    # Criar script de build padrão se não existir
    mkdir -p scripts
    cat > $BUILD_SCRIPT << 'EOF'
#!/bin/bash
# Script para compilar CCcam3 para múltiplas arquiteturas

set -e

VERSION=$(grep -oP 'CCCAM3_VERSION "\K[^"]+' include/cccam3.h 2>/dev/null || echo "3.0.1")
RELEASE_DIR="CCcam3-v${VERSION}"
BIN_DIR="${RELEASE_DIR}/bin"
CONF_DIR="${RELEASE_DIR}/conf"
DOCS_DIR="${RELEASE_DIR}/docs"

echo "🚀 A compilar CCcam3 v${VERSION}..."

# Criar diretórios
mkdir -p ${BIN_DIR} ${CONF_DIR} ${DOCS_DIR}

# --- Compilar para x86_64 ---
echo "📦 A compilar para x86_64..."
make clean
make CC=gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -m64"
cp bin/cccam3 ${BIN_DIR}/cccam3-x86_64
make clean

# --- Compilar para ARMv7 ---
echo "📦 A compilar para ARMv7..."
if command -v arm-linux-gnueabihf-gcc &> /dev/null; then
    make CC=arm-linux-gnueabihf-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -march=armv7-a -mfpu=neon"
    cp bin/cccam3 ${BIN_DIR}/cccam3-armv7
    make clean
else
    echo "⚠️  ARMv7: compilador não encontrado"
fi

# --- Compilar para ARMv8 ---
echo "📦 A compilar para ARMv8..."
if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    make CC=aarch64-linux-gnu-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -march=armv8-a"
    cp bin/cccam3 ${BIN_DIR}/cccam3-armv8
    make clean
else
    echo "⚠️  ARMv8: compilador não encontrado"
fi

# --- Compilar para MIPS ---
echo "📦 A compilar para MIPS..."
if command -v mipsel-linux-gcc &> /dev/null; then
    make CC=mipsel-linux-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL -march=mips32"
    cp bin/cccam3 ${BIN_DIR}/cccam3-mips
    make clean
else
    echo "⚠️  MIPS: compilador não encontrado"
fi

# --- Copiar ficheiros de configuração ---
cp conf/*.conf ${CONF_DIR}/ 2>/dev/null || true
cp conf/*.users ${CONF_DIR}/ 2>/dev/null || true
cp conf/*.readers ${CONF_DIR}/ 2>/dev/null || true

# --- Copiar documentação ---
cp docs/*.md ${DOCS_DIR}/ 2>/dev/null || true

# --- Copiar README e LICENSE ---
cp README.md ${RELEASE_DIR}/ 2>/dev/null || true
cp LICENSE ${RELEASE_DIR}/ 2>/dev/null || true

# --- Criar ficheiro de versão ---
cat > ${RELEASE_DIR}/VERSION << EOV
CCcam3 - Versão ${VERSION}
Data: $(date +%Y-%m-%d)
Plataformas: x86_64, ARMv7, ARMv8, MIPS
EOV

# --- Criar arquivo de release ---
echo "📦 A criar arquivo de release..."
tar -czf CCcam3-v${VERSION}.tar.gz ${RELEASE_DIR}/
zip -r CCcam3-v${VERSION}.zip ${RELEASE_DIR}/ 2>/dev/null || true

echo ""
echo "✅ Release concluída!"
echo "📦 Ficheiros gerados:"
ls -la CCcam3-v${VERSION}.*
EOF

    chmod +x $BUILD_SCRIPT
fi

# --- Executar o script de build ---
echo -e "${YELLOW}🔧 A executar build...${NC}"
echo ""
./$BUILD_SCRIPT

# --- Resultado ---
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Build concluída com sucesso!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}📁 Ficheiros gerados:${NC}"
ls -la CCcam3-v*.tar.gz CCcam3-v*.zip 2>/dev/null || echo "   Nenhum ficheiro de release encontrado"
echo ""
echo -e "${YELLOW}📂 Localização: $(pwd)${NC}"
echo ""
