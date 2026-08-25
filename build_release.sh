#!/bin/bash
# Script para compilar CCcam3 para múltiplas arquiteturas

set -e

VERSION="3.0.1"
RELEASE_DIR="CCcam3-v${VERSION}"
BIN_DIR="${RELEASE_DIR}/bin"
CONF_DIR="${RELEASE_DIR}/conf"
DOCS_DIR="${RELEASE_DIR}/docs"

echo "🚀 A preparar release ${VERSION}..."

# Limpar compilações anteriores
make clean

# Criar diretórios
mkdir -p ${BIN_DIR}
mkdir -p ${CONF_DIR}
mkdir -p ${DOCS_DIR}

# --- Compilação para x86_64 (nativo) ---
echo "📦 A compilar para x86_64..."
make CC=gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -Isrc/core -Isrc/network -Isrc/CCshare -Isrc/api -Isrc/hardware -DUSE_OPENSSL -m64"
cp bin/cccam3 ${BIN_DIR}/cccam3-x86_64
make clean

# --- Compilação para ARMv7 ---
echo "📦 A compilar para ARMv7..."
if command -v arm-linux-gnueabihf-gcc &> /dev/null; then
    make CC=arm-linux-gnueabihf-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -Isrc/core -Isrc/network -Isrc/CCshare -Isrc/api -Isrc/hardware -DUSE_OPENSSL -march=armv7-a -mfpu=neon"
    cp bin/cccam3 ${BIN_DIR}/cccam3-armv7
    make clean
else
    echo "⚠️  arm-linux-gnueabihf-gcc não encontrado. A saltar ARMv7."
fi

# --- Compilação para ARMv8 (aarch64) ---
echo "📦 A compilar para ARMv8..."
if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    make CC=aarch64-linux-gnu-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -Isrc/core -Isrc/network -Isrc/CCshare -Isrc/api -Isrc/hardware -DUSE_OPENSSL -march=armv8-a"
    cp bin/cccam3 ${BIN_DIR}/cccam3-armv8
    make clean
else
    echo "⚠️  aarch64-linux-gnu-gcc não encontrado. A saltar ARMv8."
fi

# --- Compilação para MIPS ---
echo "📦 A compilar para MIPS..."
if command -v mipsel-linux-gcc &> /dev/null; then
    make CC=mipsel-linux-gcc CFLAGS="-Wall -Wextra -O2 -Iinclude -Isrc/core -Isrc/network -Isrc/CCshare -Isrc/api -Isrc/hardware -DUSE_OPENSSL -march=mips32"
    cp bin/cccam3 ${BIN_DIR}/cccam3-mips
    make clean
else
    echo "⚠️  mipsel-linux-gcc não encontrado. A saltar MIPS."
fi

# --- Copiar ficheiros de configuração ---
echo "📄 A copiar ficheiros de configuração..."
cp conf/cccam3.conf ${CONF_DIR}/
cp conf/cccam3.users ${CONF_DIR}/
cp conf/cccam3.readers ${CONF_DIR}/

# --- Copiar documentação ---
echo "📚 A copiar documentação..."
cp docs/API.md ${DOCS_DIR}/
cp docs/INSTALL.md ${DOCS_DIR}/

# --- Copiar README e LICENSE ---
cp README.md ${RELEASE_DIR}/
cp LICENSE ${RELEASE_DIR}/

# --- Criar ficheiro de versão ---
echo "📝 A criar ficheiro de versão..."
cat > ${RELEASE_DIR}/VERSION << EOF
CCcam3 - Versão ${VERSION}
Data: $(date +%Y-%m-%d)
Plataformas: x86_64, ARMv7, ARMv8, MIPS
EOF

# --- Criar ficheiro README da release ---
cat > ${RELEASE_DIR}/RELEASE_README.md << EOF
# CCcam3 v${VERSION}

## 📦 Conteúdo da Release

### Binários
| Arquitetura | Ficheiro | Notas |
|:---|:---|:---|
| x86_64 | \`bin/cccam3-x86_64\` | Linux 64 bits |
| ARMv7 | \`bin/cccam3-armv7\` | Linux ARM 32 bits (Raspberry Pi 2/3/4, etc.) |
| ARMv8 | \`bin/cccam3-armv8\` | Linux ARM 64 bits (Raspberry Pi 4/5, etc.) |
| MIPS | \`bin/cccam3-mips\` | Linux MIPS 32 bits (boxes VU+, Dreambox, etc.) |

## 🚀 Instalação Rápida

1. Escolha o binário correto para a sua arquitetura
2. Dê permissão de execução:
   \`\`\`bash
   chmod +x bin/cccam3-<arquitetura>
   \`\`\`
3. Copie os ficheiros de configuração para \`/etc/cccam3/\`:
   \`\`\`bash
   mkdir -p /etc/cccam3
   cp conf/* /etc/cccam3/
   \`\`\`
4. Execute o servidor:
   \`\`\`bash
   ./bin/cccam3-x86_64 -c /etc/cccam3/cccam3.conf
   \`\`\`

## 🔧 Compilação a Partir do Código Fonte

Para compilar manualmente:

\`\`\`bash
make clean
make
\`\`\`

Para compilar para outras arquiteturas:

\`\`\`bash
make mips   # MIPS
make arm    # ARM
make debug  # Modo debug
\`\`\`

## 📚 Documentação

- [Guia de Instalação](docs/INSTALL.md)
- [API REST](docs/API.md)

## ⚠️ Aviso Legal

Este software é fornecido **apenas para fins educacionais e de estudo**.

## 📞 Suporte

- Issues: https://github.com/seuuser/cccam3/issues
- Wiki: https://github.com/seuuser/cccam3/wiki
EOF

# --- Criar arquivo tar.gz ---
echo "📦 A criar arquivo de release..."
tar -czf CCcam3-v${VERSION}.tar.gz ${RELEASE_DIR}/

# --- Criar arquivo zip ---
if command -v zip &> /dev/null; then
    zip -r CCcam3-v${VERSION}.zip ${RELEASE_DIR}/
fi

echo "✅ Release criada com sucesso!"
echo "📦 Ficheiros gerados:"
echo "   - CCcam3-v${VERSION}.tar.gz"
if command -v zip &> /dev/null; then
    echo "   - CCcam3-v${VERSION}.zip"
fi
echo ""
echo "📁 Pasta da release: ${RELEASE_DIR}/"
ls -la ${RELEASE_DIR}/
