#!/bin/bash
# =====================================================================
# CCcam3 - Instalador de 1 comando para VPS ou Box (STB)
#
# Uso (um único comando, como root):
#   curl -fsSL https://raw.githubusercontent.com/sharillas/CCcam-3.0.1-by-Sharillas/main/install.sh | bash
#
# O que faz:
#   1. Deteta a arquitetura (x86_64, x86_32, armv7, aarch64, mipsel, mips64el)
#   2. Descarrega o binário correspondente da release GitHub v3.0.1
#   3. Instala o binário em /usr/local/bin/cccam3
#   4. Instala as configurações de exemplo em /etc/cccam3/ (se não existirem)
#   5. Desativa o leitor DVB automaticamente se não houver /dev/dvb (VPS)
#   6. Instala o serviço (systemd ou init.d) e inicia-o
#
# Opções:
#   --no-service   não instala o serviço (apenas binário + configs)
#   --from-source  compila a partir do código-fonte em vez de usar o binário
#   -h|--help      mostra esta ajuda
#
# Depois da instalação:
#   systemctl status cccam3       (ver estado do serviço)
#   tail -f /var/log/cccam3.log   (ver o log)
#   http://IP:8080/web            (painel web)
# =====================================================================

VERSION="v3.0.1"
REPO="sharillas/CCcam-3.0.1-by-Sharillas"
RAW="https://raw.githubusercontent.com/$REPO/main"
RELEASE_URL="https://github.com/$REPO/releases/download/$VERSION"

BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/cccam3"
INSTALL_SERVICE=1
FROM_SOURCE=0

for arg in "$@"; do
    case "$arg" in
        --no-service) INSTALL_SERVICE=0 ;;
        --from-source) FROM_SOURCE=1 ;;
        -h|--help)
            echo "Uso: curl -fsSL $RAW/install.sh | bash [--no-service] [--from-source]"
            exit 0
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: precisa de root. Correr: sudo su -   e depois repetir o comando."
    exit 1
fi

# --- Função de download (curl -> wget -> python) ---
download() {
    url="$1"; dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url" || return 1
    elif command -v python >/dev/null 2>&1; then
        python -c 'import sys
if sys.version_info[0] >= 3:
    from urllib.request import urlretrieve
else:
    from urllib import urlretrieve
urlretrieve(sys.argv[1], sys.argv[2])' "$url" "$dest" || return 1
    else
        echo "ERRO: nem curl, nem wget, nem python disponiveis."
        return 1
    fi
}

# --- Detetar arquitetura ---
detect_arch() {
    m=$(uname -m)
    case "$m" in
        x86_64|amd64)            echo "x86_64" ;;
        i686|i586|i386)          echo "x86_32" ;;
        aarch64|arm64)           echo "aarch64" ;;
        armv7l|armv8l)           echo "armv7" ;;
        armv6l|armhf)            echo "armv7" ;;
        mips)
            # endianness: 0111 (octal) = little-endian
            if [ "$(printf I | od -to2 | head -n1 | awk '{print $2}')" = "0111" ]; then
                echo "mipsel"
            else
                echo ""
            fi
            ;;
        mips64)
            if [ "$(printf I | od -to2 | head -n1 | awk '{print $2}')" = "0111" ]; then
                echo "mips64el"
            else
                echo ""
            fi
            ;;
        *) echo "" ;;
    esac
}

ARCH=$(detect_arch)

if [ "$FROM_SOURCE" -eq 0 ] && [ -z "$ARCH" ]; then
    echo "ERRO: arquitetura não suportada pelos binários: $(uname -m)"
    echo "Tente: curl -fsSL $RAW/install.sh | bash -s -- --from-source"
    exit 1
fi

# --- Boxes enigma2 (OpenPLi/OpenATV/OpenViX): instalar via .ipk ---
if [ "$FROM_SOURCE" -eq 0 ] && command -v opkg >/dev/null 2>&1; then
    echo ">> Box enigma2 detetada - a instalar o pacote .ipk..."
    IPK_VERSION=$(echo "$VERSION" | sed 's/^v//')
    IPK="enigma2-plugin-softcams-cccam3_${IPK_VERSION}_all.ipk"
    download "$RELEASE_URL/$IPK" "/tmp/$IPK" || {
        echo "ERRO: falha a descarregar o pacote."
        exit 1
    }
    opkg install --force-overwrite "/tmp/$IPK"
    rm -f "/tmp/$IPK"
    echo ""
    echo ">> Instalado! Configuração em /etc/cccam3/"
    echo ">> Controlo: Menu > Plugins > CCcam3  ou  /etc/init.d/cccam3 {start|stop|restart|status}"
    echo ">> Painel web: http://IP-da-box:8080/web"
    exit 0
fi

echo "=============================================="
echo " CCcam3 $VERSION - Instalação"
if [ "$FROM_SOURCE" -eq 1 ]; then
    echo " Modo: compilar a partir do código-fonte"
else
    echo " Arquitetura: $ARCH"
fi
echo "=============================================="

# --- Instalar binário ---
if [ "$FROM_SOURCE" -eq 1 ]; then
    echo ">> A compilar a partir do código-fonte..."
    command -v make >/dev/null 2>&1 || { echo "ERRO: 'make' em falta."; exit 1; }
    command -v gcc >/dev/null 2>&1 || { echo "ERRO: 'gcc' em falta. Instalar build-essential."; exit 1; }
    if [ ! -f /usr/include/openssl/sha.h ]; then
        echo "ERRO: headers do OpenSSL em falta. Instalar libssl-dev."
        exit 1
    fi
    tmpdir=$(mktemp -d)
    cd "$tmpdir"
    download "https://github.com/$REPO/archive/refs/heads/main.tar.gz" "src.tar.gz" || exit 1
    tar xzf src.tar.gz
    cd CCcam-3.0.1-by-Sharillas-main
    make clean >/dev/null
    make
    install -m 0755 bin/cccam3 "$BIN_DIR/cccam3.bin"
    cd /
    rm -rf "$tmpdir"
else
    echo ">> A descarregar binário ($ARCH)..."
    mkdir -p "$BIN_DIR"
    download "$RELEASE_URL/cccam3-$ARCH" "$BIN_DIR/cccam3.tmp" || {
        echo "ERRO: falha a descarregar o binário."
        exit 1
    }
    chmod 0755 "$BIN_DIR/cccam3.tmp"
    mv -f "$BIN_DIR/cccam3.tmp" "$BIN_DIR/cccam3.bin"
fi

# --- Wrapper de controlo: cccam3 start|stop|restart|status|log ---
if [ -f "$BIN_DIR/cccam3.bin" ]; then
    download "$RAW/scripts/cccam3" "$BIN_DIR/cccam3" || {
        echo "AVISO: falha a descarregar o wrapper de controlo."
    }
    chmod 0755 "$BIN_DIR/cccam3"
    echo ">> Wrapper de controlo instalado: cccam3 start|stop|restart|status|log"
fi

echo ">> Binário instalado em $BIN_DIR/cccam3.bin"

# --- Configurações (não sobrescrever as existentes) ---
mkdir -p "$CONF_DIR"
for f in cccam3.conf cccam3.users cccam3.readers SoftCam.Key; do
    if [ ! -f "$CONF_DIR/$f" ]; then
        download "$RAW/examples/$f" "$CONF_DIR/$f" || \
            download "$RAW/conf/$f" "$CONF_DIR/$f" || true
        [ -f "$CONF_DIR/$f" ] && echo ">> Config criada: $CONF_DIR/$f"
    else
        echo ">> Config existente mantida: $CONF_DIR/$f"
    fi
done

# --- Sem /dev/dvb (VPS/PC): desativar o leitor DVB na config ---
if [ ! -d /dev/dvb ] && [ -f "$CONF_DIR/cccam3.conf" ]; then
    awk '/^\[dvb\]/{f=1} f && /^[ \t]*enabled[ \t]*=/{sub(/=.*/,"= 0"); f=0} {print}' \
        "$CONF_DIR/cccam3.conf" > "$CONF_DIR/cccam3.conf.new"
    mv -f "$CONF_DIR/cccam3.conf.new" "$CONF_DIR/cccam3.conf"
    echo ">> Sem /dev/dvb detetado: leitor DVB desativado na configuração"
fi

# --- Serviço (systemd ou init.d) ---
if [ "$INSTALL_SERVICE" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
        cat > /etc/systemd/system/cccam3.service <<EOF
[Unit]
Description=CCcam3 server
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/cccam3 -c $CONF_DIR/cccam3.conf
Restart=always
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable cccam3 >/dev/null 2>&1
        systemctl restart cccam3
        echo ">> Serviço systemd instalado e iniciado: systemctl status cccam3"
    elif [ -d /etc/init.d ]; then
        cat > /etc/init.d/cccam3 <<EOF
#!/bin/sh
case "\$1" in
  start)  $BIN_DIR/cccam3 -c $CONF_DIR/cccam3.conf >/dev/null 2>&1 & ;;
  stop)   pkill -f "$BIN_DIR/cccam3.bin -c" ;;
  restart) \$0 stop; sleep 1; \$0 start ;;
esac
EOF
        chmod +x /etc/init.d/cccam3
        /etc/init.d/cccam3 restart
        echo ">> Script init.d instalado: /etc/init.d/cccam3 {start|stop|restart}"
    else
        echo ">> Sem systemd nem init.d - inicia manualmente com:"
        echo "   $BIN_DIR/cccam3 -c $CONF_DIR/cccam3.conf"
    fi
else
    echo ">> Serviço não instalado (--no-service). Para correr:"
    echo "   $BIN_DIR/cccam3 -c $CONF_DIR/cccam3.conf"
fi

echo ""
echo "=============================================="
echo " CCcam3 instalado com sucesso!"
echo ""
echo " Ficheiros:"
echo "   binário : $BIN_DIR/cccam3"
echo "   configs : $CONF_DIR/"
echo ""
echo " Próximos passos:"
echo "   1. Controlo          : cccam3 start|stop|restart|status|log"
echo "   2. Editar utilizadores : $CONF_DIR/cccam3.users"
echo "   3. Editar leitores     : $CONF_DIR/cccam3.readers"
echo "   4. (VPS) Abrir portas 12000, 34000 e 8080 na firewall"
echo "   5. Painel web          : http://<IP>:8080/web"
echo "   6. Ver o log           : cccam3 log"
echo "=============================================="
