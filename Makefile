# Makefile para CCcam3

CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude -Isrc/core -Isrc/network -Isrc/CCshare -Isrc/api -Isrc/hardware -DUSE_OPENSSL
LDFLAGS = -lssl -lcrypto -lm -lpthread -ldl

# Suporte a leitores locais de smartcard via PC/SC:
#   make USE_PCSC=1  (requer libpcsclite-dev)
ifdef USE_PCSC
CFLAGS += -DUSE_PCSC
LDFLAGS += -lpcsclite
endif

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Lista completa de ficheiros fonte
SOURCES = $(SRC_DIR)/core/cccam3_server.c \
          $(SRC_DIR)/core/cccam3_config.c \
          $(SRC_DIR)/core/cccam3_client.c \
          $(SRC_DIR)/core/cccam3_logger.c \
          $(SRC_DIR)/core/cccam3_utils.c \
          $(SRC_DIR)/core/cccam3_optimizer.c \
          $(SRC_DIR)/network/cccam3_protocol.c \
          $(SRC_DIR)/network/cccam3_handshake.c \
          $(SRC_DIR)/network/cccam3_handshake_advanced.c \
          $(SRC_DIR)/network/cccam3_crypto.c \
          $(SRC_DIR)/network/cccam3_crypto_advanced.c \
          $(SRC_DIR)/network/cccam3_newcamd.c \
          $(SRC_DIR)/hardware/cccam3_dvbapi.c \
          $(SRC_DIR)/hardware/cccam3_stapi.c \
          $(SRC_DIR)/hardware/cccam3_dvb.c \
          $(SRC_DIR)/hardware/cccam3_smartcard.c \
          $(SRC_DIR)/CCshare/cccam3_cache.c \
          $(SRC_DIR)/CCshare/cccam3_ecm.c \
          $(SRC_DIR)/CCshare/cccam3_card_manager.c \
          $(SRC_DIR)/CCshare/cccam3_hop_control.c \
          $(SRC_DIR)/CCshare/cccam3_user_manager.c \
          $(SRC_DIR)/CCshare/cccam3_emu.c \
          $(SRC_DIR)/CCshare/cccam3_emu_des.c \
          $(SRC_DIR)/CCshare/cccam3_emu_idea.c \
          $(SRC_DIR)/CCshare/cccam3_emu_viaccess.c \
          $(SRC_DIR)/CCshare/cccam3_emu_viaccess_tables.c \
          $(SRC_DIR)/CCshare/cccam3_emu_cryptoworks.c \
          $(SRC_DIR)/CCshare/cccam3_emu_powervu.c \
          $(SRC_DIR)/CCshare/cccam3_emu_nagravision.c \
          $(SRC_DIR)/CCshare/cccam3_emu_irdeto.c \
          $(SRC_DIR)/api/cccam3_rest_api.c \
          $(SRC_DIR)/api/cccam3_web_interface.c

OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))
TARGET = $(BIN_DIR)/cccam3

.PHONY: all clean test install uninstall docs dist

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ CCcam3 compilado com sucesso!"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	@echo "🧪 A executar testes básicos..."
	./$(TARGET) -t

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "🧹 Ficheiros objetos e binários removidos."

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "✅ CCcam3 instalado em /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/cccam3
	@echo "🗑️ CCcam3 removido."

docs:
	@echo "📚 Gerando documentação..."
	@cat docs/INSTALL.md docs/API.md > docs/README_FULL.md
	@echo "✅ Documentação gerada em docs/README_FULL.md"

dist: clean docs
	@echo "📦 Criando pacote de distribuição..."
	mkdir -p dist/cccam3
	cp -r src include conf docs Makefile README.md LICENSE dist/cccam3/
	cd dist && tar -czf cccam3-$(shell date +%Y%m%d).tar.gz cccam3/
	@echo "✅ Pacote criado em dist/cccam3-$(shell date +%Y%m%d).tar.gz"

# Cross-compile para MIPS
mips:
	$(MAKE) CC=mipsel-linux-gcc CFLAGS="$(CFLAGS) -march=mips32"

# Cross-compile para ARM
arm:
	$(MAKE) CC=arm-linux-gnueabi-gcc CFLAGS="$(CFLAGS) -march=armv7-a"

# Compilação com debug
debug:
	$(MAKE) CFLAGS="$(CFLAGS) -g -O0 -DDEBUG"
