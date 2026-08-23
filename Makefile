# Makefile para CCcam3

CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude -DUSE_OPENSSL
LDFLAGS = -lssl -lcrypto -lm -lpthread

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Lista completa de ficheiros fonte
SOURCES = $(SRC_DIR)/core/cccam3_server.c \
          $(SRC_DIR)/core/cccam3_config.c \
          $(SRC_DIR)/core/cccam3_client.c \
          $(SRC_DIR)/core/cccam3_logger.c \
          $(SRC_DIR)/core/cccam3_utils.c \
          $(SRC_DIR)/network/cccam3_protocol.c \
          $(SRC_DIR)/network/cccam3_handshake.c \
          $(SRC_DIR)/network/cccam3_crypto.c \
          $(SRC_DIR)/hardware/cccam3_dvbapi.c \
          $(SRC_DIR)/hardware/cccam3_stapi.c \
          $(SRC_DIR)/CCshare/cccam3_cache.c \
          $(SRC_DIR)/CCshare/cccam3_ecm.c \
          $(SRC_DIR)/CCshare/cccam3_card_manager.c \
          $(SRC_DIR)/CCshare/cccam3_hop_control.c \
          $(SRC_DIR)/api/cccam3_rest_api.c

OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))
TARGET = $(BIN_DIR)/cccam3

.PHONY: all clean test install uninstall

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

# Cross-compile para MIPS
mips:
	$(MAKE) CC=mipsel-linux-gcc CFLAGS="$(CFLAGS) -march=mips32"

# Cross-compile para ARM
arm:
	$(MAKE) CC=arm-linux-gnueabi-gcc CFLAGS="$(CFLAGS) -march=armv7-a"

# Compilação com debug
debug:
	$(MAKE) CFLAGS="$(CFLAGS) -g -O0 -DDEBUG"
