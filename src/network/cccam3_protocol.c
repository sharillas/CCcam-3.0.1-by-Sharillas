#include "cccam3_protocol.h"
#include "cccam3_crypto.h"
#include "cccam3_utils.h"
#include "cccam3_logger.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static uint8_t g_crypt_mode = CCCAM_CRYPT_MODE_NONE;
static uint8_t g_crypt_key[32];
static size_t g_crypt_key_len = 0;
static uint32_t g_allowed_crypt_modes = 0;

static void write_be32(uint8_t *ptr, uint32_t val) {
    uint32_t net = cccam_hton32(val);
    memcpy(ptr, &net, 4);
}

static uint32_t read_be32(const uint8_t *ptr) {
    uint32_t net;
    memcpy(&net, ptr, 4);
    return cccam_ntoh32(net);
}

static void write_be16(uint8_t *ptr, uint16_t val) {
    uint16_t net = cccam_hton16(val);
    memcpy(ptr, &net, 2);
}

static uint16_t read_be16(const uint8_t *ptr) {
    uint16_t net;
    memcpy(&net, ptr, 2);
    return cccam_ntoh16(net);
}

static int crypt_mode_allowed(uint8_t mode) {
    if (g_allowed_crypt_modes == 0) {
        return 1;
    }
    switch (mode) {
        case CCCAM_CRYPT_MODE_NONE:
            return 1;
        case CCCAM_CRYPT_MODE_RC4:
            return (g_allowed_crypt_modes & 0x01) != 0;
        case CCCAM_CRYPT_MODE_AES:
            return (g_allowed_crypt_modes & 0x02) != 0;
        case CCCAM_CRYPT_MODE_3DES:
            return (g_allowed_crypt_modes & 0x04) != 0;
        case CCCAM_CRYPT_MODE_AES_GCM:
            return (g_allowed_crypt_modes & 0x10) != 0;
        default:
            return 0;
    }
}

int cccam_protocol_init(void) {
    g_crypt_mode = CCCAM_CRYPT_MODE_NONE;
    memset(g_crypt_key, 0, sizeof(g_crypt_key));
    g_crypt_key_len = 0;
    g_allowed_crypt_modes = 0;
    cccam_log(LOG_INFO, "Protocolo CCcam inicializado");
    return 0;
}

void cccam_protocol_cleanup(void) {
    memset(g_crypt_key, 0, sizeof(g_crypt_key));
    g_crypt_key_len = 0;
    g_crypt_mode = CCCAM_CRYPT_MODE_NONE;
    g_allowed_crypt_modes = 0;
}

void cccam_protocol_set_allowed_modes(uint32_t bitmask) {
    g_allowed_crypt_modes = bitmask;
}

// --- Funções de Parsing ---

int cccam_protocol_parse(const uint8_t *buffer, size_t buf_len,
                         cccam_msg_header_t *header, void **payload,
                         size_t *payload_len) {
    if (!buffer || !header || buf_len < CCCAM_HEADER_SIZE) {
        return -1;
    }

    header->msg_id = read_be32(buffer);
    header->msg_len = read_be32(buffer + 4);
    header->flags = buffer[8];
    header->crypt_mode = buffer[9];
    header->reserved = read_be16(buffer + 10);

    if (header->msg_len < CCCAM_HEADER_SIZE) {
        cccam_log(LOG_ERROR, "Tamanho de mensagem inválido: %u", header->msg_len);
        return -1;
    }

    if (header->msg_len > CCCAM3_BUFFER_SIZE || header->msg_len > buf_len) {
        cccam_log(LOG_ERROR, "Tamanho de mensagem inválido: %u", header->msg_len);
        return -1;
    }

    size_t payload_size = header->msg_len - CCCAM_HEADER_SIZE;
    if (payload_size > 0) {
        if (!payload || !payload_len) {
            return -1;
        }
        *payload = malloc(payload_size);
        if (!*payload) {
            return -1;
        }
        memcpy(*payload, buffer + CCCAM_HEADER_SIZE, payload_size);

        if (header->crypt_mode != CCCAM_CRYPT_MODE_NONE) {
            if (cccam_protocol_decrypt((uint8_t *)*payload, payload_size) != 0) {
                free(*payload);
                *payload = NULL;
                *payload_len = 0;
                return -1;
            }
        }
        *payload_len = payload_size;
    } else {
        if (payload) *payload = NULL;
        if (payload_len) *payload_len = 0;
    }

    return 0;
}

// --- Funções de Construção de Mensagens ---

int cccam_protocol_build_login(uint8_t *buffer, size_t *buf_len,
                               const char *username, const char *password,
                               uint32_t version, const uint8_t *handshake) {
    if (!buffer || !buf_len || !username || !password || !handshake) {
        return -1;
    }

    size_t user_len = strlen(username);
    size_t pass_len = strlen(password);
    if (user_len == 0 || pass_len == 0 || user_len > 63 || pass_len > 63) {
        return -1;
    }
    size_t total_len = CCCAM_HEADER_SIZE + 16 + user_len + 1 + pass_len + 1 + 4;

    if (*buf_len < total_len || total_len > CCCAM3_BUFFER_SIZE) {
        return -1;
    }

    uint8_t *ptr = buffer;
    write_be32(ptr, CCCAM_MSG_LOGIN);
    ptr += 4;
    write_be32(ptr, (uint32_t)total_len);
    ptr += 4;
    *ptr++ = 0;
    *ptr++ = CCCAM_CRYPT_MODE_NONE;
    write_be16(ptr, 0);
    ptr += 2;

    memcpy(ptr, handshake, 16);
    ptr += 16;
    memcpy(ptr, username, user_len + 1);
    ptr += user_len + 1;
    memcpy(ptr, password, pass_len + 1);
    ptr += pass_len + 1;
    write_be32(ptr, version);

    *buf_len = total_len;
    return 0;
}

int cccam_protocol_build_ecm(uint8_t *buffer, size_t *buf_len,
                             uint16_t caid, uint16_t provid, uint16_t sid,
                             const uint8_t *ecm_data, uint16_t ecm_len) {
    if (!buffer || !buf_len || !ecm_data) {
        return -1;
    }

    size_t total_len = CCCAM_HEADER_SIZE + 6 + ecm_len;
    if (*buf_len < total_len || total_len > CCCAM3_BUFFER_SIZE) {
        return -1;
    }

    uint8_t *ptr = buffer;
    write_be32(ptr, CCCAM_MSG_ECM);
    ptr += 4;
    write_be32(ptr, (uint32_t)total_len);
    ptr += 4;
    *ptr++ = 0;
    *ptr++ = (uint8_t)g_crypt_mode;
    write_be16(ptr, 0);
    ptr += 2;

    write_be16(ptr, caid);
    ptr += 2;
    write_be16(ptr, provid);
    ptr += 2;
    write_be16(ptr, sid);
    ptr += 2;
    memcpy(ptr, ecm_data, ecm_len);

    if (g_crypt_mode != CCCAM_CRYPT_MODE_NONE) {
        size_t payload_len = total_len - CCCAM_HEADER_SIZE;
        if (cccam_protocol_encrypt(buffer + CCCAM_HEADER_SIZE, payload_len) != 0) {
            return -1;
        }
    }

    *buf_len = total_len;
    return 0;
}

int cccam_protocol_build_cw(uint8_t *buffer, size_t *buf_len,
                            const cccam_cw_msg_t *cw_msg) {
    if (!buffer || !buf_len || !cw_msg) {
        return -1;
    }

    size_t total_len = CCCAM_HEADER_SIZE + 4 + 16 + 1 + 6;
    if (*buf_len < total_len || total_len > CCCAM3_BUFFER_SIZE) {
        return -1;
    }

    uint8_t *ptr = buffer;
    write_be32(ptr, CCCAM_MSG_CW);
    ptr += 4;
    write_be32(ptr, (uint32_t)total_len);
    ptr += 4;
    *ptr++ = 0;
    *ptr++ = (uint8_t)g_crypt_mode;
    write_be16(ptr, 0);
    ptr += 2;

    write_be32(ptr, cw_msg->ecm_time);
    ptr += 4;
    memcpy(ptr, cw_msg->cw, 16);
    ptr += 16;
    *ptr++ = cw_msg->hop;
    write_be16(ptr, cw_msg->caid);
    ptr += 2;
    write_be16(ptr, cw_msg->provid);
    ptr += 2;
    write_be16(ptr, cw_msg->sid);

    if (g_crypt_mode != CCCAM_CRYPT_MODE_NONE) {
        size_t payload_len = total_len - CCCAM_HEADER_SIZE;
        if (cccam_protocol_encrypt(buffer + CCCAM_HEADER_SIZE, payload_len) != 0) {
            return -1;
        }
    }

    *buf_len = total_len;
    return 0;
}

int cccam_protocol_build_login_ack(uint8_t *buffer, size_t *buf_len,
                                   const uint8_t *handshake, size_t handshake_len) {
    if (!buffer || !buf_len || !handshake || handshake_len == 0) {
        return -1;
    }

    size_t total_len = CCCAM_HEADER_SIZE + handshake_len;
    if (*buf_len < total_len || total_len > CCCAM3_BUFFER_SIZE) {
        return -1;
    }

    uint8_t *ptr = buffer;
    write_be32(ptr, CCCAM_MSG_LOGIN_ACK);
    ptr += 4;
    write_be32(ptr, (uint32_t)total_len);
    ptr += 4;
    *ptr++ = 0;
    *ptr++ = (uint8_t)g_crypt_mode;
    write_be16(ptr, 0);
    ptr += 2;
    memcpy(ptr, handshake, handshake_len);

    *buf_len = total_len;
    return 0;
}

// --- Funções de Encriptação ---

int cccam_protocol_set_crypto(uint8_t crypt_mode, const uint8_t *key, size_t key_len) {
    if (!key || key_len > sizeof(g_crypt_key)) {
        return -1;
    }

    if (!crypt_mode_allowed(crypt_mode)) {
        cccam_log(LOG_WARN, "Modo de criptografia 0x%02X não permitido", crypt_mode);
        return -1;
    }

    switch (crypt_mode) {
        case CCCAM_CRYPT_MODE_NONE:
        case CCCAM_CRYPT_MODE_RC4:
        case CCCAM_CRYPT_MODE_AES:
        case CCCAM_CRYPT_MODE_RC6:
        case CCCAM_CRYPT_MODE_IDEA:
        case CCCAM_CRYPT_MODE_3DES:
        case CCCAM_CRYPT_MODE_AES_GCM:
            g_crypt_mode = crypt_mode;
            memcpy(g_crypt_key, key, key_len);
            g_crypt_key_len = key_len;
            return 0;
        default:
            return -1;
    }
}

int cccam_protocol_encrypt(uint8_t *data, size_t len) {
    if (!data || len == 0) return -1;

    switch (g_crypt_mode) {
        case CCCAM_CRYPT_MODE_RC4:
            return cccam_crypto_rc4(data, len, g_crypt_key, g_crypt_key_len);
        case CCCAM_CRYPT_MODE_AES:
            return cccam_crypto_aes(data, len, g_crypt_key, g_crypt_key_len, 1);
        case CCCAM_CRYPT_MODE_3DES:
            return cccam_crypto_3des(data, len, g_crypt_key, g_crypt_key_len, 1);
        case CCCAM_CRYPT_MODE_NONE:
        default:
            return 0;
    }
}

int cccam_protocol_decrypt(uint8_t *data, size_t len) {
    if (!data || len == 0) return -1;

    switch (g_crypt_mode) {
        case CCCAM_CRYPT_MODE_RC4:
            return cccam_crypto_rc4(data, len, g_crypt_key, g_crypt_key_len);
        case CCCAM_CRYPT_MODE_AES:
            return cccam_crypto_aes(data, len, g_crypt_key, g_crypt_key_len, 0);
        case CCCAM_CRYPT_MODE_3DES:
            return cccam_crypto_3des(data, len, g_crypt_key, g_crypt_key_len, 0);
        case CCCAM_CRYPT_MODE_NONE:
        default:
            return 0;
    }
}
