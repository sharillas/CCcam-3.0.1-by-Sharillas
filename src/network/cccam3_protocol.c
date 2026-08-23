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

int cccam_protocol_init(void) {
    g_crypt_mode = CCCAM_CRYPT_MODE_NONE;
    memset(g_crypt_key, 0, sizeof(g_crypt_key));
    g_crypt_key_len = 0;
    cccam_log(LOG_INFO, "Protocolo CCcam inicializado");
    return 0;
}

void cccam_protocol_cleanup(void) {
    memset(g_crypt_key, 0, sizeof(g_crypt_key));
    g_crypt_key_len = 0;
    g_crypt_mode = CCCAM_CRYPT_MODE_NONE;
}

// --- Funções de Parsing ---

int cccam_protocol_parse(const uint8_t *buffer, size_t buf_len,
                         cccam_msg_header_t *header, void **payload,
                         size_t *payload_len) {
    if (!buffer || !header || buf_len < CCCAM_HEADER_SIZE) {
        return -1;
    }

    const uint8_t *ptr = buffer;
    header->msg_id = cccam_ntoh32(*(uint32_t *)ptr);
    ptr += 4;
    header->msg_len = cccam_ntoh32(*(uint32_t *)ptr);
    ptr += 4;
    header->flags = *ptr++;
    header->crypt_mode = *ptr++;
    header->reserved = cccam_ntoh16(*(uint16_t *)ptr);

    if (header->msg_len > CCCAM3_BUFFER_SIZE || header->msg_len > buf_len) {
        cccam_log(LOG_ERROR, "Tamanho de mensagem inválido: %u", header->msg_len);
        return -1;
    }

    size_t payload_size = header->msg_len - CCCAM_HEADER_SIZE;
    if (payload_size > 0 && payload && payload_len) {
        *payload_len = payload_size;
        *payload = malloc(payload_size);
        if (!*payload) {
            return -1;
        }
        memcpy(*payload, buffer + CCCAM_HEADER_SIZE, payload_size);

        if (header->crypt_mode != CCCAM_CRYPT_MODE_NONE) {
            if (cccam_protocol_decrypt((uint8_t *)*payload, payload_size) != 0) {
                free(*payload);
                *payload = NULL;
                return -1;
            }
        }
    } else {
        *payload_len = 0;
        *payload = NULL;
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
    size_t total_len = CCCAM_HEADER_SIZE + 16 + user_len + 1 + pass_len + 1 + 4;

    if (*buf_len < total_len || total_len > CCCAM3_BUFFER_SIZE) {
        return -1;
    }

    uint8_t *ptr = buffer;
    *(uint32_t *)ptr = cccam_hton32(CCCAM_MSG_LOGIN);
    ptr += 4;
    *(uint32_t *)ptr = cccam_hton32(total_len);
    ptr += 4;
    *ptr++ = 0;
    *ptr++ = CCCAM_CRYPT_MODE_NONE;
    *(uint16_t *)ptr = 0;
    ptr += 2;

    memcpy(ptr, handshake, 16);
    ptr += 16;
    strcpy((char *)ptr, username);
    ptr += user_len + 1;
    strcpy((char *)ptr, password);
    ptr += pass_len + 1;
    *(uint32_t *)ptr = cccam_hton32(version);

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
    *(uint32_t *)ptr = cccam_hton32(CCCAM_MSG_ECM);
    ptr += 4;
    *(uint32_t *)ptr = cccam_hton32(total_len);
    ptr += 4;
    *ptr++ = 0;
    *ptr++ = (uint8_t)g_crypt_mode;
    *(uint16_t *)ptr = 0;
    ptr += 2;

    *(uint16_t *)ptr = cccam_hton16(caid);
    ptr += 2;
    *(uint16_t *)ptr = cccam_hton16(provid);
    ptr += 2;
    *(uint16_t *)ptr = cccam_hton16(sid);
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
    *(uint32_t *)ptr = cccam_hton32(CCCAM_MSG_CW);
    ptr += 4;
    *(uint32_t *)ptr = cccam_hton32(total_len);
    ptr += 4;
    *ptr++ = 0;
    *ptr++ = (uint8_t)g_crypt_mode;
    *(uint16_t *)ptr = 0;
    ptr += 2;

    *(uint32_t *)ptr = cccam_hton32(cw_msg->ecm_time);
    ptr += 4;
    memcpy(ptr, cw_msg->cw, 16);
    ptr += 16;
    *ptr++ = cw_msg->hop;
    *(uint16_t *)ptr = cccam_hton16(cw_msg->caid);
    ptr += 2;
    *(uint16_t *)ptr = cccam_hton16(cw_msg->provid);
    ptr += 2;
    *(uint16_t *)ptr = cccam_hton16(cw_msg->sid);

    if (g_crypt_mode != CCCAM_CRYPT_MODE_NONE) {
        size_t payload_len = total_len - CCCAM_HEADER_SIZE;
        if (cccam_protocol_encrypt(buffer + CCCAM_HEADER_SIZE, payload_len) != 0) {
            return -1;
        }
    }

    *buf_len = total_len;
    return 0;
}

// --- Funções de Encriptação ---

int cccam_protocol_set_crypto(uint8_t crypt_mode, const uint8_t *key, size_t key_len) {
    if (!key || key_len > sizeof(g_crypt_key)) {
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
