#include "cccam3_protocol_newcamd.h"
#include "cccam3_logger.h"
#include "cccam3_user_manager.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define NEWCAMD_HEADER_SIZE 8
#define NEWCAMD_MAX_BUFFER 4096

static uint32_t read_be32(const uint8_t *ptr) {
    uint32_t net;
    memcpy(&net, ptr, 4);
    return ntohl(net);
}

static void write_be32(uint8_t *ptr, uint32_t val) {
    uint32_t net = htonl(val);
    memcpy(ptr, &net, 4);
}

int cccam_newcamd_parse(const uint8_t *buffer, size_t buf_len, 
                        uint32_t *cmd_id, uint8_t **payload, size_t *payload_len) {
    if (!buffer || !cmd_id || !payload || !payload_len || buf_len < NEWCAMD_HEADER_SIZE) {
        return -1;
    }

    *cmd_id = read_be32(buffer);
    *payload_len = read_be32(buffer + 4);
    
    if (*payload_len > NEWCAMD_MAX_BUFFER || buf_len < NEWCAMD_HEADER_SIZE + *payload_len) {
        cccam_log(LOG_ERROR, "Newcamd: Tamanho de payload inválido");
        return -1;
    }

    if (*payload_len > 0) {
        *payload = malloc(*payload_len);
        if (!*payload) return -1;
        memcpy(*payload, buffer + NEWCAMD_HEADER_SIZE, *payload_len);
    } else {
        *payload = NULL;
    }

    return 0;
}

int cccam_newcamd_build(uint8_t *buffer, size_t *buf_len, 
                        uint32_t cmd_id, const uint8_t *payload, size_t payload_len) {
    if (!buffer || !buf_len) return -1;

    size_t total_len = NEWCAMD_HEADER_SIZE + payload_len;
    if (*buf_len < total_len || total_len > NEWCAMD_MAX_BUFFER) return -1;

    write_be32(buffer, cmd_id);
    write_be32(buffer + 4, (uint32_t)payload_len);
    
    if (payload && payload_len > 0) {
        memcpy(buffer + NEWCAMD_HEADER_SIZE, payload, payload_len);
    }

    *buf_len = total_len;
    return 0;
}

int cccam_newcamd_handle_login(const char *username, const char *password, 
                               uint8_t *response, size_t *response_len) {
    if (!username || !password || !response || !response_len) {
        return -1;
    }

    cccam_log(LOG_INFO, "Newcamd: Login do utilizador %s", username);

    cccam_user_t *user = NULL;
    if (cccam_user_manager_authenticate(username, password, &user) != 0) {
        cccam_log(LOG_WARN, "Newcamd: Autenticação falhada para %s", username);
        return -1;
    }

    const char *ok = "OK";
    size_t ok_len = strlen(ok);
    if (*response_len < ok_len) {
        return -1;
    }
    memcpy(response, ok, ok_len);
    *response_len = ok_len;

    cccam_log(LOG_DEBUG, "Newcamd: Utilizador %s autenticado (nível %d)", username, user->level);
    return 0;
}
