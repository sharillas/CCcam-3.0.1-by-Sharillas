#include "cccam3_protocol_newcamd.h"
#include "cccam3_logger.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define NEWCAMD_HEADER_SIZE 8
#define NEWCAMD_MAX_BUFFER 4096

int cccam_newcamd_parse(const uint8_t *buffer, size_t buf_len, 
                        uint32_t *cmd_id, uint8_t **payload, size_t *payload_len) {
    if (!buffer || !cmd_id || !payload || !payload_len || buf_len < NEWCAMD_HEADER_SIZE) {
        return -1;
    }

    *cmd_id = ntohl(*(uint32_t *)buffer);
    *payload_len = ntohl(*(uint32_t *)(buffer + 4));
    
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
    if (*buf_len < total_len) return -1;

    uint32_t net_cmd = htonl(cmd_id);
    uint32_t net_len = htonl(payload_len);
    memcpy(buffer, &net_cmd, 4);
    memcpy(buffer + 4, &net_len, 4);
    
    if (payload && payload_len > 0) {
        memcpy(buffer + NEWCAMD_HEADER_SIZE, payload, payload_len);
    }

    *buf_len = total_len;
    return 0;
}

int cccam_newcamd_handle_login(const char *username, const char *password, 
                               uint8_t *response, size_t *response_len) {
    cccam_log(LOG_INFO, "Newcamd: Login do utilizador %s", username);
    // TODO: Implementar autenticação Newcamd
    return 0;
}
