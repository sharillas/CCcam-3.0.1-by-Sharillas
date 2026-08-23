#ifndef CCCAM3_PROTOCOL_NEWCAMD_H
#define CCCAM3_PROTOCOL_NEWCAMD_H

#include <stdint.h>
#include <stddef.h>

// --- Comandos Newcamd ---
#define NEWCAMD_CMD_LOGIN       0x01
#define NEWCAMD_CMD_LOGIN_ACK   0x02
#define NEWCAMD_CMD_ECM         0x03
#define NEWCAMD_CMD_CW          0x04
#define NEWCAMD_CMD_KEEPALIVE   0x06

// --- Funções ---
int cccam_newcamd_parse(const uint8_t *buffer, size_t buf_len, 
                        uint32_t *cmd_id, uint8_t **payload, size_t *payload_len);

int cccam_newcamd_build(uint8_t *buffer, size_t *buf_len, 
                        uint32_t cmd_id, const uint8_t *payload, size_t payload_len);

int cccam_newcamd_handle_login(const char *username, const char *password, 
                               uint8_t *response, size_t *response_len);

#endif // CCCAM3_PROTOCOL_NEWCAMD_H
