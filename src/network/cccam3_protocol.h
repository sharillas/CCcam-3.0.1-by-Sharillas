#ifndef CCCAM3_PROTOCOL_H
#define CCCAM3_PROTOCOL_H

#include "cccam3.h"
#include <stddef.h>

int cccam_protocol_init(void);
void cccam_protocol_cleanup(void);

int cccam_protocol_parse(const uint8_t *buffer, size_t buf_len,
                         cccam_msg_header_t *header, void **payload,
                         size_t *payload_len);

int cccam_protocol_build_login(uint8_t *buffer, size_t *buf_len,
                               const char *username, const char *password,
                               uint32_t version, const uint8_t *handshake);

int cccam_protocol_build_login_ack(uint8_t *buffer, size_t *buf_len,
                                   const uint8_t *handshake, size_t handshake_len);

int cccam_protocol_build_ecm(uint8_t *buffer, size_t *buf_len,
                             uint16_t caid, uint16_t provid, uint16_t sid,
                             const uint8_t *ecm_data, uint16_t ecm_len);

int cccam_protocol_build_cw(uint8_t *buffer, size_t *buf_len,
                            const cccam_cw_msg_t *cw_msg);

int cccam_protocol_set_crypto(uint8_t crypt_mode, const uint8_t *key, size_t key_len);
void cccam_protocol_set_allowed_modes(uint32_t bitmask);
int cccam_protocol_encrypt(uint8_t *data, size_t len);
int cccam_protocol_decrypt(uint8_t *data, size_t len);

int cccam_protocol_handle_login(cccam_login_msg_t *login, uint8_t *response_handshake, size_t response_size);
int cccam_protocol_handle_login_response(cccam_login_msg_t *login, const uint8_t *server_handshake);

#endif // CCCAM3_PROTOCOL_H
