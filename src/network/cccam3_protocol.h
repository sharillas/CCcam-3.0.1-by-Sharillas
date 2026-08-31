#ifndef CCCAM3_PROTOCOL_H
#define CCCAM3_PROTOCOL_H

#include "cccam3.h"
#include <stddef.h>

// --- Inicialização ---
int cccam_protocol_init(void);
void cccam_protocol_cleanup(void);
void cccam_protocol_set_allowed_modes(uint32_t bitmask);

// --- Criptografia por sessão ---
// Inicializa um contexto de criptografia. Valida o modo e o tamanho da chave.
// Modos suportados: NONE, RC4, AES, 3DES, AES_GCM.
int cccam_protocol_set_crypto(cccam_crypto_ctx_t *crypto, uint8_t crypt_mode,
                              const uint8_t *key, size_t key_len);

// Repõe um contexto de criptografia para o estado inicial (sem cifra)
void cccam_protocol_reset_crypto(cccam_crypto_ctx_t *crypto);

// Encripta dados in-place. Para AES-GCM acrescenta um tag de 16 bytes no fim
// (*len passa a incluir o tag; capacity deve ser >= *len + 16).
int cccam_protocol_encrypt(cccam_crypto_ctx_t *crypto, uint8_t *data, size_t *len,
                           size_t capacity, uint32_t msg_id);

// Decripta dados in-place. Para AES-GCM os últimos 16 bytes são o tag
// (*len passa a excluir o tag). Falha se a autenticação não for válida.
int cccam_protocol_decrypt(cccam_crypto_ctx_t *crypto, uint8_t *data, size_t *len,
                           uint32_t msg_id);

// --- Parsing ---
int cccam_protocol_parse(const uint8_t *buffer, size_t buf_len,
                         cccam_msg_header_t *header, void **payload,
                         size_t *payload_len, const cccam_crypto_ctx_t *crypto);

// --- Construção de mensagens ---
int cccam_protocol_build_login(uint8_t *buffer, size_t *buf_len,
                               const char *username, const char *password,
                               uint32_t version, const uint8_t *handshake);

// O LOGIN_ACK viaja sempre em claro (o conteúdo do handshake já é protegido
// pelo próprio handshake: tag GCM no modo RSA_AES).
int cccam_protocol_build_login_ack(uint8_t *buffer, size_t *buf_len,
                                   const uint8_t *handshake, size_t handshake_len);

int cccam_protocol_build_ecm(uint8_t *buffer, size_t *buf_len,
                             uint16_t caid, uint16_t provid, uint16_t sid,
                             const uint8_t *ecm_data, uint16_t ecm_len,
                             const cccam_crypto_ctx_t *crypto);

// Mensagem EMM (payload: caid 2 + provid 2 + dados EMM)
int cccam_protocol_build_emm(uint8_t *buffer, size_t *buf_len,
                             uint16_t caid, uint16_t provid,
                             const uint8_t *emm_data, uint16_t emm_len,
                             const cccam_crypto_ctx_t *crypto);

int cccam_protocol_build_cw(uint8_t *buffer, size_t *buf_len,
                            const cccam_cw_msg_t *cw_msg,
                            const cccam_crypto_ctx_t *crypto);

// --- Handshake (implementado em cccam3_handshake.c) ---
int cccam_protocol_handle_login(cccam_login_msg_t *login, uint8_t *response_handshake, size_t response_size);
int cccam_protocol_handle_login_response(cccam_login_msg_t *login, const uint8_t *server_handshake, size_t handshake_len);

#endif // CCCAM3_PROTOCOL_H
