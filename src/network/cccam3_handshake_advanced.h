#ifndef CCCAM3_HANDSHAKE_ADVANCED_H
#define CCCAM3_HANDSHAKE_ADVANCED_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <stddef.h>

// --- Modos de Handshake ---
#define HANDSHAKE_MODE_LEGACY   0x00  // SHA1 + RC4-like (CCcam original)
#define HANDSHAKE_MODE_RC4      0x01  // RC4 com chave derivada
#define HANDSHAKE_MODE_AES      0x02  // AES-256 com chave derivada
#define HANDSHAKE_MODE_AES_GCM  0x03  // AES-GCM com chave derivada
#define HANDSHAKE_MODE_RSA_AES  0x04  // RSA + AES-GCM (troca de chaves)

// --- Funções do Handshake Avançado ---

// Inicializa o sistema de handshake
int cccam_handshake_advanced_init(void);

// Limpa o sistema de handshake
void cccam_handshake_advanced_cleanup(void);

// --- Handshake RSA (novo modo) ---

// Servidor: processa login com RSA
int cccam_handshake_rsa_server(cccam_login_msg_t *login, uint8_t *response_handshake, size_t response_size);

// Cliente: processa resposta do servidor RSA
int cccam_handshake_rsa_client(cccam_login_msg_t *login, const uint8_t *server_handshake);

// --- Handshake Legado (compatibilidade) ---

// Servidor: processa login com SHA1 (legado)
int cccam_handshake_legacy_server(cccam_login_msg_t *login, uint8_t *response_handshake, size_t response_size);

// Cliente: processa resposta do servidor SHA1 (legado)
int cccam_handshake_legacy_client(cccam_login_msg_t *login, const uint8_t *server_handshake);

// --- Funções de Negociação ---

// Negocia o modo de handshake com o cliente
uint8_t cccam_handshake_negotiate_mode(uint8_t client_mode);

// Obtém o modo de handshake atual
uint8_t cccam_handshake_get_mode(void);

// Obtém o tamanho da resposta de handshake para o modo atual
size_t cccam_handshake_get_response_len(void);

// Obtém a chave de sessão derivada no handshake
int cccam_handshake_get_session_key(uint8_t *key, size_t *key_len);

// --- Funções de Encriptação ---

// Encripta dados usando o modo atual
int cccam_handshake_encrypt(uint8_t *data, size_t *len, size_t capacity);

// Decripta dados usando o modo atual
int cccam_handshake_decrypt(uint8_t *data, size_t *len);

// --- Assinatura de CWs ---

// Assina uma Control Word com RSA
int cccam_handshake_sign_cw(uint8_t *cw, size_t cw_len, uint8_t *signature, size_t *sig_len);

// Verifica uma assinatura de CW
int cccam_handshake_verify_cw(uint8_t *cw, size_t cw_len, uint8_t *signature, size_t sig_len);

#endif // CCCAM3_HANDSHAKE_ADVANCED_H
