#ifndef CCCAM3_NEWCAMD_H
#define CCCAM3_NEWCAMD_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <stddef.h>

// --- Servidor Newcamd (protocolo real newcs/cs357x, NCD_524) ---

// Tamanho máximo de uma mensagem Newcamd
#define NCD_MAX_MSG 1024

// Comandos do protocolo Newcamd
#define NCD_MSG_LOGIN       0xE0
#define NCD_MSG_LOGIN_ACK   0xE1
#define NCD_MSG_LOGIN_NAK   0xE2
#define NCD_MSG_CARD_REQ    0xE3
#define NCD_MSG_CARD_DATA   0xE4
#define NCD_MSG_KEEPALIVE   0xFD
#define NCD_MSG_KEEPALIVE_ACK 0xFE

// --- Estado de sessão por cliente ---
typedef struct cccam_newcamd_session {
    int state;                  // 0 = à espera do login, 1 = autenticado
    uint8_t login_key[16];      // chave derivada da sequência de init + DES key
    uint8_t session_key[16];    // chave derivada da DES key + password
    uint8_t session_key_alt[16];// variante MD5-crypt (clientes OSCam)
    int key_mode;               // 0 = password, 1 = MD5-crypt
    uint16_t msg_id;            // último msgid recebido
    char username[64];
    uint32_t client_id;         // id do cliente (para o painel web)
    time_t last_keepalive;
} cccam_newcamd_session_t;

// Define a chave DES do servidor Newcamd (14 bytes, hex na config).
// Por omissão usa 01 02 ... 0E (o valor clássico).
void cccam_newcamd_set_des_key(const uint8_t *key14);

// Define o CAID servido pela porta Newcamd (0 = qualquer/EMU)
void cccam_newcamd_set_caid(uint16_t caid);

// Inicializa uma sessão e envia a sequência de init (14 bytes aleatórios).
int cccam_newcamd_session_start(int fd, cccam_newcamd_session_t *session);

// Liberta a sessão
void cccam_newcamd_session_reset(cccam_newcamd_session_t *session);

// Processa uma mensagem Newcamd completa (payload já lido; os 2 bytes de
// comprimento não são incluídos). Devolve 0 para continuar, -1 para encerrar.
int cccam_newcamd_process(int fd, cccam_newcamd_session_t *session,
                          uint8_t *raw, size_t raw_len);

#endif // CCCAM3_NEWCAMD_H
