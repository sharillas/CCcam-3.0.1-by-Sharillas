#ifndef CCCAM3_CC_LEGACY_H
#define CCCAM3_CC_LEGACY_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <stddef.h>

// --- Compatibilidade com clientes CCcam comerciais (2.0.11–2.1.4) ---
// Implementação do protocolo binário CCcam real, portado da referência
// GPLv3 OSCam (module-cccam.c): cc_init_crypt, cc_crypt, cc_xor, cc_cw_crypt.
//
// Fase 1: login clássico, framing encriptado, pedidos ECM e respostas CW
// (sem extended mode / sem chaCha - clientes 2.2.x+ não são suportados).

#define CCLEGACY_MAX_MSG 4096

typedef struct {
    uint8_t dec_table[256];
    uint8_t dec_state;
    int dec_counter;
    int dec_sum;
    uint8_t enc_table[256];
    uint8_t enc_state;
    int enc_counter;
    int enc_sum;
    uint8_t node_id[8];
    int logged_in;
    char username[64];
    uint8_t pending_ecm[256];
    uint16_t pending_ecm_len;
    uint16_t pending_caid;
    uint16_t pending_provid;
    uint16_t pending_sid;
    uint32_t pending_card_id;
    int has_pending;
} cclegacy_session_t;

// Processa uma ligação de cliente CCcam real (o socket está ligado e
// ainda não foi enviado nada). Bloqueia apenas com os timeouts do socket.
// Devolve 0 em sucesso, -1 em erro (o chamador fecha a ligação).
int cclegacy_serve(int fd, cccam_client_t *client, cclegacy_session_t *session);

#endif // CCCAM3_CC_LEGACY_H
