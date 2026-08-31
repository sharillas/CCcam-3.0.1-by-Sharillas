#ifndef CCCAM3_ECM_H
#define CCCAM3_ECM_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <time.h>

// --- Constantes ---
#define CCCAM_ECM_MAX_SIZE 256
#define CCCAM_CW_SIZE 16

// --- Estruturas ---
typedef struct {
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    uint8_t ecm_data[CCCAM_ECM_MAX_SIZE];
    uint16_t ecm_len;
    time_t received_at;
    uint32_t client_id;
    uint8_t hop;
} cccam_ecm_request_t;

typedef struct {
    uint8_t cw[CCCAM_CW_SIZE];
    uint8_t hop;
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    time_t generated_at;
    int found;  // 1 se encontrou CW, 0 se não
} cccam_ecm_response_t;

// --- Funções ---

// Inicializa o sistema de ECM
int cccam_ecm_init(void);

// Limpa o sistema de ECM
void cccam_ecm_cleanup(void);

// Processa um pedido ECM
int cccam_ecm_process(cccam_ecm_request_t *request, cccam_ecm_response_t *response);

// --- Sincronização ---
// O processamento de ECM pode correr em várias threads (loop principal,
// DVBAPI por ligação, leitor DVB). Estas funções protegem os subsistemas
// partilhados (cache, card manager, hop control).

// Adquire o mutex de processamento de ECM
void cccam_ecm_lock(void);

// Liberta o mutex de processamento de ECM
void cccam_ecm_unlock(void);

// Limpa entradas expiradas da cache (com o mutex de ECM adquirido)
int cccam_ecm_clean_expired_cache(void);

// Reencaminha um EMM para os leitores remotos compatíveis (com o mutex
// de ECM adquirido). Usado pelas fontes de EMM (clientes, DVBAPI, Newcamd,
// leitor DVB interno).
int cccam_ecm_forward_emm(uint16_t caid, uint16_t provid,
                          const uint8_t *emm_data, uint16_t emm_len);

// Envia CW para o cliente (usa o contexto de criptografia da sessão)
int cccam_ecm_send_cw(int client_fd, const cccam_crypto_ctx_t *crypto,
                      const cccam_ecm_response_t *response);

// Estatísticas de ECM
void cccam_ecm_get_stats(int *total_requests, int *cache_hits, int *cache_misses, 
                         int *reader_success, int *reader_fail);

// Debug - imprime estatísticas
void cccam_ecm_debug_print(void);

#endif // CCCAM3_ECM_H
