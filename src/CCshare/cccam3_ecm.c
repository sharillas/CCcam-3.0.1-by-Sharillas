#include "cccam3_ecm.h"
#include "cccam3_cache.h"
#include "cccam3_client.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// --- Variáveis Globais ---
static int g_ecm_total_requests = 0;
static int g_ecm_cache_hits = 0;
static int g_ecm_cache_misses = 0;
static int g_ecm_reader_success = 0;
static int g_ecm_reader_fail = 0;

// --- Funções Auxiliares Internas ---

// Converte CAID/SID para string legível (para logs)
static void ecm_log_info(uint16_t caid, uint16_t provid, uint16_t sid, char *buffer, size_t size) {
    snprintf(buffer, size, "CAID %04X:%04X SID %04X", caid, provid, sid);
}

// Verifica se o pedido ECM é válido
static int ecm_is_valid(cccam_ecm_request_t *request) {
    if (!request) return 0;
    if (request->ecm_len == 0 || request->ecm_len > CCCAM_ECM_MAX_SIZE) return 0;
    if (request->caid == 0) return 0;
    if (request->sid == 0) return 0;
    return 1;
}

// --- Implementação das Funções ---

int cccam_ecm_init(void) {
    g_ecm_total_requests = 0;
    g_ecm_cache_hits = 0;
    g_ecm_cache_misses = 0;
    g_ecm_reader_success = 0;
    g_ecm_reader_fail = 0;
    cccam_log(LOG_INFO, "CCshare: ECM handler inicializado");
    return 0;
}

void cccam_ecm_cleanup(void) {
    cccam_log(LOG_INFO, "CCshare: ECM handler limpo");
}

int cccam_ecm_process(cccam_ecm_request_t *request, cccam_ecm_response_t *response) {
    if (!request || !response) {
        cccam_log(LOG_ERROR, "CCshare: ECM process - ponteiros inválidos");
        return -1;
    }

    if (!ecm_is_valid(request)) {
        cccam_log(LOG_ERROR, "CCshare: ECM inválido (CAID %04X SID %04X len %d)", 
                  request->caid, request->sid, request->ecm_len);
        return -1;
    }

    g_ecm_total_requests++;
    
    char info[64];
    ecm_log_info(request->caid, request->provid, request->sid, info, sizeof(info));
    cccam_log(LOG_DEBUG, "CCshare: Processando ECM %s (hop %d)", info, request->hop);

    // Inicializa resposta
    memset(response, 0, sizeof(cccam_ecm_response_t));
    response->found = 0;
    response->caid = request->caid;
   
