#include "cccam3_ecm.h"
#include "cccam3_cache.h"
#include "cccam3_client.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include "cccam3_card_manager.h"
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
    response->provid = request->provid;
    response->sid = request->sid;
    response->hop = request->hop;
    response->generated_at = time(NULL);

    // --- PASSO 1: Verificar na Cache ---
    uint8_t hop_out;
    if (cccam_cache_find(request->caid, request->provid, request->sid, 
                         response->cw, &hop_out) == 1) {
        response->found = 1;
        response->hop = hop_out;
        g_ecm_cache_hits++;
        cccam_log(LOG_DEBUG, "CCshare: ECM %s - CACHE HIT (hop %d)", info, hop_out);
        return 0; // Sucesso, CW encontrada na cache
    }
    g_ecm_cache_misses++;

    // --- PASSO 2: Pedir ao Card Manager ---
    uint8_t cw[CCCAM_CW_SIZE];
    uint8_t hop_reader;
    uint32_t reader_id;
    
    int reader_result = cccam_card_manager_get_cw(
        request->caid, request->provid, request->sid,
        request->ecm_data, request->ecm_len,
        cw, &hop_reader, &reader_id
    );

    if (reader_result == 0) {
        // Sucesso! CW obtida do leitor
        memcpy(response->cw, cw, CCCAM_CW_SIZE);
        response->found = 1;
        response->hop = hop_reader;
        g_ecm_reader_success++;
        
        // Guarda na cache para futuras utilizações
        time_t expires_at = time(NULL) + 60; // 60 segundos de validade
        cccam_cache_add(request->caid, request->provid, request->sid, 
                        cw, hop_reader, expires_at);
        
        cccam_log(LOG_DEBUG, "CCshare: ECM %s - READER SUCCESS (hop %d, reader %u)", 
                  info, hop_reader, reader_id);
        return 0;
    } else {
        // Falha ao obter CW do leitor
        g_ecm_reader_fail++;
        response->found = 0;
        cccam_log(LOG_WARN, "CCshare: ECM %s - READER FAIL (código %d)", info, reader_result);
        return -1; // Falha
    }
}

// --- Função para obter CW do leitor (agora usa o Card Manager) ---
int cccam_ecm_get_cw_from_reader(uint16_t caid, uint16_t provid, uint16_t sid,
                                  const uint8_t *ecm_data, uint16_t ecm_len,
                                  uint8_t *cw, uint8_t *hop) {
    if (!cw || !hop) {
        return -1;
    }
    
    // Usa o Card Manager para obter a CW
    uint32_t reader_id;
    int result = cccam_card_manager_get_cw(caid, provid, sid, ecm_data, ecm_len, 
                                            cw, hop, &reader_id);
    return result;
}

// --- Função para enviar CW ao cliente ---
int cccam_ecm_send_cw(int client_fd, const cccam_ecm_response_t *response) {
    if (!response || client_fd < 0) {
        cccam_log(LOG_ERROR, "CCshare: send_cw - parâmetros inválidos");
        return -1;
    }

    if (!response->found) {
        cccam_log(LOG_WARN, "CCshare: Tentativa de enviar CW não encontrada para CAID %04X", 
                  response->caid);
        return -1;
    }

    // Constrói a mensagem CW
    uint8_t buffer[1024];
    size_t buf_len = sizeof(buffer);
    
    cccam_cw_msg_t cw_msg;
    cw_msg.ecm_time = (uint32_t)response->generated_at;
    memcpy(cw_msg.cw, response->cw, 16);
    cw_msg.hop = response->hop;
    cw_msg.caid = response->caid;
    cw_msg.provid = response->provid;
    cw_msg.sid = response->sid;
    
    if (cccam_protocol_build_cw(buffer, &buf_len, &cw_msg) != 0) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao construir mensagem CW para CAID %04X", 
                  response->caid);
        return -1;
    }
    
    // Envia para o cliente
    ssize_t sent = write(client_fd, buffer, buf_len);
    if (sent != (ssize_t)buf_len) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao enviar CW para cliente (enviado %zd de %zu)", 
                  sent, buf_len);
        return -1;
    }
    
    char cw_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(cw_hex + (i * 2), "%02x", response->cw[i]);
    }
    cccam_log(LOG_DEBUG, "CCshare: CW enviada para CAID %04X SID %04X: %s (hop %d)", 
              response->caid, response->sid, cw_hex, response->hop);
    
    return 0;
}

// --- Estatísticas ---
void cccam_ecm_get_stats(int *total_requests, int *cache_hits, int *cache_misses, 
                         int *reader_success, int *reader_fail) {
    if (total_requests) *total_requests = g_ecm_total_requests;
    if (cache_hits) *cache_hits = g_ecm_cache_hits;
    if (cache_misses) *cache_misses = g_ecm_cache_misses;
    if (reader_success) *reader_success = g_ecm_reader_success;
    if (reader_fail) *reader_fail = g_ecm_reader_fail;
}

void cccam_ecm_debug_print(void) {
    cccam_log(LOG_INFO, "=== CCshare: Estatísticas ECM ===");
    cccam_log(LOG_INFO, "Total pedidos: %d", g_ecm_total_requests);
    cccam_log(LOG_INFO, "Cache Hits: %d (%.1f%%)", g_ecm_cache_hits,
              g_ecm_total_requests > 0 ? 
              (float)g_ecm_cache_hits / g_ecm_total_requests * 100 : 0);
    cccam_log(LOG_INFO, "Cache Misses: %d (%.1f%%)", g_ecm_cache_misses,
              g_ecm_total_requests > 0 ? 
              (float)g_ecm_cache_misses / g_ecm_total_requests * 100 : 0);
    cccam_log(LOG_INFO, "Leitor Sucesso: %d", g_ecm_reader_success);
    cccam_log(LOG_INFO, "Leitor Falhas: %d", g_ecm_reader_fail);
    cccam_log(LOG_INFO, "=================================");
}
