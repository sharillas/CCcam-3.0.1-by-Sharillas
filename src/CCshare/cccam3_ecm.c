#include "cccam3_ecm.h"
#include "cccam3_cache.h"
#include "cccam3_client.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include "cccam3_card_manager.h"
#include "cccam3_hop_control.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

// --- Variáveis Globais ---
static int g_ecm_total_requests = 0;
static int g_ecm_cache_hits = 0;
static int g_ecm_cache_misses = 0;
static int g_ecm_reader_success = 0;
static int g_ecm_reader_fail = 0;

// Protege os subsistemas partilhados entre as threads que processam ECMs
// (loop principal, DVBAPI por ligação, leitor DVB).
// ORDEM DE LOCKS: nunca adquirir outro mutex (ex.: handshake) com o
// g_ecm_mutex em espera inversa — a ordem estabelecida é ecm -> handshake.
static pthread_mutex_t g_ecm_mutex = PTHREAD_MUTEX_INITIALIZER;

void cccam_ecm_lock(void) {
    pthread_mutex_lock(&g_ecm_mutex);
}

void cccam_ecm_unlock(void) {
    pthread_mutex_unlock(&g_ecm_mutex);
}

int cccam_ecm_clean_expired_cache(void) {
    int removed;
    cccam_ecm_lock();
    removed = cccam_cache_clean_expired();
    cccam_ecm_unlock();
    return removed;
}

// --- Funções Auxiliares Internas ---

// Converte CAID/SID para string legível (para logs)
static void ecm_log_info(uint16_t caid, uint16_t provid, uint16_t sid, char *buffer, size_t size) {
    snprintf(buffer, size, "CAID %04X:%04X SID %04X", caid, provid, sid);
}

// Verifica se o pedido ECM é válido
static int ecm_is_valid(cccam_ecm_request_t *request) {
    if (!request) return 0;
    if (request->ecm_len == 0 || request->ecm_len > CCCAM_ECM_MAX_SIZE) return 0;
    if (request->caid == 0 && request->sid == 0) return 0;
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

    // Serializa o acesso à cache, aos leitores e ao controlo de hops
    cccam_ecm_lock();

    __atomic_add_fetch(&g_ecm_total_requests, 1, __ATOMIC_RELAXED);
    
    char info[64];
    ecm_log_info(request->caid, request->provid, request->sid, info, sizeof(info));
    cccam_log(LOG_DEBUG, "CCshare: Processando ECM %s (hop máximo do cliente: %d)", info, request->hop);

    // Inicializa resposta
    memset(response, 0, sizeof(cccam_ecm_response_t));
    response->found = 0;
    response->caid = request->caid;
    response->provid = request->provid;
    response->sid = request->sid;
    response->generated_at = time(NULL);

    // --- PASSO 1: Verificar na Cache ---
    uint8_t source_hop = 0;
    if (cccam_cache_find(request->caid, request->provid, request->sid, 
                         response->cw, &source_hop) == 1) {
        // O hop que o cliente recebe é o hop da origem + 1
        uint8_t served_hop = cccam_hop_control_increment_hop(source_hop);
        if (!cccam_hop_control_check(request->caid, request->provid, request->sid,
                                     served_hop, request->client_id) ||
            (request->hop != 0 && served_hop > request->hop)) {
            cccam_log(LOG_WARN, "CCshare: ECM %s - HOP BLOQUEADO (servir hop %d, limite do cliente %d)",
                      info, served_hop, request->hop);
            response->found = 0;
            cccam_ecm_unlock();
            return -1;
        }
        response->found = 1;
        response->hop = served_hop;
        __atomic_add_fetch(&g_ecm_cache_hits, 1, __ATOMIC_RELAXED);
        cccam_log(LOG_DEBUG, "CCshare: ECM %s - CACHE HIT (hop %d)", info, served_hop);
        cccam_ecm_unlock();
        return 0;
    }
    __atomic_add_fetch(&g_ecm_cache_misses, 1, __ATOMIC_RELAXED);

    // --- PASSO 2: Pedir ao Card Manager ---
    uint8_t cw[CCCAM_CW_SIZE];
    uint32_t reader_id;
    
    int reader_result = cccam_card_manager_get_cw(
        request->caid, request->provid, request->sid,
        request->ecm_data, request->ecm_len,
        cw, &source_hop, &reader_id
    );

    if (reader_result == 0) {
        uint8_t served_hop = cccam_hop_control_increment_hop(source_hop);
        if (!cccam_hop_control_check(request->caid, request->provid, request->sid,
                                     served_hop, request->client_id) ||
            (request->hop != 0 && served_hop > request->hop)) {
            cccam_log(LOG_WARN, "CCshare: ECM %s - HOP BLOQUEADO (servir hop %d, limite do cliente %d)",
                      info, served_hop, request->hop);
            response->found = 0;
            cccam_ecm_unlock();
            return -1;
        }

        memcpy(response->cw, cw, CCCAM_CW_SIZE);
        response->found = 1;
        response->hop = served_hop;
        __atomic_add_fetch(&g_ecm_reader_success, 1, __ATOMIC_RELAXED);
        
        // Guarda na cache com o hop da origem (0 = usar timeout configurado)
        cccam_cache_add(request->caid, request->provid, request->sid, 
                        cw, source_hop, 0);
        
        cccam_log(LOG_DEBUG, "CCshare: ECM %s - READER SUCCESS (hop %d, reader %u)", 
                  info, served_hop, reader_id);
        cccam_ecm_unlock();
        return 0;
    }

    // Falha ao obter CW do leitor
    __atomic_add_fetch(&g_ecm_reader_fail, 1, __ATOMIC_RELAXED);
    response->found = 0;
    cccam_log(LOG_WARN, "CCshare: ECM %s - READER FAIL (código %d)", info, reader_result);
    cccam_ecm_unlock();
    return -1;
}

// --- Função para enviar CW ao cliente ---
int cccam_ecm_send_cw(int client_fd, const cccam_crypto_ctx_t *crypto,
                      const cccam_ecm_response_t *response) {
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
    
    if (cccam_protocol_build_cw(buffer, &buf_len, &cw_msg, crypto) != 0) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao construir mensagem CW para CAID %04X", 
                  response->caid);
        return -1;
    }
    
    // Envia para o cliente (trata escritas parciais)
    size_t sent_total = 0;
    while (sent_total < buf_len) {
        ssize_t sent = write(client_fd, buffer + sent_total, buf_len - sent_total);
        if (sent < 0) {
            if (errno == EINTR) continue;
            cccam_log(LOG_ERROR, "CCshare: Falha ao enviar CW para cliente (%s)", strerror(errno));
            return -1;
        }
        sent_total += (size_t)sent;
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
    // Lidos pela API REST noutra thread: cargas atómicas
    if (total_requests) *total_requests = __atomic_load_n(&g_ecm_total_requests, __ATOMIC_RELAXED);
    if (cache_hits) *cache_hits = __atomic_load_n(&g_ecm_cache_hits, __ATOMIC_RELAXED);
    if (cache_misses) *cache_misses = __atomic_load_n(&g_ecm_cache_misses, __ATOMIC_RELAXED);
    if (reader_success) *reader_success = __atomic_load_n(&g_ecm_reader_success, __ATOMIC_RELAXED);
    if (reader_fail) *reader_fail = __atomic_load_n(&g_ecm_reader_fail, __ATOMIC_RELAXED);
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
