#include "cccam3_hop_control.h"
#include "cccam3_logger.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// --- Variáveis Globais ---
static uint8_t g_max_hops = CCCAM_DEFAULT_HOP_LIMIT;
static cccam_hop_entry_t *g_hop_entries = NULL;
static int g_hop_count = 0;
static int g_hop_total_checks = 0;
static int g_hop_blocked = 0;
static int g_hop_allowed = 0;

// --- Funções Auxiliares Internas ---

// Verifica se duas entradas são iguais
static int hop_match(cccam_hop_entry_t *entry, uint16_t caid, uint16_t provid, 
                     uint16_t sid, uint32_t client_id) {
    if (!entry) return 0;
    return (entry->caid == caid && entry->provid == provid && 
            entry->sid == sid && entry->client_id == client_id);
}

// Verifica se uma entrada expirou
static int hop_is_expired(cccam_hop_entry_t *entry) {
    if (!entry) return 1;
    time_t now = time(NULL);
    return (now - entry->timestamp) > CCCAM_HOP_TIMEOUT;
}

// --- Implementação das Funções ---

int cccam_hop_control_init(void) {
    g_max_hops = CCCAM_DEFAULT_HOP_LIMIT;
    g_hop_entries = NULL;
    g_hop_count = 0;
    g_hop_total_checks = 0;
    g_hop_blocked = 0;
    g_hop_allowed = 0;
    cccam_log(LOG_INFO, "CCshare: Hop Control inicializado (limite: %d hops)", g_max_hops);
    return 0;
}

void cccam_hop_control_cleanup(void) {
    cccam_hop_entry_t *current = g_hop_entries;
    while (current) {
        cccam_hop_entry_t *next = current->next;
        free(current);
        current = next;
    }
    g_hop_entries = NULL;
    g_hop_count = 0;
    cccam_log(LOG_INFO, "CCshare: Hop Control limpo");
}

int cccam_hop_control_check(uint16_t caid, uint16_t provid, uint16_t sid, 
                            uint8_t hop, uint32_t client_id) {
    g_hop_total_checks++;
    
    // Limpa entradas expiradas
    cccam_hop_control_clean_expired();
    
    // Verifica se o hop é válido
    if (!cccam_hop_control_is_valid(hop)) {
        g_hop_blocked++;
        cccam_log(LOG_DEBUG, "CCshare: Hop Control - BLOQUEADO (CAID %04X SID %04X hop %d > %d)", 
                  caid, sid, hop, g_max_hops);
        return 0; // Bloqueado
    }
    
    // Verifica se já existe um pedido recente para este canal (prevenção de loops)
    cccam_hop_entry_t *current = g_hop_entries;
    while (current) {
        if (hop_match(current, caid, provid, sid, client_id)) {
            // Verifica se o pedido anterior ainda é recente
            if (!hop_is_expired(current)) {
                // Mesmo cliente a pedir o mesmo canal muito rapidamente
                // Pode indicar loop ou ataque
                if (current->hop >= hop) {
                    // O hop não aumentou, pode ser loop
                    g_hop_blocked++;
                    cccam_log(LOG_WARN, "CCshare: Hop Control - LOOP DETECTADO (CAID %04X SID %04X cliente %u)", 
                              caid, sid, client_id);
                    return 0; // Bloqueado
                }
            }
        }
        current = current->next;
    }
    
    // Permite o pedido
    g_hop_allowed++;
    cccam_log(LOG_DEBUG, "CCshare: Hop Control - PERMITIDO (CAID %04X SID %04X hop %d)", 
              caid, sid, hop);
    return 1; // Permitido
}

int cccam_hop_control_register(uint16_t caid, uint16_t provid, uint16_t sid,
                               uint8_t hop, uint32_t client_id) {
    if (!cccam_hop_control_is_valid(hop)) {
        return -1;
    }
    
    // Limpa entradas expiradas
    cccam_hop_control_clean_expired();
    
    // Remove entradas antigas do mesmo cliente/canal
    cccam_hop_entry_t *current = g_hop_entries;
    cccam_hop_entry_t *prev = NULL;
    while (current) {
        if (hop_match(current, caid, provid, sid, client_id)) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_hop_entries = current->next;
            }
            free(current);
            g_hop_count--;
            break;
        }
        prev = current;
        current = current->next;
    }
    
    // Cria nova entrada
    cccam_hop_entry_t *entry = malloc(sizeof(cccam_hop_entry_t));
    if (!entry) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao alocar memória para hop entry");
        return -1;
    }
    
    entry->caid = caid;
    entry->provid = provid;
    entry->sid = sid;
    entry->hop = hop;
    entry->timestamp = time(NULL);
    entry->client_id = client_id;
    entry->blocked = 0;
    
    // Adiciona à lista
    entry->next = g_hop_entries;
    g_hop_entries = entry;
    g_hop_count++;
    
    return 0;
}

uint8_t cccam_hop_control_increment_hop(uint8_t current_hop) {
    uint8_t new_hop = current_hop + 1;
    if (new_hop > g_max_hops) {
        return g_max_hops;
    }
    return new_hop;
}

int cccam_hop_control_is_valid(uint8_t hop) {
    return (hop <= g_max_hops);
}

void cccam_hop_control_set_limit(uint8_t limit) {
    if (limit > 0 && limit <= 20) {
        g_max_hops = limit;
        cccam_log(LOG_INFO, "CCshare: Limite de hops definido para %d", g_max_hops);
    } else {
        cccam_log(LOG_WARN, "CCshare: Limite de hops inválido: %d (mantido %d)", limit, g_max_hops);
    }
}

uint8_t cccam_hop_control_get_limit(void) {
    return g_max_hops;
}

int cccam_hop_control_clean_expired(void) {
    cccam_hop_entry_t *current = g_hop_entries;
    cccam_hop_entry_t *prev = NULL;
    int removed = 0;
    time_t now = time(NULL);
    
    while (current) {
        if ((now - current->timestamp) > CCCAM_HOP_TIMEOUT) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_hop_entries = current->next;
            }
            free(current);
            g_hop_count--;
            removed++;
            current = prev ? prev->next : g_hop_entries;
        } else {
            prev = current;
            current = current->next;
        }
    }
    
    if (removed > 0) {
        cccam_log(LOG_DEBUG, "CCshare: Hop Control - %d entradas expiradas removidas", removed);
    }
    return removed;
}

void cccam_hop_control_debug_print(void) {
    cccam_hop_entry_t *current = g_hop_entries;
    int count = 0;
    
    cccam_log(LOG_INFO, "=== CCshare: Estado do Hop Control ===");
    cccam_log(LOG_INFO, "Limite de hops: %d", g_max_hops);
    cccam_log(LOG_INFO, "Entradas ativas: %d", g_hop_count);
    cccam_log(LOG_INFO, "Total verificações: %d", g_hop_total_checks);
    cccam_log(LOG_INFO, "Permitidos: %d, Bloqueados: %d", g_hop_allowed, g_hop_blocked);
    
    if (g_hop_count > 0) {
        cccam_log(LOG_INFO, "--- Entradas ---");
        while (current) {
            count++;
            cccam_log(LOG_DEBUG, "  [%d] CAID %04X SID %04X hop %d cliente %u expira em %lds", 
                      count, current->caid, current->sid, current->hop, 
                      current->client_id, 
                      (current->timestamp + CCCAM_HOP_TIMEOUT) - time(NULL));
            current = current->next;
        }
    }
    cccam_log(LOG_INFO, "=====================================");
}
