#include "cccam3_cache.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// --- Estrutura Interna da Cache ---

typedef struct cache_entry {
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    uint8_t cw[16];
    uint8_t hop;
    time_t timestamp;
    time_t expires_at;
    int valid;
    struct cache_entry *next;
} cache_entry_t;

// --- Variáveis Globais da Cache ---

static cache_entry_t *g_cache_head = NULL;
static int g_cache_entries = 0;
static int g_cache_max_entries = CCCAM_CACHE_MAX_ENTRIES;
static int g_cache_timeout = CCCAM_CACHE_DEFAULT_TIMEOUT;
static int g_cache_hits = 0;
static int g_cache_misses = 0;
static int g_cache_enabled = 1;

// --- Funções Auxiliares Internas ---

// Compara se duas entradas são iguais (mesmo CAID/Provid/SID)
static int cache_match(cache_entry_t *entry, uint16_t caid, uint16_t provid, uint16_t sid) {
    if (!entry || !entry->valid) return 0;
    return (entry->caid == caid && entry->provid == provid && entry->sid == sid);
}

// --- Implementação das Funções da API ---

int cccam_cache_init(void) {
    g_cache_head = NULL;
    g_cache_entries = 0;
    g_cache_hits = 0;
    g_cache_misses = 0;
    g_cache_enabled = 1;
    cccam_log(LOG_INFO, "CCshare: Cache inicializada (máx: %d entradas, timeout: %d segundos)", 
              g_cache_max_entries, g_cache_timeout);
    return 0;
}

void cccam_cache_set_enabled(int enabled) {
    g_cache_enabled = enabled ? 1 : 0;
    cccam_log(LOG_INFO, "CCshare: Cache %s", g_cache_enabled ? "ativada" : "desativada");
}

void cccam_cache_cleanup(void) {
    cache_entry_t *current = g_cache_head;
    while (current) {
        cache_entry_t *next = current->next;
        free(current);
        current = next;
    }
    g_cache_head = NULL;
    g_cache_entries = 0;
    g_cache_hits = 0;
    g_cache_misses = 0;
    cccam_log(LOG_INFO, "CCshare: Cache limpa");
}

int cccam_cache_add(uint16_t caid, uint16_t provid, uint16_t sid, 
                    const uint8_t *cw, uint8_t hop, time_t expires_at) {
    if (!cw) {
        cccam_log(LOG_ERROR, "CCshare: Tentativa de adicionar CW nula à cache");
        return -1;
    }

    if (!g_cache_enabled) {
        return 0;
    }

    // Verifica se a cache já está cheia
    if (g_cache_entries >= g_cache_max_entries) {
        // Remove a entrada mais antiga (LRU - Least Recently Used)
        cache_entry_t *oldest = g_cache_head;
        cache_entry_t *prev = NULL;
        cache_entry_t *iter = g_cache_head;
        cache_entry_t *iter_prev = NULL;
        
        while (iter) {
            if (iter->timestamp < oldest->timestamp) {
                oldest = iter;
                prev = iter_prev;
            }
            iter_prev = iter;
            iter = iter->next;
        }
        
        if (oldest) {
            if (prev) {
                prev->next = oldest->next;
            } else {
                g_cache_head = oldest->next;
            }
            free(oldest);
            g_cache_entries--;
        }
    }

    // Cria nova entrada
    cache_entry_t *entry = malloc(sizeof(cache_entry_t));
    if (!entry) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao alocar memória para cache");
        return -1;
    }

    entry->caid = caid;
    entry->provid = provid;
    entry->sid = sid;
    memcpy(entry->cw, cw, 16);
    entry->hop = hop;
    entry->timestamp = time(NULL);
    entry->expires_at = expires_at > 0 ? expires_at : (time(NULL) + g_cache_timeout);
    entry->valid = 1;
    
    // Adiciona ao início da lista (mais recente)
    entry->next = g_cache_head;
    g_cache_head = entry;
    g_cache_entries++;

    cccam_log(LOG_DEBUG, "CCshare: Adicionada CW para CAID %04X SID %04X (hop %d, expira em %lds)", 
              caid, sid, hop, entry->expires_at - time(NULL));
    
    return 0;
}

int cccam_cache_find(uint16_t caid, uint16_t provid, uint16_t sid, 
                     uint8_t *cw, uint8_t *hop) {
    if (!cw || !hop) {
        return -1;
    }

    if (!g_cache_enabled) {
        g_cache_misses++;
        return 0;
    }

    time_t now = time(NULL);
    cache_entry_t *current = g_cache_head;
    cache_entry_t *prev = NULL;

    while (current) {
        if (cache_match(current, caid, provid, sid)) {
            // Verifica se a entrada expirou
            if (now > current->expires_at) {
                cccam_log(LOG_DEBUG, "CCshare: Entrada expirada para CAID %04X SID %04X", caid, sid);
                // Remove a entrada expirada
                if (prev) {
                    prev->next = current->next;
                } else {
                    g_cache_head = current->next;
                }
                free(current);
                g_cache_entries--;
                g_cache_misses++;
                return 0; // Não encontrou (expirada)
            }
            
            // Encontrou! Copia a CW e o hop
            memcpy(cw, current->cw, 16);
            *hop = current->hop;
            g_cache_hits++;
            
            cccam_log(LOG_DEBUG, "CCshare: HIT para CAID %04X SID %04X (hop %d)", caid, sid, *hop);
            return 1; // Encontrou
        }
        prev = current;
        current = current->next;
    }

    // Não encontrou
    g_cache_misses++;
    cccam_log(LOG_DEBUG, "CCshare: MISS para CAID %04X SID %04X", caid, sid);
    return 0;
}

int cccam_cache_remove(uint16_t caid, uint16_t provid, uint16_t sid) {
    cache_entry_t *current = g_cache_head;
    cache_entry_t *prev = NULL;
    int removed = 0;

    while (current) {
        if (cache_match(current, caid, provid, sid)) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_cache_head = current->next;
            }
            free(current);
            g_cache_entries--;
            removed++;
            cccam_log(LOG_DEBUG, "CCshare: Removida entrada para CAID %04X SID %04X", caid, sid);
            break;
        }
        prev = current;
        current = current->next;
    }

    return removed;
}

int cccam_cache_clean_expired(void) {
    cache_entry_t *current = g_cache_head;
    cache_entry_t *prev = NULL;
    int removed = 0;
    time_t now = time(NULL);

    while (current) {
        cache_entry_t *next = current->next;
        if (now > current->expires_at) {
            if (prev) {
                prev->next = next;
            } else {
                g_cache_head = next;
            }
            free(current);
            g_cache_entries--;
            removed++;
        } else {
            prev = current;
        }
        current = next;
    }

    if (removed > 0) {
        cccam_log(LOG_DEBUG, "CCshare: Removidas %d entradas expiradas", removed);
    }
    return removed;
}

void cccam_cache_get_stats(int *total_entries, int *hit_count, int *miss_count) {
    if (total_entries) *total_entries = g_cache_entries;
    if (hit_count) *hit_count = g_cache_hits;
    if (miss_count) *miss_count = g_cache_misses;
}

void cccam_cache_set_timeout(int timeout_seconds) {
    if (timeout_seconds > 0) {
        g_cache_timeout = timeout_seconds;
        cccam_log(LOG_INFO, "CCshare: Cache timeout definido para %d segundos", timeout_seconds);
    }
}

void cccam_cache_debug_print(void) {
    cache_entry_t *current = g_cache_head;
    int count = 0;
    
    cccam_log(LOG_INFO, "=== CCshare: Estado da Cache ===");
    cccam_log(LOG_INFO, "Entradas: %d/%d", g_cache_entries, g_cache_max_entries);
    cccam_log(LOG_INFO, "Hits: %d, Misses: %d (Ratio: %.2f%%)", 
              g_cache_hits, g_cache_misses,
              (g_cache_hits + g_cache_misses) > 0 ? 
              (float)g_cache_hits / (g_cache_hits + g_cache_misses) * 100 : 0);
    
    while (current) {
        count++;
        char cw_hex[33];
        for (int i = 0; i < 16; i++) {
            sprintf(cw_hex + (i * 2), "%02x", current->cw[i]);
        }
        cccam_log(LOG_DEBUG, "  [%d] CAID %04X SID %04X CW %s hop %d expira em %lds", 
                  count, current->caid, current->sid, cw_hex, 
                  current->hop, current->expires_at - time(NULL));
        current = current->next;
    }
    cccam_log(LOG_INFO, "=================================");
}
