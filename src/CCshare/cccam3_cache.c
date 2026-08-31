#include "cccam3_cache.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

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
    struct cache_entry *prev;
    struct cache_entry *next;
} cache_entry_t;

// --- Variáveis Globais da Cache ---
// Lista ordenada por utilização: g_cache_head é o mais recente,
// g_cache_tail é o menos recente (evicção LRU).
static cache_entry_t *g_cache_head = NULL;
static cache_entry_t *g_cache_tail = NULL;
static int g_cache_entries = 0;
static int g_cache_max_entries = CCCAM_CACHE_MAX_ENTRIES;
static int g_cache_timeout = CCCAM_CACHE_DEFAULT_TIMEOUT;
static int g_cache_hits = 0;
static int g_cache_misses = 0;
static int g_cache_enabled = 1;

// A cache é acedida por várias threads (loop principal, DVBAPI, DVB)
static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// --- Funções Auxiliares Internas ---

static int cache_match(cache_entry_t *entry, uint16_t caid, uint16_t provid, uint16_t sid) {
    if (!entry || !entry->valid) return 0;
    return (entry->caid == caid && entry->provid == provid && entry->sid == sid);
}

static void cache_unlink(cache_entry_t *entry) {
    if (entry->prev) entry->prev->next = entry->next;
    else g_cache_head = entry->next;
    if (entry->next) entry->next->prev = entry->prev;
    else g_cache_tail = entry->prev;
    entry->prev = NULL;
    entry->next = NULL;
}

// Move (ou coloca) a entrada no início da lista (mais recente)
static void cache_move_to_head(cache_entry_t *entry) {
    if (g_cache_head == entry) return;
    cache_unlink(entry);
    entry->next = g_cache_head;
    if (g_cache_head) g_cache_head->prev = entry;
    g_cache_head = entry;
    if (!g_cache_tail) g_cache_tail = entry;
}

// Remove e liberta a entrada menos recente (cauda)
static void cache_evict_lru(void) {
    if (!g_cache_tail) return;
    cache_entry_t *tail = g_cache_tail;
    cache_unlink(tail);
    free(tail);
    __atomic_sub_fetch(&g_cache_entries, 1, __ATOMIC_RELAXED);
}

static void cache_free_entry(cache_entry_t *entry) {
    cache_unlink(entry);
    free(entry);
    __atomic_sub_fetch(&g_cache_entries, 1, __ATOMIC_RELAXED);
}

// --- Implementação das Funções da API ---

int cccam_cache_init(void) {
    g_cache_head = NULL;
    g_cache_tail = NULL;
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
    g_cache_tail = NULL;
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

    pthread_mutex_lock(&g_cache_mutex);

    // Substitui a entrada existente para o mesmo canal
    cache_entry_t *current = g_cache_head;
    while (current) {
        if (cache_match(current, caid, provid, sid)) {
            memcpy(current->cw, cw, 16);
            current->hop = hop;
            current->timestamp = time(NULL);
            current->expires_at = expires_at > 0 ? expires_at : (time(NULL) + g_cache_timeout);
            current->valid = 1;
            cache_move_to_head(current);
            pthread_mutex_unlock(&g_cache_mutex);
            return 0;
        }
        current = current->next;
    }

    // Cache cheia: evicção LRU (entrada menos usada recentemente)
    while (__atomic_load_n(&g_cache_entries, __ATOMIC_RELAXED) >= g_cache_max_entries) {
        cache_evict_lru();
    }

    cache_entry_t *entry = malloc(sizeof(cache_entry_t));
    if (!entry) {
        pthread_mutex_unlock(&g_cache_mutex);
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
    entry->prev = NULL;
    entry->next = NULL;

    // Adiciona ao início da lista (mais recente)
    entry->next = g_cache_head;
    if (g_cache_head) g_cache_head->prev = entry;
    g_cache_head = entry;
    if (!g_cache_tail) g_cache_tail = entry;
    __atomic_add_fetch(&g_cache_entries, 1, __ATOMIC_RELAXED);

    pthread_mutex_unlock(&g_cache_mutex);

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
        __atomic_add_fetch(&g_cache_misses, 1, __ATOMIC_RELAXED);
        return 0;
    }

    pthread_mutex_lock(&g_cache_mutex);

    time_t now = time(NULL);
    cache_entry_t *current = g_cache_head;

    while (current) {
        if (cache_match(current, caid, provid, sid)) {
            if (now > current->expires_at) {
                cccam_log(LOG_DEBUG, "CCshare: Entrada expirada para CAID %04X SID %04X", caid, sid);
                cache_entry_t *expired = current;
                current = current->next;
                cache_free_entry(expired);
                __atomic_add_fetch(&g_cache_misses, 1, __ATOMIC_RELAXED);
                pthread_mutex_unlock(&g_cache_mutex);
                return 0;
            }
            
            memcpy(cw, current->cw, 16);
            *hop = current->hop;
            __atomic_add_fetch(&g_cache_hits, 1, __ATOMIC_RELAXED);
            
            // LRU: a entrada passa a ser a mais recente
            cache_move_to_head(current);
            
            cccam_log(LOG_DEBUG, "CCshare: HIT para CAID %04X SID %04X (hop %d)", caid, sid, *hop);
            pthread_mutex_unlock(&g_cache_mutex);
            return 1;
        }
        current = current->next;
    }

    __atomic_add_fetch(&g_cache_misses, 1, __ATOMIC_RELAXED);
    cccam_log(LOG_DEBUG, "CCshare: MISS para CAID %04X SID %04X", caid, sid);
    pthread_mutex_unlock(&g_cache_mutex);
    return 0;
}

int cccam_cache_remove(uint16_t caid, uint16_t provid, uint16_t sid) {
    pthread_mutex_lock(&g_cache_mutex);
    cache_entry_t *current = g_cache_head;

    while (current) {
        if (cache_match(current, caid, provid, sid)) {
            cache_entry_t *removed = current;
            current = current->next;
            cache_free_entry(removed);
            cccam_log(LOG_DEBUG, "CCshare: Removida entrada para CAID %04X SID %04X", caid, sid);
            pthread_mutex_unlock(&g_cache_mutex);
            return 1;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&g_cache_mutex);
    return 0;
}

int cccam_cache_clean_expired(void) {
    int removed = 0;
    time_t now = time(NULL);

    pthread_mutex_lock(&g_cache_mutex);

    cache_entry_t *current = g_cache_head;

    while (current) {
        cache_entry_t *next = current->next;
        if (now > current->expires_at) {
            cache_free_entry(current);
            removed++;
        }
        current = next;
    }

    pthread_mutex_unlock(&g_cache_mutex);

    if (removed > 0) {
        cccam_log(LOG_DEBUG, "CCshare: Removidas %d entradas expiradas", removed);
    }
    return removed;
}

void cccam_cache_get_stats(int *total_entries, int *hit_count, int *miss_count) {
    if (total_entries) *total_entries = __atomic_load_n(&g_cache_entries, __ATOMIC_RELAXED);
    if (hit_count) *hit_count = __atomic_load_n(&g_cache_hits, __ATOMIC_RELAXED);
    if (miss_count) *miss_count = __atomic_load_n(&g_cache_misses, __ATOMIC_RELAXED);
}

void cccam_cache_set_timeout(int timeout_seconds) {
    if (timeout_seconds > 0) {
        g_cache_timeout = timeout_seconds;
        cccam_log(LOG_INFO, "CCshare: Cache timeout definido para %d segundos", timeout_seconds);
    }
}

int cccam_cache_get_timeout(void) {
    return g_cache_timeout;
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
