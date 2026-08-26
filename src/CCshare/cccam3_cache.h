#ifndef CCCAM3_CACHE_H
#define CCCAM3_CACHE_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <time.h>

// --- Constantes da Cache ---
#define CCCAM_CACHE_MAX_ENTRIES 1024
#define CCCAM_CACHE_DEFAULT_TIMEOUT 10  // segundos

// --- Funções da Cache ---

// Inicializa o sistema de cache
int cccam_cache_init(void);

// Limpa toda a cache
void cccam_cache_cleanup(void);

// Adiciona uma CW à cache
int cccam_cache_add(uint16_t caid, uint16_t provid, uint16_t sid, 
                    const uint8_t *cw, uint8_t hop, time_t expires_at);

// Procura uma CW na cache
int cccam_cache_find(uint16_t caid, uint16_t provid, uint16_t sid, 
                     uint8_t *cw, uint8_t *hop);

// Remove uma entrada da cache
int cccam_cache_remove(uint16_t caid, uint16_t provid, uint16_t sid);

// Limpa entradas expiradas
int cccam_cache_clean_expired(void);

// Obtém estatísticas da cache
void cccam_cache_get_stats(int *total_entries, int *hit_count, int *miss_count);

// Define o timeout global da cache
void cccam_cache_set_timeout(int timeout_seconds);

// Obtém o timeout global da cache (segundos)
int cccam_cache_get_timeout(void);

// Ativa/desativa a cache
void cccam_cache_set_enabled(int enabled);

// Debug - imprime estado da cache
void cccam_cache_debug_print(void);

#endif // CCCAM3_CACHE_H
