#ifndef CCCAM3_OPTIMIZER_H
#define CCCAM3_OPTIMIZER_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

// --- Gestão de Memória ---
void *cccam_malloc(size_t size);
void *cccam_calloc(size_t nmemb, size_t size);
void cccam_free(void *ptr, size_t size);
void cccam_memory_stats(uint32_t *allocated, uint32_t *freed, uint32_t *leak);

// --- Gestão de Timeouts ---
int cccam_timeout_check(time_t start_time, int timeout_seconds);
void cccam_sleep_ms(int milliseconds);

// --- Balanceamento de Carga ---
int cccam_load_balancer_allow_connection(void);
void cccam_load_balancer_release_connection(void);
int cccam_load_balancer_get_connections(void);
void cccam_load_balancer_set_max_connections(int max);

// --- Failover ---
int cccam_failover_should_retry(int attempt);
void cccam_failover_wait_retry(int attempt);
void cccam_failover_set_params(int enabled, int retry_count, int retry_delay);

// --- Estatísticas do Sistema ---
void cccam_system_stats(char *buffer, size_t size);

// --- Inicialização ---
int cccam_optimizer_init(void);
void cccam_optimizer_cleanup(void);

#endif // CCCAM3_OPTIMIZER_H
