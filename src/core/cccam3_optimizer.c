#include "cccam3_optimizer.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// --- Variáveis Globais ---
static time_t g_start_time = 0;
static uint32_t g_total_memory_allocated = 0;
static uint32_t g_total_memory_freed = 0;

// --- Gestão de Memória ---

void *cccam_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr) {
        g_total_memory_allocated += size;
    }
    return ptr;
}

void *cccam_calloc(size_t nmemb, size_t size) {
    void *ptr = calloc(nmemb, size);
    if (ptr) {
        g_total_memory_allocated += (nmemb * size);
    }
    return ptr;
}

void cccam_free(void *ptr, size_t size) {
    if (ptr) {
        g_total_memory_freed += size;
        free(ptr);
    }
}

void cccam_memory_stats(uint32_t *allocated, uint32_t *freed, uint32_t *leak) {
    if (allocated) *allocated = g_total_memory_allocated;
    if (freed) *freed = g_total_memory_freed;
    if (leak) *leak = g_total_memory_allocated - g_total_memory_freed;
}

// --- Gestão de Timeouts ---

int cccam_timeout_check(time_t start_time, int timeout_seconds) {
    time_t now = time(NULL);
    return (now - start_time) > timeout_seconds;
}

void cccam_sleep_ms(int milliseconds) {
    usleep(milliseconds * 1000);
}

// --- Balanceamento de Carga ---

static int g_connection_count = 0;
static int g_max_connections = 100;

int cccam_load_balancer_allow_connection(void) {
    if (g_connection_count >= g_max_connections) {
        cccam_log(LOG_WARN, "CCshare: Limite de ligações atingido (%d)", g_max_connections);
        return 0;
    }
    g_connection_count++;
    return 1;
}

void cccam_load_balancer_release_connection(void) {
    if (g_connection_count > 0) {
        g_connection_count--;
    }
}

int cccam_load_balancer_get_connections(void) {
    return g_connection_count;
}

void cccam_load_balancer_set_max_connections(int max) {
    if (max > 0) {
        g_max_connections = max;
    }
}

// --- Failover ---

static int g_failover_enabled = 1;
static int g_retry_count = 3;
static int g_retry_delay = 5; // segundos

int cccam_failover_should_retry(int attempt) {
    if (!g_failover_enabled) return 0;
    return (attempt < g_retry_count);
}

void cccam_failover_wait_retry(int attempt) {
    if (attempt < g_retry_count) {
        cccam_log(LOG_DEBUG, "CCshare: Failover - aguardando %d segundos (tentativa %d/%d)", 
                  g_retry_delay, attempt + 1, g_retry_count);
        sleep(g_retry_delay);
    }
}

void cccam_failover_set_params(int enabled, int retry_count, int retry_delay) {
    g_failover_enabled = enabled;
    if (retry_count > 0) g_retry_count = retry_count;
    if (retry_delay > 0) g_retry_delay = retry_delay;
}

// --- Estatísticas do Sistema ---

void cccam_system_stats(char *buffer, size_t size) {
    time_t now = time(NULL);
    long uptime = now - g_start_time;
    
    snprintf(buffer, size,
        "{\n"
        "  \"uptime_seconds\": %ld,\n"
        "  \"connections\": %d,\n"
        "  \"memory_allocated\": %u,\n"
        "  \"memory_freed\": %u,\n"
        "  \"memory_leak\": %u\n"
        "}",
        uptime, g_connection_count, g_total_memory_allocated, g_total_memory_freed,
        g_total_memory_allocated - g_total_memory_freed
    );
}

// --- Inicialização ---

int cccam_optimizer_init(void) {
    g_start_time = time(NULL);
    g_total_memory_allocated = 0;
    g_total_memory_freed = 0;
    g_connection_count = 0;
    cccam_log(LOG_INFO, "CCshare: Optimizer inicializado");
    return 0;
}

void cccam_optimizer_cleanup(void) {
    cccam_log(LOG_INFO, "CCshare: Optimizer limpo");
}
