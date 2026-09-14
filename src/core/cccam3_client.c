#include "cccam3.h"
#include "cccam3_client.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>

#define MAX_CLIENTS CCCAM3_CLIENT_SLOTS

static cccam_client_t *g_clients[MAX_CLIENTS];
static int g_client_count = 0;

// Protege a lista e os refcounts. O destroy marca o cliente como zombie e
// só o liberta quando o último utilizador fizer unref - as threads de ECM
// (DVBAPI/DVB) e a REST mantêm uma referência enquanto usam o ponteiro.
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

// +1 referência (devolve NULL se já estiver marcado para remoção)
static cccam_client_t *pool_acquire_locked(cccam_client_t *client) {
    if (client && !client->zombie) {
        client->refs++;
        return client;
    }
    return NULL;
}

cccam_client_t *cccam_client_create(int socket_fd, struct sockaddr_in *addr) {
    if (__atomic_load_n(&g_client_count, __ATOMIC_RELAXED) >= MAX_CLIENTS) {
        cccam_log(LOG_WARN, "Máximo de clientes atingido (%d)", MAX_CLIENTS);
        return NULL;
    }

    cccam_client_t *client = calloc(1, sizeof(cccam_client_t));
    if (!client) {
        cccam_log(LOG_ERROR, "Falha ao alocar memória para cliente");
        return NULL;
    }

    client->socket_fd = socket_fd;
    client->client_id = time(NULL) ^ (uint32_t)(uintptr_t)client;
    client->is_authenticated = 0;
    client->connected_at = time(NULL);
    client->last_keepalive = time(NULL);
    client->hop_count = 1;
    client->refs = 1; // referência do pool
    client->zombie = 0;
    cccam_protocol_reset_crypto(&client->crypto);

    if (addr) {
        memcpy(&client->addr, addr, sizeof(struct sockaddr_in));
    }

    pthread_mutex_lock(&g_pool_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] == NULL) {
            g_clients[i] = client;
            __atomic_add_fetch(&g_client_count, 1, __ATOMIC_RELAXED);
            pthread_mutex_unlock(&g_pool_mutex);
            cccam_log(LOG_INFO, "Cliente %u ligado (socket %d)", client->client_id, socket_fd);
            return client;
        }
    }
    pthread_mutex_unlock(&g_pool_mutex);

    free(client);
    return NULL;
}

void cccam_client_destroy(cccam_client_t *client) {
    int free_now = 0;

    if (!client) return;

    cccam_log(LOG_INFO, "Cliente %u a ser removido", client->client_id);

    // shutdown() (em vez de close()): impede escritas de outras threads e
    // evita que o número do fd seja reutilizado enquanto há referências
    if (client->socket_fd >= 0) {
        shutdown(client->socket_fd, SHUT_RDWR);
    }

    pthread_mutex_lock(&g_pool_mutex);
    client->zombie = 1;

    // Remove do pool (se ainda lá estiver)
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] == client) {
            g_clients[i] = NULL;
            __atomic_sub_fetch(&g_client_count, 1, __ATOMIC_RELAXED);
            break;
        }
    }

    client->refs--; // liberta a referência do pool
    if (client->refs == 0) {
        free_now = 1;
    }
    pthread_mutex_unlock(&g_pool_mutex);

    if (free_now) {
        if (client->socket_fd >= 0) {
            close(client->socket_fd);
            client->socket_fd = -1;
        }
        free(client);
    }
}

// Liberta uma referência obtida com find_* / get_by_index_ref
void cccam_client_unref(cccam_client_t *client) {
    int free_now = 0;

    if (!client) return;

    pthread_mutex_lock(&g_pool_mutex);
    if (client->refs > 0) {
        client->refs--;
    }
    if (client->refs == 0 && client->zombie) {
        free_now = 1;
    }
    pthread_mutex_unlock(&g_pool_mutex);

    if (free_now) {
        if (client->socket_fd >= 0) {
            close(client->socket_fd);
            client->socket_fd = -1;
        }
        free(client);
    }
}

cccam_client_t *cccam_client_find_by_socket(int socket_fd) {
    // Sem referência: apenas para uso no loop principal (dono do pool)
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] && g_clients[i]->socket_fd == socket_fd) {
            return g_clients[i];
        }
    }
    return NULL;
}

cccam_client_t *cccam_client_find_by_id(uint32_t client_id) {
    // Devolve o cliente COM referência: chamar cccam_client_unref() depois
    pthread_mutex_lock(&g_pool_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] && g_clients[i]->client_id == client_id) {
            cccam_client_t *c = pool_acquire_locked(g_clients[i]);
            pthread_mutex_unlock(&g_pool_mutex);
            return c;
        }
    }
    pthread_mutex_unlock(&g_pool_mutex);
    return NULL;
}

cccam_client_t *cccam_client_get_by_index(int index) {
    // Sem referência: apenas para uso no loop principal (dono do pool)
    if (index < 0 || index >= MAX_CLIENTS) {
        return NULL;
    }
    return g_clients[index];
}

cccam_client_t *cccam_client_get_by_index_ref(int index) {
    // Com referência (para threads como a REST): chamar cccam_client_unref()
    if (index < 0 || index >= MAX_CLIENTS) {
        return NULL;
    }
    pthread_mutex_lock(&g_pool_mutex);
    cccam_client_t *c = pool_acquire_locked(g_clients[index]);
    pthread_mutex_unlock(&g_pool_mutex);
    return c;
}

int cccam_client_get_count(void) {
    return __atomic_load_n(&g_client_count, __ATOMIC_RELAXED);
}

void cccam_client_authenticate(cccam_client_t *client) {
    if (client) {
        // Release: publica também o username/versão/hop escritos antes;
        // os leitores (painel REST) usam acquire
        __atomic_store_n(&client->is_authenticated, 1, __ATOMIC_RELEASE);
        cccam_log(LOG_INFO, "Cliente %u autenticado", client->client_id);
    }
}

void cccam_client_set_hop(cccam_client_t *client, uint8_t hop) {
    if (client) {
        client->hop_count = hop;
    }
}

void cccam_client_update_keepalive(cccam_client_t *client) {
    if (client) {
        client->last_keepalive = time(NULL);
    }
}

int cccam_client_is_timeout(cccam_client_t *client, int timeout_seconds) {
    if (!client) return 1;
    time_t now = time(NULL);
    return (now - client->last_keepalive) > timeout_seconds;
}

void cccam_client_close_all(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i]) {
            cccam_client_destroy(g_clients[i]);
        }
    }
    __atomic_store_n(&g_client_count, 0, __ATOMIC_RELAXED);
}
