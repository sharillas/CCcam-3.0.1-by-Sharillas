#include "cccam3.h"
#include "cccam3_client.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_CLIENTS CCCAM3_CLIENT_SLOTS

static cccam_client_t *g_clients[MAX_CLIENTS];
static int g_client_count = 0;

cccam_client_t *cccam_client_create(int socket_fd, struct sockaddr_in *addr) {
    if (g_client_count >= MAX_CLIENTS) {
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
    
    if (addr) {
        memcpy(&client->addr, addr, sizeof(struct sockaddr_in));
    }
    
    // Adiciona à lista
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] == NULL) {
            g_clients[i] = client;
            g_client_count++;
            cccam_log(LOG_INFO, "Cliente %u ligado (socket %d)", client->client_id, socket_fd);
            return client;
        }
    }
    
    free(client);
    return NULL;
}

void cccam_client_destroy(cccam_client_t *client) {
    if (!client) return;
    
    cccam_log(LOG_INFO, "Cliente %u a ser removido", client->client_id);
    
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    
    // Remove da lista
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] == client) {
            g_clients[i] = NULL;
            g_client_count--;
            break;
        }
    }
    
    free(client);
}

cccam_client_t *cccam_client_find_by_socket(int socket_fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] && g_clients[i]->socket_fd == socket_fd) {
            return g_clients[i];
        }
    }
    return NULL;
}

cccam_client_t *cccam_client_find_by_id(uint32_t client_id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] && g_clients[i]->client_id == client_id) {
            return g_clients[i];
        }
    }
    return NULL;
}

cccam_client_t *cccam_client_get_by_index(int index) {
    if (index < 0 || index >= MAX_CLIENTS) {
        return NULL;
    }
    return g_clients[index];
}

int cccam_client_get_count(void) {
    return g_client_count;
}

void cccam_client_authenticate(cccam_client_t *client) {
    if (client) {
        client->is_authenticated = 1;
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
    g_client_count = 0;
}
