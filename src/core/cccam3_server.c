#include "cccam3.h"
#include "cccam3_protocol.h"
#include "cccam3_logger.h"
#include "cccam3_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_server_fd = -1;
static int g_running = 1;

// Handler para sinais (CTRL+C, etc.)
static void cccam_signal_handler(int sig) {
    (void)sig;
    cccam_log(LOG_INFO, "Recebido sinal de interrupção. A encerrar...");
    g_running = 0;
}

// Inicialização do servidor
int cccam3_init(cccam_config_t *config) {
    // Configurar handlers de sinais
    signal(SIGINT, cccam_signal_handler);
    signal(SIGTERM, cccam_signal_handler);

    // Inicializar sub-sistemas
    if (cccam_protocol_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar protocolo");
        return -1;
    }

    // Criar socket
    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        cccam_log(LOG_ERROR, "Falha ao criar socket: %s", strerror(errno));
        return -1;
    }

    // Permitir reutilização do porto
    int opt = 1;
    if (setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cccam_log(LOG_WARN, "Falha ao definir SO_REUSEADDR: %s", strerror(errno));
    }

    // Bind ao porto
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cccam_log(LOG_ERROR, "Falha ao bindar porta %d: %s", config->listen_port, strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    // Iniciar escuta
    if (listen(g_server_fd, config->max_clients) < 0) {
        cccam_log(LOG_ERROR, "Falha ao iniciar escuta: %s", strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    cccam_log(LOG_INFO, "CCcam3 servidor iniciado na porta %d (max clientes: %d)", 
              config->listen_port, config->max_clients);
    return 0;
}

// Loop principal
int cccam3_run(void) {
    if (g_server_fd < 0) {
        cccam_log(LOG_ERROR, "Servidor não inicializado");
        return -1;
    }

    fd_set read_fds;
    int max_fd = g_server_fd;

    while (g_running) {
        FD_ZERO(&read_fds);
        FD_SET(g_server_fd, &read_fds);

        // TODO: Adicionar sockets de clientes ao set
        // FD_SET(client->socket_fd, &read_fds);
        // if (client->socket_fd > max_fd) max_fd = client->socket_fd;

        struct timeval tv = {1, 0}; // Timeout de 1 segundo
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (activity < 0) {
            if (g_running) {
                cccam_log(LOG_ERROR, "Erro no select: %s", strerror(errno));
            }
            break;
        }

        // Verificar novas ligações
        if (FD_ISSET(g_server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, &addr_len);
            
            if (client_fd < 0) {
                cccam_log(LOG_ERROR, "Falha ao aceitar cliente: %s", strerror(errno));
                continue;
            }

            cccam_log(LOG_INFO, "Nova ligação de %s:%d", 
                      inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            
            // TODO: Criar cliente e adicionar à lista
            // cccam_client_t *new_client = cccam_client_create(client_fd, &client_addr);
            // add_client_to_list(new_client);
        }

        // TODO: Processar dados dos clientes
    }

    return 0;
}

// Limpeza
void cccam3_cleanup(void) {
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    cccam_protocol_cleanup();
    cccam_log(LOG_INFO, "CCcam3 encerrado");
}
