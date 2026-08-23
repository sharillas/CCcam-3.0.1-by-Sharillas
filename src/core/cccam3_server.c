#include "cccam3.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include "cccam3_cache.h"
#include "cccam3_ecm.h"
#include "cccam3_client.h"
#include "cccam3_card_manager.h"
#include "cccam3_hop_control.h"
#include "cccam3_rest_api.h"
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
static cccam_config_t g_config;

// Handler para sinais (CTRL+C, etc.)
static void cccam_signal_handler(int sig) {
    (void)sig;
    cccam_log(LOG_INFO, "Recebido sinal de interrupção. A encerrar...");
    g_running = 0;
}

// Inicialização do servidor
int cccam3_init(cccam_config_t *config) {
    if (config) {
        g_config = *config;
    }

    // Configurar handlers de sinais
    signal(SIGINT, cccam_signal_handler);
    signal(SIGTERM, cccam_signal_handler);

    // Inicializar sub-sistemas
    if (cccam_protocol_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar protocolo");
        return -1;
    }

    if (cccam_cache_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar cache");
        return -1;
    }

    if (cccam_ecm_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar ECM handler");
        return -1;
    }

    if (cccam_card_manager_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar Card Manager");
        return -1;
    }

    if (cccam_hop_control_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar Hop Control");
        return -1;
    }

    // Inicializar API REST
    if (cccam_rest_api_init(REST_API_DEFAULT_PORT) != 0) {
        cccam_log(LOG_WARN, "Falha ao iniciar API REST (porta %d)", REST_API_DEFAULT_PORT);
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
    addr.sin_port = htons(g_config.listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cccam_log(LOG_ERROR, "Falha ao bindar porta %d: %s", g_config.listen_port, strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    // Iniciar escuta
    if (listen(g_server_fd, g_config.max_clients) < 0) {
        cccam_log(LOG_ERROR, "Falha ao iniciar escuta: %s", strerror(errno));
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    cccam_log(LOG_INFO, "CCcam3 servidor iniciado na porta %d (max clientes: %d)", 
              g_config.listen_port, g_config.max_clients);
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

    cccam_log(LOG_INFO, "Servidor em execução...");
    
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

        // Limpar entradas expiradas da cache periodicamente
        static time_t last_cache_clean = 0;
        time_t now = time(NULL);
        if (now - last_cache_clean > 30) { // A cada 30 segundos
            cccam_cache_clean_expired();
            last_cache_clean = now;
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
    cccam_rest_api_cleanup();
    cccam_hop_control_cleanup();
    cccam_card_manager_cleanup();
    cccam_cache_cleanup();
    cccam_ecm_cleanup();
    cccam_protocol_cleanup();
    cccam_log(LOG_INFO, "CCcam3 encerrado");
}

// Função main
int main(int argc, char *argv[]) {
    char *config_file = "conf/cccam3.conf";
    int opt;

    // Processar argumentos da linha de comando
    while ((opt = getopt(argc, argv, "c:hv")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'h':
                printf("CCcam3 %s\n", CCCAM3_VERSION);
                printf("Uso: %s [opções]\n", argv[0]);
                printf("  -c <file>  Ficheiro de configuração\n");
                printf("  -h         Mostrar esta ajuda\n");
                printf("  -v         Mostrar versão\n");
                return 0;
            case 'v':
                printf("CCcam3 versão %s\n", CCCAM3_VERSION);
                return 0;
            default:
                fprintf(stderr, "Uso: %s -c <config_file>\n", argv[0]);
                return 1;
        }
    }

    // Carregar configuração
    cccam_config_t config;
    if (cccam_load_config(config_file, &config) != 0) {
        fprintf(stderr, "Falha ao carregar configuração de %s\n", config_file);
        return 1;
    }

    // Inicializar logger
    cccam_log_init(config.log_file, config.log_level);

    // Mostrar configuração
    cccam_print_config(&config);

    // Inicializar servidor
    if (cccam3_init(&config) != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar servidor");
        return 1;
    }

    // Executar servidor
    int result = cccam3_run();

    // Limpeza
    cccam3_cleanup();
    cccam_log_close();

    return result;
}
