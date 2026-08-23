#include "cccam3_rest_api.h"
#include "cccam3_web_interface.h"
#include "cccam3_logger.h"
#include "cccam3_cache.h"
#include "cccam3_ecm.h"
#include "cccam3_card_manager.h"
#include "cccam3_hop_control.h"
#include "cccam3_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

// --- Variáveis Globais ---
static int g_rest_api_fd = -1;
static int g_rest_api_port = REST_API_DEFAULT_PORT;
static int g_rest_api_running = 0;
static pthread_t g_rest_api_thread;

// --- Funções Auxiliares ---

// Converte bytes para hexadecimal
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

// Gera resposta JSON com estatísticas da cache
static void json_cache_stats(char *buffer, size_t size) {
    int total, hits, misses;
    cccam_cache_get_stats(&total, &hits, &misses);
    
    snprintf(buffer, size,
        "{\n"
        "  \"cache\": {\n"
        "    \"entries\": %d,\n"
        "    \"hits\": %d,\n"
        "    \"misses\": %d,\n"
        "    \"hit_ratio\": %.2f\n"
        "  }\n"
        "}",
        total, hits, misses,
        (hits + misses) > 0 ? (float)hits / (hits + misses) * 100 : 0
    );
}

// Gera resposta JSON com estatísticas ECM
static void json_ecm_stats(char *buffer, size_t size) {
    int total, cache_hits, cache_misses, reader_success, reader_fail;
    cccam_ecm_get_stats(&total, &cache_hits, &cache_misses, &reader_success, &reader_fail);
    
    snprintf(buffer, size,
        "{\n"
        "  \"ecm\": {\n"
        "    \"total_requests\": %d,\n"
        "    \"cache_hits\": %d,\n"
        "    \"cache_misses\": %d,\n"
        "    \"reader_success\": %d,\n"
        "    \"reader_fail\": %d,\n"
        "    \"cache_hit_ratio\": %.2f\n"
        "  }\n"
        "}",
        total, cache_hits, cache_misses, reader_success, reader_fail,
        total > 0 ? (float)cache_hits / total * 100 : 0
    );
}

// Gera resposta JSON com estatísticas dos leitores
static void json_reader_stats(char *buffer, size_t size) {
    int total, active, local, remote;
    cccam_card_manager_get_stats(&total, &active, &local, &remote);
    
    snprintf(buffer, size,
        "{\n"
        "  \"readers\": {\n"
        "    \"total\": %d,\n"
        "    \"active\": %d,\n"
        "    \"local\": %d,\n"
        "    \"remote\": %d\n"
        "  }\n"
        "}",
        total, active, local, remote
    );
}

// Gera resposta JSON com estado do servidor
static void json_server_status(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    int client_count = cccam_client_get_count();
    uint8_t hop_limit = cccam_hop_control_get_limit();
    
    snprintf(buffer, size,
        "{\n"
        "  \"server\": {\n"
        "    \"name\": \"CCcam3\",\n"
        "    \"version\": \"%s\",\n"
        "    \"status\": \"online\",\n"
        "    \"uptime\": \"%s\",\n"
        "    \"clients\": %d,\n"
        "    \"hop_limit\": %d,\n"
        "    \"port\": %d\n"
        "  }\n"
        "}",
        CCCAM3_VERSION, time_str, client_count, hop_limit, g_rest_api_port
    );
}

// Gera resposta JSON com todas as estatísticas
static void json_all_stats(char *buffer, size_t size) {
    char cache_buf[512], ecm_buf[512], reader_buf[512], status_buf[512];
    
    json_cache_stats(cache_buf, sizeof(cache_buf));
    json_ecm_stats(ecm_buf, sizeof(ecm_buf));
    json_reader_stats(reader_buf, sizeof(reader_buf));
    json_server_status(status_buf, sizeof(status_buf));
    
    snprintf(buffer, size,
        "{\n"
        "  \"timestamp\": %ld,\n"
        "  %s,\n"
        "  %s,\n"
        "  %s,\n"
        "  %s\n"
        "}",
        time(NULL),
        status_buf + 1,  // Remove o primeiro '{'
        cache_buf + 1,
        ecm_buf + 1,
        reader_buf + 1
    );
}

// --- Handler de Requisições HTTP ---

static void handle_request(int client_fd, const char *request) {
    char response[8192];
    char *path = NULL;
    
    // Parse do caminho da requisição
    char *method_end = strstr(request, " ");
    if (!method_end) {
        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        write(client_fd, bad_request, strlen(bad_request));
        return;
    }
    
    char *path_start = method_end + 1;
    char *path_end = strstr(path_start, " ");
    if (!path_end) {
        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        write(client_fd, bad_request, strlen(bad_request));
        return;
    }
    
    *path_end = '\0';
    path = path_start;
    
    // --- Rotas ---
    if (strcmp(path, "/") == 0 || strcmp(path, "/status") == 0) {
        json_server_status(response, sizeof(response));
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "%s",
            response
        );
    } else if (strcmp(path, "/web") == 0 || strcmp(path, "/web/") == 0) {
        cccam_web_interface_serve(client_fd);
        return;
    } else if (strcmp(path, "/stats") == 0 || strcmp(path, "/stats/all") == 0) {
        json_all_stats(response, sizeof(response));
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "%s",
            response
        );
    } else if (strcmp(path, "/stats/cache") == 0) {
        json_cache_stats(response, sizeof(response));
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "%s",
            response
        );
    } else if (strcmp(path, "/stats/ecm") == 0) {
        json_ecm_stats(response, sizeof(response));
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "%s",
            response
        );
    } else if (strcmp(path, "/stats/readers") == 0) {
        json_reader_stats(response, sizeof(response));
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "%s",
            response
        );
    } else {
        // Rota não encontrada
        snprintf(response, sizeof(response),
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Rota não encontrada: %s\n"
            "Rotas disponíveis: /status, /stats, /stats/cache, /stats/ecm, /stats/readers, /web",
            path
        );
    }
    
    write(client_fd, response, strlen(response));
    close(client_fd);
}

// --- Thread da API REST ---

static void *rest_api_thread_func(void *arg) {
    (void)arg;
    
    g_rest_api_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_rest_api_fd < 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao criar socket");
        return NULL;
    }
    
    int opt = 1;
    setsockopt(g_rest_api_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_rest_api_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(g_rest_api_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao bindar porta %d", g_rest_api_port);
        close(g_rest_api_fd);
        g_rest_api_fd = -1;
        return NULL;
    }
    
    if (listen(g_rest_api_fd, 10) < 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao iniciar escuta");
        close(g_rest_api_fd);
        g_rest_api_fd = -1;
        return NULL;
    }
    
    cccam_log(LOG_INFO, "REST API: Servidor HTTP iniciado na porta %d", g_rest_api_port);
    cccam_log(LOG_INFO, "REST API: Interface web disponível em http://localhost:%d/web", g_rest_api_port);
    g_rest_api_running = 1;
    
    while (g_rest_api_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_rest_api_fd, &read_fds);
        
        struct timeval tv = {1, 0};
        int activity = select(g_rest_api_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (activity < 0) {
            if (g_rest_api_running) {
                cccam_log(LOG_ERROR, "REST API: Erro no select");
            }
            break;
        }
        
        if (FD_ISSET(g_rest_api_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(g_rest_api_fd, (struct sockaddr *)&client_addr, &addr_len);
            
            if (client_fd < 0) {
                continue;
            }
            
            char buffer[REST_API_MAX_BUFFER];
            ssize_t received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
            
            if (received > 0) {
                buffer[received] = '\0';
                handle_request(client_fd, buffer);
            } else {
                close(client_fd);
            }
        }
    }
    
    if (g_rest_api_fd >= 0) {
        close(g_rest_api_fd);
        g_rest_api_fd = -1;
    }
    
    cccam_log(LOG_INFO, "REST API: Servidor HTTP encerrado");
    return NULL;
}

// --- Implementação das Funções da API ---

int cccam_rest_api_init(int port) {
    if (g_rest_api_running) {
        cccam_log(LOG_WARN, "REST API: Já está em execução");
        return 0;
    }
    
    if (port > 0) {
        g_rest_api_port = port;
    }
    
    if (pthread_create(&g_rest_api_thread, NULL, rest_api_thread_func, NULL) != 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao criar thread");
        return -1;
    }
    
    // Aguarda um pouco para a thread iniciar
    usleep(100000);
    
    return 0;
}

void cccam_rest_api_cleanup(void) {
    if (!g_rest_api_running) {
        return;
    }
    
    g_rest_api_running = 0;
    
    if (g_rest_api_fd >= 0) {
        close(g_rest_api_fd);
        g_rest_api_fd = -1;
    }
    
    pthread_join(g_rest_api_thread, NULL);
    cccam_log(LOG_INFO, "REST API: Limpeza concluída");
}

int cccam_rest_api_is_running(void) {
    return g_rest_api_running;
}

int cccam_rest_api_get_port(void) {
    return g_rest_api_port;
}
