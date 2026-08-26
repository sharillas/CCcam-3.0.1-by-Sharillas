#include "cccam3.h"
#include "cccam3_rest_api.h"
#include "cccam3_web_interface.h"
#include "cccam3_logger.h"
#include "cccam3_cache.h"
#include "cccam3_ecm.h"
#include "cccam3_card_manager.h"
#include "cccam3_hop_control.h"
#include "cccam3_client.h"
#include "cccam3_dvb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <strings.h>
#include <openssl/sha.h>

// --- Variáveis Globais ---
static int g_rest_api_fd = -1;
static int g_rest_api_port = REST_API_DEFAULT_PORT;
static int g_rest_api_running = 0;
static pthread_t g_rest_api_thread;
static int g_rest_api_thread_started = 0;
static pthread_mutex_t g_rest_api_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_rest_api_cond = PTHREAD_COND_INITIALIZER;
static char g_auth_user[64] = "";
static char g_auth_password[64] = "";
static char g_web_path[64] = "/web";

void cccam_rest_api_set_auth(const char *user, const char *password) {
    if (user && password) {
        strncpy(g_auth_user, user, sizeof(g_auth_user) - 1);
        strncpy(g_auth_password, password, sizeof(g_auth_password) - 1);
        cccam_log(LOG_INFO, "REST API: Autenticação Basic ativada (utilizador '%s')", user);
    }
}

void cccam_rest_api_set_web_path(const char *path) {
    if (path && path[0] == '/' && strlen(path) < sizeof(g_web_path)) {
        strncpy(g_web_path, path, sizeof(g_web_path) - 1);
        g_web_path[sizeof(g_web_path) - 1] = '\0';
    }
}

// --- Funções Auxiliares ---

static int send_all(int fd, const void *data, size_t len) {
    const char *p = (const char *)data;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static void send_http_response(int client_fd, int code, const char *status,
                               const char *content_type, const char *body) {
    char header[512];
    size_t body_len = strlen(body);
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n",
             code, status, content_type, body_len);
    send_all(client_fd, header, strlen(header));
    send_all(client_fd, body, body_len);
}

static void send_json_response(int client_fd, const char *json) {
    send_http_response(client_fd, 200, "OK", "application/json", json);
}

static void send_not_found(int client_fd, const char *path) {
    char response[512];
    snprintf(response, sizeof(response),
             "Rota não encontrada: %s\n"
             "Rotas disponíveis: /status, /stats, /stats/cache, /stats/ecm, "
             "/stats/readers, /channels, %s",
             path, g_web_path);
    send_http_response(client_fd, 404, "Not Found", "text/plain", response);
}

// --- Autenticação Basic ---

// Decodifica base64 e devolve 1 se as credenciais batem com as configuradas
static int check_basic_auth(const char *auth_header) {
    const char *prefix = "Basic ";
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (strncmp(auth_header, prefix, 6) != 0) return 0;

    char decoded[256];
    size_t in_len = strlen(auth_header + 6);
    if (in_len == 0 || in_len > sizeof(decoded) * 4 / 3) return 0;

    // Base64 decode
    size_t out_len = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = auth_header[6 + i];
        if (c == '=') break;
        const char *p = strchr(b64, c);
        if (!p) return 0;
        buf = (buf << 6) | (uint32_t)(p - b64);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded[out_len++] = (char)((buf >> bits) & 0xFF);
        }
    }
    decoded[out_len] = '\0';

    char *colon = strchr(decoded, ':');
    if (!colon) return 0;
    *colon = '\0';
    const char *user = decoded;
    const char *pass = colon + 1;

    // Comparação com hash SHA256 (evita timing attacks e comparações diretas)
    if (strlen(user) != strlen(g_auth_user)) return 0;
    if (strlen(pass) != strlen(g_auth_password)) return 0;

    uint8_t h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)user, strlen(user), h1);
    SHA256((const unsigned char *)g_auth_user, strlen(g_auth_user), h2);
    if (memcmp(h1, h2, sizeof(h1)) != 0) return 0;
    SHA256((const unsigned char *)pass, strlen(pass), h1);
    SHA256((const unsigned char *)g_auth_password, strlen(g_auth_password), h2);
    if (memcmp(h1, h2, sizeof(h1)) != 0) return 0;

    return 1;
}

// --- Geração de JSON ---

static void json_cache_stats(char *buffer, size_t size) {
    int total, hits, misses;
    cccam_cache_get_stats(&total, &hits, &misses);
    
    snprintf(buffer, size,
        "\"cache\": {\n"
        "    \"entries\": %d,\n"
        "    \"hits\": %d,\n"
        "    \"misses\": %d,\n"
        "    \"hit_ratio\": %.2f\n"
        "  }",
        total, hits, misses,
        (hits + misses) > 0 ? (float)hits / (hits + misses) * 100 : 0
    );
}

static void json_ecm_stats(char *buffer, size_t size) {
    int total, cache_hits, cache_misses, reader_success, reader_fail;
    cccam_ecm_get_stats(&total, &cache_hits, &cache_misses, &reader_success, &reader_fail);
    
    snprintf(buffer, size,
        "\"ecm\": {\n"
        "    \"total_requests\": %d,\n"
        "    \"cache_hits\": %d,\n"
        "    \"cache_misses\": %d,\n"
        "    \"reader_success\": %d,\n"
        "    \"reader_fail\": %d,\n"
        "    \"cache_hit_ratio\": %.2f\n"
        "  }",
        total, cache_hits, cache_misses, reader_success, reader_fail,
        total > 0 ? (float)cache_hits / total * 100 : 0
    );
}

static void json_reader_stats(char *buffer, size_t size) {
    int total, active, local, remote;
    cccam_card_manager_get_stats(&total, &active, &local, &remote);
    
    snprintf(buffer, size,
        "\"readers\": {\n"
        "    \"total\": %d,\n"
        "    \"active\": %d,\n"
        "    \"local\": %d,\n"
        "    \"remote\": %d\n"
        "  }",
        total, active, local, remote
    );
}

static void json_server_status(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    
    int client_count = cccam_client_get_count();
    uint8_t hop_limit = cccam_hop_control_get_limit();
    cccam_config_t *config = cccam_get_config();
    
    snprintf(buffer, size,
        "\"server\": {\n"
        "    \"name\": \"%s\",\n"
        "    \"version\": \"%s\",\n"
        "    \"status\": \"online\",\n"
        "    \"uptime\": \"%s\",\n"
        "    \"clients\": %d,\n"
        "    \"hop_limit\": %d,\n"
        "    \"port\": %d,\n"
        "    \"rest_port\": %d\n"
        "  }",
        config->server_name, CCCAM3_VERSION, time_str, client_count, hop_limit,
        config->listen_port, g_rest_api_port
    );
}

static void json_channels(char *buffer, size_t size) {
    cccam_dvb_channel_t channels[CCCAM3_DVB_MAX_CHANNELS];
    int count = cccam_dvb_get_channels(channels, CCCAM3_DVB_MAX_CHANNELS);
    if (count > 64) count = 64;

    size_t used = 0;
    used += (size_t)snprintf(buffer + used, size - used,
        "\"channels\": {\n"
        "    \"count\": %d,\n"
        "    \"services\": [\n", count);

    for (int i = 0; i < count && used + 128 < size; i++) {
        used += (size_t)snprintf(buffer + used, size - used,
            "%s      { \"sid\": %u, \"caid\": %u, \"ecm_pid\": %u, \"pmt_pid\": %u, \"video_pid\": %u, \"name\": \"%s\" }",
            i > 0 ? ",\n" : "",
            channels[i].sid, channels[i].caid, channels[i].ecm_pid,
            channels[i].pmt_pid, channels[i].video_pid, channels[i].name);
    }

    snprintf(buffer + used, size - used, "\n    ]\n  }");
}

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
        (long)time(NULL),
        status_buf,
        cache_buf,
        ecm_buf,
        reader_buf
    );
}

// --- Handler de Requisições HTTP ---

static void handle_request(int client_fd, char *request, size_t request_len) {
    char json[4096];
    char method[16] = "";
    char path[512] = "";
    char auth_header[256] = "";
    int auth_header_found = 0;

    // Linha de pedido: METHOD PATH HTTP/x.y
    char *line_end = strstr(request, "\r\n");
    if (!line_end) line_end = request + request_len;
    *line_end = '\0';

    if (sscanf(request, "%15s %511s", method, path) != 2) {
        send_http_response(client_fd, 400, "Bad Request", "text/plain", "Pedido inválido\n");
        return;
    }

    if (strcmp(method, "GET") != 0) {
        send_http_response(client_fd, 400, "Bad Request", "text/plain", "Método não suportado\n");
        return;
    }

    // Cabeçalhos (Authorization)
    char *header_start = line_end + 2;
    while (header_start < request + request_len) {
        char *end = strstr(header_start, "\r\n");
        if (!end || end == header_start) break;
        *end = '\0';
        if (strncasecmp(header_start, "Authorization:", 14) == 0) {
            const char *value = header_start + 14;
            while (*value == ' ' || *value == '\t') value++;
            strncpy(auth_header, value, sizeof(auth_header) - 1);
            auth_header[sizeof(auth_header) - 1] = '\0';
            auth_header_found = 1;
        }
        header_start = end + 2;
    }

    // Autenticação Basic (se configurada)
    if (g_auth_user[0] != '\0' && g_auth_password[0] != '\0') {
        if (!auth_header_found || !check_basic_auth(auth_header)) {
            send_http_response(client_fd, 401, "Unauthorized", "text/plain",
                               "Unauthorized\n");
            return;
        }
    }

    // --- Rotas ---
    if (strcmp(path, "/") == 0 || strcmp(path, "/status") == 0) {
        json_server_status(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strcmp(path, g_web_path) == 0 ||
               (strcmp(g_web_path, "/web") == 0 && strcmp(path, "/web/") == 0)) {
        cccam_web_interface_serve(client_fd);
        return;
    } else if (strcmp(path, "/stats") == 0 || strcmp(path, "/stats/all") == 0) {
        json_all_stats(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strcmp(path, "/stats/cache") == 0) {
        json_cache_stats(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strcmp(path, "/stats/ecm") == 0) {
        json_ecm_stats(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strcmp(path, "/stats/readers") == 0) {
        json_reader_stats(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strcmp(path, "/channels") == 0) {
        json_channels(json, sizeof(json));
        send_json_response(client_fd, json);
    } else {
        send_not_found(client_fd, path);
    }
}

// --- Thread da API REST ---

static void *rest_api_thread_func(void *arg) {
    (void)arg;
    int bind_failed = 0;
    
    g_rest_api_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_rest_api_fd < 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao criar socket");
        bind_failed = 1;
        goto started;
    }
    
    int opt = 1;
    setsockopt(g_rest_api_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_rest_api_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(g_rest_api_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao bindar porta %d: %s",
                  g_rest_api_port, strerror(errno));
        close(g_rest_api_fd);
        g_rest_api_fd = -1;
        bind_failed = 1;
        goto started;
    }
    
    if (listen(g_rest_api_fd, 10) < 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao iniciar escuta");
        close(g_rest_api_fd);
        g_rest_api_fd = -1;
        bind_failed = 1;
        goto started;
    }

started:
    pthread_mutex_lock(&g_rest_api_mutex);
    g_rest_api_running = 1;
    pthread_cond_broadcast(&g_rest_api_cond);
    pthread_mutex_unlock(&g_rest_api_mutex);

    if (bind_failed) {
        return NULL;
    }
    
    cccam_log(LOG_INFO, "REST API: Servidor HTTP iniciado na porta %d", g_rest_api_port);
    cccam_log(LOG_INFO, "REST API: Interface web disponível em http://localhost:%d%s",
              g_rest_api_port, g_web_path);
    
    while (g_rest_api_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_rest_api_fd, &read_fds);
        
        struct timeval tv = {1, 0};
        int activity = select(g_rest_api_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (activity < 0) {
            if (errno == EINTR) continue;
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
            
            // Lê o pedido até ao fim dos cabeçalhos (\r\n\r\n)
            char buffer[REST_API_MAX_BUFFER];
            size_t received = 0;
            int done = 0;
            while (received < sizeof(buffer) - 1 && !done) {
                ssize_t n = recv(client_fd, buffer + received,
                                 sizeof(buffer) - 1 - received, 0);
                if (n <= 0) {
                    done = -1;
                    break;
                }
                received += (size_t)n;
                buffer[received] = '\0';
                if (strstr(buffer, "\r\n\r\n") != NULL) {
                    done = 1;
                }
            }
            
            if (done == 1) {
                handle_request(client_fd, buffer, received);
            }
            close(client_fd);
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
    pthread_mutex_lock(&g_rest_api_mutex);
    if (g_rest_api_running) {
        pthread_mutex_unlock(&g_rest_api_mutex);
        cccam_log(LOG_WARN, "REST API: Já está em execução");
        return 0;
    }
    pthread_mutex_unlock(&g_rest_api_mutex);
    
    if (port > 0) {
        g_rest_api_port = port;
    }
    
    if (pthread_create(&g_rest_api_thread, NULL, rest_api_thread_func, NULL) != 0) {
        cccam_log(LOG_ERROR, "REST API: Falha ao criar thread");
        return -1;
    }
    g_rest_api_thread_started = 1;
    
    // Aguarda a thread assinalar que está pronta (bind concluído ou falhado)
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 3;
    pthread_mutex_lock(&g_rest_api_mutex);
    while (!g_rest_api_running) {
        if (pthread_cond_timedwait(&g_rest_api_cond, &g_rest_api_mutex, &ts) != 0) {
            break;
        }
    }
    pthread_mutex_unlock(&g_rest_api_mutex);
    
    return 0;
}

void cccam_rest_api_cleanup(void) {
    pthread_mutex_lock(&g_rest_api_mutex);
    int was_running = g_rest_api_running;
    g_rest_api_running = 0;
    pthread_mutex_unlock(&g_rest_api_mutex);
    
    if (g_rest_api_fd >= 0) {
        close(g_rest_api_fd);
        g_rest_api_fd = -1;
    }
    
    if (g_rest_api_thread_started) {
        pthread_join(g_rest_api_thread, NULL);
        g_rest_api_thread_started = 0;
    }
    (void)was_running;
    cccam_log(LOG_INFO, "REST API: Limpeza concluída");
}

int cccam_rest_api_is_running(void) {
    return g_rest_api_running;
}

int cccam_rest_api_get_port(void) {
    return g_rest_api_port;
}
