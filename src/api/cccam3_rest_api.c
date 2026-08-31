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
#include "cccam3_user_manager.h"
#include "cccam3_emu.h"
#include "cccam3_channels.h"
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
#include <sys/stat.h>
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
    time_t started_at = config ? 0 : 0;
    (void)started_at;
    
    snprintf(buffer, size,
        "\"server\": {\n"
        "    \"name\": \"%s\",\n"
        "    \"version\": \"%s\",\n"
        "    \"status\": \"online\",\n"
        "    \"uptime\": \"%s\",\n"
        "    \"clients\": %d,\n"
        "    \"hop_limit\": %d,\n"
        "    \"port\": %d,\n"
        "    \"newcamd_port\": %d,\n"
        "    \"rest_port\": %d\n"
        "  }",
        config->server_name, CCCAM3_VERSION, time_str, client_count, hop_limit,
        config->listen_port, config->newcamd_port, g_rest_api_port
    );
}

// Lista de leitores (nome, tipo, estado, caid, hop, prioridade, ECMs)
static void json_readers_list(char *buffer, size_t size) {
    size_t used = 0;
    int count = cccam_card_manager_get_count();
    used += (size_t)snprintf(buffer + used, size - used,
        "\"readers_list\": {\n"
        "    \"count\": %d,\n"
        "    \"list\": [\n", count);

    for (int i = 0; i < count; i++) {
        cccam_reader_t *r = cccam_card_manager_get_by_index(i);
        if (!r) continue;
        if (used + 256 > size) break;
        used += (size_t)snprintf(buffer + used, size - used,
            "%s      { \"name\": \"%s\", \"type\": %d, \"state\": %d, "
            "\"caid\": %u, \"hop\": %d, \"priority\": %d, "
            "\"ecm_requests\": %u, \"ecm_success\": %u, \"ecm_fail\": %u }",
            i > 0 ? ",\n" : "",
            r->name, (int)r->type, (int)r->state,
            r->caid, r->hop, r->priority,
            r->ecm_requests, r->ecm_success, r->ecm_fail);
    }
    snprintf(buffer + used, size - used, "\n    ]\n  }");
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

// --- Endpoints de gestão ---

// Extrai o valor de um parâmetro da query string (path?param=value)
static int get_query_param(const char *path, const char *param, char *out, size_t out_size) {
    char query[256];
    snprintf(query, sizeof(query), "?%s=", param);
    const char *start = strstr(path, query);
    if (!start) {
        return -1;
    }
    start += strlen(query);
    size_t len = strcspn(start, "& \t");
    if (len == 0 || len >= out_size) {
        return -1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static void json_clients(char *buffer, size_t size) {
    size_t used = 0;
    used += (size_t)snprintf(buffer + used, size - used,
        "\"clients\": {\n"
        "    \"count\": %d,\n"
        "    \"list\": [\n", cccam_client_get_count());

    int first = 1;
    for (int i = 0; i < CCCAM3_CLIENT_SLOTS; i++) {
        cccam_client_t *client = cccam_client_get_by_index(i);
        if (!client) continue;

        if (used + 384 > size) break;

        // Nome do canal que está a ver (via CCcam.channelinfo)
        const char *channel = NULL;
        const char *provider = NULL;
        if (client->cur_sid != 0) {
            channel = cccam_channels_get_name(client->cur_caid, 0, client->cur_sid);
            if (!channel) {
                channel = cccam_channels_get_name(0, 0, client->cur_sid);
            }
            provider = cccam_channels_get_provider(client->cur_caid, 0);
        }

        used += (size_t)snprintf(buffer + used, size - used,
            "%s      { \"id\": %u, \"user\": \"%s\", \"ip\": \"%s\", "
            "\"newcamd\": %d, \"authenticated\": %d, \"connected_at\": %ld, "
            "\"ecm_total\": %u, \"sid\": %u, \"caid\": %u, "
            "\"channel\": \"%s\", \"provider\": \"%s\" }",
            first ? "" : ",\n",
            client->client_id,
            client->username[0] != '\0' ? client->username : "-",
            inet_ntoa(client->addr.sin_addr),
            client->is_newcamd,
            client->is_authenticated,
            (long)client->connected_at,
            client->ecm_total,
            client->cur_sid,
            client->cur_caid,
            channel ? channel : "—",
            provider ? provider : "—");
        first = 0;
    }
    snprintf(buffer + used, size - used, "\n    ]\n  }");
}

static void json_users(char *buffer, size_t size) {
    size_t used = 0;
    int count = cccam_user_manager_get_count();
    used += (size_t)snprintf(buffer + used, size - used,
        "\"users\": {\n"
        "    \"count\": %d,\n"
        "    \"list\": [\n", count);

    for (int i = 0; i < count; i++) {
        cccam_user_t *user = cccam_user_manager_get_by_index(i);
        if (!user) continue;
        if (used + 256 > size) break;
        used += (size_t)snprintf(buffer + used, size - used,
            "%s      { \"name\": \"%s\", \"level\": %d, \"max_hops\": %d, "
            "\"enabled\": %d, \"logins\": %u, \"ecm\": %u, \"ecm_ok\": %u }",
            i > 0 ? ",\n" : "",
            user->username, (int)user->level, user->max_hops, user->enabled,
            user->login_count, user->ecm_requests, user->ecm_success);
    }
    snprintf(buffer + used, size - used, "\n    ]\n  }");
}

static void json_emu_keys(char *buffer, size_t size) {
    int total, biss, via, cw, pvu, nagra, ird;
    cccam_emu_stats(&total, &biss, &via, &cw, &pvu, &nagra, &ird);
    snprintf(buffer, size,
        "\"emu\": {\n"
        "    \"total\": %d,\n"
        "    \"biss\": %d,\n"
        "    \"viaccess\": %d,\n"
        "    \"cryptoworks\": %d,\n"
        "    \"powervu\": %d,\n"
        "    \"nagra\": %d,\n"
        "    \"irdeto\": %d\n"
        "  }",
        total, biss, via, cw, pvu, nagra, ird);
}

// --- Handler de Requisições HTTP ---

// Ficheiros editáveis no painel (nome -> caminho real)
static const char *g_editable_files[] = {
    "cccam3.conf", "cccam3.users", "cccam3.readers",
    "SoftCam.Key", "CCcam.providers", "CCcam.channelinfo"
};
#define EDITABLE_FILE_COUNT ((int)(sizeof(g_editable_files) / sizeof(g_editable_files[0])))

// Resolve o caminho de um ficheiro editável (config -> /etc/cccam3 fallback)
static int rest_file_path(const char *name, char *out, size_t out_size) {
    int allowed = 0;
    for (int i = 0; i < EDITABLE_FILE_COUNT; i++) {
        if (strcmp(name, g_editable_files[i]) == 0) {
            allowed = 1;
            break;
        }
    }
    if (!allowed) {
        return -1;
    }

    cccam_config_t *cfg = cccam_get_config();

    if (strcmp(name, "cccam3.conf") == 0) {
        snprintf(out, out_size, "conf/cccam3.conf");
    } else if (strcmp(name, "cccam3.users") == 0) {
        snprintf(out, out_size, "%s", cfg->user_file[0] ? cfg->user_file : "conf/cccam3.users");
    } else if (strcmp(name, "cccam3.readers") == 0) {
        snprintf(out, out_size, "conf/cccam3.readers");
    } else if (strcmp(name, "SoftCam.Key") == 0) {
        snprintf(out, out_size, "%s", cfg->emu_key_file[0] ? cfg->emu_key_file : "conf/SoftCam.Key");
    } else if (strcmp(name, "CCcam.providers") == 0) {
        snprintf(out, out_size, "%s", cfg->providers_file[0] ? cfg->providers_file : "conf/CCcam.providers");
    } else {
        snprintf(out, out_size, "%s", cfg->channelinfo_file[0] ? cfg->channelinfo_file : "conf/CCcam.channelinfo");
    }

    // Fallback: /etc/cccam3/<nome> se o caminho relativo não existir
    if (out[0] != '/' && access(out, R_OK) != 0) {
        snprintf(out, out_size, "/etc/cccam3/%s", name);
    }
    return 0;
}

static void json_files(char *buffer, size_t size) {
    size_t used = 0;
    used += (size_t)snprintf(buffer + used, size - used,
        "\"files\": {\n    \"list\": [\n");

    for (int i = 0; i < EDITABLE_FILE_COUNT; i++) {
        char path[256];
        rest_file_path(g_editable_files[i], path, sizeof(path));
        struct stat st;
        long fsize = -1;
        if (stat(path, &st) == 0) {
            fsize = (long)st.st_size;
        }
        used += (size_t)snprintf(buffer + used, size - used,
            "%s      { \"name\": \"%s\", \"path\": \"%s\", \"size\": %ld }",
            i > 0 ? ",\n" : "",
            g_editable_files[i], path, fsize);
    }
    snprintf(buffer + used, size - used, "\n    ]\n  }");
}

static void json_file_content(char *buffer, size_t size, const char *name) {
    char path[256];
    FILE *fp;
    long fsize;

    if (rest_file_path(name, path, sizeof(path)) != 0) {
        snprintf(buffer, size, "{\"result\": \"not_allowed\"}");
        return;
    }

    fp = fopen(path, "r");
    if (!fp) {
        snprintf(buffer, size, "{\"result\": \"not_found\", \"path\": \"%s\"}", path);
        return;
    }
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize < 0) fsize = 0;
    if (fsize > (long)(size - 64)) fsize = (long)(size - 64);

    size_t off = 0;
    off += (size_t)snprintf(buffer + off, size - off,
        "{\n  \"result\": \"ok\",\n  \"name\": \"%s\",\n  \"path\": \"%s\",\n  \"content\": \"",
        name, path);
    for (long i = 0; i < fsize; i++) {
        int ch = fgetc(fp);
        if (ch == EOF) break;
        switch (ch) {
            case '\\': buffer[off++] = '\\'; buffer[off++] = '\\'; break;
            case '"':  buffer[off++] = '\\'; buffer[off++] = '"'; break;
            case '\n': buffer[off++] = '\\'; buffer[off++] = 'n'; break;
            case '\r': buffer[off++] = '\\'; buffer[off++] = 'r'; break;
            case '\t': buffer[off++] = '\\'; buffer[off++] = 't'; break;
            default:
                if (ch >= 0x20 && ch < 0x7F) buffer[off++] = (char)ch;
                break;
        }
        if (off >= size - 8) break;
    }
    fclose(fp);
    snprintf(buffer + off, size - off, "\"\n}");
}

// Guarda o conteúdo de um ficheiro e aplica o reload correspondente
static void rest_file_save(const char *name, const char *content, size_t content_len,
                           char *resp, size_t resp_size) {
    char path[256];
    char tmp[280];

    if (rest_file_path(name, path, sizeof(path)) != 0) {
        snprintf(resp, resp_size, "{\"result\": \"not_allowed\"}");
        return;
    }

    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *fp = fopen(tmp, "w");
    if (!fp) {
        snprintf(resp, resp_size, "{\"result\": \"write_error\"}");
        return;
    }
    fwrite(content, 1, content_len, fp);
    fclose(fp);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        snprintf(resp, resp_size, "{\"result\": \"write_error\"}");
        return;
    }

    // Aplica o reload adequado
    const char *action = "";
    if (strcmp(name, "cccam3.users") == 0) {
        cccam_user_manager_reload();
        action = "users_reloaded";
    } else if (strcmp(name, "cccam3.readers") == 0) {
        cccam_card_manager_reload();
        action = "readers_reloaded";
    } else if (strcmp(name, "SoftCam.Key") == 0) {
        cccam_emu_reload();
        action = "keys_reloaded";
    } else if (strcmp(name, "CCcam.providers") == 0 || strcmp(name, "CCcam.channelinfo") == 0) {
        cccam_channels_init();
        action = "channels_reloaded";
    } else {
        action = "restart_required";
    }

    snprintf(resp, resp_size, "{\"result\": \"ok\", \"action\": \"%s\"}", action);
}

static void handle_request(int client_fd, char *request, size_t request_len, size_t body_len) {
    char json[8192];
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

    if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0) {
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
    } else if (strcmp(path, "/files") == 0) {
        json_files(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strncmp(path, "/files/get", 10) == 0) {
        char name[64];
        if (get_query_param(path, "name", name, sizeof(name)) == 0) {
            json_file_content(json, sizeof(json), name);
        } else {
            snprintf(json, sizeof(json), "{\"result\": \"missing_name\"}");
        }
        send_json_response(client_fd, json);
    } else if (strncmp(path, "/files/save", 11) == 0) {
        char name[64];
        if (strcmp(method, "POST") != 0) {
            send_http_response(client_fd, 400, "Bad Request", "text/plain", "Usar POST\n");
            return;
        }
        if (get_query_param(path, "name", name, sizeof(name)) == 0) {
            char *body = strstr(request, "\r\n\r\n");
            if (body) {
                body += 4;
                rest_file_save(name, body, body_len, json, sizeof(json));
            } else {
                snprintf(json, sizeof(json), "{\"result\": \"no_body\"}");
            }
        } else {
            snprintf(json, sizeof(json), "{\"result\": \"missing_name\"}");
        }
        send_json_response(client_fd, json);
    } else if (strncmp(path, "/clients/kick", 13) == 0) {
        char id_str[16];
        if (get_query_param(path, "id", id_str, sizeof(id_str)) == 0) {
            uint32_t id = (uint32_t)atoi(id_str);
            cccam_client_t *c = cccam_client_find_by_id(id);
            if (c) {
                c->to_kick = 1;
                send_json_response(client_fd, "{\"result\": \"ok\", \"kick\": true}");
            } else {
                send_json_response(client_fd, "{\"result\": \"not_found\"}");
            }
        } else {
            send_json_response(client_fd, "{\"result\": \"missing_id\"}");
        }
    } else if (strcmp(path, "/clients") == 0) {
        json_clients(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strncmp(path, "/users/set", 10) == 0) {
        char name[64], value[16];
        if (get_query_param(path, "name", name, sizeof(name)) == 0) {
            cccam_user_t *user = cccam_user_manager_get_user(name);
            if (!user) {
                send_json_response(client_fd, "{\"result\": \"not_found\"}");
            } else if (get_query_param(path, "enabled", value, sizeof(value)) == 0) {
                cccam_user_manager_set_enabled(name, (uint8_t)(atoi(value) != 0));
                send_json_response(client_fd, "{\"result\": \"ok\"}");
            } else if (get_query_param(path, "max_hops", value, sizeof(value)) == 0) {
                cccam_user_manager_set_max_hops(name, (uint8_t)atoi(value));
                send_json_response(client_fd, "{\"result\": \"ok\"}");
            } else if (get_query_param(path, "level", value, sizeof(value)) == 0) {
                cccam_user_manager_set_level(name, (cccam_user_level_t)atoi(value));
                send_json_response(client_fd, "{\"result\": \"ok\"}");
            } else {
                send_json_response(client_fd, "{\"result\": \"missing_param\"}");
            }
        } else {
            send_json_response(client_fd, "{\"result\": \"missing_name\"}");
        }
    } else if (strcmp(path, "/readers") == 0) {
        json_readers_list(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strcmp(path, "/users") == 0) {
        json_users(json, sizeof(json));
        send_json_response(client_fd, json);
    } else if (strcmp(path, "/reload/keys") == 0) {
        int rc = cccam_emu_reload();
        snprintf(json, sizeof(json), "{\"result\": %s}",
                 rc == 0 ? "\"ok\"" : "\"error\"");
        send_json_response(client_fd, json);
    } else if (strcmp(path, "/reload/users") == 0) {
        cccam_user_manager_reload();
        send_json_response(client_fd, "{\"result\": \"ok\"}");
    } else if (strcmp(path, "/reload/readers") == 0) {
        cccam_card_manager_reload();
        send_json_response(client_fd, "{\"result\": \"ok\"}");
    } else if (strcmp(path, "/emu/keys") == 0) {
        json_emu_keys(json, sizeof(json));
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
            
            // Lê o pedido: cabeçalhos até \r\n\r\n e corpo (Content-Length)
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
                // Corpo de um POST (Content-Length)
                char *body_start = strstr(buffer, "\r\n\r\n");
                size_t header_len = (size_t)(body_start - buffer) + 4;
                size_t body_len = 0;

                char *cl = strcasestr(buffer, "Content-Length:");
                if (cl) {
                    body_len = (size_t)atol(cl + 15);
                }

                size_t already = received > header_len ? received - header_len : 0;
                if (already > body_len) already = body_len;

                while (already < body_len && received < sizeof(buffer) - 1) {
                    ssize_t n = recv(client_fd, buffer + received,
                                     sizeof(buffer) - 1 - received, 0);
                    if (n <= 0) break;
                    received += (size_t)n;
                    already += (size_t)n;
                }

                handle_request(client_fd, buffer, received, body_len);
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
