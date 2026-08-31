#include "cccam3.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include "cccam3_cache.h"
#include "cccam3_ecm.h"
#include "cccam3_client.h"
#include "cccam3_card_manager.h"
#include "cccam3_hop_control.h"
#include "cccam3_rest_api.h"
#include "cccam3_user_manager.h"
#include "cccam3_handshake_advanced.h"
#include "cccam3_optimizer.h"
#include "cccam3_dvbapi.h"
#include "cccam3_stapi.h"
#include "cccam3_dvb.h"
#include "cccam3_newcamd.h"
#include "cccam3_emu.h"
#include "cccam3_emu_des.h"
#include "cccam3_channels.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_server_fd = -1;
static int g_newcamd_fd = -1;
static int g_running = 1;
static volatile sig_atomic_t g_reload_requested = 0;
static volatile sig_atomic_t g_rotate_requested = 0;
static cccam_config_t g_config;

// --- Listas de IPs (allow/deny) ---

#define SERVER_MAX_IP_ENTRIES 64
static uint32_t g_allow_ips[SERVER_MAX_IP_ENTRIES];
static int g_allow_ip_prefix[SERVER_MAX_IP_ENTRIES];
static int g_allow_count = 0;
static uint32_t g_deny_ips[SERVER_MAX_IP_ENTRIES];
static int g_deny_ip_prefix[SERVER_MAX_IP_ENTRIES];
static int g_deny_count = 0;

// Converte um IP em network byte order e devolve o prefixo (1-4 octetos)
static int parse_ip_entry(const char *entry, uint32_t *ip_out) {
    // Suporta "a.b.c.d" ou prefixos "a.b" / "a.b.c"
    unsigned int a = 0, b = 0, c = 0, d = 0;
    int parts = sscanf(entry, "%u.%u.%u.%u", &a, &b, &c, &d);
    if (parts < 1 || a > 255 || b > 255 || c > 255 || d > 255) {
        return -1;
    }
    *ip_out = htonl((a << 24) | (b << 16) | (c << 8) | d);
    return parts;
}

static void server_load_ip_lists(void) {
    char buf[256];
    char *save = NULL;

    g_allow_count = 0;
    if (g_config.allow_ips[0] != '\0') {
        strncpy(buf, g_config.allow_ips, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *tok = strtok_r(buf, ", \t", &save);
        while (tok && g_allow_count < SERVER_MAX_IP_ENTRIES) {
            uint32_t ip = 0;
            int parts = parse_ip_entry(tok, &ip);
            if (parts > 0) {
                g_allow_ips[g_allow_count] = ip;
                g_allow_ip_prefix[g_allow_count] = parts;
                g_allow_count++;
            }
            tok = strtok_r(NULL, ", \t", &save);
        }
    }

    g_deny_count = 0;
    if (g_config.deny_ips[0] != '\0') {
        strncpy(buf, g_config.deny_ips, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *tok = strtok_r(buf, ", \t", &save);
        while (tok && g_deny_count < SERVER_MAX_IP_ENTRIES) {
            uint32_t ip = 0;
            int parts = parse_ip_entry(tok, &ip);
            if (parts > 0) {
                g_deny_ips[g_deny_count] = ip;
                g_deny_ip_prefix[g_deny_count] = parts;
                g_deny_count++;
            }
            tok = strtok_r(NULL, ", \t", &save);
        }
    }

    if (g_allow_count > 0 || g_deny_count > 0) {
        cccam_log(LOG_INFO, "Filtros de IP: %d permitido(s), %d bloqueado(s)",
                  g_allow_count, g_deny_count);
    }
}

static int ip_match(uint32_t ip, const uint32_t *list, const int *prefix, int count) {
    for (int i = 0; i < count; i++) {
        uint32_t mask = 0;
        if (prefix[i] >= 1) mask |= 0xFF000000u;
        if (prefix[i] >= 2) mask |= 0x00FF0000u;
        if (prefix[i] >= 3) mask |= 0x0000FF00u;
        if (prefix[i] >= 4) mask |= 0x000000FFu;
        if ((ip & mask) == (list[i] & mask)) {
            return 1;
        }
    }
    return 0;
}

static int server_ip_allowed(struct sockaddr_in *addr) {
    uint32_t ip = (uint32_t)addr->sin_addr.s_addr;

    if (g_deny_count > 0 && ip_match(ip, g_deny_ips, g_deny_ip_prefix, g_deny_count)) {
        return 0;
    }
    if (g_allow_count > 0 && !ip_match(ip, g_allow_ips, g_allow_ip_prefix, g_allow_count)) {
        return 0;
    }
    return 1;
}

// --- Proteção contra bruteforce de login ---

#define LOGIN_FAIL_SLOTS 64
static uint32_t g_fail_ip[LOGIN_FAIL_SLOTS];
static int g_fail_count[LOGIN_FAIL_SLOTS];
static time_t g_fail_since[LOGIN_FAIL_SLOTS];
static time_t g_fail_blocked_until[LOGIN_FAIL_SLOTS];

static void server_login_failure(struct sockaddr_in *addr) {
    uint32_t ip = (uint32_t)addr->sin_addr.s_addr;
    time_t now = time(NULL);
    int slot = -1;

    for (int i = 0; i < LOGIN_FAIL_SLOTS; i++) {
        if (g_fail_ip[i] == ip) {
            slot = i;
            break;
        }
        if (g_fail_ip[i] == 0 && slot < 0) {
            slot = i;
        }
    }
    if (slot < 0) {
        slot = (int)(ip % LOGIN_FAIL_SLOTS);
    }

    if (g_fail_ip[slot] != ip || (now - g_fail_since[slot]) > 60) {
        g_fail_ip[slot] = ip;
        g_fail_count[slot] = 1;
        g_fail_since[slot] = now;
    } else {
        g_fail_count[slot]++;
    }

    int limit = g_config.max_login_failures > 0 ? g_config.max_login_failures : 5;
    if (g_fail_count[slot] >= limit) {
        g_fail_blocked_until[slot] = now + 60;
        cccam_log(LOG_WARN, "Login: IP %s bloqueado por 60s (bruteforce)",
                  inet_ntoa(addr->sin_addr));
    }
}

static void server_login_success(struct sockaddr_in *addr) {
    uint32_t ip = (uint32_t)addr->sin_addr.s_addr;
    for (int i = 0; i < LOGIN_FAIL_SLOTS; i++) {
        if (g_fail_ip[i] == ip) {
            g_fail_ip[i] = 0;
            g_fail_count[i] = 0;
        }
    }
}

static int server_login_blocked(struct sockaddr_in *addr) {
    uint32_t ip = (uint32_t)addr->sin_addr.s_addr;
    time_t now = time(NULL);
    for (int i = 0; i < LOGIN_FAIL_SLOTS; i++) {
        if (g_fail_ip[i] == ip && g_fail_blocked_until[i] > now) {
            return 1;
        }
    }
    return 0;
}

// --- Rate limit de ECMs por cliente ---

static int client_ecm_allowed(cccam_client_t *client) {
    int limit = g_config.max_ecm_per_sec;
    if (limit <= 0) {
        return 1;
    }

    time_t now = time(NULL);
    if (client->ecm_window_start == 0 || (now - client->ecm_window_start) >= 1) {
        client->ecm_window_start = now;
        client->ecm_window_count = 1;
        return 1;
    }

    client->ecm_window_count++;
    if (client->ecm_window_count > limit) {
        return 0;
    }
    return 1;
}

// Handler para sinais (CTRL+C, SIGHUP recarrega chaves, SIGUSR1 roda o log)
static void cccam_signal_handler(int sig) {
    if (sig == SIGHUP) {
        g_reload_requested = 1;
        return;
    }
    if (sig == SIGUSR1) {
        g_rotate_requested = 1;
        return;
    }
    cccam_log(LOG_INFO, "Recebido sinal de interrupção. A encerrar...");
    g_running = 0;
}

// Resolve caminhos de configuração com fallback para /etc/cccam3/
static void server_resolve_path(const char *path, char *out, size_t out_size) {
    if (path && path[0] == '/') {
        snprintf(out, out_size, "%s", path);
        return;
    }
    if (path && access(path, R_OK) == 0) {
        snprintf(out, out_size, "%s", path);
        return;
    }
    const char *base = path ? strrchr(path, '/') : NULL;
    base = base ? base + 1 : (path ? path : "");
    snprintf(out, out_size, "/etc/cccam3/%s", base);
}

// Inicialização do servidor
int cccam3_init(cccam_config_t *config) {
    if (config) {
        g_config = *config;
    }

    // Configurar handlers de sinais
    signal(SIGINT, cccam_signal_handler);
    signal(SIGTERM, cccam_signal_handler);
    signal(SIGHUP, cccam_signal_handler);
    signal(SIGUSR1, cccam_signal_handler);
    signal(SIGPIPE, SIG_IGN);

    // Filtros de IP
    server_load_ip_lists();

    // Aplicar limite de ligações do balanceador
    cccam_load_balancer_set_max_connections(g_config.max_clients > 0 ? g_config.max_clients : CCCAM3_MAX_CLIENTS);

    // Inicializar sub-sistemas
    if (cccam_protocol_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar protocolo");
        return -1;
    }
    cccam_protocol_set_allowed_modes(g_config.allowed_crypt_modes);

    if (cccam_cache_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar cache");
        return -1;
    }
    cccam_cache_set_enabled(g_config.enable_cache);
    cccam_cache_set_timeout(g_config.cache_timeout);

    if (cccam_ecm_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar ECM handler");
        return -1;
    }

    // Resolver caminhos dos ficheiros de utilizadores e leitores
    // (fallback para /etc/cccam3/ quando o cwd não tem os ficheiros)
    char resolved_path[256];
    server_resolve_path("conf/cccam3.readers", resolved_path, sizeof(resolved_path));
    cccam_card_manager_set_config_file(resolved_path);
    cccam_log(LOG_INFO, "Ficheiro de leitores: %s", resolved_path);

    const char *user_file = g_config.user_file[0] != '\0' ? g_config.user_file : "conf/cccam3.users";
    server_resolve_path(user_file, resolved_path, sizeof(resolved_path));
    cccam_user_manager_set_config_file(resolved_path);
    cccam_log(LOG_INFO, "Ficheiro de utilizadores: %s", resolved_path);

    // Ficheiro de chaves da emulação (SoftCam.Key)
    if (g_config.emu_key_file[0] != '\0') {
        server_resolve_path(g_config.emu_key_file, resolved_path, sizeof(resolved_path));
        cccam_emu_set_key_file(resolved_path);
        cccam_log(LOG_INFO, "Ficheiro de chaves EMU: %s", resolved_path);
    }

    // Ficheiros de canais/provedores (para o painel web)
    {
        char prov_path[256];
        char chan_path[256];
        const char *pf = g_config.providers_file[0] != '\0' ? g_config.providers_file : "conf/CCcam.providers";
        const char *cf = g_config.channelinfo_file[0] != '\0' ? g_config.channelinfo_file : "conf/CCcam.channelinfo";
        server_resolve_path(pf, prov_path, sizeof(prov_path));
        server_resolve_path(cf, chan_path, sizeof(chan_path));
        cccam_channels_set_files(prov_path, chan_path);
        cccam_channels_init();
    }

    // Registo automático de utilizadores
    cccam_user_manager_set_auto_register(g_config.auto_register);

    if (cccam_card_manager_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar Card Manager");
        return -1;
    }

    if (cccam_hop_control_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar Hop Control");
        return -1;
    }
    cccam_hop_control_set_limit((uint8_t)g_config.hop_limit);
    cccam_hop_control_set_timeout(g_config.hop_timeout);

    if (g_config.user_manager_enabled) {
        if (cccam_user_manager_init() != 0) {
            cccam_log(LOG_ERROR, "Falha ao inicializar User Manager");
            return -1;
        }
    }

    if (cccam_handshake_advanced_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar Handshake Avançado");
        return -1;
    }

    if (cccam_optimizer_init() != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar Optimizer");
        return -1;
    }

    // Inicializar DVB-API
    if (g_config.dvbapi_enabled) {
        if (g_config.dvbapi_socket[0] != '\0') {
            cccam_dvbapi_set_socket_path(g_config.dvbapi_socket);
        }
        cccam_dvbapi_set_max_demux(g_config.dvbapi_max_demux);
        if (cccam_dvbapi_init() != 0) {
            cccam_log(LOG_WARN, "DVBAPI: Falha ao inicializar (continuando sem hardware)");
        }
    } else {
        cccam_log(LOG_INFO, "DVBAPI: Desativada pela configuração");
    }

    // Inicializar STAPI
    if (g_config.stapi_enabled) {
        if (g_config.stapi_device[0] != '\0') {
            cccam_stapi_set_device(g_config.stapi_device);
        }
        if (cccam_stapi_init() != 0) {
            cccam_log(LOG_WARN, "STAPI: Falha ao inicializar (continuando sem hardware)");
        }
    } else {
        cccam_log(LOG_INFO, "STAPI: Desativada pela configuração");
    }

    // Inicializar leitor DVB direto (S/S2/C/C2)
    if (g_config.dvb_enabled) {
        cccam_dvb_config_t dvb;
        memset(&dvb, 0, sizeof(dvb));
        dvb.enabled = 1;
        dvb.adapter = g_config.dvb_adapter;
        dvb.frontend = g_config.dvb_frontend;
        dvb.demux = g_config.dvb_demux;
        dvb.frequency_khz = g_config.dvb_frequency_khz;
        dvb.symbol_rate = g_config.dvb_symbol_rate;
        dvb.delivery_system = g_config.dvb_delivery_system;
        dvb.modulation = g_config.dvb_modulation;
        dvb.fec = g_config.dvb_fec;
        dvb.inversion = g_config.dvb_inversion;
        dvb.polarity = g_config.dvb_polarity;
        dvb.service_id = g_config.dvb_service_id;
        dvb.bandwidth = g_config.dvb_bandwidth;
        if (cccam_dvb_init(&dvb) != 0) {
            cccam_log(LOG_WARN, "DVB: Falha ao inicializar leitor de hardware (sem /dev/dvb?)");
        }
    } else {
        cccam_log(LOG_INFO, "DVB: Leitor de hardware desativado pela configuração");
    }

    // Inicializar API REST
    if (g_config.rest_api_enabled) {
        if (g_config.rest_api_user[0] != '\0' && g_config.rest_api_password[0] != '\0') {
            cccam_rest_api_set_auth(g_config.rest_api_user, g_config.rest_api_password);
        }
        cccam_rest_api_set_web_path(g_config.web_path[0] != '\0' ? g_config.web_path : "/web");
        if (cccam_rest_api_init(g_config.rest_api_port) != 0) {
            cccam_log(LOG_WARN, "Falha ao iniciar API REST (porta %d)", g_config.rest_api_port);
        }
    } else {
        cccam_log(LOG_INFO, "API REST: Desativada pela configuração");
    }

    // Criar listener Newcamd
    if (g_config.newcamd_enabled) {
        // Chave DES do protocolo Newcamd
        if (g_config.newcamd_des_key[0] != '\0') {
            uint8_t des_key[14] = {0};
            if (strlen(g_config.newcamd_des_key) >= 28) {
                for (int i = 0; i < 14; i++) {
                    unsigned int byte;
                    if (sscanf(g_config.newcamd_des_key + i * 2, "%2x", &byte) != 1) {
                        break;
                    }
                    des_key[i] = (uint8_t)byte;
                }
                cccam_newcamd_set_des_key(des_key);
            } else {
                cccam_log(LOG_WARN, "Newcamd: Chave DES inválida na configuração (28 chars hex esperados)");
            }
        }
        cccam_newcamd_set_caid((uint16_t)g_config.newcamd_caid);

        g_newcamd_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (g_newcamd_fd >= 0) {
            int nc_opt = 1;
            setsockopt(g_newcamd_fd, SOL_SOCKET, SO_REUSEADDR, &nc_opt, sizeof(nc_opt));
            struct sockaddr_in nc_addr;
            memset(&nc_addr, 0, sizeof(nc_addr));
            nc_addr.sin_family = AF_INET;
            nc_addr.sin_port = htons((uint16_t)g_config.newcamd_port);
            nc_addr.sin_addr.s_addr = INADDR_ANY;

            if (bind(g_newcamd_fd, (struct sockaddr *)&nc_addr, sizeof(nc_addr)) < 0 ||
                listen(g_newcamd_fd, g_config.max_clients) < 0) {
                cccam_log(LOG_WARN, "Newcamd: Falha ao iniciar listener na porta %d: %s",
                          g_config.newcamd_port, strerror(errno));
                close(g_newcamd_fd);
                g_newcamd_fd = -1;
            } else {
                cccam_log(LOG_INFO, "Newcamd: Listener iniciado na porta %d", g_config.newcamd_port);
            }
        }
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
    cccam_log(LOG_INFO, "Handshake avançado: RSA 2048 bits + AES-GCM");
    return 0;
}

// --- Comunicação com clientes ---

static int recv_exact(int fd, uint8_t *buffer, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(fd, buffer + received, len - received, 0);
        if (n <= 0) {
            return -1;
        }
        received += (size_t)n;
    }
    return 0;
}

static int read_client_message(int fd, uint8_t *buffer, size_t buf_size, size_t *msg_len) {
    uint8_t header[CCCAM3_HEADER_SIZE];
    if (recv_exact(fd, header, sizeof(header)) != 0) {
        return -1;
    }

    uint32_t len_net;
    memcpy(&len_net, header + 4, sizeof(len_net));
    uint32_t total = ntohl(len_net);

    if (total < CCCAM3_HEADER_SIZE || total > CCCAM3_BUFFER_SIZE || total > buf_size) {
        cccam_log(LOG_WARN, "Tamanho de mensagem inválido: %u", total);
        return -1;
    }

    memcpy(buffer, header, sizeof(header));
    if (recv_exact(fd, buffer + sizeof(header), total - sizeof(header)) != 0) {
        return -1;
    }

    *msg_len = (size_t)total;
    return 0;
}

static void server_destroy_client(cccam_client_t *client) {
    if (client->ncd_session) {
        free(client->ncd_session);
        client->ncd_session = NULL;
    }
    cccam_client_destroy(client);
    cccam_load_balancer_release_connection();
}

static uint8_t handshake_mode_to_crypt_mode(uint8_t mode) {
    switch (mode) {
        case HANDSHAKE_MODE_LEGACY:
            return CCCAM_CRYPT_MODE_NONE;
        case HANDSHAKE_MODE_RC4:
            return CCCAM_CRYPT_MODE_RC4;
        case HANDSHAKE_MODE_AES:
            return CCCAM_CRYPT_MODE_AES;
        case HANDSHAKE_MODE_AES_GCM:
        case HANDSHAKE_MODE_RSA_AES:
            return CCCAM_CRYPT_MODE_AES_GCM;
        default:
            return CCCAM_CRYPT_MODE_NONE;
    }
}

static int handle_client_login(cccam_client_t *client, const void *payload, size_t payload_len) {
    if (client->is_authenticated) {
        return 0;
    }

    // Proteção contra bruteforce
    if (server_login_blocked(&client->addr)) {
        cccam_log(LOG_WARN, "Login de %s rejeitado (bloqueio temporário)",
                  inet_ntoa(client->addr.sin_addr));
        return -1;
    }

    if (!payload || payload_len < 16 + 1 + 1 + 4) {
        cccam_log(LOG_WARN, "Login com payload inválido (%zu bytes)", payload_len);
        return -1;
    }

    const uint8_t *ptr = (const uint8_t *)payload;
    cccam_login_msg_t login;
    memset(&login, 0, sizeof(login));
    memcpy(login.handshake, ptr, 16);

    size_t off = 16;
    if (off > payload_len) return -1;
    size_t remaining = payload_len - off;

    size_t user_len = strnlen((const char *)(ptr + off), remaining);
    if (user_len >= remaining || user_len >= sizeof(login.username)) return -1;
    memcpy(login.username, ptr + off, user_len);
    off += user_len + 1;
    if (off > payload_len) return -1;
    remaining = payload_len - off;

    size_t pass_len = strnlen((const char *)(ptr + off), remaining);
    if (pass_len >= remaining || pass_len >= sizeof(login.password)) return -1;
    memcpy(login.password, ptr + off, pass_len);
    off += pass_len + 1;
    if (off + 4 > payload_len) return -1;

    uint32_t version_net;
    memcpy(&version_net, ptr + off, sizeof(version_net));
    login.version = ntohl(version_net);

    cccam_user_t *user = NULL;
    if (cccam_user_manager_authenticate(login.username, login.password, &user) != 0) {
        if (g_config.auto_register) {
            // Registo automático: cria o utilizador e persiste no ficheiro
            if (cccam_user_manager_auto_register(login.username, login.password, &user) != 0) {
                cccam_log(LOG_WARN, "Autenticação falhada para '%s' (auto-registo recusado)", login.username);
                server_login_failure(&client->addr);
                return -1;
            }
            cccam_log(LOG_INFO, "Cliente '%s' registado automaticamente", login.username);
        } else {
            cccam_log(LOG_WARN, "Autenticação falhada para '%s'", login.username);
            server_login_failure(&client->addr);
            return -1;
        }
    }
    server_login_success(&client->addr);

    uint8_t handshake_resp[16 + 12 + 16 + 16] = {0};
    // O estado do handshake é global: proteger a sequência completa
    cccam_handshake_lock();
    if (cccam_protocol_handle_login(&login, handshake_resp, sizeof(handshake_resp)) != 0) {
        cccam_handshake_unlock();
        cccam_log(LOG_ERROR, "Handshake falhado com '%s'", login.username);
        return -1;
    }

    uint8_t wire_mode = handshake_mode_to_crypt_mode(cccam_handshake_get_mode());
    uint8_t session_key[32];
    size_t key_len = sizeof(session_key);
    if (cccam_handshake_get_session_key(session_key, &key_len) != 0) {
        key_len = 0;
        wire_mode = CCCAM_CRYPT_MODE_NONE;
    }
    size_t resp_len = cccam_handshake_get_response_len();
    cccam_handshake_unlock();

    if (cccam_protocol_set_crypto(&client->crypto, wire_mode, session_key, key_len) != 0) {
        cccam_log(LOG_ERROR, "Falha ao definir criptografia para '%s'", login.username);
        return -1;
    }

    strncpy(client->username, login.username, sizeof(client->username) - 1);
    client->version = login.version;
    client->crypt_mode = wire_mode;
    client->hop_count = user->max_hops;
    cccam_client_authenticate(client);

    uint8_t ack_buffer[CCCAM3_BUFFER_SIZE];
    size_t ack_len = sizeof(ack_buffer);
    if (cccam_protocol_build_login_ack(ack_buffer, &ack_len, handshake_resp, resp_len) != 0) {
        cccam_log(LOG_ERROR, "Falha ao construir ACK de login");
        return -1;
    }

    if (send(client->socket_fd, ack_buffer, ack_len, MSG_NOSIGNAL) != (ssize_t)ack_len) {
        cccam_log(LOG_ERROR, "Falha ao enviar ACK de login");
        return -1;
    }

    cccam_log(LOG_INFO, "Cliente '%s' autenticado (nível %d, max hops %d, modo crypto 0x%02X)",
              login.username, user->level, user->max_hops, wire_mode);
    return 0;
}

static int parse_ecm_payload(const void *payload, size_t payload_len, cccam_ecm_request_t *request) {
    if (!payload || !request || payload_len < 6) {
        return -1;
    }

    const uint8_t *ptr = (const uint8_t *)payload;
    memset(request, 0, sizeof(*request));
    request->caid = (uint16_t)((ptr[0] << 8) | ptr[1]);
    request->provid = (uint16_t)((ptr[2] << 8) | ptr[3]);
    request->sid = (uint16_t)((ptr[4] << 8) | ptr[5]);
    request->ecm_len = (uint16_t)(payload_len - 6);
    if (request->ecm_len > CCCAM_ECM_MAX_SIZE) {
        return -1;
    }
    memcpy(request->ecm_data, ptr + 6, request->ecm_len);
    return 0;
}

static int handle_client_ecm(cccam_client_t *client, const void *payload, size_t payload_len) {
    if (!client->is_authenticated) {
        cccam_log(LOG_WARN, "ECM de cliente não autenticado (ID %u)", client->client_id);
        return -1;
    }

    // Rate limit por cliente (anti-flood)
    if (!client_ecm_allowed(client)) {
        cccam_log(LOG_WARN, "ECM de %s excede o limite (%d/s) - pedido ignorado",
                  client->username, g_config.max_ecm_per_sec);
        return 0;
    }

    cccam_ecm_request_t request;
    if (parse_ecm_payload(payload, payload_len, &request) != 0) {
        cccam_log(LOG_WARN, "ECM com payload inválido (%zu bytes)", payload_len);
        return -1;
    }
    request.client_id = client->client_id;
    request.hop = client->hop_count;
    request.received_at = time(NULL);

    cccam_ecm_response_t response;
    int result = cccam_ecm_process(&request, &response);
    if (result == 0 && response.found) {
        cccam_ecm_send_cw(client->socket_fd, &client->crypto, &response);
        cccam_user_manager_register_ecm(client->username, 1);
    } else {
        cccam_user_manager_register_ecm(client->username, 0);
    }
    return 0;
}

// --- Handlers Newcamd ---

static void handle_newcamd_message(cccam_client_t *client) {
    cccam_newcamd_session_t *session = (cccam_newcamd_session_t *)client->ncd_session;
    uint8_t buffer[NCD_MAX_MSG];
    uint8_t len_hdr[2];

    // Formato real newcamd: [2 bytes de comprimento][payload encriptado]
    if (recv_exact(client->socket_fd, len_hdr, sizeof(len_hdr)) != 0) {
        cccam_log(LOG_INFO, "Newcamd: Cliente %u desligado", client->client_id);
        server_destroy_client(client);
        return;
    }

    uint32_t payload_len = ((uint32_t)len_hdr[0] << 8) | len_hdr[1];
    if (payload_len > sizeof(buffer)) {
        cccam_log(LOG_WARN, "Newcamd: Mensagem demasiado grande (%u bytes)", payload_len);
        server_destroy_client(client);
        return;
    }

    if (recv_exact(client->socket_fd, buffer, payload_len) != 0) {
        cccam_log(LOG_INFO, "Newcamd: Cliente %u desligado", client->client_id);
        server_destroy_client(client);
        return;
    }

    if (cccam_newcamd_process(client->socket_fd, session, buffer, payload_len) != 0) {
        cccam_log(LOG_INFO, "Newcamd: Cliente %u terminou a sessão", client->client_id);
        server_destroy_client(client);
    }
}

static void handle_client_message(cccam_client_t *client) {
    if (client->is_newcamd) {
        handle_newcamd_message(client);
        return;
    }

    uint8_t buffer[CCCAM3_BUFFER_SIZE];
    size_t msg_len = 0;

    if (read_client_message(client->socket_fd, buffer, sizeof(buffer), &msg_len) != 0) {
        cccam_log(LOG_INFO, "Cliente %u desligado", client->client_id);
        server_destroy_client(client);
        return;
    }

    cccam_msg_header_t header;
    void *payload = NULL;
    size_t payload_len = 0;

    if (cccam_protocol_parse(buffer, msg_len, &header, &payload, &payload_len,
                             &client->crypto) != 0) {
        cccam_log(LOG_WARN, "Mensagem inválida do cliente %u", client->client_id);
        server_destroy_client(client);
        return;
    }

    int failed = 0;
    switch (header.msg_id) {
        case CCCAM_MSG_LOGIN:
            failed = handle_client_login(client, payload, payload_len);
            break;
        case CCCAM_MSG_ECM:
            failed = handle_client_ecm(client, payload, payload_len);
            break;
        case CCCAM_MSG_EMM:
            // EMM de um cliente: reencaminhar para os leitores remotos
            if (payload_len >= 4) {
                const uint8_t *p = (const uint8_t *)payload;
                uint16_t emm_caid = (uint16_t)((p[0] << 8) | p[1]);
                uint16_t emm_provid = (uint16_t)((p[2] << 8) | p[3]);
                cccam_ecm_forward_emm(emm_caid, emm_provid, p + 4,
                                      (uint16_t)(payload_len - 4));
            }
            break;
        case CCCAM_MSG_KEEPALIVE:
            cccam_client_update_keepalive(client);
            break;
        default:
            cccam_log(LOG_DEBUG, "Mensagem 0x%02X ignorada do cliente %u", header.msg_id, client->client_id);
            break;
    }

    free(payload);
    if (failed) {
        server_destroy_client(client);
    }
}

// Loop principal
int cccam3_run(void) {
    if (g_server_fd < 0) {
        cccam_log(LOG_ERROR, "Servidor não inicializado");
        return -1;
    }

    cccam_log(LOG_INFO, "Servidor em execução...");

    while (g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_server_fd, &read_fds);
        int max_fd = g_server_fd;

        if (g_newcamd_fd >= 0) {
            FD_SET(g_newcamd_fd, &read_fds);
            if (g_newcamd_fd > max_fd) {
                max_fd = g_newcamd_fd;
            }
        }

        for (int i = 0; i < CCCAM3_CLIENT_SLOTS; i++) {
            cccam_client_t *client = cccam_client_get_by_index(i);
            if (client && client->socket_fd >= 0) {
                FD_SET(client->socket_fd, &read_fds);
                if (client->socket_fd > max_fd) {
                    max_fd = client->socket_fd;
                }
            }
        }

        struct timeval tv = {1, 0};
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (activity < 0) {
            if (g_running) {
                cccam_log(LOG_ERROR, "Erro no select: %s", strerror(errno));
            }
            break;
        }

        // SIGHUP: recarregar o SoftCam.Key sem reiniciar o servidor
        if (g_reload_requested) {
            g_reload_requested = 0;
            cccam_log(LOG_INFO, "SIGHUP recebido: a recarregar SoftCam.Key");
            cccam_emu_reload();
        }

        // SIGUSR1: rodar o ficheiro de log
        if (g_rotate_requested) {
            g_rotate_requested = 0;
            cccam_log(LOG_INFO, "SIGUSR1 recebido: a rodar o log");
            cccam_log_rotate();
        }

        // Clientes marcados para desligar (kick pela API REST)
        for (int i = 0; i < CCCAM3_CLIENT_SLOTS; i++) {
            cccam_client_t *kclient = cccam_client_get_by_index(i);
            if (kclient && kclient->to_kick) {
                cccam_log(LOG_INFO, "Cliente %u desligado (pedido pela API)", kclient->client_id);
                server_destroy_client(kclient);
            }
        }

        if (FD_ISSET(g_server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, &addr_len);

            if (client_fd < 0) {
                cccam_log(LOG_ERROR, "Falha ao aceitar cliente: %s", strerror(errno));
                continue;
            }

            if (!server_ip_allowed(&client_addr)) {
                cccam_log(LOG_WARN, "Ligação de %s rejeitada (filtro de IP)",
                          inet_ntoa(client_addr.sin_addr));
                close(client_fd);
                continue;
            }

            if (!cccam_load_balancer_allow_connection()) {
                cccam_log(LOG_WARN, "Ligação de %s rejeitada (limite atingido)",
                          inet_ntoa(client_addr.sin_addr));
                close(client_fd);
                continue;
            }

            struct timeval rcv_timeout = {10, 0};
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));

            cccam_client_t *client = cccam_client_create(client_fd, &client_addr);
            if (!client) {
                cccam_load_balancer_release_connection();
                close(client_fd);
                continue;
            }

            cccam_log(LOG_INFO, "Nova ligação de %s:%d (ID %u)",
                      inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client->client_id);
        }

        if (g_newcamd_fd >= 0 && FD_ISSET(g_newcamd_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(g_newcamd_fd, (struct sockaddr *)&client_addr, &addr_len);

            if (client_fd < 0) {
                cccam_log(LOG_ERROR, "Newcamd: Falha ao aceitar cliente: %s", strerror(errno));
            } else if (!server_ip_allowed(&client_addr)) {
                cccam_log(LOG_WARN, "Newcamd: Ligação de %s rejeitada (filtro de IP)",
                          inet_ntoa(client_addr.sin_addr));
                close(client_fd);
            } else if (!cccam_load_balancer_allow_connection()) {
                cccam_log(LOG_WARN, "Newcamd: Ligação de %s rejeitada (limite atingido)",
                          inet_ntoa(client_addr.sin_addr));
                close(client_fd);
            } else {
                struct timeval rcv_timeout = {10, 0};
                setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));

                cccam_client_t *client = cccam_client_create(client_fd, &client_addr);
                if (!client) {
                    cccam_load_balancer_release_connection();
                    close(client_fd);
                } else {
                    client->is_newcamd = 1;
                    client->ncd_session = calloc(1, sizeof(cccam_newcamd_session_t));
                    if (client->ncd_session) {
                        ((cccam_newcamd_session_t *)client->ncd_session)->client_id = client->client_id;
                    }
                    if (!client->ncd_session ||
                        cccam_newcamd_session_start(client_fd,
                            (cccam_newcamd_session_t *)client->ncd_session) != 0) {
                        cccam_log(LOG_WARN, "Newcamd: Falha ao iniciar sessão com %s:%d",
                                  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                        server_destroy_client(client);
                    } else {
                        cccam_log(LOG_INFO, "Newcamd: Nova ligação de %s:%d (ID %u)",
                                  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client->client_id);
                    }
                }
            }
        }

        for (int i = 0; i < CCCAM3_CLIENT_SLOTS; i++) {
            cccam_client_t *client = cccam_client_get_by_index(i);
            if (client && client->socket_fd >= 0 && FD_ISSET(client->socket_fd, &read_fds)) {
                handle_client_message(client);
            }
        }

        time_t now = time(NULL);
        for (int i = 0; i < CCCAM3_CLIENT_SLOTS; i++) {
            cccam_client_t *client = cccam_client_get_by_index(i);
            if (client && cccam_client_is_timeout(client, CCCAM3_CLIENT_TIMEOUT)) {
                cccam_log(LOG_INFO, "Cliente %u expirou (timeout de %d segundos)",
                          client->client_id, CCCAM3_CLIENT_TIMEOUT);
                server_destroy_client(client);
            }
        }

        static time_t last_cache_clean = 0;
        if (now - last_cache_clean > 30) {
            cccam_ecm_clean_expired_cache();
            last_cache_clean = now;
        }
    }

    return 0;
}

// Limpeza
void cccam3_cleanup(void) {
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    if (g_newcamd_fd >= 0) {
        close(g_newcamd_fd);
        g_newcamd_fd = -1;
    }
    cccam_client_close_all();
    cccam_dvb_cleanup();
    cccam_dvbapi_cleanup();
    cccam_stapi_cleanup();
    cccam_optimizer_cleanup();
    cccam_handshake_advanced_cleanup();
    cccam_user_manager_cleanup();
    cccam_rest_api_cleanup();
    cccam_hop_control_cleanup();
    cccam_card_manager_cleanup();
    cccam_cache_cleanup();
    cccam_ecm_cleanup();
    cccam_protocol_cleanup();
    cccam_channels_cleanup();
    cccam_log(LOG_INFO, "CCcam3 encerrado");
}

// Testes automáticos (-t)
static int run_self_tests(void) {
    int failures = 0;

    // Cache: adicionar e encontrar
    cccam_cache_init();
    uint8_t test_cw[16];
    for (int i = 0; i < 16; i++) test_cw[i] = (uint8_t)i;
    cccam_cache_add(0x0100, 0, 0x0001, test_cw, 1, time(NULL) + 30);
    uint8_t out_cw[16] = {0};
    uint8_t out_hop = 0;
    if (cccam_cache_find(0x0100, 0, 0x0001, out_cw, &out_hop) != 1 ||
        memcmp(out_cw, test_cw, 16) != 0 || out_hop != 1) {
        failures++;
        printf("TESTE FALHOU: cache add/find\n");
    }
    cccam_cache_cleanup();

    // Protocolo: round-trip de login
    cccam_protocol_init();
    uint8_t buf[512];
    size_t len = sizeof(buf);
    uint8_t seed[16] = {0};
    if (cccam_protocol_build_login(buf, &len, "user", "pass", 300, seed) != 0) {
        failures++;
        printf("TESTE FALHOU: build login\n");
    } else {
        cccam_msg_header_t hdr;
        void *pl = NULL;
        size_t pl_len = 0;
        if (cccam_protocol_parse(buf, len, &hdr, &pl, &pl_len, NULL) != 0 ||
            hdr.msg_id != CCCAM_MSG_LOGIN || pl_len != len - CCCAM3_HEADER_SIZE) {
            failures++;
            printf("TESTE FALHOU: parse login\n");
        }
        free(pl);
    }
    cccam_protocol_cleanup();

    // Utilizadores: autenticação
    cccam_user_manager_init();
    cccam_user_t *user = NULL;
    if (cccam_user_manager_authenticate("admin", "admin123", &user) != 0) {
        failures++;
        printf("TESTE FALHOU: autenticação de utilizador\n");
    }
    cccam_user_manager_cleanup();

    // Hop control: validade
    cccam_hop_control_init();
    if (!cccam_hop_control_is_valid(2) || cccam_hop_control_is_valid(99)) {
        failures++;
        printf("TESTE FALHOU: hop control\n");
    }
    cccam_hop_control_cleanup();

    // Criptografia por sessão: AES-GCM round-trip
    {
        cccam_crypto_ctx_t ctx;
        cccam_protocol_reset_crypto(&ctx);
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
        uint8_t data[64];
        for (int i = 0; i < 64; i++) data[i] = (uint8_t)(i * 3);
        uint8_t original[64];
        memcpy(original, data, sizeof(data));
        size_t len = 64;

        if (cccam_protocol_set_crypto(&ctx, CCCAM_CRYPT_MODE_AES_GCM, key, 32) != 0 ||
            cccam_protocol_encrypt(&ctx, data, &len, sizeof(data), CCCAM_MSG_ECM) != 0 ||
            len != 64 + 16 ||
            cccam_protocol_decrypt(&ctx, data, &len, CCCAM_MSG_ECM) != 0 ||
            len != 64 || memcmp(data, original, 64) != 0) {
            failures++;
            printf("TESTE FALHOU: AES-GCM round-trip\n");
        }
    }

    // Newcamd DES round-trip
    {
        uint8_t ncd_key[16];
        uint8_t msg[64];
        for (int i = 0; i < 14; i++) ncd_key[i] = (uint8_t)(i + 1);
        uint8_t des14[14];
        for (int i = 0; i < 14; i++) des14[i] = (uint8_t)(0x10 + i);
        cccam_newcamd_login_key(des14, ncd_key, 14, ncd_key);

        memset(msg, 0, sizeof(msg));
        msg[0] = 0x02;
        msg[1] = 0x03;
        strcpy((char *)msg + 8, "\xE0hello");
        int len_n = 15;
        len_n = cccam_newcamd_des_encrypt(msg, len_n, ncd_key);
        if (len_n < 0) {
            failures++;
            printf("TESTE FALHOU: newcamd des encrypt\n");
        } else {
            int dlen = cccam_newcamd_des_decrypt(msg, len_n, ncd_key);
            if (dlen < 15 || msg[8] != 0xE0 || strcmp((char *)msg + 9, "hello") != 0) {
                failures++;
                printf("TESTE FALHOU: newcamd des decrypt (dlen %d)\n", dlen);
            }
        }
    }

    // EMU: carregamento de chaves SoftCam.Key
    {
        const char *key_file = "/tmp/cccam3_test_softcam.key";
        FILE *fp = fopen(key_file, "w");
        if (fp) {
            fprintf(fp, "# teste\nF 26000001 00 1122334455667788\nI 030B00 08 0102030405060708\n");
            fclose(fp);
        }
        cccam_emu_set_key_file(key_file);
        if (cccam_emu_init() != 0 || cccam_emu_get_key_count() != 2) {
            failures++;
            printf("TESTE FALHOU: emu key load\n");
        }
        uint8_t sw[8];
        if (cccam_emu_find_key('F', 0x26000001, NULL, 0, sw, sizeof(sw)) != 8) {
            failures++;
            printf("TESTE FALHOU: emu key find\n");
        }
        cccam_emu_cleanup();
        unlink(key_file);
    }

    if (failures == 0) {
        printf("Todos os testes passaram.\n");
        return 0;
    }
    printf("%d teste(s) falharam.\n", failures);
    return 1;
}

// --- Daemonização (-d) ---

static void server_daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) {
        cccam_log(LOG_ERROR, "Falha no fork: %s", strerror(errno));
        exit(1);
    }
    if (pid > 0) {
        _exit(0); // pai termina
    }

    if (setsid() < 0) {
        cccam_log(LOG_ERROR, "Falha no setsid: %s", strerror(errno));
        exit(1);
    }

    pid = fork();
    if (pid < 0) {
        exit(1);
    }
    if (pid > 0) {
        _exit(0);
    }

    chdir("/");

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) {
            close(devnull);
        }
    }

    // Pidfile
    if (g_config.pid_file[0] != '\0') {
        FILE *fp = fopen(g_config.pid_file, "w");
        if (fp) {
            fprintf(fp, "%d\n", (int)getpid());
            fclose(fp);
        }
    }
}

// Função main
int main(int argc, char *argv[]) {
    char *config_file = "conf/cccam3.conf";
    int daemon_mode = 0;
    int opt;

    while ((opt = getopt(argc, argv, "c:htvd")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'h':
                printf("CCcam3 %s\n", CCCAM3_VERSION);
                printf("Uso: %s [opções]\n", argv[0]);
                printf("  -c <file>  Ficheiro de configuração\n");
                printf("  -d         Correr em background (daemon)\n");
                printf("  -h         Mostrar esta ajuda\n");
                printf("  -t         Executar testes automáticos\n");
                printf("  -v         Mostrar versão\n");
                return 0;
            case 't':
                cccam_log_init("", LOG_INFO);
                return run_self_tests();
            case 'v':
                printf("CCcam3 versão %s\n", CCCAM3_VERSION);
                return 0;
            case 'd':
                daemon_mode = 1;
                break;
            default:
                fprintf(stderr, "Uso: %s -c <config_file>\n", argv[0]);
                return 1;
        }
    }

    cccam_config_t config;
    if (cccam_load_config(config_file, &config) != 0) {
        fprintf(stderr, "Falha ao carregar configuração de %s\n", config_file);
        return 1;
    }

    if (daemon_mode) {
        g_config = config;
        cccam_log_init(config.log_file, config.log_level);
        cccam_log(LOG_INFO, "A iniciar em modo daemon...");
        server_daemonize();
    } else {
        cccam_log_init(config.log_file, config.log_level);
    }

    if (config.log_max_mb > 0) {
        cccam_log_set_max_size((long)config.log_max_mb * 1024 * 1024);
    }

    cccam_print_config(&config);

    if (cccam3_init(&config) != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar servidor");
        return 1;
    }

    int result = cccam3_run();
    cccam3_cleanup();

    if (config.pid_file[0] != '\0') {
        unlink(config.pid_file);
    }

    cccam_log_close();

    return result;
}
