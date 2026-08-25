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
#include "cccam3_protocol_newcamd.h"
#include "cccam3_dvbapi.h"
#include "cccam3_stapi.h"
#include "cccam3_dvb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_server_fd = -1;
static int g_newcamd_fd = -1;
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
    signal(SIGPIPE, SIG_IGN);

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

    if (g_config.user_file[0] != '\0') {
        cccam_user_manager_set_config_file(g_config.user_file);
    }
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
        if (cccam_dvbapi_init() != 0) {
            cccam_log(LOG_WARN, "DVBAPI: Falha ao inicializar (continuando sem hardware)");
        }
    } else {
        cccam_log(LOG_INFO, "DVBAPI: Desativada pela configuração");
    }

    // Inicializar STAPI (stub)
    if (g_config.stapi_enabled) {
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
        if (cccam_dvb_init(&dvb) != 0) {
            cccam_log(LOG_WARN, "DVB: Falha ao inicializar leitor de hardware (sem /dev/dvb?)");
        }
    } else {
        cccam_log(LOG_INFO, "DVB: Leitor de hardware desativado pela configuração");
    }

    // Inicializar API REST
    if (g_config.rest_api_enabled) {
        if (cccam_rest_api_init(g_config.rest_api_port) != 0) {
            cccam_log(LOG_WARN, "Falha ao iniciar API REST (porta %d)", g_config.rest_api_port);
        }
    } else {
        cccam_log(LOG_INFO, "API REST: Desativada pela configuração");
    }

    // Criar listener Newcamd
    if (g_config.newcamd_enabled) {
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
        cccam_log(LOG_WARN, "Autenticação falhada para '%s'", login.username);
        return -1;
    }

    uint8_t handshake_resp[16 + 12 + 16 + 16] = {0};
    if (cccam_protocol_handle_login(&login, handshake_resp, sizeof(handshake_resp)) != 0) {
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
    if (cccam_protocol_set_crypto(wire_mode, session_key, key_len) != 0) {
        cccam_log(LOG_ERROR, "Falha ao definir criptografia para '%s'", login.username);
        return -1;
    }

    strncpy(client->username, login.username, sizeof(client->username) - 1);
    client->version = login.version;
    client->crypt_mode = wire_mode;
    client->hop_count = user->max_hops;
    cccam_client_authenticate(client);

    size_t resp_len = cccam_handshake_get_response_len();
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
        cccam_ecm_send_cw(client->socket_fd, &response);
        cccam_user_manager_register_ecm(client->username, 1);
    } else {
        cccam_user_manager_register_ecm(client->username, 0);
    }
    return 0;
}

// --- Handlers Newcamd ---

static int handle_newcamd_login(cccam_client_t *client, const void *payload, size_t payload_len) {
    if (client->is_authenticated) {
        return 0;
    }

    if (!payload || payload_len < 2) {
        cccam_log(LOG_WARN, "Newcamd: Login com payload inválido");
        return -1;
    }

    const char *p = (const char *)payload;
    size_t user_len = strnlen(p, payload_len);
    if (user_len >= payload_len || user_len >= sizeof(client->username)) {
        return -1;
    }

    size_t pass_off = user_len + 1;
    if (pass_off >= payload_len) {
        return -1;
    }
    size_t pass_len = strnlen(p + pass_off, payload_len - pass_off);
    if (pass_len >= payload_len - pass_off || pass_len >= sizeof(client->password)) {
        return -1;
    }

    char username[64] = {0};
    char password[64] = {0};
    memcpy(username, p, user_len);
    memcpy(password, p + pass_off, pass_len);

    cccam_user_t *user = NULL;
    if (cccam_user_manager_authenticate(username, password, &user) != 0) {
        cccam_log(LOG_WARN, "Newcamd: Autenticação falhada para '%s'", username);
        return -1;
    }

    strncpy(client->username, username, sizeof(client->username) - 1);
    client->hop_count = user->max_hops;
    cccam_client_authenticate(client);

    uint8_t ack[256];
    size_t ack_len = sizeof(ack);
    if (cccam_newcamd_build(ack, &ack_len, NEWCAMD_CMD_LOGIN_ACK, (const uint8_t *)"OK", 2) != 0) {
        return -1;
    }
    if (send(client->socket_fd, ack, ack_len, MSG_NOSIGNAL) != (ssize_t)ack_len) {
        return -1;
    }

    cccam_log(LOG_INFO, "Newcamd: Cliente '%s' autenticado (nível %d, max hops %d)",
              username, user->level, user->max_hops);
    return 0;
}

static int handle_newcamd_ecm(cccam_client_t *client, const void *payload, size_t payload_len) {
    if (!client->is_authenticated) {
        cccam_log(LOG_WARN, "Newcamd: ECM de cliente não autenticado (ID %u)", client->client_id);
        return -1;
    }

    cccam_ecm_request_t request;
    if (parse_ecm_payload(payload, payload_len, &request) != 0) {
        cccam_log(LOG_WARN, "Newcamd: ECM com payload inválido (%zu bytes)", payload_len);
        return -1;
    }
    request.client_id = client->client_id;
    request.hop = client->hop_count;
    request.received_at = time(NULL);

    cccam_ecm_response_t response;
    int result = cccam_ecm_process(&request, &response);
    if (result == 0 && response.found) {
        uint8_t cw_payload[4 + 16 + 1 + 6] = {0};
        uint32_t ecm_time = htonl((uint32_t)response.generated_at);
        memcpy(cw_payload, &ecm_time, 4);
        memcpy(cw_payload + 4, response.cw, 16);
        cw_payload[20] = response.hop;
        cw_payload[21] = (uint8_t)(response.caid >> 8);
        cw_payload[22] = (uint8_t)(response.caid & 0xFF);
        cw_payload[23] = (uint8_t)(response.provid >> 8);
        cw_payload[24] = (uint8_t)(response.provid & 0xFF);
        cw_payload[25] = (uint8_t)(response.sid >> 8);
        cw_payload[26] = (uint8_t)(response.sid & 0xFF);

        uint8_t msg[CCCAM3_BUFFER_SIZE];
        size_t msg_len = sizeof(msg);
        if (cccam_newcamd_build(msg, &msg_len, NEWCAMD_CMD_CW, cw_payload, sizeof(cw_payload)) == 0) {
            send(client->socket_fd, msg, msg_len, MSG_NOSIGNAL);
        }
        cccam_user_manager_register_ecm(client->username, 1);
    } else {
        cccam_user_manager_register_ecm(client->username, 0);
    }
    return 0;
}

static void handle_newcamd_message(cccam_client_t *client) {
    uint8_t buffer[CCCAM3_BUFFER_SIZE];
    size_t msg_len = 0;

    uint8_t header[8];
    if (recv_exact(client->socket_fd, header, sizeof(header)) != 0) {
        cccam_log(LOG_INFO, "Newcamd: Cliente %u desligado", client->client_id);
        server_destroy_client(client);
        return;
    }

    uint32_t len_net;
    memcpy(&len_net, header + 4, 4);
    uint32_t payload_len = ntohl(len_net);
    if (payload_len > sizeof(buffer) - 8) {
        cccam_log(LOG_WARN, "Newcamd: Mensagem demasiado grande (%u bytes)", payload_len);
        server_destroy_client(client);
        return;
    }

    if (recv_exact(client->socket_fd, buffer + 8, payload_len) != 0) {
        cccam_log(LOG_INFO, "Newcamd: Cliente %u desligado", client->client_id);
        server_destroy_client(client);
        return;
    }
    memcpy(buffer, header, sizeof(header));
    msg_len = 8 + payload_len;

    uint32_t cmd_id = 0;
    uint8_t *payload = NULL;
    size_t parsed_payload_len = 0;
    if (cccam_newcamd_parse(buffer, msg_len, &cmd_id, &payload, &parsed_payload_len) != 0) {
        cccam_log(LOG_WARN, "Newcamd: Mensagem inválida do cliente %u", client->client_id);
        server_destroy_client(client);
        return;
    }

    int failed = 0;
    switch (cmd_id) {
        case NEWCAMD_CMD_LOGIN:
            failed = handle_newcamd_login(client, payload, parsed_payload_len);
            break;
        case NEWCAMD_CMD_ECM:
            failed = handle_newcamd_ecm(client, payload, parsed_payload_len);
            break;
        case NEWCAMD_CMD_KEEPALIVE:
            cccam_client_update_keepalive(client);
            break;
        default:
            cccam_log(LOG_DEBUG, "Newcamd: Comando 0x%02X ignorado do cliente %u", cmd_id, client->client_id);
            break;
    }

    free(payload);
    if (failed) {
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

    if (cccam_protocol_parse(buffer, msg_len, &header, &payload, &payload_len) != 0) {
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

        if (FD_ISSET(g_server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, &addr_len);

            if (client_fd < 0) {
                cccam_log(LOG_ERROR, "Falha ao aceitar cliente: %s", strerror(errno));
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
                    cccam_log(LOG_INFO, "Newcamd: Nova ligação de %s:%d (ID %u)",
                              inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client->client_id);
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
            cccam_cache_clean_expired();
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
        if (cccam_protocol_parse(buf, len, &hdr, &pl, &pl_len) != 0 ||
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

    if (failures == 0) {
        printf("Todos os testes passaram.\n");
        return 0;
    }
    printf("%d teste(s) falharam.\n", failures);
    return 1;
}

// Função main
int main(int argc, char *argv[]) {
    char *config_file = "conf/cccam3.conf";
    int opt;

    while ((opt = getopt(argc, argv, "c:htv")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'h':
                printf("CCcam3 %s\n", CCCAM3_VERSION);
                printf("Uso: %s [opções]\n", argv[0]);
                printf("  -c <file>  Ficheiro de configuração\n");
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

    cccam_log_init(config.log_file, config.log_level);
    cccam_print_config(&config);

    if (cccam3_init(&config) != 0) {
        cccam_log(LOG_ERROR, "Falha ao inicializar servidor");
        return 1;
    }

    int result = cccam3_run();
    cccam3_cleanup();
    cccam_log_close();

    return result;
}
