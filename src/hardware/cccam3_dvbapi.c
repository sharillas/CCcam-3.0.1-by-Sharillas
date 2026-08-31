// DVBAPI real (protocolo ca_pmt OSCam). O CCcam3 escuta no socket UNIX e os
// descodificadores ligam-se a ele. Baseado no README.dvbapi_protocol e no
// OSCam module-dvbapi.c (GPLv3).

#include "cccam3_dvbapi.h"
#include "cccam3_logger.h"
#include "cccam3_ecm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <pthread.h>
#include <time.h>

#define DVBAPI_MAX_ECM_PIDS 8

// --- Estado de um demux (canal em descodificação) ---
typedef struct {
    int used;
    uint16_t sid;
    uint16_t caid;
    uint32_t provid;
    uint16_t ecm_pid;
    uint16_t video_pid;
    uint16_t audio_pids[8];
    int audio_pid_count;
    time_t last_ecm;
} dvbapi_demux_t;

// --- Estado de uma ligação ---
typedef struct {
    int fd;
    int alive;
    dvbapi_demux_t demux;
} dvbapi_client_t;

// --- Variáveis Globais ---
static int g_listen_fd = -1;
static char g_socket_path[108] = DVBAPI_SOCKET_PATH;
static int g_max_demux = DVBAPI_DEFAULT_MAX_DEMUX;
static int g_running = 0;
static pthread_t g_thread;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static int g_active_clients = 0;
static dvbapi_client_t g_clients[DVBAPI_DEFAULT_MAX_DEMUX * 2];

void cccam_dvbapi_set_socket_path(const char *path) {
    if (path && path[0] != '\0') {
        strncpy(g_socket_path, path, sizeof(g_socket_path) - 1);
        g_socket_path[sizeof(g_socket_path) - 1] = '\0';
    }
}

void cccam_dvbapi_set_max_demux(int max_demux) {
    if (max_demux > 0 && max_demux <= 32) {
        g_max_demux = max_demux;
    }
}

// --- I/O ---

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

static int recv_all(int fd, uint8_t *buffer, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = read(fd, buffer + received, len - received);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        received += (size_t)n;
    }
    return 0;
}

// --- Construção de pacotes de resposta ---

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

// Envia CA_SET_DESCR (CW par + ímpar) para o descodificador
static int dvbapi_send_descr(int fd, const uint8_t *cw) {
    uint8_t packet[2 * (4 + 1 + 16)];
    size_t off = 0;

    for (int parity = 0; parity < 2; parity++) {
        put_be32(packet + off, DVBAPI_CA_SET_DESCR);
        off += 4;
        packet[off++] = 0;                      // adapter index
        put_be32(packet + off, 0);              // ca_descr.index
        off += 4;
        put_be32(packet + off, (uint32_t)parity); // ca_descr.parity (0=par, 1=ímpar)
        off += 4;
        memcpy(packet + off, cw + parity * 8, 8);
        off += 8;
    }

    return send_all(fd, packet, off);
}

// Envia CA_SET_PID para um PID de stream
static int dvbapi_send_pid(int fd, uint16_t pid, int32_t index) {
    uint8_t packet[4 + 1 + 8];
    put_be32(packet, DVBAPI_CA_SET_PID);
    packet[4] = 0;                       // adapter index
    put_be32(packet + 5, (uint32_t)pid); // ca_pid.pid (network byte order)
    uint32_t idx = (uint32_t)index;
    packet[9] = (uint8_t)(idx >> 24);
    packet[10] = (uint8_t)(idx >> 16);
    packet[11] = (uint8_t)(idx >> 8);
    packet[12] = (uint8_t)(idx & 0xFF);

    return send_all(fd, packet, sizeof(packet));
}

// Envia CA_SET_DESCR_MODE (DVBCSA/ECB)
static int dvbapi_send_descr_mode(int fd) {
    uint8_t packet[4 + 1 + 12];
    put_be32(packet, DVBAPI_CA_SET_DESCR_MODE);
    packet[4] = 0;                       // adapter index
    put_be32(packet + 5, 0);             // index
    put_be32(packet + 9, 0);             // algo = CA_ALGO_DVBCSA
    put_be32(packet + 13, 0);            // cipher_mode = CA_MODE_ECB

    return send_all(fd, packet, sizeof(packet));
}

// Pede ao descodificador para filtrar o PID de ECM
static int dvbapi_send_set_filter(int fd, uint16_t ecm_pid) {
    uint8_t packet[4 + 1 + 1 + 1 + 2 + 16 + 16 + 16 + 4 + 4];
    size_t off = 0;

    put_be32(packet + off, DVBAPI_DMX_SET_FILTER);
    off += 4;
    packet[off++] = 0;               // adapter index
    packet[off++] = 0;               // demux index
    packet[off++] = 0;               // filter number

    // dmx_sct_filter_params
    put_be16(packet + off, ecm_pid);
    off += 2;
    // filter: tabela 0x80/0x81 (par/ímpar)
    memset(packet + off, 0, 16);
    packet[off] = 0x80;
    off += 16;
    memset(packet + off, 0, 16);
    packet[off] = 0xF0;
    off += 16;
    memset(packet + off, 0, 16);     // mode
    off += 16;
    put_be32(packet + off, 0);       // timeout
    off += 4;
    put_be32(packet + off, 0);       // flags
    off += 4;

    return send_all(fd, packet, off);
}

// --- Parsing do CA_PMT ---

// O ca_pmt tem: [list_mgmt 1][program_number 2][version 1][prog_info_len 2(12 bits)]
// seguido dos descritores do programa.
static int dvbapi_parse_capmt(const uint8_t *data, size_t len, dvbapi_demux_t *demux) {
    if (len < 6) return -1;

    size_t pos = 0;
    uint8_t list_mgmt = data[pos++];
    (void)list_mgmt;
    uint16_t sid = get_be16(data + pos);
    pos += 2;
    pos++; // version
    uint16_t info_len = (uint16_t)(get_be16(data + pos) & 0x0FFF);
    pos += 2;

    if (pos + info_len > len) return -1;

    memset(demux, 0, sizeof(*demux));
    demux->used = 1;
    demux->sid = sid;
    demux->video_pid = 0;
    demux->audio_pid_count = 0;

    // Percorre os descritores do programa (CA 0x09, privado 0x81, ...)
    size_t end = pos + info_len;
    while (pos + 2 <= end) {
        uint8_t tag = data[pos];
        uint8_t dlen = data[pos + 1];
        if (pos + 2 + dlen > end) break;

        if (tag == 0x09 && dlen >= 4) {
            // CA descriptor: caid + ecmpid
            demux->caid = get_be16(data + pos + 2);
            demux->ecm_pid = (uint16_t)(get_be16(data + pos + 4) & 0x1FFF);
            if (dlen >= 6) {
                demux->provid = ((uint32_t)data[pos + 6] << 16) |
                                ((uint32_t)data[pos + 7] << 8) | data[pos + 8];
            }
        }
        pos += 2 + dlen;
    }

    // Streams elementares (vídeo/áudio)
    while (pos + 5 <= len) {
        uint8_t stream_type = data[pos];
        uint16_t es_pid = (uint16_t)(get_be16(data + pos + 1) & 0x1FFF);
        uint16_t es_info_len = (uint16_t)(get_be16(data + pos + 3) & 0x0FFF);
        pos += 5;
        if (pos + es_info_len > len) break;

        if (stream_type == 0x01 || stream_type == 0x02 || stream_type == 0x10 ||
            stream_type == 0x1B || stream_type == 0x24 || stream_type == 0x42) {
            if (demux->video_pid == 0) {
                demux->video_pid = es_pid;
            }
        } else if ((stream_type >= 0x03 && stream_type <= 0x06) ||
                   stream_type == 0x0F || stream_type == 0x11 || stream_type == 0x81) {
            if (demux->audio_pid_count < 8) {
                demux->audio_pids[demux->audio_pid_count++] = es_pid;
            }
        }
        pos += es_info_len;
    }

    if (demux->ecm_pid == 0 || demux->caid == 0) {
        cccam_log(LOG_WARN, "DVBAPI: CA_PMT sem ECM PID/CAID válidos (SID %04X)", sid);
        return -1;
    }

    demux->last_ecm = time(NULL);
    cccam_log(LOG_INFO, "DVBAPI: Canal SID %04X CAID %04X ECM PID %04X vídeo %04X",
              demux->sid, demux->caid, demux->ecm_pid, demux->video_pid);
    return 0;
}

// --- Thread de ligação ---

static void *dvbapi_client_thread(void *arg) {
    dvbapi_client_t *client = (dvbapi_client_t *)arg;
    uint8_t buffer[DVBAPI_BUFFER_SIZE];
    int fd = client->fd;

    cccam_log(LOG_INFO, "DVBAPI: Descodificador ligado (fd %d)", fd);

    while (g_running) {
        uint8_t opcode_hdr[4];
        if (recv_all(fd, opcode_hdr, 4) != 0) {
            break;
        }
        uint32_t opcode = get_be32(opcode_hdr);

        if ((opcode & 0xFFFFF000) == 0x9F803000) {
            // CA_PMT / CA_STOP: comprimento no byte menos significativo
            uint32_t data_len = opcode & 0x7F;
            if (data_len > sizeof(buffer) || recv_all(fd, buffer, data_len) != 0) {
                break;
            }

            if ((opcode & 0xFFFFFF00) == DVBAPI_AOT_CA_PMT) {
                if (dvbapi_parse_capmt(buffer, data_len, &client->demux) == 0) {
                    // Pede o filtro de ECM e associa os PIDs
                    dvbapi_send_set_filter(fd, client->demux.ecm_pid);
                    dvbapi_send_descr_mode(fd);
                    if (client->demux.video_pid) {
                        dvbapi_send_pid(fd, client->demux.video_pid, 0);
                    }
                    for (int i = 0; i < client->demux.audio_pid_count; i++) {
                        dvbapi_send_pid(fd, client->demux.audio_pids[i], i + 1);
                    }
                }
            } else if ((opcode & 0xFFFFFF00) == (DVBAPI_AOT_CA_STOP & 0xFFFFFF00)) {
                memset(&client->demux, 0, sizeof(client->demux));
                cccam_log(LOG_INFO, "DVBAPI: Descrambling parado (SID removido)");
            }
        } else if (opcode == DVBAPI_CLIENT_INFO) {
            // [version 2][name_len 1][name]
            uint8_t info_hdr[3];
            if (recv_all(fd, info_hdr, 3) != 0) break;
            uint32_t name_len = info_hdr[2];
            if (name_len > sizeof(buffer) - 1) name_len = sizeof(buffer) - 1;
            if (recv_all(fd, buffer, name_len) != 0) break;
            buffer[name_len] = '\0';
            cccam_log(LOG_INFO, "DVBAPI: Cliente: %s (protocolo v%d)",
                      (char *)buffer, get_be16(info_hdr));

            // Resposta SERVER_INFO: [opcode][version 2][name_len 1][name]
            uint8_t reply[4 + 2 + 1 + 32];
            size_t off = 0;
            put_be32(reply + off, DVBAPI_SERVER_INFO);
            off += 4;
            put_be16(reply + off, DVBAPI_PROTOCOL_VERSION);
            off += 2;
            const char *srv_name = "CCcam3";
            size_t srv_len = strlen(srv_name);
            reply[off++] = (uint8_t)srv_len;
            memcpy(reply + off, srv_name, srv_len);
            off += srv_len;
            send_all(fd, reply, off);
        } else if (opcode == DVBAPI_FILTER_DATA) {
            // [demux 1][filter 1][len 2 (12 bits)][dados]
            uint8_t fhdr[4];
            if (recv_all(fd, fhdr, 4) != 0) break;
            uint32_t sec_len = (uint32_t)((fhdr[2] << 8 | fhdr[3]) & 0x0FFF);
            if (sec_len > sizeof(buffer) || sec_len < 3) break;
            if (recv_all(fd, buffer, sec_len) != 0) break;

            // buffer = secção DVB completa (tabela 0x80/0x81)
            if (!client->demux.used) continue;

            cccam_ecm_request_t request;
            memset(&request, 0, sizeof(request));
            request.caid = client->demux.caid;
            request.provid = (uint16_t)(client->demux.provid & 0xFFFF);
            request.sid = client->demux.sid;
            request.ecm_len = (uint16_t)sec_len;
            if (request.ecm_len > CCCAM_ECM_MAX_SIZE) request.ecm_len = CCCAM_ECM_MAX_SIZE;
            memcpy(request.ecm_data, buffer, request.ecm_len);
            request.received_at = time(NULL);
            request.client_id = 0;
            request.hop = 0;

            cccam_ecm_response_t response;
            if (cccam_ecm_process(&request, &response) == 0 && response.found) {
                dvbapi_send_descr(fd, response.cw);
                client->demux.last_ecm = time(NULL);
                cccam_log(LOG_DEBUG, "DVBAPI: CW enviada para SID %04X", client->demux.sid);
            } else {
                cccam_log(LOG_DEBUG, "DVBAPI: ECM falhou para SID %04X", client->demux.sid);
            }
        } else {
            // Comando desconhecido: ignorar o payload se houver
            cccam_log(LOG_DEBUG, "DVBAPI: Opcode desconhecido 0x%08X", opcode);
            break;
        }
    }

    cccam_log(LOG_INFO, "DVBAPI: Descodificador desligado (fd %d)", fd);

    // O socket é fechado exatamente uma vez (aqui). O cleanup usa
    // shutdown() para acordar as threads, nunca close().
    pthread_mutex_lock(&g_lock);
    if (client->fd >= 0) {
        close(client->fd);
        client->fd = -1;
    }
    client->alive = 0;
    __atomic_sub_fetch(&g_active_clients, 1, __ATOMIC_RELAXED);
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

// --- Thread principal ---

static void *dvbapi_thread_func(void *arg) {
    (void)arg;

    g_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao criar socket: %s", strerror(errno));
        return NULL;
    }

    unlink(g_socket_path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path) - 1);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao bindar %s: %s", g_socket_path, strerror(errno));
        close(g_listen_fd);
        g_listen_fd = -1;
        return NULL;
    }

    if (listen(g_listen_fd, 8) < 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao escutar: %s", strerror(errno));
        close(g_listen_fd);
        g_listen_fd = -1;
        return NULL;
    }

    cccam_log(LOG_INFO, "DVBAPI: À escuta em %s", g_socket_path);

    while (g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_listen_fd, &read_fds);

        struct timeval tv = {1, 0};
        int activity = select(g_listen_fd + 1, &read_fds, NULL, NULL, &tv);
        if (activity < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (!FD_ISSET(g_listen_fd, &read_fds)) continue;

        int client_fd = accept(g_listen_fd, NULL, NULL);
        if (client_fd < 0) continue;

        // Encontra um slot livre
        pthread_mutex_lock(&g_lock);
        dvbapi_client_t *slot = NULL;
        for (int i = 0; i < (int)(sizeof(g_clients) / sizeof(g_clients[0])); i++) {
            if (!g_clients[i].alive) {
                slot = &g_clients[i];
                break;
            }
        }
        if (slot) {
            memset(slot, 0, sizeof(*slot));
            slot->fd = client_fd;
            slot->alive = 1;
            __atomic_add_fetch(&g_active_clients, 1, __ATOMIC_RELAXED);
            pthread_t t;
            pthread_create(&t, NULL, dvbapi_client_thread, slot);
            pthread_detach(t);
        } else {
            cccam_log(LOG_WARN, "DVBAPI: Limite de ligações atingido");
            close(client_fd);
        }
        pthread_mutex_unlock(&g_lock);
    }

    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    unlink(g_socket_path);
    cccam_log(LOG_INFO, "DVBAPI: Terminada");
    return NULL;
}

// --- Funções Públicas ---

int cccam_dvbapi_init(void) {
    memset(g_clients, 0, sizeof(g_clients));
    g_running = 1;

    if (pthread_create(&g_thread, NULL, dvbapi_thread_func, NULL) != 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao criar thread: %s", strerror(errno));
        g_running = 0;
        return -1;
    }

    return 0;
}

void cccam_dvbapi_cleanup(void) {
    g_running = 0;

    // Acorda as threads dos clientes com shutdown (nunca close aqui:
    // cada thread fecha o seu próprio fd exatamente uma vez)
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < (int)(sizeof(g_clients) / sizeof(g_clients[0])); i++) {
        if (g_clients[i].alive && g_clients[i].fd >= 0) {
            shutdown(g_clients[i].fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (g_thread) {
        pthread_join(g_thread, NULL);
        g_thread = 0;
    }

    // Espera que as threads de clientes (detached) terminem: podem estar
    // dentro do processamento de ECM, que usa a cache/leitores - têm de
    // sair antes do cleanup desses subsistemas
    pthread_mutex_lock(&g_lock);
    while (__atomic_load_n(&g_active_clients, __ATOMIC_RELAXED) > 0) {
        pthread_cond_wait(&g_cond, &g_lock);
    }
    pthread_mutex_unlock(&g_lock);

    cccam_log(LOG_INFO, "DVBAPI: Limpeza concluída");
}
