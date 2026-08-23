#include "cccam3_dvbapi.h"
#include "cccam3_logger.h"
#include "cccam3_ecm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>
#include <linux/dvb/version.h>

// --- Constantes ---
#define DVBAPI_SOCKET_PATH "/tmp/camd.socket"
#define DVBAPI_BUFFER_SIZE 4096
#define DVBAPI_MAX_DEMUX 8

// --- Estruturas Internas ---
typedef struct {
    int fd;
    int demux_id;
    uint16_t caid;
    uint16_t sid;
    uint8_t enabled;
    uint8_t ecm_data[256];
    uint16_t ecm_len;
    time_t last_ecm;
} cccam_dvbapi_demux_t;

// --- Variáveis Globais ---
static int g_dvbapi_socket_fd = -1;
static cccam_dvbapi_demux_t g_demux[DVBAPI_MAX_DEMUX];
static int g_dvbapi_running = 0;
static pthread_t g_dvbapi_thread;

// --- Funções Auxiliares ---

// Converte CAID/SID para string legível
static void dvbapi_log_info(uint16_t caid, uint16_t sid, char *buffer, size_t size) {
    snprintf(buffer, size, "CAID %04X SID %04X", caid, sid);
}

// Inicializa um demux
static void dvbapi_demux_init(int idx) {
    memset(&g_demux[idx], 0, sizeof(cccam_dvbapi_demux_t));
    g_demux[idx].fd = -1;
    g_demux[idx].demux_id = idx;
    g_demux[idx].enabled = 0;
}

// Procura um demux por CAID/SID
static int dvbapi_demux_find(uint16_t caid, uint16_t sid) {
    for (int i = 0; i < DVBAPI_MAX_DEMUX; i++) {
        if (g_demux[i].enabled && g_demux[i].caid == caid && g_demux[i].sid == sid) {
            return i;
        }
    }
    return -1;
}

// Procura um demux livre
static int dvbapi_demux_find_free(void) {
    for (int i = 0; i < DVBAPI_MAX_DEMUX; i++) {
        if (!g_demux[i].enabled) {
            return i;
        }
    }
    return -1;
}

// --- Parsing de Mensagens DVBAPI ---

// Parse de uma mensagem ECM recebida do socket
static int dvbapi_parse_ecm(const uint8_t *buffer, size_t buf_len, 
                            uint16_t *caid, uint16_t *sid, 
                            uint8_t *ecm_data, uint16_t *ecm_len) {
    if (!buffer || buf_len < 6) return -1;

    // Formato: [cmd] [caid] [sid] [ecm_data...]
    uint8_t cmd = buffer[0];
    if (cmd != 0x00) return -1; // Não é ECM

    *caid = (buffer[1] << 8) | buffer[2];
    *sid = (buffer[3] << 8) | buffer[4];
    *ecm_len = buf_len - 5;
    
    if (*ecm_len > 256) *ecm_len = 256;
    memcpy(ecm_data, buffer + 5, *ecm_len);

    return 0;
}

// Constroi uma mensagem CW para enviar ao socket
static int dvbapi_build_cw(uint8_t *buffer, size_t *buf_len, const uint8_t *cw) {
    if (!buffer || !buf_len || !cw) return -1;

    // Formato: [cmd] [cw_odd] [cw_even]
    buffer[0] = 0x01; // Comando CW
    memcpy(buffer + 1, cw, 16); // CW (16 bytes)
    *buf_len = 17;

    return 0;
}

// --- Gestão do Socket DVBAPI ---

// Cria o socket e liga ao caminho
static int dvbapi_socket_connect(void) {
    struct sockaddr_un addr;
    
    g_dvbapi_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_dvbapi_socket_fd < 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao criar socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DVBAPI_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(g_dvbapi_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao ligar ao socket %s", DVBAPI_SOCKET_PATH);
        close(g_dvbapi_socket_fd);
        g_dvbapi_socket_fd = -1;
        return -1;
    }

    cccam_log(LOG_INFO, "DVBAPI: Ligado ao socket %s", DVBAPI_SOCKET_PATH);
    return 0;
}

// Fecha o socket
static void dvbapi_socket_close(void) {
    if (g_dvbapi_socket_fd >= 0) {
        close(g_dvbapi_socket_fd);
        g_dvbapi_socket_fd = -1;
    }
}

// --- Thread Principal da DVBAPI ---

static void *dvbapi_thread_func(void *arg) {
    (void)arg;
    
    uint8_t buffer[DVBAPI_BUFFER_SIZE];
    fd_set read_fds;

    cccam_log(LOG_INFO, "DVBAPI: Thread iniciada");

    while (g_dvbapi_running) {
        FD_ZERO(&read_fds);
        
        if (g_dvbapi_socket_fd >= 0) {
            FD_SET(g_dvbapi_socket_fd, &read_fds);
        }

        struct timeval tv = {1, 0};
        int activity = select(g_dvbapi_socket_fd + 1, &read_fds, NULL, NULL, &tv);

        if (activity < 0) {
            if (g_dvbapi_running) {
                cccam_log(LOG_ERROR, "DVBAPI: Erro no select");
            }
            break;
        }

        if (FD_ISSET(g_dvbapi_socket_fd, &read_fds)) {
            ssize_t received = recv(g_dvbapi_socket_fd, buffer, sizeof(buffer), 0);
            if (received > 0) {
                // Parse do ECM
                uint16_t caid, sid;
                uint8_t ecm_data[256];
                uint16_t ecm_len;
                
                if (dvbapi_parse_ecm(buffer, received, &caid, &sid, ecm_data, &ecm_len) == 0) {
                    cccam_log(LOG_DEBUG, "DVBAPI: ECM recebido para CAID %04X SID %04X", caid, sid);

                    // --- Processar ECM ---
                    cccam_ecm_request_t ecm_req;
                    memset(&ecm_req, 0, sizeof(ecm_req));
                    ecm_req.caid = caid;
                    ecm_req.sid = sid;
                    ecm_req.ecm_len = ecm_len;
                    memcpy(ecm_req.ecm_data, ecm_data, ecm_len);
                    ecm_req.received_at = time(NULL);
                    ecm_req.client_id = 0;
                    ecm_req.hop = 1;

                    cccam_ecm_response_t ecm_resp;
                    if (cccam_ecm_process(&ecm_req, &ecm_resp) == 0) {
                        // --- Enviar CW ---
                        uint8_t cw_buffer[32];
                        size_t cw_len = sizeof(cw_buffer);
                        if (dvbapi_build_cw(cw_buffer, &cw_len, ecm_resp.cw) == 0) {
                            send(g_dvbapi_socket_fd, cw_buffer, cw_len, 0);
                            cccam_log(LOG_DEBUG, "DVBAPI: CW enviada para CAID %04X SID %04X", caid, sid);
                        }
                    } else {
                        cccam_log(LOG_WARN, "DVBAPI: Falha ao processar ECM para CAID %04X SID %04X", caid, sid);
                    }
                }
            } else if (received == 0) {
                cccam_log(LOG_WARN, "DVBAPI: Ligação ao socket fechada");
                dvbapi_socket_close();
                // Tentar religar
                if (dvbapi_socket_connect() != 0) {
                    break;
                }
            }
        }

        // Limpeza de demux expirados
        time_t now = time(NULL);
        for (int i = 0; i < DVBAPI_MAX_DEMUX; i++) {
            if (g_demux[i].enabled && (now - g_demux[i].last_ecm) > 60) {
                // Desativa demux inativo
                g_demux[i].enabled = 0;
                cccam_log(LOG_DEBUG, "DVBAPI: Demux %d expirado (CAID %04X SID %04X)", 
                          i, g_demux[i].caid, g_demux[i].sid);
            }
        }
    }

    cccam_log(LOG_INFO, "DVBAPI: Thread terminada");
    return NULL;
}

// --- Funções Públicas ---

int cccam_dvbapi_init(void) {
    cccam_log(LOG_INFO, "DVBAPI: Inicializando (modo Direto)");

    // Inicializa demux
    for (int i = 0; i < DVBAPI_MAX_DEMUX; i++) {
        dvbapi_demux_init(i);
    }

    // Liga ao socket
    if (dvbapi_socket_connect() != 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao ligar ao socket");
        return -1;
    }

    // Inicia thread
    g_dvbapi_running = 1;
    if (pthread_create(&g_dvbapi_thread, NULL, dvbapi_thread_func, NULL) != 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao criar thread");
        dvbapi_socket_close();
        return -1;
    }

    cccam_log(LOG_INFO, "DVBAPI: Inicializada com sucesso");
    return 0;
}

void cccam_dvbapi_cleanup(void) {
    g_dvbapi_running = 0;
    if (g_dvbapi_thread) {
        pthread_join(g_dvbapi_thread, NULL);
        g_dvbapi_thread = 0;
    }
    dvbapi_socket_close();
    cccam_log(LOG_INFO, "DVBAPI: Limpeza concluída");
}

int cccam_dvbapi_send(const uint8_t *data, size_t len) {
    if (g_dvbapi_socket_fd < 0) return -1;
    ssize_t sent = write(g_dvbapi_socket_fd, data, len);
    if (sent != (ssize_t)len) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao enviar dados (%zd de %zu)", sent, len);
        return -1;
    }
    return 0;
}

int cccam_dvbapi_recv(uint8_t *buffer, size_t buf_len) {
    if (g_dvbapi_socket_fd < 0) return -1;
    ssize_t received = read(g_dvbapi_socket_fd, buffer, buf_len);
    if (received < 0) {
        cccam_log(LOG_ERROR, "DVBAPI: Falha ao receber dados");
        return -1;
    }
    return (int)received;
}

int cccam_dvbapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw) {
    if (!cw || g_dvbapi_socket_fd < 0) return -1;

    // Constrói e envia a CW
    uint8_t buffer[32];
    size_t buf_len = sizeof(buffer);
    if (dvbapi_build_cw(buffer, &buf_len, cw) != 0) {
        return -1;
    }

    return cccam_dvbapi_send(buffer, buf_len);
}
