#include "cccam3.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define DVBAPI_SOCKET "/tmp/camd.socket"
#define DVBAPI_BUFFER_SIZE 4096

static int g_dvbapi_fd = -1;

int cccam_dvbapi_init(void) {
    struct sockaddr_un addr;
    
    g_dvbapi_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_dvbapi_fd < 0) {
        cccam_log(LOG_ERROR, "Falha ao criar socket DVBAPI");
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DVBAPI_SOCKET, sizeof(addr.sun_path) - 1);
    
    if (connect(g_dvbapi_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cccam_log(LOG_ERROR, "Falha ao ligar ao socket DVBAPI: %s", DVBAPI_SOCKET);
        close(g_dvbapi_fd);
        g_dvbapi_fd = -1;
        return -1;
    }
    
    cccam_log(LOG_INFO, "DVBAPI inicializado (%s)", DVBAPI_SOCKET);
    return 0;
}

void cccam_dvbapi_cleanup(void) {
    if (g_dvbapi_fd >= 0) {
        close(g_dvbapi_fd);
        g_dvbapi_fd = -1;
    }
}

int cccam_dvbapi_send(const uint8_t *data, size_t len) {
    if (g_dvbapi_fd < 0) return -1;
    ssize_t sent = write(g_dvbapi_fd, data, len);
    if (sent != (ssize_t)len) {
        cccam_log(LOG_ERROR, "Falha ao enviar dados DVBAPI (enviado %zd de %zu)", sent, len);
        return -1;
    }
    return 0;
}

int cccam_dvbapi_recv(uint8_t *buffer, size_t buf_len) {
    if (g_dvbapi_fd < 0) return -1;
    ssize_t received = read(g_dvbapi_fd, buffer, buf_len);
    if (received < 0) {
        cccam_log(LOG_ERROR, "Falha ao receber dados DVBAPI");
        return -1;
    }
    return (int)received;
}

int cccam_dvbapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw) {
    // TODO: Formatar e enviar a Control Word para o descodificador
    // Formato específico depende da implementação DVBAPI
    
    char cw_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(cw_hex + (i * 2), "%02x", cw[i]);
    }
    
    cccam_log(LOG_DEBUG, "DVBAPI: CW para CAID %04X SID %04X: %s", caid, sid, cw_hex);
    
    // Implementação real: enviar CW via DVBAPI
    return 0;
}
