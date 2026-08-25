#ifndef CCCAM3_DVBAPI_H
#define CCCAM3_DVBAPI_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

// --- Constantes ---
#define DVBAPI_SOCKET_PATH "/tmp/camd.socket"
#define DVBAPI_BUFFER_SIZE 4096
#define DVBAPI_MAX_DEMUX 8

// --- Estruturas ---
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

// --- Funções ---

// Inicializa a DVB-API
int cccam_dvbapi_init(void);

// Define o caminho do socket DVBAPI (antes do init)
void cccam_dvbapi_set_socket_path(const char *path);

// Limpa a DVB-API
void cccam_dvbapi_cleanup(void);

// Envia dados para o socket DVBAPI
int cccam_dvbapi_send(const uint8_t *data, size_t len);

// Recebe dados do socket DVBAPI
int cccam_dvbapi_recv(uint8_t *buffer, size_t buf_len);

// Escreve uma Control Word (CW) no descodificador
int cccam_dvbapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw);

#endif // CCCAM3_DVBAPI_H
