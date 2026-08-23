#ifndef CCCAM3_DVBAPI_H
#define CCCAM3_DVBAPI_H

#include <stdint.h>
#include <stddef.h>

// --- Funções ---

// Inicializa a DVB-API
int cccam_dvbapi_init(void);

// Limpa a DVB-API
void cccam_dvbapi_cleanup(void);

// Envia dados para o socket DVBAPI
int cccam_dvbapi_send(const uint8_t *data, size_t len);

// Recebe dados do socket DVBAPI
int cccam_dvbapi_recv(uint8_t *buffer, size_t buf_len);

// Escreve uma Control Word (CW) no descodificador
int cccam_dvbapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw);

#endif // CCCAM3_DVBAPI_H
