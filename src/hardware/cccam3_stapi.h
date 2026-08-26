#ifndef CCCAM3_STAPI_H
#define CCCAM3_STAPI_H

#include <stdint.h>
#include <stddef.h>

// --- STAPI (STMicroelectronics) ---
// Injeção de CWs via libstapi.so (STLinux). Sem a biblioteca ou sem
// hardware ST, as funções devolvem erro (não há dados simulados).

// Define o caminho do dispositivo STAPI (antes do init)
void cccam_stapi_set_device(const char *device);

int cccam_stapi_init(void);
void cccam_stapi_cleanup(void);

// Injeta uma CW (16 bytes: par + ímpar) no descrambler
int cccam_stapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw);

#endif // CCCAM3_STAPI_H
