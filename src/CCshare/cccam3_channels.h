#ifndef CCCAM3_CHANNELS_H
#define CCCAM3_CHANNELS_H

#include <stdint.h>

// --- Canais e Provedores (CCcam.providers + CCcam.channelinfo) ---
// Usado pelo painel web para mostrar o canal que cada cliente está a ver.

// Define os ficheiros antes do init
void cccam_channels_set_files(const char *providers_file, const char *channelinfo_file);

// Carrega os ficheiros
int cccam_channels_init(void);

// Limpa
void cccam_channels_cleanup(void);

// Devolve o nome do provedor (ou NULL). Ex.: caid 0500, provid 030B00 -> "TNTSAT"
const char *cccam_channels_get_provider(uint16_t caid, uint16_t provid);

// Devolve o nome do canal (ou NULL). Ex.: caid 0500, sid 2001 -> "TF1"
const char *cccam_channels_get_name(uint16_t caid, uint16_t provid, uint16_t sid);

// Número de entradas carregadas (para o painel)
int cccam_channels_get_count(void);

#endif // CCCAM3_CHANNELS_H
