#ifndef CCCAM3_DVBAPI_H
#define CCCAM3_DVBAPI_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

// --- DVBAPI (protocolo ca_pmt OSCam, modo "network") ---
// O CCcam3 escuta num socket UNIX (por omissão /tmp/camd.socket) e os
// descodificadores (Enigma2 etc.) ligam-se a ele, tal como no OSCam.

// --- Constantes ---
#define DVBAPI_SOCKET_PATH "/tmp/camd.socket"
#define DVBAPI_BUFFER_SIZE 8192
#define DVBAPI_DEFAULT_MAX_DEMUX 8

// --- Códigos de operação do protocolo ---
#define DVBAPI_AOT_CA_PMT      0x9F803200
#define DVBAPI_AOT_CA_STOP     0x9F803F04
#define DVBAPI_FILTER_DATA     0xFFFF0000
#define DVBAPI_CLIENT_INFO     0xFFFF0001
#define DVBAPI_SERVER_INFO     0xFFFF0002
#define DVBAPI_ECM_INFO        0xFFFF0003
#define DVBAPI_CA_SET_PID      0x40086f87
#define DVBAPI_CA_SET_DESCR    0x40106f86
#define DVBAPI_CA_SET_DESCR_MODE 0x400c6f88
#define DVBAPI_DMX_SET_FILTER  0x403c6f2b
#define DVBAPI_DMX_STOP        0x00006f2a

#define DVBAPI_PROTOCOL_VERSION 2

// --- Funções ---

// Define o caminho do socket DVBAPI (antes do init)
void cccam_dvbapi_set_socket_path(const char *path);

// Define o número máximo de demux (antes do init)
void cccam_dvbapi_set_max_demux(int max_demux);

// Inicializa a DVBAPI (cria o socket UNIX e escuta ligações)
int cccam_dvbapi_init(void);

// Limpa a DVB-API
void cccam_dvbapi_cleanup(void);

#endif // CCCAM3_DVBAPI_H
