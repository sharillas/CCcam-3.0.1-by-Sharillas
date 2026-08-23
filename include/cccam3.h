#ifndef CCCAM3_H
#define CCCAM3_H

#include "cccam3_structs.h"

// --- Constantes Globais ---
#define CCCAM3_VERSION "3.0.0"
#define CCCAM3_DEFAULT_PORT 12000
#define CCCAM3_MAX_CLIENTS 100
#define CCCAM3_BUFFER_SIZE 4096
#define CCCAM3_HEADER_SIZE 8

// --- IDs de Mensagens ---
#define CCCAM_MSG_LOGIN         0x01
#define CCCAM_MSG_LOGIN_ACK     0x02
#define CCCAM_MSG_ECM           0x03
#define CCCAM_MSG_CW            0x04
#define CCCAM_MSG_EMM           0x05
#define CCCAM_MSG_KEEPALIVE     0x06
#define CCCAM_MSG_CARD_DATA     0x07
#define CCCAM_MSG_SRV_DATA      0x08
#define CCCAM_MSG_CMD_0C        0x0C
#define CCCAM_MSG_CMD_0D        0x0D

// --- Modos de Encriptação ---
#define CCCAM_CRYPT_MODE_NONE   0x00
#define CCCAM_CRYPT_MODE_RC4    0x01
#define CCCAM_CRYPT_MODE_AES    0x02
#define CCCAM_CRYPT_MODE_RC6    0x03
#define CCCAM_CRYPT_MODE_IDEA   0x04
#define CCCAM_CRYPT_MODE_3DES   0x10
#define CCCAM_CRYPT_MODE_AES_GCM 0x11

// --- Funções Principais ---
int cccam3_init(cccam_config_t *config);
void cccam3_cleanup(void);
int cccam3_run(void);

#endif // CCCAM3_H
