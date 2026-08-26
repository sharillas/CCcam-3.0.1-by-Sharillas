#ifndef CCCAM3_EMU_DES_H
#define CCCAM3_EMU_DES_H

#include <stdint.h>
#include <stddef.h>

// --- DES "nc_des" (Viaccess Eurocrypt) ---
// Modos usados pelo algoritmo Viaccess:
#define NC_DES_ECM_CRYPT 0
#define NC_DES_ECM_HASH  8

// Executa o DES Viaccess sobre 8 bytes de dados
void cccam_emu_nc_des(uint8_t *key, uint8_t mode, uint8_t *data);

// --- DES standard (OpenSSL-compatível no esquema de bytes do OSCam) ---
// Nota: usa a ordem de bytes interna do OSCam (as chaves Viaccess foram
// geradas para este esquema). Não usar com dados de outros protocolos.
#define CCCAM_EMU_DES_KEY_SCHEDULE_SIZE 32

int cccam_emu_des_set_key(const uint8_t *key, uint32_t *schedule);
void cccam_emu_des(uint8_t *data, const uint32_t *schedule, int do_encrypt);

// AES-128 ECB: decripta um bloco de 16 bytes
void cccam_emu_aes_decrypt_block(uint8_t *data, const uint8_t *key);

// Verifica o checksum interno de uma CW (byte 3 = soma dos 3 primeiros)
int cccam_emu_is_valid_dcw(const uint8_t *cw);

// --- DES do protocolo Newcamd (newcs/cs357x) ---

// Encripta uma mensagem Newcamd (padding aleatório + checksum + IV no fim).
// Devolve o novo tamanho ou -1 em erro. O encriptação começa no byte 2.
int cccam_newcamd_des_encrypt(uint8_t *buffer, int len, const uint8_t *deskey);

// Decripta uma mensagem Newcamd. Devolve o novo tamanho ou -1 se o
// checksum falhar (chave errada).
int cccam_newcamd_des_decrypt(uint8_t *buffer, int len, const uint8_t *deskey);

// Deriva a chave de sessão Newcamd: spread(key1 XOR key2[0..len]) → 16 bytes
void cccam_newcamd_login_key(const uint8_t *key1, const uint8_t *key2,
                             int len, uint8_t *des16);

#endif // CCCAM3_EMU_DES_H
