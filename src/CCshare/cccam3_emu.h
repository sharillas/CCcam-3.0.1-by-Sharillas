#ifndef CCCAM3_EMU_H
#define CCCAM3_EMU_H

#include <stdint.h>
#include <stddef.h>

// --- Motor de Emulação (SoftCam.Key) ---

// Inicializa o motor de emulação (carrega o ficheiro de chaves)
int cccam_emu_init(void);

// Limpa o motor de emulação
void cccam_emu_cleanup(void);

// Define o caminho do ficheiro SoftCam.Key (antes do init)
void cccam_emu_set_key_file(const char *path);

// Procura uma chave no armazenamento. Devolve o tamanho da chave ou 0.
// type: 'F', 'I' ou 'T'. provider: identificador de 24 bits.
// key_index: índice da chave (0-255). key_name: nome em texto (ex.: "08").
int cccam_emu_find_key(char type, uint32_t provider, const char *key_name,
                       uint8_t key_index, uint8_t *key_out, size_t key_out_size);

// Tenta resolver um ECM com o motor de emulação.
// Devolve 0 se a CW foi obtida (16 bytes em cw), -1 caso contrário.
int cccam_emu_get_cw(uint16_t caid, uint16_t provid, uint16_t sid,
                     const uint8_t *ecm, uint16_t ecm_len, uint8_t *cw);

// Número de chaves carregadas
int cccam_emu_get_key_count(void);

// Resultados internos do processamento de ECM (para estatísticas)
#define CCCAM_EMU_OK             0
#define CCCAM_EMU_NOT_SUPPORTED -1
#define CCCAM_EMU_KEY_NOT_FOUND -2
#define CCCAM_EMU_CORRUPT_DATA  -3
#define CCCAM_EMU_CHECKSUM_ERROR -4

#endif // CCCAM3_EMU_H
