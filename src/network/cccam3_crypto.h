#ifndef CCCAM3_CRYPTO_H
#define CCCAM3_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Estado RC4 contínuo (keystream não é reiniciada entre mensagens)
typedef struct {
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
    int ready;
} cccam_rc4_state_t;

// RC4 com estado: a keystream continua entre chamadas (evita reutilização)
int cccam_crypto_rc4_init(cccam_rc4_state_t *state, const uint8_t *key, size_t key_len);
int cccam_crypto_rc4_stream(cccam_rc4_state_t *state, uint8_t *data, size_t len);

// AES-CBC (IV de 16 bytes por mensagem)
int cccam_crypto_aes_cbc(uint8_t *data, size_t len, const uint8_t *key, size_t key_len,
                         const uint8_t iv[16], int encrypt);

// 3DES-EDE-CBC (IV de 8 bytes por mensagem)
int cccam_crypto_3des_cbc(uint8_t *data, size_t len, const uint8_t *key,
                          const uint8_t iv[8], int encrypt);

#endif // CCCAM3_CRYPTO_H
