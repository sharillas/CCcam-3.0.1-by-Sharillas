#ifndef CCCAM3_CRYPTO_H
#define CCCAM3_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

int cccam_crypto_rc4(uint8_t *data, size_t len, const uint8_t *key, size_t key_len);
int cccam_crypto_aes(uint8_t *data, size_t len, const uint8_t *key, size_t key_len, int encrypt);
int cccam_crypto_3des(uint8_t *data, size_t len, const uint8_t *key, size_t key_len, int encrypt);

#endif // CCCAM3_CRYPTO_H
