#include "cccam3_crypto.h"
#include <string.h>
#include <openssl/evp.h>

// --- RC4 (estado contínuo por sessão) ---

int cccam_crypto_rc4_init(cccam_rc4_state_t *state, const uint8_t *key, size_t key_len) {
    if (!state || !key || key_len == 0 || key_len > 256) return -1;

    for (int i = 0; i < 256; i++) {
        state->s[i] = (uint8_t)i;
    }
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (uint8_t)(j + state->s[i] + key[i % key_len]);
        uint8_t tmp = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = tmp;
    }
    state->i = 0;
    state->j = 0;
    state->ready = 1;
    return 0;
}

int cccam_crypto_rc4_stream(cccam_rc4_state_t *state, uint8_t *data, size_t len) {
    if (!state || !state->ready || (!data && len > 0)) return -1;

    for (size_t n = 0; n < len; n++) {
        state->i = (uint8_t)(state->i + 1);
        state->j = (uint8_t)(state->j + state->s[state->i]);
        uint8_t tmp = state->s[state->i];
        state->s[state->i] = state->s[state->j];
        state->s[state->j] = tmp;
        uint8_t k = state->s[(uint8_t)(state->s[state->i] + state->s[state->j])];
        data[n] ^= k;
    }
    return 0;
}

// --- CBC (EVP, compatível com OpenSSL 1.1 e 3.x) ---

static int evp_cbc(const EVP_CIPHER *cipher, uint8_t *data, size_t len,
                   const uint8_t *key, const uint8_t *iv, int iv_len, int encrypt) {
    EVP_CIPHER_CTX *ctx;
    int out_len1 = 0, out_len2 = 0;
    uint8_t iv_copy[16];

    if (!data || !key || !iv || len == 0 || len % (size_t)iv_len != 0) return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    memcpy(iv_copy, iv, (size_t)iv_len);
    if (EVP_CipherInit_ex(ctx, cipher, NULL, key, iv_copy, encrypt) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); // sem padding: tamanhos já são múltiplos do bloco
    if (EVP_CipherUpdate(ctx, data, &out_len1, data, (int)len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CipherFinal_ex(ctx, data + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int cccam_crypto_aes_cbc(uint8_t *data, size_t len, const uint8_t *key, size_t key_len,
                         const uint8_t iv[16], int encrypt) {
    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_cbc();
    else if (key_len == 24) cipher = EVP_aes_192_cbc();
    else if (key_len == 32) cipher = EVP_aes_256_cbc();
    else return -1;
    return evp_cbc(cipher, data, len, key, iv, 16, encrypt);
}

int cccam_crypto_3des_cbc(uint8_t *data, size_t len, const uint8_t *key,
                          const uint8_t iv[8], int encrypt) {
    return evp_cbc(EVP_des_ede3_cbc(), data, len, key, iv, 8, encrypt);
}
