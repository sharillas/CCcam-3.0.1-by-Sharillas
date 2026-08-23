#include "cccam3_crypto.h"
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/des.h>

// --- RC4 ---
int cccam_crypto_rc4(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, (int)key_len, key);
    RC4(&rc4_key, len, data, data);
    return 0;
}

// --- AES (ECB mode para simplificar, mas idealmente usar GCM) ---
int cccam_crypto_aes(uint8_t *data, size_t len, const uint8_t *key, 
                     size_t key_len, int encrypt) {
    AES_KEY aes_key;
    if (key_len == 16) {
        AES_set_encrypt_key(key, 128, &aes_key);
    } else if (key_len == 32) {
        AES_set_encrypt_key(key, 256, &aes_key);
    } else {
        return -1;
    }

    // Processar em blocos de 16 bytes
    for (size_t i = 0; i < len; i += 16) {
        if (encrypt) {
            AES_encrypt(data + i, data + i, &aes_key);
        } else {
            AES_decrypt(data + i, data + i, &aes_key);
        }
    }
    return 0;
}

// --- 3DES ---
int cccam_crypto_3des(uint8_t *data, size_t len, const uint8_t *key, 
                      size_t key_len, int encrypt) {
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock k1, k2, k3;

    if (key_len < 24) return -1;

    memcpy(k1, key, 8);
    memcpy(k2, key + 8, 8);
    memcpy(k3, key + 16, 8);

    DES_set_key(&k1, &ks1);
    DES_set_key(&k2, &ks2);
    DES_set_key(&k3, &ks3);

    // Processar em blocos de 8 bytes
    for (size_t i = 0; i < len; i += 8) {
        if (encrypt) {
            DES_ecb3_encrypt((DES_cblock *)(data + i), (DES_cblock *)(data + i),
                             &ks1, &ks2, &ks3, DES_ENCRYPT);
        } else {
            DES_ecb3_encrypt((DES_cblock *)(data + i), (DES_cblock *)(data + i),
                             &ks1, &ks2, &ks3, DES_DECRYPT);
        }
    }
    return 0;
}
