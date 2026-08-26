#include "cccam3_crypto_advanced.h"
#include "cccam3_logger.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>

// --- AES-GCM ---

int cccam_crypto_aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                                  const uint8_t *key, size_t key_len,
                                  const uint8_t *iv, size_t iv_len,
                                  uint8_t *ciphertext, uint8_t *tag, size_t *tag_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ciphertext_len;

    if (!plaintext || !key || !iv || !ciphertext || !tag || !tag_len) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Seleciona o algoritmo AES com base no tamanho da chave
    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_gcm();
    else if (key_len == 24) cipher = EVP_aes_192_gcm();
    else if (key_len == 32) cipher = EVP_aes_256_gcm();
    else {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Inicializa a encriptação
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encripta os dados
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finaliza a encriptação
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Obtém o tag de autenticação
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *tag_len = 16;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int cccam_crypto_aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                                  const uint8_t *key, size_t key_len,
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *tag, size_t tag_len,
                                  uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;

    if (!ciphertext || !key || !iv || !tag || !plaintext) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_gcm();
    else if (key_len == 24) cipher = EVP_aes_192_gcm();
    else if (key_len == 32) cipher = EVP_aes_256_gcm();
    else {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Inicializa a decriptação
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Define o tag esperado
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decripta os dados
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finaliza e verifica o tag
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Autenticação falhou
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Gera um IV aleatório para AES-GCM
int cccam_crypto_generate_iv(uint8_t *iv, size_t iv_len) {
    if (!iv || iv_len != 12) return -1;
    return RAND_bytes(iv, iv_len);
}

// --- AES-GCM com AAD ---

int cccam_crypto_aes_gcm_encrypt_aad(const uint8_t *plaintext, size_t plaintext_len,
                                      const uint8_t *key, size_t key_len,
                                      const uint8_t *iv, size_t iv_len,
                                      const uint8_t *aad, size_t aad_len,
                                      uint8_t *ciphertext, uint8_t *tag, size_t *tag_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ciphertext_len;

    if (!plaintext || !key || !iv || !ciphertext || !tag || !tag_len) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_gcm();
    else if (key_len == 24) cipher = EVP_aes_192_gcm();
    else if (key_len == 32) cipher = EVP_aes_256_gcm();
    else {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *tag_len = 16;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int cccam_crypto_aes_gcm_decrypt_aad(const uint8_t *ciphertext, size_t ciphertext_len,
                                      const uint8_t *key, size_t key_len,
                                      const uint8_t *iv, size_t iv_len,
                                      const uint8_t *aad, size_t aad_len,
                                      const uint8_t *tag, size_t tag_len,
                                      uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;

    if (!ciphertext || !key || !iv || !tag || !plaintext) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) cipher = EVP_aes_128_gcm();
    else if (key_len == 24) cipher = EVP_aes_192_gcm();
    else if (key_len == 32) cipher = EVP_aes_256_gcm();
    else {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// --- RSA ---

// Gera par de chaves RSA
int cccam_crypto_rsa_generate_keypair(int bits, RSA **rsa) {
    if (!rsa) return -1;

    *rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if (!*rsa) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao gerar par de chaves RSA (%d bits)", bits);
        return -1;
    }

    cccam_log(LOG_DEBUG, "CCshare: Par de chaves RSA gerado (%d bits)", bits);
    return 0;
}

// Exporta chave pública RSA para formato PEM
int cccam_crypto_rsa_export_public_key(RSA *rsa, char **pem_out, size_t *pem_len) {
    if (!rsa || !pem_out || !pem_len) return -1;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;

    if (PEM_write_bio_RSA_PUBKEY(bio, rsa) != 1) {
        BIO_free(bio);
        return -1;
    }

    *pem_len = BIO_pending(bio);
    *pem_out = malloc(*pem_len + 1);
    if (!*pem_out) {
        BIO_free(bio);
        return -1;
    }

    BIO_read(bio, *pem_out, *pem_len);
    (*pem_out)[*pem_len] = '\0';
    BIO_free(bio);

    return 0;
}

// Importa chave pública RSA a partir de PEM
RSA *cccam_crypto_rsa_import_public_key(const char *pem, size_t pem_len) {
    if (!pem || pem_len == 0) return NULL;

    BIO *bio = BIO_new_mem_buf(pem, pem_len);
    if (!bio) return NULL;

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return rsa;
}

// Encripta dados com RSA
int cccam_crypto_rsa_encrypt(RSA *rsa, const uint8_t *data, size_t data_len,
                              uint8_t *ciphertext, size_t *ciphertext_len) {
    if (!rsa || !data || !ciphertext || !ciphertext_len) return -1;

    int rsa_size = RSA_size(rsa);
    if (*ciphertext_len < (size_t)rsa_size) {
        *ciphertext_len = rsa_size;
        return -2; // Buffer muito pequeno
    }

    int result = RSA_public_encrypt(data_len, data, ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result < 0) {
        cccam_log(LOG_ERROR, "CCshare: Falha na encriptação RSA");
        return -1;
    }

    *ciphertext_len = result;
    return 0;
}

// Decripta dados com RSA
int cccam_crypto_rsa_decrypt(RSA *rsa, const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext, size_t *plaintext_len) {
    if (!rsa || !ciphertext || !plaintext || !plaintext_len) return -1;

    int rsa_size = RSA_size(rsa);
    if (ciphertext_len != (size_t)rsa_size) {
        return -1;
    }

    int result = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result < 0) {
        cccam_log(LOG_ERROR, "CCshare: Falha na decriptação RSA");
        return -1;
    }

    *plaintext_len = result;
    return 0;
}

// Assina dados com RSA
int cccam_crypto_rsa_sign(RSA *rsa, const uint8_t *data, size_t data_len,
                           uint8_t *signature, size_t *signature_len) {
    if (!rsa || !data || !signature || !signature_len) return -1;

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, hash);

    unsigned int sig_len = RSA_size(rsa);
    int result = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, rsa);
    if (result != 1) {
        cccam_log(LOG_ERROR, "CCshare: Falha na assinatura RSA");
        return -1;
    }

    *signature_len = sig_len;
    return 0;
}

// Verifica assinatura RSA
int cccam_crypto_rsa_verify(RSA *rsa, const uint8_t *data, size_t data_len,
                             const uint8_t *signature, size_t signature_len) {
    if (!rsa || !data || !signature) return -1;

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, hash);

    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signature_len, rsa);
    if (result != 1) {
        cccam_log(LOG_WARN, "CCshare: Falha na verificação da assinatura RSA");
        return -1;
    }

    return 0;
}

// Liberta memória RSA
void cccam_crypto_rsa_free(RSA *rsa) {
    if (rsa) RSA_free(rsa);
}

// --- Funções Utilitárias ---

// Gera uma chave aleatória para AES
int cccam_crypto_generate_aes_key(uint8_t *key, size_t key_len) {
    if (!key || (key_len != 16 && key_len != 24 && key_len != 32)) return -1;
    return RAND_bytes(key, key_len);
}

// Derivada de chave simples (PBKDF2)
int cccam_crypto_derive_key(const char *password, const uint8_t *salt, size_t salt_len,
                             uint8_t *key, size_t key_len, int iterations) {
    if (!password || !salt || !key) return -1;

    return PKCS5_PBKDF2_HMAC(password, strlen(password),
                             salt, salt_len,
                             iterations, EVP_sha256(),
                             key_len, key);
}
