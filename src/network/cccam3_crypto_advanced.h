#ifndef CCCAM3_CRYPTO_ADVANCED_H
#define CCCAM3_CRYPTO_ADVANCED_H

#include <openssl/rsa.h>
#include <stdint.h>
#include <stddef.h>

// --- AES-GCM ---

// Encripta dados com AES-GCM
int cccam_crypto_aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                                  const uint8_t *key, size_t key_len,
                                  const uint8_t *iv, size_t iv_len,
                                  uint8_t *ciphertext, uint8_t *tag, size_t *tag_len);

// Decripta dados com AES-GCM
int cccam_crypto_aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                                  const uint8_t *key, size_t key_len,
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *tag, size_t tag_len,
                                  uint8_t *plaintext);

// Gera um IV aleatório para AES-GCM (12 bytes)
int cccam_crypto_generate_iv(uint8_t *iv, size_t iv_len);

// Gera uma chave aleatória para AES
int cccam_crypto_generate_aes_key(uint8_t *key, size_t key_len);

// --- RSA ---

// Gera par de chaves RSA
int cccam_crypto_rsa_generate_keypair(int bits, RSA **rsa);

// Exporta chave pública RSA para formato PEM
int cccam_crypto_rsa_export_public_key(RSA *rsa, char **pem_out, size_t *pem_len);

// Importa chave pública RSA a partir de PEM
RSA *cccam_crypto_rsa_import_public_key(const char *pem, size_t pem_len);

// Encripta dados com RSA (chave pública)
int cccam_crypto_rsa_encrypt(RSA *rsa, const uint8_t *data, size_t data_len,
                              uint8_t *ciphertext, size_t *ciphertext_len);

// Decripta dados com RSA (chave privada)
int cccam_crypto_rsa_decrypt(RSA *rsa, const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext, size_t *plaintext_len);

// Assina dados com RSA (chave privada)
int cccam_crypto_rsa_sign(RSA *rsa, const uint8_t *data, size_t data_len,
                           uint8_t *signature, size_t *signature_len);

// Verifica assinatura RSA (chave pública)
int cccam_crypto_rsa_verify(RSA *rsa, const uint8_t *data, size_t data_len,
                             const uint8_t *signature, size_t signature_len);

// Liberta memória RSA
void cccam_crypto_rsa_free(RSA *rsa);

// --- Funções Utilitárias ---

// Derivada de chave (PBKDF2)
int cccam_crypto_derive_key(const char *password, const uint8_t *salt, size_t salt_len,
                             uint8_t *key, size_t key_len, int iterations);

#endif // CCCAM3_CRYPTO_ADVANCED_H
