#include "cccam3_handshake_advanced.h"
#include "cccam3_crypto_advanced.h"
#include "cccam3_crypto.h"
#include "cccam3_utils.h"
#include "cccam3_logger.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// --- Variáveis Globais ---
static RSA *g_server_rsa_key = NULL;
static uint8_t g_session_key[32];
static size_t g_session_key_len = 0;
static uint8_t g_handshake_mode = HANDSHAKE_MODE_LEGACY;

// Protege o estado global do handshake (usado por várias threads)
static pthread_mutex_t g_handshake_mutex = PTHREAD_MUTEX_INITIALIZER;

void cccam_handshake_lock(void) {
    pthread_mutex_lock(&g_handshake_mutex);
}

void cccam_handshake_unlock(void) {
    pthread_mutex_unlock(&g_handshake_mutex);
}

// --- Funções Auxiliares ---

// Gera seed aleatória para handshake
static void generate_seed(uint8_t *seed, size_t size) {
    RAND_bytes(seed, size);
}

// Deriva chave de sessão usando PBKDF2
static void derive_session_key(const char *password, const uint8_t *salt, size_t salt_len,
                               uint8_t *key, size_t key_len) {
    cccam_crypto_derive_key(password, salt, salt_len, key, key_len, 10000);
}

// --- Funções Principais ---

int cccam_handshake_advanced_init(void) {
    // Gera par de chaves RSA para o servidor
    if (cccam_crypto_rsa_generate_keypair(2048, &g_server_rsa_key) != 0) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao gerar chave RSA para handshake");
        return -1;
    }

    // Exporta chave pública para uso futuro
    char *pem = NULL;
    size_t pem_len = 0;
    if (cccam_crypto_rsa_export_public_key(g_server_rsa_key, &pem, &pem_len) == 0) {
        cccam_log(LOG_DEBUG, "CCshare: Chave RSA do servidor gerada e exportada");
        free(pem);
    }

    g_handshake_mode = HANDSHAKE_MODE_LEGACY;
    memset(g_session_key, 0, sizeof(g_session_key));
    g_session_key_len = 0;

    cccam_log(LOG_INFO, "CCshare: Handshake avançado inicializado (RSA 2048 bits)");
    return 0;
}

void cccam_handshake_advanced_cleanup(void) {
    if (g_server_rsa_key) {
        cccam_crypto_rsa_free(g_server_rsa_key);
        g_server_rsa_key = NULL;
    }
    memset(g_session_key, 0, sizeof(g_session_key));
    g_session_key_len = 0;
    cccam_log(LOG_INFO, "CCshare: Handshake avançado limpo");
}

// --- Handshake RSA ---

int cccam_handshake_rsa_server(cccam_login_msg_t *login, uint8_t *response_handshake, size_t response_size) {
    if (!login || !response_handshake || response_size < 16 + 12 + 16 + 16) {
        cccam_log(LOG_ERROR, "CCshare: Handshake RSA - parâmetros inválidos");
        return -1;
    }

    cccam_log(LOG_INFO, "CCshare: Handshake RSA iniciado com cliente %s", login->username);

    // 1. Gerar seed do servidor
    uint8_t server_seed[16];
    generate_seed(server_seed, sizeof(server_seed));
    memcpy(response_handshake, server_seed, 16);

    // 2. Derivar chave de sessão usando PBKDF2
    uint8_t salt[32];
    memcpy(salt, login->handshake, 16);
    memcpy(salt + 16, server_seed, 16);
    
    uint8_t session_key[32];
    derive_session_key(login->password, salt, sizeof(salt), session_key, sizeof(session_key));
    memcpy(g_session_key, session_key, sizeof(session_key));
    g_session_key_len = sizeof(session_key);

    // 3. Definir modo de handshake
    g_handshake_mode = HANDSHAKE_MODE_RSA_AES;

    // 4. Encriptar a resposta com AES-GCM (usando a chave derivada)
    uint8_t iv[12];
    generate_seed(iv, sizeof(iv));
    memcpy(response_handshake + 16, iv, 12);

    uint8_t tag[16];
    size_t tag_len = sizeof(tag);
    uint8_t plaintext[16];
    memcpy(plaintext, server_seed, 16);

    cccam_crypto_aes_gcm_encrypt(plaintext, sizeof(plaintext),
                                  session_key, sizeof(session_key),
                                  iv, sizeof(iv),
                                  response_handshake + 16 + 12,
                                  tag, &tag_len);
    memcpy(response_handshake + 16 + 12 + 16, tag, 16);

    cccam_log(LOG_DEBUG, "CCshare: Handshake RSA concluído com sucesso");
    return 0;
}

int cccam_handshake_rsa_client(cccam_login_msg_t *login, const uint8_t *server_handshake) {
    if (!login || !server_handshake) {
        return -1;
    }

    // 1. Extrair seed do servidor e IV
    uint8_t server_seed[16];
    memcpy(server_seed, server_handshake, 16);
    uint8_t iv[12];
    memcpy(iv, server_handshake + 16, 12);
    uint8_t tag[16];
    memcpy(tag, server_handshake + 16 + 12 + 16, 16);

    // 2. Derivar a mesma chave de sessão
    uint8_t salt[32];
    memcpy(salt, login->handshake, 16);
    memcpy(salt + 16, server_seed, 16);
    
    uint8_t session_key[32];
    derive_session_key(login->password, salt, sizeof(salt), session_key, sizeof(session_key));
    memcpy(g_session_key, session_key, sizeof(session_key));
    g_session_key_len = sizeof(session_key);

    // 3. Verificar o tag (decrypt do server_seed)
    uint8_t plaintext[16];
    if (cccam_crypto_aes_gcm_decrypt(server_handshake + 16 + 12, 16,
                                      session_key, sizeof(session_key),
                                      iv, sizeof(iv),
                                      tag, 16,
                                      plaintext) < 0) {
        cccam_log(LOG_WARN, "CCshare: Falha na autenticação do handshake RSA");
        return -1;
    }

    // 4. Verificar server_seed
    if (memcmp(plaintext, server_seed, 16) != 0) {
        cccam_log(LOG_WARN, "CCshare: Handshake RSA - seed do servidor inválida");
        return -1;
    }

    g_handshake_mode = HANDSHAKE_MODE_RSA_AES;
    cccam_log(LOG_DEBUG, "CCshare: Handshake RSA cliente concluído");
    return 0;
}

// --- Handshake Legado (compatibilidade) ---

int cccam_handshake_legacy_server(cccam_login_msg_t *login, uint8_t *response_handshake, size_t response_size) {
    if (!login || !response_handshake || response_size < 16) {
        return -1;
    }

    cccam_log(LOG_INFO, "CCshare: Handshake legado iniciado com cliente %s", login->username);

    // 1. Gerar seed do servidor
    generate_seed(response_handshake, 16);

    // 2. Derivar chave usando SHA1 (compatível com CCcam original)
    uint8_t combined[16 + 16 + 64];
    memcpy(combined, login->handshake, 16);
    memcpy(combined + 16, response_handshake, 16);
    strcpy((char *)combined + 32, login->password);

    uint8_t crypto_key[20];
    cccam_sha1(combined, 32 + strlen(login->password), crypto_key);
    memcpy(g_session_key, crypto_key, 20);
    g_session_key_len = 20;

    g_handshake_mode = HANDSHAKE_MODE_LEGACY;
    cccam_log(LOG_DEBUG, "CCshare: Handshake legado concluído");
    return 0;
}

int cccam_handshake_legacy_client(cccam_login_msg_t *login, const uint8_t *server_handshake) {
    if (!login || !server_handshake) {
        return -1;
    }

    uint8_t combined[16 + 16 + 64];
    memcpy(combined, login->handshake, 16);
    memcpy(combined + 16, server_handshake, 16);
    strcpy((char *)combined + 32, login->password);

    uint8_t crypto_key[20];
    cccam_sha1(combined, 32 + strlen(login->password), crypto_key);
    memcpy(g_session_key, crypto_key, 20);
    g_session_key_len = 20;

    g_handshake_mode = HANDSHAKE_MODE_LEGACY;
    return 0;
}

// --- Funções de Negociação ---

uint8_t cccam_handshake_negotiate_mode(uint8_t client_mode) {
    // Prioridade: RSA_AES > AES_GCM > AES > RC4 > LEGACY
    if (client_mode & HANDSHAKE_MODE_RSA_AES) {
        g_handshake_mode = HANDSHAKE_MODE_RSA_AES;
        cccam_log(LOG_DEBUG, "CCshare: Modo RSA_AES selecionado");
        return HANDSHAKE_MODE_RSA_AES;
    } else if (client_mode & HANDSHAKE_MODE_AES_GCM) {
        g_handshake_mode = HANDSHAKE_MODE_AES_GCM;
        cccam_log(LOG_DEBUG, "CCshare: Modo AES_GCM selecionado");
        return HANDSHAKE_MODE_AES_GCM;
    } else if (client_mode & HANDSHAKE_MODE_AES) {
        g_handshake_mode = HANDSHAKE_MODE_AES;
        cccam_log(LOG_DEBUG, "CCshare: Modo AES selecionado");
        return HANDSHAKE_MODE_AES;
    } else if (client_mode & HANDSHAKE_MODE_RC4) {
        g_handshake_mode = HANDSHAKE_MODE_RC4;
        cccam_log(LOG_DEBUG, "CCshare: Modo RC4 selecionado");
        return HANDSHAKE_MODE_RC4;
    } else {
        g_handshake_mode = HANDSHAKE_MODE_LEGACY;
        cccam_log(LOG_DEBUG, "CCshare: Modo LEGACY selecionado");
        return HANDSHAKE_MODE_LEGACY;
    }
}

// --- Funções de Encriptação ---

uint8_t cccam_handshake_get_mode(void) {
    return g_handshake_mode;
}

size_t cccam_handshake_get_response_len(void) {
    if (g_handshake_mode >= HANDSHAKE_MODE_RSA_AES) {
        return 16 + 12 + 16 + 16;
    }
    return 16;
}

int cccam_handshake_get_session_key(uint8_t *key, size_t *key_len) {
    if (!key || !key_len) {
        return -1;
    }
    if (g_session_key_len == 0) {
        return -1;
    }
    if (*key_len < g_session_key_len) {
        *key_len = g_session_key_len;
        return -1;
    }
    memcpy(key, g_session_key, g_session_key_len);
    *key_len = g_session_key_len;
    return 0;
}

int cccam_handshake_encrypt(uint8_t *data, size_t *len, size_t capacity) {
    if (!data || !len || *len == 0) return -1;

    switch (g_handshake_mode) {
        case HANDSHAKE_MODE_RSA_AES:
        case HANDSHAKE_MODE_AES_GCM:
            // AES-GCM com chave de sessão
            if (capacity < *len + 12 + 16) {
                cccam_log(LOG_ERROR, "CCshare: Buffer insuficiente para encriptação AES-GCM");
                return -1;
            }
            {
                uint8_t iv[12];
                generate_seed(iv, sizeof(iv));
                uint8_t tag[16];
                size_t tag_len = sizeof(tag);
                uint8_t *ciphertext = malloc(*len + 16);
                if (!ciphertext) return -1;

                int result = cccam_crypto_aes_gcm_encrypt(data, *len,
                                                           g_session_key, g_session_key_len,
                                                           iv, sizeof(iv),
                                                           ciphertext, tag, &tag_len);
                if (result < 0) {
                    free(ciphertext);
                    return -1;
                }

                // Substitui dados originais: IV + Ciphertext + Tag
                memcpy(data, iv, sizeof(iv));
                memcpy(data + sizeof(iv), ciphertext, *len);
                memcpy(data + sizeof(iv) + *len, tag, tag_len);
                free(ciphertext);
                *len = *len + sizeof(iv) + tag_len;
                return 0;
            }
        case HANDSHAKE_MODE_AES:
            if (*len % 16 != 0) {
                return -1;
            }
            return cccam_crypto_aes(data, *len, g_session_key, g_session_key_len, 1);
        case HANDSHAKE_MODE_RC4:
            return cccam_crypto_rc4(data, *len, g_session_key, g_session_key_len);
        case HANDSHAKE_MODE_LEGACY:
        default:
            return 0;
    }
}

int cccam_handshake_decrypt(uint8_t *data, size_t *len) {
    if (!data || !len || *len == 0) return -1;

    switch (g_handshake_mode) {
        case HANDSHAKE_MODE_RSA_AES:
        case HANDSHAKE_MODE_AES_GCM:
            // AES-GCM com chave de sessão
            if (*len < 12 + 16) return -1;
            {
                uint8_t iv[12];
                memcpy(iv, data, 12);
                uint8_t tag[16];
                memcpy(tag, data + *len - 16, 16);
                size_t ciphertext_len = *len - 12 - 16;
                uint8_t *plaintext = malloc(ciphertext_len + 1);
                if (!plaintext) return -1;

                int result = cccam_crypto_aes_gcm_decrypt(data + 12, ciphertext_len,
                                                           g_session_key, g_session_key_len,
                                                           iv, sizeof(iv),
                                                           tag, 16,
                                                           plaintext);
                if (result < 0) {
                    free(plaintext);
                    return -1;
                }

                memcpy(data, plaintext, ciphertext_len);
                free(plaintext);
                *len = ciphertext_len;
                return 0;
            }
        case HANDSHAKE_MODE_AES:
            if (*len % 16 != 0) {
                return -1;
            }
            return cccam_crypto_aes(data, *len, g_session_key, g_session_key_len, 0);
        case HANDSHAKE_MODE_RC4:
            return cccam_crypto_rc4(data, *len, g_session_key, g_session_key_len);
        case HANDSHAKE_MODE_LEGACY:
        default:
            return 0;
    }
}

// --- Assinatura de CWs ---

int cccam_handshake_sign_cw(uint8_t *cw, size_t cw_len, uint8_t *signature, size_t *sig_len) {
    if (!cw || !signature || !sig_len || !g_server_rsa_key) {
        return -1;
    }

    return cccam_crypto_rsa_sign(g_server_rsa_key, cw, cw_len, signature, sig_len);
}

int cccam_handshake_verify_cw(uint8_t *cw, size_t cw_len, uint8_t *signature, size_t sig_len) {
    if (!cw || !signature || !g_server_rsa_key) {
        return -1;
    }

    return cccam_crypto_rsa_verify(g_server_rsa_key, cw, cw_len, signature, sig_len);
}
