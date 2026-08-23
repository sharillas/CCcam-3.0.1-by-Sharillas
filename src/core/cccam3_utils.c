#include "cccam3_utils.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

uint32_t cccam_hton32(uint32_t host_val) {
    return htonl(host_val);
}

uint32_t cccam_ntoh32(uint32_t net_val) {
    return ntohl(net_val);
}

uint16_t cccam_hton16(uint16_t host_val) {
    return htons(host_val);
}

uint16_t cccam_ntoh16(uint16_t net_val) {
    return ntohs(net_val);
}

void cccam_generate_seed(uint8_t *seed, size_t size) {
    srand((unsigned int)time(NULL) ^ (unsigned int)clock());
    for (size_t i = 0; i < size; i++) {
        seed[i] = (uint8_t)(rand() & 0xFF);
    }
}

void cccam_sha1(const uint8_t *data, size_t len, uint8_t *hash) {
    // Implementação SHA-1 usando OpenSSL
    #ifdef USE_OPENSSL
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(hash, &ctx);
    #else
    // Fallback simples (apenas para demonstração)
    memset(hash, 0, 20);
    #endif
}

uint32_t cccam_hash_string(const char *str) {
    uint32_t hash = 0x811c9dc5; // FNV-1a offset basis
    while (*str) {
        hash ^= (uint8_t)(*str++);
        hash *= 0x01000193; // FNV-1a prime
    }
    return hash;
}
