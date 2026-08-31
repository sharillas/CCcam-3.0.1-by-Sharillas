#include "cccam3_utils.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

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
    if (size > 0 && RAND_bytes(seed, (int)size) == 1) {
        return;
    }
    srand((unsigned int)time(NULL) ^ (unsigned int)clock());
    for (size_t i = 0; i < size; i++) {
        seed[i] = (uint8_t)(rand() & 0xFF);
    }
}

void cccam_sha1(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(hash, &ctx);
}

uint32_t cccam_hash_string(const char *str) {
    uint32_t hash = 0x811c9dc5; // FNV-1a offset basis
    while (*str) {
        hash ^= (uint8_t)(*str++);
        hash *= 0x01000193; // FNV-1a prime
    }
    return hash;
}

// Identificador da build: converte __DATE__ ("Aug 31 2026") e __TIME__
// ("14:32:05") para "v31.08.2026.14:32". Atualiza automaticamente em
// cada compilação.
const char *cccam3_build_id(void) {
    static char id[32];
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    char month[4] = {0};
    int day = 0, year = 0, hour = 0, min = 0;

    sscanf(__DATE__, "%3s %d %d", month, &day, &year);
    sscanf(__TIME__, "%d:%d", &hour, &min);

    int mon = 1;
    for (int i = 0; i < 12; i++) {
        if (strcmp(month, months[i]) == 0) {
            mon = i + 1;
            break;
        }
    }

    snprintf(id, sizeof(id), "v%02d.%02d.%d.%02d:%02d", day, mon, year, hour, min);
    return id;
}
