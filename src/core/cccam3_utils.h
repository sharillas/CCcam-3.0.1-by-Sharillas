#ifndef CCCAM3_UTILS_H
#define CCCAM3_UTILS_H

#include <stdint.h>
#include <stddef.h>

uint32_t cccam_hton32(uint32_t host_val);
uint32_t cccam_ntoh32(uint32_t net_val);
uint16_t cccam_hton16(uint16_t host_val);
uint16_t cccam_ntoh16(uint16_t net_val);
void cccam_generate_seed(uint8_t *seed, size_t size);
void cccam_sha1(const uint8_t *data, size_t len, uint8_t *hash);
uint32_t cccam_hash_string(const char *str);

// Identificador da build (derivado de __DATE__/__TIME__ em cada compilação).
// Formato: "v31.08.2026.14:32"
const char *cccam3_build_id(void);

#endif // CCCAM3_UTILS_H
