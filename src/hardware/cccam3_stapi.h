#ifndef CCCAM3_STAPI_H
#define CCCAM3_STAPI_H

#include <stdint.h>
#include <stddef.h>

int cccam_stapi_init(void);
void cccam_stapi_cleanup(void);
int cccam_stapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw);
int cccam_stapi_get_ecm(uint16_t *caid, uint16_t *sid, uint8_t *ecm_data, uint16_t *ecm_len);
int cccam_stapi_send(const uint8_t *data, size_t len);
int cccam_stapi_recv(uint8_t *buffer, size_t buf_len);

#endif // CCCAM3_STAPI_H
