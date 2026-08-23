#include "cccam3.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <string.h>

// Nota: Este ficheiro é específico para hardware STMicroelectronics (STAPI)
// As funções reais dependem da SDK da ST

int cccam_stapi_init(void) {
    cccam_log(LOG_INFO, "STAPI inicializada (modo stub)");
    // TODO: Implementar inicialização STAPI
    // Exemplo: stapi_init();
    return 0;
}

void cccam_stapi_cleanup(void) {
    cccam_log(LOG_INFO, "STAPI cleanup (modo stub)");
    // TODO: Implementar cleanup STAPI
}

int cccam_stapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw) {
    // TODO: Implementar injeção de CW via STAPI
    // Exemplo: stapi_set_descrambler(caid, sid, cw);
    
    char cw_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(cw_hex + (i * 2), "%02x", cw[i]);
    }
    
    cccam_log(LOG_DEBUG, "STAPI: CW para CAID %04X SID %04X: %s", caid, sid, cw_hex);
    return 0;
}

int cccam_stapi_get_ecm(uint16_t *caid, uint16_t *sid, uint8_t *ecm_data, uint16_t *ecm_len) {
    // TODO: Implementar leitura de ECM via STAPI
    // Exemplo: stapi_get_ecm(caid, sid, ecm_data, ecm_len);
    
    // Modo stub: retorna dados simulados
    static int counter = 0;
    counter++;
    
    *caid = 0x0100;  // SECA
    *sid = 0x0001;
    *ecm_len = 32;
    memset(ecm_data, 0xAA, 32);
    
    cccam_log(LOG_DEBUG, "STAPI: ECM obtido (stub)");
    return 0;
}
