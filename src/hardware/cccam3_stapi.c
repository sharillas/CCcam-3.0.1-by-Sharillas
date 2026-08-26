#include "cccam3_stapi.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

// --- STAPI via libstapi.so (STLinux) ---
// API STPTI documentada no SDK STLinux. Os protótipos são declarados
// manualmente para evitar dependência dos headers proprietários.

typedef uint32_t ST_ErrorCode_t;
typedef uint32_t STPTI_Handle_t;
typedef uint32_t STPTI_ServiceType_t;
typedef uint32_t STPTI_DescramblerKeyNumber_t;

// STPTI_ServiceType_t (valores do SDK STLinux)
#define STPTI_SERVICE_DESCR_KEY_SET  0x02

typedef struct {
    STPTI_DescramblerKeyNumber_t DescramblerKeyNumber;
    uint32_t SessionID;
    uint8_t DescramblerKey[16];
} STPTI_DescramblerKeyParams_t;

typedef ST_ErrorCode_t (*stpti_init_fn)(void);
typedef ST_ErrorCode_t (*stpti_term_fn)(void);
typedef ST_ErrorCode_t (*stpti_open_fn)(const char *name, STPTI_Handle_t *handle);
typedef ST_ErrorCode_t (*stpti_close_fn)(STPTI_Handle_t handle);
typedef ST_ErrorCode_t (*stpti_service_fn)(STPTI_Handle_t handle,
                                           STPTI_ServiceType_t service,
                                           void *params);

static void *g_stapi_lib = NULL;
static stpti_init_fn p_STPTI_Init = NULL;
static stpti_term_fn p_STPTI_Term = NULL;
static stpti_open_fn p_STPTI_Open = NULL;
static stpti_close_fn p_STPTI_Close = NULL;
static stpti_service_fn p_STPTI_Service = NULL;
static STPTI_Handle_t g_stapi_handle = 0;
static char g_stapi_device[128] = "/dev/stapi";

void cccam_stapi_set_device(const char *device) {
    if (device && device[0] != '\0') {
        strncpy(g_stapi_device, device, sizeof(g_stapi_device) - 1);
        g_stapi_device[sizeof(g_stapi_device) - 1] = '\0';
    }
}

int cccam_stapi_init(void) {
    g_stapi_lib = dlopen("libstapi.so", RTLD_NOW | RTLD_GLOBAL);
    if (!g_stapi_lib) {
        cccam_log(LOG_WARN, "STAPI: libstapi.so não disponível (%s) - STAPI desativada",
                  dlerror());
        return -1;
    }

    p_STPTI_Init = (stpti_init_fn)dlsym(g_stapi_lib, "STPTI_Init");
    p_STPTI_Term = (stpti_term_fn)dlsym(g_stapi_lib, "STPTI_Term");
    p_STPTI_Open = (stpti_open_fn)dlsym(g_stapi_lib, "STPTI_Open");
    p_STPTI_Close = (stpti_close_fn)dlsym(g_stapi_lib, "STPTI_Close");
    p_STPTI_Service = (stpti_service_fn)dlsym(g_stapi_lib, "STPTI_Service");

    if (!p_STPTI_Init || !p_STPTI_Open || !p_STPTI_Service) {
        cccam_log(LOG_WARN, "STAPI: Símbolos STPTI em falta na libstapi.so");
        dlclose(g_stapi_lib);
        g_stapi_lib = NULL;
        return -1;
    }

    if (p_STPTI_Init() != 0) {
        cccam_log(LOG_WARN, "STAPI: STPTI_Init falhou");
        dlclose(g_stapi_lib);
        g_stapi_lib = NULL;
        return -1;
    }

    if (p_STPTI_Open(g_stapi_device, &g_stapi_handle) != 0 || g_stapi_handle == 0) {
        cccam_log(LOG_WARN, "STAPI: Falha ao abrir '%s' (sem hardware ST?)", g_stapi_device);
        if (p_STPTI_Term) p_STPTI_Term();
        dlclose(g_stapi_lib);
        g_stapi_lib = NULL;
        return -1;
    }

    cccam_log(LOG_INFO, "STAPI: Inicializada (%s)", g_stapi_device);
    return 0;
}

void cccam_stapi_cleanup(void) {
    if (g_stapi_lib) {
        if (g_stapi_handle && p_STPTI_Close) {
            p_STPTI_Close(g_stapi_handle);
            g_stapi_handle = 0;
        }
        if (p_STPTI_Term) p_STPTI_Term();
        dlclose(g_stapi_lib);
        g_stapi_lib = NULL;
        cccam_log(LOG_INFO, "STAPI: Limpeza concluída");
    }
}

int cccam_stapi_write_cw(uint16_t caid, uint16_t sid, const uint8_t *cw) {
    STPTI_DescramblerKeyParams_t params;

    if (!cw) {
        cccam_log(LOG_ERROR, "STAPI: CW nula recebida");
        return -1;
    }

    if (!g_stapi_lib || !g_stapi_handle) {
        cccam_log(LOG_WARN, "STAPI: Não inicializada (CW não injetada)");
        return -1;
    }

    // Define as duas chaves (par/ímpar) do descrambler
    for (int key = 0; key < 2; key++) {
        memset(&params, 0, sizeof(params));
        params.DescramblerKeyNumber = (STPTI_DescramblerKeyNumber_t)key;
        params.SessionID = (uint32_t)sid;
        memcpy(params.DescramblerKey, cw, 16);

        if (p_STPTI_Service(g_stapi_handle, STPTI_SERVICE_DESCR_KEY_SET, &params) != 0) {
            cccam_log(LOG_ERROR, "STAPI: STPTI_Service(DESCR_KEY_SET) falhou (chave %d)", key);
            return -1;
        }
    }

    cccam_log(LOG_DEBUG, "STAPI: CW injetada para CAID %04X SID %04X", caid, sid);
    return 0;
}
