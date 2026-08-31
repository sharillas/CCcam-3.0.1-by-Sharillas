#include "cccam3_emu.h"
#include "cccam3_ecm.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>

// Algoritmos por sistema de acesso condicional
int cccam_emu_viaccess_ecm(const uint8_t *ecm, uint16_t ecm_len, uint8_t *dw);
int cccam_emu_biss_ecm(uint16_t caid, uint16_t sid, const uint8_t *ecm,
                       uint16_t ecm_len, uint8_t *dw);
int cccam_emu_cryptoworks_ecm(uint32_t caid, uint8_t *ecm, uint8_t *cw);
int cccam_emu_powervu_ecm(uint16_t caid, uint16_t sid, const uint8_t *ecm,
                          uint16_t ecm_len, uint8_t *dw);
int cccam_emu_powervu_emm(uint16_t caid, const uint8_t *emm, uint16_t emm_len);
int cccam_emu_nagravision_ecm(uint16_t caid, uint8_t *ecm, uint8_t *dw);
int cccam_emu_irdeto_ecm(uint16_t caid, uint8_t *ecm, uint8_t *dw);
int cccam_emu_irdeto_emm(uint16_t caid, const uint8_t *oemm, uint16_t emm_len);

// --- Estrutura de Chaves ---

#define CCCAM_EMU_MAX_KEYS  4096
#define CCCAM_EMU_MAX_KEY_DATA 320  // chaves T do Viaccess têm 300 bytes

typedef struct cccam_emu_key {
    char type;                  // 'F', 'I', 'T', 'W' ou 'P'
    uint32_t provider;          // identificador (24 ou 32 bits)
    uint8_t key_index;          // índice da chave (0-255)
    char name[12];              // nome alternativo (ex.: UA PowerVU, 8 hex)
    uint32_t date;              // data de expiração YYYYMMDD (0 = sem data)
    uint8_t data[CCCAM_EMU_MAX_KEY_DATA];
    uint8_t data_len;
    struct cccam_emu_key *next;
} cccam_emu_key_t;

static cccam_emu_key_t *g_emu_keys = NULL;
static int g_emu_key_count = 0;
static char g_emu_key_file[256] = "conf/SoftCam.Key";
static int g_emu_initialized = 0;

// As chaves são consultadas por várias threads (ECMs) e atualizadas por
// EMMs (processamento local) — mutex próprio
static pthread_mutex_t g_emu_mutex = PTHREAD_MUTEX_INITIALIZER;

void cccam_emu_set_key_file(const char *path) {
    if (path && path[0] != '\0') {
        strncpy(g_emu_key_file, path, sizeof(g_emu_key_file) - 1);
        g_emu_key_file[sizeof(g_emu_key_file) - 1] = '\0';
    }
}

static void emu_free_keys(void) {
    cccam_emu_key_t *current = g_emu_keys;
    while (current) {
        cccam_emu_key_t *next = current->next;
        free(current);
        current = next;
    }
    g_emu_keys = NULL;
    g_emu_key_count = 0;
}

static int hex_to_bin(const char *hex, uint8_t *out, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_len) {
        return -1;
    }
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }
    return (int)(len / 2);
}

static void emu_add_key(char type, uint32_t provider, uint8_t key_index,
                        const uint8_t *data, uint8_t data_len, uint32_t date,
                        const char *name) {
    if (g_emu_key_count >= CCCAM_EMU_MAX_KEYS) {
        cccam_log(LOG_WARN, "EMU: Limite de chaves atingido (%d)", CCCAM_EMU_MAX_KEYS);
        return;
    }

    pthread_mutex_lock(&g_emu_mutex);

    // Substitui chave idêntica existente (por nome ou por índice)
    cccam_emu_key_t *current = g_emu_keys;
    while (current) {
        int match = (current->type == type && current->provider == provider &&
                     current->key_index == key_index);
        if (name && name[0] != '\0' && current->name[0] != '\0') {
            match = (current->type == type && current->provider == provider &&
                     strcmp(current->name, name) == 0);
        }
        if (match) {
            memcpy(current->data, data, data_len);
            current->data_len = data_len;
            current->date = date;
            if (name) {
                snprintf(current->name, sizeof(current->name), "%s", name);
            }
            pthread_mutex_unlock(&g_emu_mutex);
            return;
        }
        current = current->next;
    }

    cccam_emu_key_t *key = calloc(1, sizeof(cccam_emu_key_t));
    if (!key) {
        pthread_mutex_unlock(&g_emu_mutex);
        return;
    }

    key->type = type;
    key->provider = provider;
    key->key_index = key_index;
    if (name) {
        snprintf(key->name, sizeof(key->name), "%s", name);
    }
    memcpy(key->data, data, data_len);
    key->data_len = data_len;
    key->date = date;
    key->next = g_emu_keys;
    g_emu_keys = key;
    g_emu_key_count++;

    pthread_mutex_unlock(&g_emu_mutex);
}

// Data atual em formato YYYYMMDD
static uint32_t emu_current_date(void) {
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    return (uint32_t)((tm_info.tm_year + 1900) * 10000 +
                      (tm_info.tm_mon + 1) * 100 + tm_info.tm_mday);
}

// Devolve 0 se a chave tiver expirado (data no passado)
static int emu_key_valid(const cccam_emu_key_t *key) {
    if (key->date == 0) {
        return 1;
    }
    return emu_current_date() <= key->date;
}

int cccam_emu_find_key(char type, uint32_t provider, const char *key_name,
                       uint8_t key_index, uint8_t *key_out, size_t key_out_size) {
    uint8_t index = key_index;
    if (key_name && key_name[0] != '\0') {
        index = (uint8_t)strtoul(key_name, NULL, 16);
    }

    pthread_mutex_lock(&g_emu_mutex);

    cccam_emu_key_t *current = g_emu_keys;
    while (current) {
        if (current->type == type && current->provider == provider &&
            current->key_index == index && emu_key_valid(current)) {
            if (key_out && key_out_size >= current->data_len) {
                memcpy(key_out, current->data, current->data_len);
                pthread_mutex_unlock(&g_emu_mutex);
                return current->data_len;
            }
            pthread_mutex_unlock(&g_emu_mutex);
            return 0;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&g_emu_mutex);
    return 0;
}

// --- Parser de SoftCam.Key ---
// Formato por linha:
//   F <provider 6 hex> <keyindex hex> <keydata hex> [; comentário]
//   I <provider 6 hex> <keyindex hex> <keydata hex>
//   T <provider 6 hex> <keyindex hex> <keydata hex> <data hex>
//   W <provider 6 hex> <keyindex hex> <keydata hex>   (Cryptoworks)
//   P <provider 8 hex> <keyindex hex> <keydata hex>   (PowerVU, chave 7 bytes)
//   F <provider 8 hex> <data 8 hex> <keydata hex>     (BISS com data)

static void emu_parse_line(char *line) {
    char *p = line;
    while (isspace((unsigned char)*p)) p++;

    char *comment = strchr(p, ';');
    if (comment) *comment = '\0';
    comment = strchr(p, '#');
    if (comment) *comment = '\0';

    if (*p == '\0') return;

    char type = (char)toupper((unsigned char)*p);
    if (type != 'F' && type != 'I' && type != 'T' && type != 'W' && type != 'P') return;
    p++;

    char *tok_provider = strtok(p, " \t");
    char *tok_index = strtok(NULL, " \t");
    char *tok_data = strtok(NULL, " \t");
    if (!tok_provider || !tok_index || !tok_data) return;

    size_t prov_len = strlen(tok_provider);
    if (prov_len != 6 && prov_len != 8) return;
    for (size_t i = 0; i < prov_len; i++) {
        if (!isxdigit((unsigned char)tok_provider[i])) return;
    }

    size_t idx_len = strlen(tok_index);
    if (idx_len == 0 || idx_len > 8) return;
    for (size_t i = 0; i < idx_len; i++) {
        if (!isxdigit((unsigned char)tok_index[i])) return;
    }

    uint8_t data[CCCAM_EMU_MAX_KEY_DATA];
    int data_len = hex_to_bin(tok_data, data, sizeof(data));
    if (data_len <= 0) return;

    uint32_t provider = (uint32_t)strtoul(tok_provider, NULL, 16);
    uint32_t date = 0;

    // Linhas T: token extra com a data de expiração (hex YYYYMMDD)
    if (type == 'T') {
        char *tok_date = strtok(NULL, " \t");
        if (tok_date) {
            date = (uint32_t)strtoul(tok_date, NULL, 16);
        }
    }

    if (prov_len == 8) {
        // Provider de 32 bits.
        if (idx_len == 8) {
            // Formato BISS com data: F <provider8> <YYYYMMDD> <key>
            date = (uint32_t)strtoul(tok_index, NULL, 16);
            emu_add_key(type, provider, 0, data, (uint8_t)data_len, date, NULL);
        } else if (idx_len >= 3 && type == 'P') {
            // PowerVU EMM key: P <provider8> <UA 8 hex> <key 7 bytes>
            emu_add_key(type, provider, 0, data, (uint8_t)data_len, date, tok_index);
        } else {
            uint8_t key_index = (uint8_t)strtoul(tok_index, NULL, 16);
            emu_add_key(type, provider, key_index, data, (uint8_t)data_len, date, NULL);
            // Formato antigo (índice embutido no provider de 8 hex)
            if (key_index == 0 && (provider & 0xFF) != 0) {
                emu_add_key(type, provider >> 8, (uint8_t)(provider & 0xFF),
                            data, (uint8_t)data_len, date, NULL);
            }
        }
    } else {
        uint8_t key_index = (uint8_t)strtoul(tok_index, NULL, 16);
        emu_add_key(type, provider, key_index, data, (uint8_t)data_len, date, NULL);
    }
}

static int emu_load_key_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        cccam_log(LOG_WARN, "EMU: Ficheiro de chaves '%s' não encontrado", path);
        return -1;
    }

    char line[1024];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        int before = g_emu_key_count;
        emu_parse_line(line);
        if (g_emu_key_count != before) count++;
    }

    fclose(fp);
    cccam_log(LOG_INFO, "EMU: %d chave(s) carregadas de '%s'", count, path);
    return 0;
}

int cccam_emu_init(void) {
    if (g_emu_initialized) return 0;

    emu_free_keys();
    g_emu_initialized = 1;

    emu_load_key_file(g_emu_key_file);
    cccam_log(LOG_INFO, "EMU: Motor de emulação inicializado (%d chaves)", g_emu_key_count);
    return 0;
}

int cccam_emu_reload(void) {
    cccam_emu_key_t *old;
    int old_count;

    pthread_mutex_lock(&g_emu_mutex);
    old = g_emu_keys;
    old_count = g_emu_key_count;
    g_emu_keys = NULL;
    g_emu_key_count = 0;
    pthread_mutex_unlock(&g_emu_mutex);

    // Recarrega num armazenamento novo; só troca se o ficheiro for válido
    if (emu_load_key_file(g_emu_key_file) == 0) {
        // Liberta as chaves antigas
        cccam_emu_key_t *current = old;
        while (current) {
            cccam_emu_key_t *next = current->next;
            free(current);
            current = next;
        }
        (void)old_count;
        cccam_log(LOG_INFO, "EMU: SoftCam.Key recarregado (%d chaves)", g_emu_key_count);
        return 0;
    }

    // Falha ao carregar: mantém as chaves antigas
    pthread_mutex_lock(&g_emu_mutex);
    g_emu_keys = old;
    g_emu_key_count = old_count;
    pthread_mutex_unlock(&g_emu_mutex);
    cccam_log(LOG_WARN, "EMU: Falha ao recarregar SoftCam.Key (chaves antigas mantidas)");
    return -1;
}

void cccam_emu_cleanup(void) {
    emu_free_keys();
    g_emu_initialized = 0;
    cccam_log(LOG_INFO, "EMU: Motor de emulação limpo");
}

int cccam_emu_get_key_count(void) {
    return __atomic_load_n(&g_emu_key_count, __ATOMIC_RELAXED);
}

void cccam_emu_stats(int *total, int *biss, int *viaccess, int *cryptoworks,
                     int *powervu, int *nagra, int *irdeto) {
    int t = 0, b = 0, v = 0, c = 0, p = 0, n = 0, i = 0;

    pthread_mutex_lock(&g_emu_mutex);
    cccam_emu_key_t *current = g_emu_keys;
    while (current) {
        t++;
        switch (current->type) {
            case 'F':
            case 'T':
                // BISS vs Viaccess: decidir pelo provider
                if ((current->provider >> 16) == 0x2600) b++;
                else v++;
                break;
            case 'W':
                c++;
                break;
            case 'P':
                p++;
                break;
            case 'N':
                n++;
                break;
            case 'I':
                i++;
                break;
            default:
                break;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&g_emu_mutex);

    if (total) *total = t;
    if (biss) *biss = b;
    if (viaccess) *viaccess = v;
    if (cryptoworks) *cryptoworks = c;
    if (powervu) *powervu = p;
    if (nagra) *nagra = n;
    if (irdeto) *irdeto = i;
}

void cccam_emu_add_runtime_key(char type, uint32_t provider, const char *key_name,
                               const uint8_t *data, uint8_t data_len, int persist) {
    uint8_t index = 0;
    const char *name = NULL;

    if (key_name && key_name[0] != '\0') {
        size_t name_len = strlen(key_name);
        if (name_len > 2) {
            name = key_name;        // nome arbitrário (ex.: UA de 8 hex)
        } else {
            index = (uint8_t)strtoul(key_name, NULL, 16);
        }
    }

    emu_add_key(type, provider, index, data, data_len, 0, name);

    if (!persist) {
        return;
    }

    // Persiste no ficheiro (anexa)
    FILE *fp = fopen(g_emu_key_file, "a");
    if (fp) {
        fprintf(fp, "%c %08X %s ", type, provider, key_name ? key_name : "00");
        for (int i = 0; i < data_len; i++) {
            fprintf(fp, "%02X", data[i]);
        }
        fprintf(fp, "\n");
        fclose(fp);
        cccam_log(LOG_DEBUG, "EMU: Chave %c %08X %s persistida no SoftCam.Key",
                  type, provider, key_name ? key_name : "00");
    }
}

// Procura uma chave pelo nome (ex.: UA PowerVU). Devolve o tamanho ou 0.
// Se found_provider != NULL, recebe o provider armazenado.
int cccam_emu_find_key_name(char type, const char *name, uint8_t *key_out,
                            size_t key_out_size, uint32_t *found_provider) {
    if (!name || name[0] == '\0') {
        return 0;
    }

    pthread_mutex_lock(&g_emu_mutex);

    cccam_emu_key_t *current = g_emu_keys;
    while (current) {
        if (current->type == type && current->name[0] != '\0' &&
            strcmp(current->name, name) == 0 && emu_key_valid(current)) {
            if (key_out && key_out_size >= current->data_len) {
                memcpy(key_out, current->data, current->data_len);
                if (found_provider) *found_provider = current->provider;
                pthread_mutex_unlock(&g_emu_mutex);
                return current->data_len;
            }
            if (found_provider) *found_provider = current->provider;
            pthread_mutex_unlock(&g_emu_mutex);
            return 0;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&g_emu_mutex);
    return 0;
}

int cccam_emu_find_key_masked(char type, uint16_t provider16, uint8_t key_index,
                              uint8_t *key_out, size_t key_out_size) {
    pthread_mutex_lock(&g_emu_mutex);

    cccam_emu_key_t *current = g_emu_keys;
    while (current) {
        if (current->type == type && current->key_index == key_index &&
            (current->provider & 0xFFFF) == provider16 && emu_key_valid(current)) {
            if (key_out && key_out_size >= current->data_len) {
                memcpy(key_out, current->data, current->data_len);
                pthread_mutex_unlock(&g_emu_mutex);
                return current->data_len;
            }
            pthread_mutex_unlock(&g_emu_mutex);
            return 0;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&g_emu_mutex);
    return 0;
}

int cccam_emu_process_emm(uint16_t caid, const uint8_t *emm, uint16_t emm_len) {
    if (!emm || emm_len < 8) {
        return -1;
    }

    // Irdeto: EMM atualiza chaves (OP e PMK)
    if ((caid & 0xFF00) == 0x0600 || caid == 0x4AE1 || caid == 0x4ABF) {
        return cccam_emu_irdeto_emm(caid, emm, emm_len);
    }

    // PowerVU: EMM atualiza as chaves 'P' dos grupos
    if (caid == 0x0E00) {
        return cccam_emu_powervu_emm(caid, emm, emm_len);
    }

    return -1;
}

// --- Dispatcher ---

static int is_viaccess_caid(uint16_t caid) {
    return (caid & 0xFF00) == 0x0500;
}

static int is_biss_caid(uint16_t caid) {
    return caid == 0x2600 || caid == 0x2602;
}

static int is_cryptoworks_caid(uint16_t caid) {
    return caid == 0x0D00 || caid == 0x0D02 || caid == 0x0D03 ||
           caid == 0x0D05 || caid == 0x0D0C;
}

static int is_powervu_caid(uint16_t caid) {
    return caid == 0x0E00;
}

static int is_nagra_caid(uint16_t caid) {
    return (caid & 0xFF00) == 0x1800 || (caid & 0xFF00) == 0x1700;
}

static int is_irdeto_caid(uint16_t caid) {
    return (caid & 0xFF00) == 0x0600 || caid == 0x4AE1 || caid == 0x4ABF;
}

int cccam_emu_get_cw(uint16_t caid, uint16_t provid, uint16_t sid,
                     const uint8_t *ecm, uint16_t ecm_len, uint8_t *cw) {
    if (!ecm || !cw || ecm_len == 0) {
        return CCCAM_EMU_CORRUPT_DATA;
    }

    if (is_viaccess_caid(caid)) {
        return cccam_emu_viaccess_ecm(ecm, ecm_len, cw);
    }
    if (is_biss_caid(caid)) {
        return cccam_emu_biss_ecm(caid, sid, ecm, ecm_len, cw);
    }
    if (is_cryptoworks_caid(caid)) {
        uint8_t ecm_copy[CCCAM_ECM_MAX_SIZE + 4];
        if (ecm_len > sizeof(ecm_copy)) return CCCAM_EMU_CORRUPT_DATA;
        memcpy(ecm_copy, ecm, ecm_len);
        return cccam_emu_cryptoworks_ecm(caid, ecm_copy, cw);
    }
    if (is_powervu_caid(caid)) {
        return cccam_emu_powervu_ecm(caid, sid, ecm, ecm_len, cw);
    }
    if (is_nagra_caid(caid)) {
        uint8_t ecm_copy[CCCAM_ECM_MAX_SIZE + 4];
        if (ecm_len > sizeof(ecm_copy)) return CCCAM_EMU_CORRUPT_DATA;
        memcpy(ecm_copy, ecm, ecm_len);
        return cccam_emu_nagravision_ecm(caid, ecm_copy, cw);
    }
    if (is_irdeto_caid(caid)) {
        uint8_t ecm_copy[CCCAM_ECM_MAX_SIZE + 4];
        if (ecm_len > sizeof(ecm_copy)) return CCCAM_EMU_CORRUPT_DATA;
        memcpy(ecm_copy, ecm, ecm_len);
        return cccam_emu_irdeto_ecm(caid, ecm_copy, cw);
    }

    cccam_log(LOG_DEBUG, "EMU: Sistema CAID %04X não suportado", caid);
    return CCCAM_EMU_NOT_SUPPORTED;
}

// --- BISS ---

// BISS Mode 1: a CW é a própria chave (session word). O ECM não transporta
// dados encriptados relevantes. As chaves são identificadas pelo SID.
// Formatos aceites de provider no SoftCam.Key:
//   1. "2600" + SID (ex.: F 26000001 00 <16 hex>)
//   2. SID << 16 | 0x0001 (formato antigo)
//   3. SID simples (ex.: F 00000001 00 <16 hex>)
//   4. 0xA11FEED5 (chave "All Feeds")
static int biss_find_session_word(uint16_t caid, uint16_t sid, uint8_t *sw) {
    uint8_t key[16];
    uint32_t providers[5];
    int count = 0;

    providers[count++] = (0x2600u << 16) | sid;
    providers[count++] = ((uint32_t)sid << 16) | 0x0001;
    providers[count++] = (uint32_t)sid;
    providers[count++] = 0xA11FEED5;

    for (int i = 0; i < count; i++) {
        int len = cccam_emu_find_key('F', providers[i], NULL, 0, key, sizeof(key));
        if (len == 8) {
            memcpy(sw, key, 8);
            return 0;
        }
        if (len == 16) {
            memcpy(sw, key, 8);
            return 0;
        }
    }
    return -1;
}

int cccam_emu_biss_ecm(uint16_t caid, uint16_t sid, const uint8_t *ecm,
                       uint16_t ecm_len, uint8_t *dw) {
    (void)ecm;
    (void)ecm_len;

    uint8_t sw[8];
    if (biss_find_session_word(caid, sid, sw) != 0) {
        cccam_log(LOG_DEBUG, "EMU BISS: Chave não encontrada para SID %04X", sid);
        return CCCAM_EMU_KEY_NOT_FOUND;
    }

    // A CW para o descrambler CSA é o session word repetido 2x
    memcpy(dw, sw, 8);
    memcpy(dw + 8, sw, 8);

    cccam_log(LOG_DEBUG, "EMU BISS: CW obtida para SID %04X", sid);
    return CCCAM_EMU_OK;
}
