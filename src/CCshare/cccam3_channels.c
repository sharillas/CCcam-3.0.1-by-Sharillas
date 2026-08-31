#include "cccam3_channels.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

// --- Estruturas ---

#define CHANNELS_MAX_ENTRIES 4096

typedef struct ch_provider {
    uint16_t caid;
    uint16_t provid;
    char name[64];
} ch_provider_t;

typedef struct ch_channel {
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    char name[96];
} ch_channel_t;

static ch_provider_t *g_providers = NULL;
static int g_provider_count = 0;
static ch_channel_t *g_channels = NULL;
static int g_channel_count = 0;

static char g_providers_file[256] = "conf/CCcam.providers";
static char g_channelinfo_file[256] = "conf/CCcam.channelinfo";

static pthread_mutex_t g_channels_mutex = PTHREAD_MUTEX_INITIALIZER;

void cccam_channels_set_files(const char *providers_file, const char *channelinfo_file) {
    if (providers_file && providers_file[0] != '\0') {
        strncpy(g_providers_file, providers_file, sizeof(g_providers_file) - 1);
        g_providers_file[sizeof(g_providers_file) - 1] = '\0';
    }
    if (channelinfo_file && channelinfo_file[0] != '\0') {
        strncpy(g_channelinfo_file, channelinfo_file, sizeof(g_channelinfo_file) - 1);
        g_channelinfo_file[sizeof(g_channelinfo_file) - 1] = '\0';
    }
}

static void channels_free(void) {
    free(g_providers);
    free(g_channels);
    g_providers = NULL;
    g_channels = NULL;
    g_provider_count = 0;
    g_channel_count = 0;
}

static char *ch_trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

// --- Parsing ---
// CCcam.providers:   caid:provid:nome_do_provedor
// CCcam.channelinfo: caid:provid:sid:nome_do_canal   (provid 0000 = qualquer)

static int ch_load_providers(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        cccam_log(LOG_WARN, "Channels: '%s' não encontrado (nomes de provedores indisponíveis)", path);
        return -1;
    }

    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < CHANNELS_MAX_ENTRIES) {
        char *p = ch_trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;

        unsigned int caid = 0, provid = 0;
        char name[64] = "";
        // Formato: caid:provid:nome  (pode ter caid:provid:nome com espaços)
        if (sscanf(p, "%x:%x:%63[^\r\n]", &caid, &provid, name) == 3) {
            char *np = ch_trim(name);
            if (np[0] != '\0') {
                g_providers[count].caid = (uint16_t)caid;
                g_providers[count].provid = (uint16_t)provid;
                strncpy(g_providers[count].name, np, sizeof(g_providers[count].name) - 1);
                count++;
            }
        }
    }
    fclose(fp);
    cccam_log(LOG_INFO, "Channels: %d provedores carregados de '%s'", count, path);
    return count;
}

static int ch_load_channelinfo(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        cccam_log(LOG_WARN, "Channels: '%s' não encontrado (nomes de canais indisponíveis)", path);
        return -1;
    }

    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < CHANNELS_MAX_ENTRIES) {
        char *p = ch_trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;

        unsigned int caid = 0, provid = 0, sid = 0;
        char name[96] = "";
        if (sscanf(p, "%x:%x:%x:%95[^\r\n]", &caid, &provid, &sid, name) == 4) {
            char *np = ch_trim(name);
            if (np[0] != '\0') {
                g_channels[count].caid = (uint16_t)caid;
                g_channels[count].provid = (uint16_t)provid;
                g_channels[count].sid = (uint16_t)sid;
                strncpy(g_channels[count].name, np, sizeof(g_channels[count].name) - 1);
                count++;
            }
        }
    }
    fclose(fp);
    cccam_log(LOG_INFO, "Channels: %d canais carregados de '%s'", count, path);
    return count;
}

int cccam_channels_init(void) {
    pthread_mutex_lock(&g_channels_mutex);
    channels_free();

    g_providers = calloc(CHANNELS_MAX_ENTRIES, sizeof(ch_provider_t));
    g_channels = calloc(CHANNELS_MAX_ENTRIES, sizeof(ch_channel_t));
    if (!g_providers || !g_channels) {
        channels_free();
        pthread_mutex_unlock(&g_channels_mutex);
        return -1;
    }

    ch_load_providers(g_providers_file);
    ch_load_channelinfo(g_channelinfo_file);
    pthread_mutex_unlock(&g_channels_mutex);
    return 0;
}

void cccam_channels_cleanup(void) {
    pthread_mutex_lock(&g_channels_mutex);
    channels_free();
    pthread_mutex_unlock(&g_channels_mutex);
}

const char *cccam_channels_get_provider(uint16_t caid, uint16_t provid) {
    const char *result = NULL;
    pthread_mutex_lock(&g_channels_mutex);

    for (int i = 0; i < g_provider_count; i++) {
        if (g_providers[i].caid == caid &&
            (g_providers[i].provid == provid || g_providers[i].provid == 0)) {
            result = g_providers[i].name;
            break;
        }
    }
    pthread_mutex_unlock(&g_channels_mutex);
    return result;
}

const char *cccam_channels_get_name(uint16_t caid, uint16_t provid, uint16_t sid) {
    const char *result = NULL;
    pthread_mutex_lock(&g_channels_mutex);

    // 1º: caid + provid + sid exatos
    for (int i = 0; i < g_channel_count; i++) {
        if (g_channels[i].caid == caid && g_channels[i].sid == sid &&
            g_channels[i].provid == provid) {
            result = g_channels[i].name;
            goto done;
        }
    }
    // 2º: caid + sid com provid 0000 (wildcard)
    for (int i = 0; i < g_channel_count; i++) {
        if (g_channels[i].caid == caid && g_channels[i].sid == sid &&
            g_channels[i].provid == 0) {
            result = g_channels[i].name;
            goto done;
        }
    }
    // 3º: só sid (transponder FTA / qualquer CAID)
    for (int i = 0; i < g_channel_count; i++) {
        if (g_channels[i].caid == 0 && g_channels[i].sid == sid) {
            result = g_channels[i].name;
            goto done;
        }
    }

done:
    pthread_mutex_unlock(&g_channels_mutex);
    return result;
}

int cccam_channels_get_count(void) {
    return g_channel_count;
}
