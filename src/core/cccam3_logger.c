#include "cccam3_logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>

static int g_log_level = LOG_INFO;
static FILE *g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static const char *log_levels[] = {
    "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};
#define LOG_LEVEL_COUNT ((int)(sizeof(log_levels) / sizeof(log_levels[0])))

static char g_log_path[256] = "";
static long g_log_max_bytes = 0;
static long g_log_write_count = 0;

int cccam_log_init(const char *log_file, int level) {
    g_log_level = level;
    g_log_path[0] = '\0';
    if (log_file && log_file[0] != '\0') {
        strncpy(g_log_path, log_file, sizeof(g_log_path) - 1);
        g_log_file = fopen(log_file, "a");
        if (!g_log_file) {
            return -1;
        }
    }
    return 0;
}

// Define o tamanho máximo do ficheiro de log (bytes; 0 = sem rotação)
void cccam_log_set_max_size(long max_bytes) {
    g_log_max_bytes = max_bytes > 0 ? max_bytes : 0;
    if (g_log_max_bytes > 0) {
        cccam_log(LOG_INFO, "Rotação de log ativada (%ld MB)", g_log_max_bytes / (1024 * 1024));
    }
}

// Rotação: log -> log.1 (fecha e reabre)
void cccam_log_rotate(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_file && g_log_path[0] != '\0') {
        fclose(g_log_file);
        char old_path[280];
        snprintf(old_path, sizeof(old_path), "%s.1", g_log_path);
        rename(g_log_path, old_path);
        g_log_file = fopen(g_log_path, "a");
    }
    pthread_mutex_unlock(&g_log_mutex);
}

void cccam_log_close(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

void cccam_log(int level, const char *format, ...) {
    if (level > g_log_level) return;

    const char *level_name = "?";
    if (level >= 0 && level < LOG_LEVEL_COUNT) {
        level_name = log_levels[level];
    }

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

    va_list args;
    va_start(args, format);

    // Cópia ANTES de consumir args (o va_copy após o uso é UB)
    va_list args_copy;
    if (g_log_file) {
        va_copy(args_copy, args);
    }

    // Múltiplas threads escrevem no log: evitar linhas intercaladas
    pthread_mutex_lock(&g_log_mutex);

    FILE *out = (level <= LOG_ERROR) ? stderr : stdout;
    fprintf(out, "[%s] [%-5s] ", time_str, level_name);
    vfprintf(out, format, args);
    fprintf(out, "\n");
    fflush(out);
    va_end(args);

    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%-5s] ", time_str, level_name);
        vfprintf(g_log_file, format, args_copy);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
        va_end(args_copy);

        // Verifica o tamanho periodicamente (a cada 100 escritas)
        if (g_log_max_bytes > 0 && (++g_log_write_count % 100) == 0) {
            struct stat st;
            if (stat(g_log_path, &st) == 0 && st.st_size > g_log_max_bytes) {
                pthread_mutex_unlock(&g_log_mutex);
                cccam_log_rotate();
                pthread_mutex_lock(&g_log_mutex);
            }
        }
    }

    pthread_mutex_unlock(&g_log_mutex);
}
