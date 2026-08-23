#include "cccam3_logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

static int g_log_level = LOG_INFO;
static FILE *g_log_file = NULL;
static const char *log_levels[] = {
    "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

int cccam_log_init(const char *log_file, int level) {
    g_log_level = level;
    if (log_file && log_file[0] != '\0') {
        g_log_file = fopen(log_file, "a");
        if (!g_log_file) {
            return -1;
        }
    }
    return 0;
}

void cccam_log_close(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

void cccam_log(int level, const char *format, ...) {
    if (level > g_log_level) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    va_list args;
    va_start(args, format);

    // Imprimir no stdout
    FILE *out = (level <= LOG_ERROR) ? stderr : stdout;
    fprintf(out, "[%s] [%-5s] ", time_str, log_levels[level]);
    vfprintf(out, format, args);
    fprintf(out, "\n");
    fflush(out);

    // Imprimir no ficheiro de log
    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%-5s] ", time_str, log_levels[level]);
        vfprintf(g_log_file, format, args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }

    va_end(args);
}
