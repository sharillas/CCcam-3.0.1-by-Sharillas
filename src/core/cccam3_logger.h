#ifndef CCCAM3_LOGGER_H
#define CCCAM3_LOGGER_H

#ifndef LOG_ERROR
#define LOG_ERROR 0
#endif

#ifndef LOG_WARN
#define LOG_WARN  1
#endif

#ifndef LOG_INFO
#define LOG_INFO  2
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG 3
#endif

#ifndef LOG_TRACE
#define LOG_TRACE 4
#endif

int cccam_log_init(const char *log_file, int level);
void cccam_log_close(void);
void cccam_log(int level, const char *format, ...);

// Rotação do ficheiro de log (bytes; 0 = desativada)
void cccam_log_set_max_size(long max_bytes);

// Força a rotação (log -> log.1)
void cccam_log_rotate(void);

#endif // CCCAM3_LOGGER_H
