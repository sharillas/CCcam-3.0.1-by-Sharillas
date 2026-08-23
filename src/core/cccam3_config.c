#include "cccam3.h"
#include "cccam3_logger.h"
#include "cccam3_hop_control.h"
#include "cccam3_rest_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static cccam_config_t g_config = {
    .listen_port = 12000,
    .server_name = "CCcam3",
    .max_clients = 100,
    .enable_cache = 1,
    .cache_timeout = 10,
    .enable_logging = 1,
    .log_level = 2
};

// Remove espaços e quebras de linha no início/fim
static char *trim(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

// Parsing de uma linha de configuração
static int parse_line(char *line, cccam_config_t *config) {
    char *key, *value;
    char *colon = strchr(line, '=');
    if (!colon) return -1;
    
    *colon = '\0';
    key = trim(line);
    value = trim(colon + 1);
    
    if (strcmp(key, "port") == 0) {
        config->listen_port = atoi(value);
    } else if (strcmp(key, "server_name") == 0) {
        strncpy(config->server_name, value, sizeof(config->server_name) - 1);
    } else if (strcmp(key, "max_clients") == 0) {
        config->max_clients = atoi(value);
    } else if (strcmp(key, "cache_enabled") == 0) {
        config->enable_cache = (strcmp(value, "1") == 0 || strcmp(value, "yes") == 0);
    } else if (strcmp(key, "cache_timeout") == 0) {
        config->cache_timeout = atoi(value);
        cccam_cache_set_timeout(atoi(value));
    } else if (strcmp(key, "log_level") == 0) {
        config->log_level = atoi(value);
    } else if (strcmp(key, "log_file") == 0) {
        strncpy(config->log_file, value, sizeof(config->log_file) - 1);
    } else if (strcmp(key, "max_hops") == 0) {
        cccam_hop_control_set_limit((uint8_t)atoi(value));
    }
    
    return 0;
}

int cccam_load_config(const char *config_file, cccam_config_t *config) {
    FILE *fp;
    char line[256];
    int line_num = 0;
    char current_section[64] = "";
    
    if (!config) {
        config = &g_config;
    }
    
    fp = fopen(config_file, "r");
    if (!fp) {
        cccam_log(LOG_WARN, "Ficheiro de configuração '%s' não encontrado. A usar valores por omissão.", config_file);
        *config = g_config;
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *p = line;
        
        // Remove espaços no início
        while (isspace((unsigned char)*p)) p++;
        
        // Ignora linhas vazias e comentários
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        
        // Remove quebra de linha
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        
        // Verifica se é uma secção
        if (*p == '[') {
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                strncpy(current_section, p + 1, sizeof(current_section) - 1);
            }
            continue;
        }
        
        // Parsing da secção [hop_control]
        if (strcmp(current_section, "hop_control") == 0) {
            char *key, *value;
            char *colon = strchr(p, '=');
            if (colon) {
                *colon = '\0';
                key = trim(p);
                value = trim(colon + 1);
                if (strcmp(key, "max_hops") == 0) {
                    cccam_hop_control_set_limit((uint8_t)atoi(value));
                }
            }
            continue;
        }
        
        // Parsing da secção [rest_api]
        if (strcmp(current_section, "rest_api") == 0) {
            char *key, *value;
            char *colon = strchr(p, '=');
            if (colon) {
                *colon = '\0';
                key = trim(p);
                value = trim(colon + 1);
                if (strcmp(key, "port") == 0) {
                    // A porta será usada no cccam3_init
                } else if (strcmp(key, "enabled") == 0) {
                    // Será verificado no cccam3_init
                }
            }
            continue;
        }
        
        // Parsing da secção [web_interface]
        if (strcmp(current_section, "web_interface") == 0) {
            char *key, *value;
            char *colon = strchr(p, '=');
            if (colon) {
                *colon = '\0';
                key = trim(p);
                value = trim(colon + 1);
                if (strcmp(key, "enabled") == 0) {
                    // Será verificado no cccam3_init
                } else if (strcmp(key, "path") == 0) {
                    // Será verificado no cccam3_init
                }
            }
            continue;
        }
        
        // Parsing da secção [user_manager]
        if (strcmp(current_section, "user_manager") == 0) {
            char *key, *value;
            char *colon = strchr(p, '=');
            if (colon) {
                *colon = '\0';
                key = trim(p);
                value = trim(colon + 1);
                // Armazenar configuração se necessário
            }
            continue;
        }
        
        // Parsing normal para as outras secções
        parse_line(p, config);
    }
    
    fclose(fp);
    cccam_log(LOG_INFO, "Configuração carregada de '%s'", config_file);
    return 0;
}

cccam_config_t *cccam_get_config(void) {
    return &g_config;
}

void cccam_print_config(cccam_config_t *config) {
    if (!config) config = &g_config;
    cccam_log(LOG_INFO, "=== Configuração CCcam3 ===");
    cccam_log(LOG_INFO, "Porta: %d", config->listen_port);
    cccam_log(LOG_INFO, "Nome do Servidor: %s", config->server_name);
    cccam_log(LOG_INFO, "Máximo de Clientes: %d", config->max_clients);
    cccam_log(LOG_INFO, "Cache: %s (timeout: %d segundos)", 
              config->enable_cache ? "ativada" : "desativada", config->cache_timeout);
    cccam_log(LOG_INFO, "Nível de Log: %d", config->log_level);
    if (config->log_file[0] != '\0') {
        cccam_log(LOG_INFO, "Ficheiro de Log: %s", config->log_file);
    }
    cccam_log(LOG_INFO, "Limite de Hops: %d", cccam_hop_control_get_limit());
    cccam_log(LOG_INFO, "API REST: %s (porta %d)", 
              cccam_rest_api_is_running() ? "ativa" : "inativa", 
              cccam_rest_api_get_port());
    cccam_log(LOG_INFO, "Interface Web: %s", cccam_rest_api_is_running() ? "ativa" : "inativa");
    cccam_log(LOG_INFO, "Utilizadores: %d", cccam_user_manager_get_count());
}
