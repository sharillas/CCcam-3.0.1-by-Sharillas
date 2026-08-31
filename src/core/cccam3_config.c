#include "cccam3.h"
#include "cccam3_logger.h"
#include "cccam3_hop_control.h"
#include "cccam3_rest_api.h"
#include "cccam3_client.h"
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
    .log_level = 2,
    .rest_api_enabled = 1,
    .rest_api_port = 8080,
    .web_interface_enabled = 1,
    .newcamd_enabled = 0,
    .newcamd_port = 34000,
    .dvbapi_enabled = 1,
    .stapi_enabled = 0,
    .user_manager_enabled = 1,
    .hop_limit = 3,
    .hop_timeout = 60,
    .allowed_crypt_modes = 0,
    .dvb_enabled = 0,
    .dvb_adapter = 0,
    .dvb_frontend = 0,
    .dvb_demux = 0,
    .dvb_frequency_khz = 0,
    .dvb_symbol_rate = 27500000,
    .dvb_delivery_system = 0,
    .dvb_modulation = 0,
    .dvb_fec = 0,
    .dvb_inversion = 0,
    .dvb_polarity = 0,
    .dvb_service_id = 0
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

static int parse_bool(const char *value) {
    return (strcmp(value, "1") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "true") == 0);
}

// Parsing de uma linha de configuração (formato key = value)
static void parse_key_value(char *line, cccam_config_t *config, const char *section) {
    char *eq = strchr(line, '=');
    if (!eq) return;

    *eq = '\0';
    char *key = trim(line);
    char *value = trim(eq + 1);

    if (strcmp(section, "global") == 0 || section[0] == '\0') {
        if (strcmp(key, "port") == 0) {
            config->listen_port = atoi(value);
        } else if (strcmp(key, "server_name") == 0) {
            strncpy(config->server_name, value, sizeof(config->server_name) - 1);
        } else if (strcmp(key, "max_clients") == 0) {
            config->max_clients = atoi(value);
        } else if (strcmp(key, "max_ecm_per_sec") == 0) {
            config->max_ecm_per_sec = atoi(value);
        } else if (strcmp(key, "allow_ips") == 0) {
            strncpy(config->allow_ips, value, sizeof(config->allow_ips) - 1);
        } else if (strcmp(key, "deny_ips") == 0) {
            strncpy(config->deny_ips, value, sizeof(config->deny_ips) - 1);
        } else if (strcmp(key, "pid_file") == 0) {
            strncpy(config->pid_file, value, sizeof(config->pid_file) - 1);
        } else if (strcmp(key, "providers_file") == 0) {
            strncpy(config->providers_file, value, sizeof(config->providers_file) - 1);
        } else if (strcmp(key, "channelinfo_file") == 0) {
            strncpy(config->channelinfo_file, value, sizeof(config->channelinfo_file) - 1);
        }
    } else if (strcmp(section, "logging") == 0) {
        if (strcmp(key, "level") == 0 || strcmp(key, "log_level") == 0) {
            config->log_level = atoi(value);
        } else if (strcmp(key, "file") == 0 || strcmp(key, "log_file") == 0) {
            strncpy(config->log_file, value, sizeof(config->log_file) - 1);
        } else if (strcmp(key, "enabled") == 0) {
            config->enable_logging = parse_bool(value);
        } else if (strcmp(key, "max_size_mb") == 0) {
            config->log_max_mb = atoi(value);
        }
    } else if (strcmp(section, "cache") == 0) {
        if (strcmp(key, "enabled") == 0 || strcmp(key, "cache_enabled") == 0) {
            config->enable_cache = parse_bool(value);
        } else if (strcmp(key, "timeout") == 0 || strcmp(key, "cache_timeout") == 0) {
            config->cache_timeout = atoi(value);
        }
    } else if (strcmp(section, "security") == 0) {
        if (strcmp(key, "allowed_crypt_modes") == 0) {
            config->allowed_crypt_modes = (uint32_t)strtoul(value, NULL, 16);
        } else if (strcmp(key, "max_login_failures") == 0) {
            config->max_login_failures = atoi(value);
        }
    } else if (strcmp(section, "hop_control") == 0) {
        if (strcmp(key, "max_hops") == 0) {
            config->hop_limit = atoi(value);
        } else if (strcmp(key, "timeout") == 0) {
            config->hop_timeout = atoi(value);
        } else if (strcmp(key, "block_loops") == 0) {
            config->block_loops = parse_bool(value);
        }
    } else if (strcmp(section, "rest_api") == 0) {
        if (strcmp(key, "port") == 0) {
            config->rest_api_port = atoi(value);
        } else if (strcmp(key, "enabled") == 0) {
            config->rest_api_enabled = parse_bool(value);
        } else if (strcmp(key, "user") == 0) {
            strncpy(config->rest_api_user, value, sizeof(config->rest_api_user) - 1);
        } else if (strcmp(key, "password") == 0) {
            strncpy(config->rest_api_password, value, sizeof(config->rest_api_password) - 1);
        }
    } else if (strcmp(section, "web_interface") == 0) {
        if (strcmp(key, "enabled") == 0) {
            config->web_interface_enabled = parse_bool(value);
        } else if (strcmp(key, "path") == 0) {
            strncpy(config->web_path, value, sizeof(config->web_path) - 1);
        }
    } else if (strcmp(section, "user_manager") == 0) {
        if (strcmp(key, "enabled") == 0) {
            config->user_manager_enabled = parse_bool(value);
        } else if (strcmp(key, "file") == 0) {
            strncpy(config->user_file, value, sizeof(config->user_file) - 1);
        } else if (strcmp(key, "auto_register") == 0) {
            config->auto_register = parse_bool(value);
        }
    } else if (strcmp(section, "newcamd") == 0) {
        if (strcmp(key, "enabled") == 0) {
            config->newcamd_enabled = parse_bool(value);
        } else if (strcmp(key, "port") == 0) {
            config->newcamd_port = atoi(value);
        } else if (strcmp(key, "caid") == 0) {
            config->newcamd_caid = (int)strtol(value, NULL, 16);
        } else if (strcmp(key, "key") == 0) {
            strncpy(config->newcamd_des_key, value, sizeof(config->newcamd_des_key) - 1);
            config->newcamd_des_key[sizeof(config->newcamd_des_key) - 1] = '\0';
        }
    } else if (strcmp(section, "dvbapi") == 0) {
        if (strcmp(key, "enabled") == 0) {
            config->dvbapi_enabled = parse_bool(value);
        } else if (strcmp(key, "socket") == 0) {
            strncpy(config->dvbapi_socket, value, sizeof(config->dvbapi_socket) - 1);
        } else if (strcmp(key, "max_demux") == 0) {
            config->dvbapi_max_demux = atoi(value);
        }
    } else if (strcmp(section, "stapi") == 0) {
        if (strcmp(key, "enabled") == 0) {
            config->stapi_enabled = parse_bool(value);
        } else if (strcmp(key, "device") == 0) {
            strncpy(config->stapi_device, value, sizeof(config->stapi_device) - 1);
        }
    } else if (strcmp(section, "emu") == 0) {
        if (strcmp(key, "key_file") == 0 || strcmp(key, "softcam_key") == 0) {
            strncpy(config->emu_key_file, value, sizeof(config->emu_key_file) - 1);
        }
    } else if (strcmp(section, "dvb") == 0) {
        if (strcmp(key, "enabled") == 0) {
            config->dvb_enabled = parse_bool(value);
        } else if (strcmp(key, "adapter") == 0) {
            config->dvb_adapter = atoi(value);
        } else if (strcmp(key, "frontend") == 0) {
            config->dvb_frontend = atoi(value);
        } else if (strcmp(key, "demux") == 0) {
            config->dvb_demux = atoi(value);
        } else if (strcmp(key, "frequency_khz") == 0) {
            config->dvb_frequency_khz = atoi(value);
        } else if (strcmp(key, "symbol_rate") == 0) {
            config->dvb_symbol_rate = atoi(value);
        } else if (strcmp(key, "delivery_system") == 0) {
            if (strcmp(value, "dvb-s") == 0) config->dvb_delivery_system = 1;
            else if (strcmp(value, "dvb-s2") == 0) config->dvb_delivery_system = 2;
            else if (strcmp(value, "dvb-c") == 0) config->dvb_delivery_system = 3;
            else if (strcmp(value, "dvb-c2") == 0) config->dvb_delivery_system = 4;
            else if (strcmp(value, "dvb-t") == 0) config->dvb_delivery_system = 5;
            else if (strcmp(value, "dvb-t2") == 0) config->dvb_delivery_system = 6;
            else config->dvb_delivery_system = 0;
        } else if (strcmp(key, "bandwidth") == 0) {
            config->dvb_bandwidth = atoi(value);
        } else if (strcmp(key, "modulation") == 0) {
            if (strcmp(value, "qpsk") == 0) config->dvb_modulation = 1;
            else if (strcmp(value, "psk_8") == 0) config->dvb_modulation = 2;
            else if (strcmp(value, "qam_16") == 0) config->dvb_modulation = 3;
            else if (strcmp(value, "qam_32") == 0) config->dvb_modulation = 4;
            else if (strcmp(value, "qam_64") == 0) config->dvb_modulation = 5;
            else if (strcmp(value, "qam_128") == 0) config->dvb_modulation = 6;
            else if (strcmp(value, "qam_256") == 0) config->dvb_modulation = 7;
            else config->dvb_modulation = 0;
        } else if (strcmp(key, "fec") == 0) {
            if (strcmp(value, "1_2") == 0) config->dvb_fec = 1;
            else if (strcmp(value, "2_3") == 0) config->dvb_fec = 2;
            else if (strcmp(value, "3_4") == 0) config->dvb_fec = 3;
            else if (strcmp(value, "5_6") == 0) config->dvb_fec = 4;
            else if (strcmp(value, "7_8") == 0) config->dvb_fec = 5;
            else if (strcmp(value, "8_9") == 0) config->dvb_fec = 6;
            else if (strcmp(value, "9_10") == 0) config->dvb_fec = 7;
            else config->dvb_fec = 0;
        } else if (strcmp(key, "inversion") == 0) {
            if (strcmp(value, "on") == 0) config->dvb_inversion = 1;
            else if (strcmp(value, "off") == 0) config->dvb_inversion = 2;
            else config->dvb_inversion = 0;
        } else if (strcmp(key, "polarity") == 0) {
            if (strcmp(value, "h") == 0) config->dvb_polarity = 1;
            else if (strcmp(value, "v") == 0) config->dvb_polarity = 2;
            else config->dvb_polarity = 0;
        } else if (strcmp(key, "service_id") == 0) {
            config->dvb_service_id = (int)strtol(value, NULL, 0);
        }
    }
}

int cccam_load_config(const char *config_file, cccam_config_t *config) {
    FILE *fp;
    char line[256];
    char current_section[64] = "";
    
    if (!config) {
        config = &g_config;
    }

    // Valores por omissão
    *config = g_config;
    memset(config->log_file, 0, sizeof(config->log_file));
    memset(config->user_file, 0, sizeof(config->user_file));
    memset(config->dvbapi_socket, 0, sizeof(config->dvbapi_socket));
    
    fp = fopen(config_file, "r");
    if (!fp) {
        cccam_log(LOG_WARN, "Ficheiro de configuração '%s' não encontrado. A usar valores por omissão.", config_file);
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp)) {
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
                current_section[sizeof(current_section) - 1] = '\0';
            }
            continue;
        }
        
        parse_key_value(p, config, current_section);
    }
    
    fclose(fp);

    // Validação de valores (produção)
    if (config->listen_port < 1 || config->listen_port > 65535) {
        cccam_log(LOG_WARN, "Configuração: porta inválida %d, a usar 12000", config->listen_port);
        config->listen_port = 12000;
    }
    if (config->newcamd_port < 1 || config->newcamd_port > 65535) {
        config->newcamd_port = 34000;
    }
    if (config->rest_api_port < 1 || config->rest_api_port > 65535) {
        config->rest_api_port = 8080;
    }
    if (config->max_clients < 1 || config->max_clients > CCCAM3_CLIENT_SLOTS) {
        cccam_log(LOG_WARN, "Configuração: max_clients %d fora do intervalo, limitado a %d",
                  config->max_clients, CCCAM3_CLIENT_SLOTS);
        if (config->max_clients < 1) config->max_clients = 1;
        else config->max_clients = CCCAM3_CLIENT_SLOTS;
    }
    if (config->hop_limit < 1 || config->hop_limit > 20) {
        config->hop_limit = 3;
    }
    if (config->cache_timeout < 1) {
        config->cache_timeout = 10;
    }
    if (config->log_level < 0 || config->log_level > 4) {
        config->log_level = 2;
    }
    if (config->dvbapi_max_demux < 1 || config->dvbapi_max_demux > 64) {
        config->dvbapi_max_demux = 8;
    }

    // Sincronizar a configuração global (usada pela API REST e outros módulos)
    g_config = *config;

    // Aplicar valores carregados aos subsistemas
    if (config->user_file[0] != '\0') {
        cccam_user_manager_set_config_file(config->user_file);
    }
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
    cccam_log(LOG_INFO, "Limite de Hops: %d (timeout: %d segundos)", config->hop_limit, config->hop_timeout);
    cccam_log(LOG_INFO, "API REST: %s (porta %d)", 
              config->rest_api_enabled ? "ativada" : "desativada", config->rest_api_port);
    cccam_log(LOG_INFO, "Interface Web: %s", config->web_interface_enabled ? "ativada" : "desativada");
    cccam_log(LOG_INFO, "Newcamd: %s (porta %d, CAID %04X)", 
              config->newcamd_enabled ? "ativado" : "desativado", config->newcamd_port,
              config->newcamd_caid);
    cccam_log(LOG_INFO, "DVB-API: %s (%s)", 
              config->dvbapi_enabled ? "ativada" : "desativada",
              config->dvbapi_socket[0] != '\0' ? config->dvbapi_socket : "caminho por omissão");
    cccam_log(LOG_INFO, "STAPI: %s", config->stapi_enabled ? "ativada" : "desativada");
    cccam_log(LOG_INFO, "DVB: %s (adapter %d, frontend %d, %d kHz, SR %d, serviço %d)",
              config->dvb_enabled ? "ativado" : "desativado",
              config->dvb_adapter, config->dvb_frontend,
              config->dvb_frequency_khz, config->dvb_symbol_rate, config->dvb_service_id);
    cccam_log(LOG_INFO, "Modos de criptografia permitidos: 0x%02X", config->allowed_crypt_modes);
    if (config->user_file[0] != '\0') {
        cccam_log(LOG_INFO, "Ficheiro de utilizadores: %s", config->user_file);
    }
}
