#include "cccam3_user_manager.h"
#include "cccam3_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

// --- Variáveis Globais ---
static cccam_user_t *g_users = NULL;
static int g_user_count = 0;
static uint32_t g_next_user_id = 1;
static int g_initialized = 0;

// --- Funções Auxiliares ---

// Hash simples para password (em produção, usar SHA256)
static void simple_hash(const char *password, char *hash_out) {
    // Simulação de hash - em produção usar OpenSSL SHA256
    uint32_t hash = 0x811c9dc5;
    while (*password) {
        hash ^= (uint8_t)(*password++);
        hash *= 0x01000193;
    }
    snprintf(hash_out, 64, "%08x%08x%08x%08x", hash, hash, hash, hash);
}

// Gera um ID único
static uint32_t generate_user_id(void) {
    return g_next_user_id++;
}

// --- Implementação das Funções ---

int cccam_user_manager_init(void) {
    if (g_initialized) return 0;
    
    g_users = NULL;
    g_user_count = 0;
    g_next_user_id = 1;
    g_initialized = 1;
    
    cccam_log(LOG_INFO, "CCshare: User Manager inicializado");
    
    // Carregar utilizadores da configuração
    cccam_user_manager_load_from_config("conf/cccam3.users");
    
    // Se não houver utilizadores, criar utilizador admin padrão
    if (g_user_count == 0) {
        cccam_user_manager_add_user("admin", "admin123", USER_LEVEL_ROOT, 0);
        cccam_log(LOG_WARN, "CCshare: Utilizador admin criado (password: admin123) - ALTERE A PASSWORD!");
    }
    
    return 0;
}

void cccam_user_manager_cleanup(void) {
    cccam_user_t *current = g_users;
    while (current) {
        cccam_user_t *next = current->next;
        free(current);
        current = next;
    }
    g_users = NULL;
    g_user_count = 0;
    g_initialized = 0;
    cccam_log(LOG_INFO, "CCshare: User Manager limpo");
}

int cccam_user_manager_add_user(const char *username, const char *password,
                                cccam_user_level_t level, uint8_t max_hops) {
    if (!username || !password || strlen(username) == 0 || strlen(password) == 0) {
        cccam_log(LOG_ERROR, "CCshare: Utilizador inválido (username/password vazio)");
        return -1;
    }
    
    // Verifica se o utilizador já existe
    if (cccam_user_manager_get_user(username) != NULL) {
        cccam_log(LOG_WARN, "CCshare: Utilizador '%s' já existe", username);
        return -1;
    }
    
    // Limite de utilizadores
    if (g_user_count >= CCCAM_MAX_USERS) {
        cccam_log(LOG_ERROR, "CCshare: Limite de utilizadores atingido (%d)", CCCAM_MAX_USERS);
        return -1;
    }
    
    cccam_user_t *user = calloc(1, sizeof(cccam_user_t));
    if (!user) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao alocar memória para utilizador");
        return -1;
    }
    
    user->id = generate_user_id();
    strncpy(user->username, username, CCCAM_MAX_USERNAME - 1);
    simple_hash(password, user->password_hash);
    user->level = level;
    user->max_hops = max_hops;
    user->enabled = 1;
    user->created_at = time(NULL);
    user->last_login = 0;
    user->login_count = 0;
    user->ecm_requests = 0;
    user->ecm_success = 0;
    
    // Adiciona à lista
    user->next = g_users;
    g_users = user;
    g_user_count++;
    
    cccam_log(LOG_INFO, "CCshare: Utilizador '%s' adicionado (ID %u, nível %d)", 
              username, user->id, level);
    return 0;
}

int cccam_user_manager_remove_user(const char *username) {
    if (!username) return -1;
    
    cccam_user_t *current = g_users;
    cccam_user_t *prev = NULL;
    
    while (current) {
        if (strcmp(current->username, username) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_users = current->next;
            }
            free(current);
            g_user_count--;
            cccam_log(LOG_INFO, "CCshare: Utilizador '%s' removido", username);
            return 0;
        }
        prev = current;
        current = current->next;
    }
    
    cccam_log(LOG_WARN, "CCshare: Utilizador '%s' não encontrado", username);
    return -1;
}

int cccam_user_manager_authenticate(const char *username, const char *password,
                                    cccam_user_t **user_out) {
    if (!username || !password) return -1;
    
    cccam_user_t *user = cccam_user_manager_get_user(username);
    if (!user) {
        cccam_log(LOG_WARN, "CCshare: Tentativa de login com utilizador inexistente: %s", username);
        return -1;
    }
    
    if (!user->enabled) {
        cccam_log(LOG_WARN, "CCshare: Utilizador '%s' desativado", username);
        return -2;
    }
    
    char hash[64];
    simple_hash(password, hash);
    
    if (strcmp(user->password_hash, hash) == 0) {
        user->last_login = time(NULL);
        user->login_count++;
        if (user_out) *user_out = user;
        cccam_log(LOG_DEBUG, "CCshare: Utilizador '%s' autenticado (nível %d)", 
                  username, user->level);
        return 0; // Sucesso
    }
    
    cccam_log(LOG_WARN, "CCshare: Falha de autenticação para '%s'", username);
    return -3; // Password errada
}

cccam_user_t *cccam_user_manager_get_user(const char *username) {
    if (!username) return NULL;
    
    cccam_user_t *current = g_users;
    while (current) {
        if (strcmp(current->username, username) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

cccam_user_t *cccam_user_manager_get_user_by_id(uint32_t id) {
    cccam_user_t *current = g_users;
    while (current) {
        if (current->id == id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

int cccam_user_manager_set_level(const char *username, cccam_user_level_t level) {
    cccam_user_t *user = cccam_user_manager_get_user(username);
    if (!user) return -1;
    
    user->level = level;
    cccam_log(LOG_INFO, "CCshare: Utilizador '%s' nível alterado para %d", username, level);
    return 0;
}

int cccam_user_manager_set_max_hops(const char *username, uint8_t max_hops) {
    cccam_user_t *user = cccam_user_manager_get_user(username);
    if (!user) return -1;
    
    user->max_hops = max_hops;
    cccam_log(LOG_INFO, "CCshare: Utilizador '%s' limite de hops alterado para %d", 
              username, max_hops);
    return 0;
}

int cccam_user_manager_set_enabled(const char *username, uint8_t enabled) {
    cccam_user_t *user = cccam_user_manager_get_user(username);
    if (!user) return -1;
    
    user->enabled = enabled;
    cccam_log(LOG_INFO, "CCshare: Utilizador '%s' %s", 
              username, enabled ? "ativado" : "desativado");
    return 0;
}

void cccam_user_manager_register_ecm(const char *username, int success) {
    cccam_user_t *user = cccam_user_manager_get_user(username);
    if (!user) return;
    
    user->ecm_requests++;
    if (success) {
        user->ecm_success++;
    }
}

int cccam_user_manager_load_from_config(const char *config_file) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        cccam_log(LOG_WARN, "CCshare: Ficheiro de utilizadores '%s' não encontrado", config_file);
        return 0;
    }
    
    char line[256];
    char username[64] = "";
    char password[64] = "";
    int level = 1;
    int max_hops = 2;
    
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        
        if (*p == '[') {
            // Finaliza utilizador anterior
            if (username[0] != '\0') {
                cccam_user_manager_add_user(username, password, level, max_hops);
                username[0] = '\0';
                password[0] = '\0';
                level = 1;
                max_hops = 2;
            }
            
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                strncpy(username, p + 1, sizeof(username) - 1);
            }
            continue;
        }
        
        if (username[0] == '\0') continue;
        
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        
        while (isspace((unsigned char)*key)) key++;
        char *key_end = key + strlen(key) - 1;
        while (key_end > key && isspace((unsigned char)*key_end)) {
            *key_end = '\0';
            key_end--;
        }
        while (isspace((unsigned char)*value)) value++;
        char *val_end = value + strlen(value) - 1;
        while (val_end > value && isspace((unsigned char)*val_end)) {
            *val_end = '\0';
            val_end--;
        }
        
        if (strcmp(key, "password") == 0) {
            strncpy(password, value, sizeof(password) - 1);
        } else if (strcmp(key, "level") == 0) {
            level = atoi(value);
        } else if (strcmp(key, "max_hops") == 0) {
            max_hops = atoi(value);
        }
    }
    
    // Adiciona último utilizador
    if (username[0] != '\0' && password[0] != '\0') {
        cccam_user_manager_add_user(username, password, level, max_hops);
    }
    
    fclose(fp);
    cccam_log(LOG_INFO, "CCshare: Utilizadores carregados de '%s'", config_file);
    return 0;
}

int cccam_user_manager_get_count(void) {
    return g_user_count;
}

void cccam_user_manager_debug_print(void) {
    cccam_user_t *current = g_users;
    int count = 0;
    
    cccam_log(LOG_INFO, "=== CCshare: Utilizadores ===");
    cccam_log(LOG_INFO, "Total: %d utilizadores", g_user_count);
    
    const char *level_names[] = {"Desativado", "User", "Admin", "Root"};
    
    while (current) {
        count++;
        cccam_log(LOG_INFO, "[%d] %s", count, current->username);
        cccam_log(LOG_INFO, "    ID: %u", current->id);
        cccam_log(LOG_INFO, "    Nível: %s", level_names[current->level]);
        cccam_log(LOG_INFO, "    Max Hops: %d", current->max_hops);
        cccam_log(LOG_INFO, "    Ativo: %s", current->enabled ? "Sim" : "Não");
        cccam_log(LOG_INFO, "    Logins: %d", current->login_count);
        cccam_log(LOG_INFO, "    ECM: %d pedidos, %d sucesso", 
                  current->ecm_requests, current->ecm_success);
        current = current->next;
    }
    cccam_log(LOG_INFO, "===============================");
}
