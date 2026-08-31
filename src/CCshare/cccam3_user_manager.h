#ifndef CCCAM3_USER_MANAGER_H
#define CCCAM3_USER_MANAGER_H

#include <stdint.h>
#include <time.h>

// --- Constantes ---
#define CCCAM_MAX_USERNAME 64
#define CCCAM_MAX_PASSWORD 128
#define CCCAM_MAX_USERS 256

// --- Níveis de Acesso ---
typedef enum {
    USER_LEVEL_DISABLED = 0,
    USER_LEVEL_USER = 1,
    USER_LEVEL_ADMIN = 2,
    USER_LEVEL_ROOT = 3
} cccam_user_level_t;

// --- Estrutura do Utilizador ---
typedef struct cccam_user_t {
    uint32_t id;
    char username[CCCAM_MAX_USERNAME];
    char password_hash[65];         // Hash SHA256 hex (64 chars) + NUL
    char password[CCCAM_MAX_PASSWORD]; // Password em claro (para Newcamd MD5-crypt)
    cccam_user_level_t level;
    uint8_t max_hops;                // Limite de hops para este utilizador
    uint8_t enabled;                 // 1 = ativo, 0 = inativo
    time_t created_at;
    time_t last_login;
    uint32_t login_count;
    uint32_t ecm_requests;
    uint32_t ecm_success;
    struct cccam_user_t *next;
} cccam_user_t;

// --- Funções ---

// Inicializa o gestor de utilizadores
int cccam_user_manager_init(void);

// Limpa o gestor de utilizadores
void cccam_user_manager_cleanup(void);

// Adiciona um utilizador
int cccam_user_manager_add_user(const char *username, const char *password,
                                cccam_user_level_t level, uint8_t max_hops);

// Remove um utilizador
int cccam_user_manager_remove_user(const char *username);

// Autentica um utilizador
int cccam_user_manager_authenticate(const char *username, const char *password,
                                    cccam_user_t **user_out);

// Registo automático: cria o utilizador se não existir e persiste no ficheiro
// de utilizadores. Nível USER e max_hops 2 por omissão.
int cccam_user_manager_auto_register(const char *username, const char *password,
                                     cccam_user_t **user_out);

// Ativa/desativa o registo automático (usado pelo handler de login)
void cccam_user_manager_set_auto_register(int enabled);

// Verifica se o registo automático está ativo
int cccam_user_manager_auto_register_enabled(void);

// Obtém um utilizador pelo nome
cccam_user_t *cccam_user_manager_get_user(const char *username);

// Obtém um utilizador pelo ID
cccam_user_t *cccam_user_manager_get_user_by_id(uint32_t id);

// Atualiza o nível de acesso de um utilizador
int cccam_user_manager_set_level(const char *username, cccam_user_level_t level);

// Atualiza o limite de hops de um utilizador
int cccam_user_manager_set_max_hops(const char *username, uint8_t max_hops);

// Ativa/desativa um utilizador
int cccam_user_manager_set_enabled(const char *username, uint8_t enabled);

// Regista um pedido ECM de um utilizador
void cccam_user_manager_register_ecm(const char *username, int success);

// Carrega utilizadores de um ficheiro de configuração
int cccam_user_manager_load_from_config(const char *config_file);

// Recarrega os utilizadores do ficheiro configurado (em runtime)
int cccam_user_manager_reload(void);

// Define o caminho do ficheiro de utilizadores (usado no init)
void cccam_user_manager_set_config_file(const char *path);

// Obtém o número total de utilizadores
int cccam_user_manager_get_count(void);

// Obtém um utilizador pelo índice (para listagens da API REST)
cccam_user_t *cccam_user_manager_get_by_index(int index);

// Debug - imprime todos os utilizadores
void cccam_user_manager_debug_print(void);

#endif // CCCAM3_USER_MANAGER_H
