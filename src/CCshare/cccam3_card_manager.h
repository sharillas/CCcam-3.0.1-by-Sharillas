#ifndef CCCAM3_CARD_MANAGER_H
#define CCCAM3_CARD_MANAGER_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <time.h>

// --- Constantes ---
#define CCCAM_MAX_READERS 32
#define CCCAM_READER_NAME_LEN 64
#define CCCAM_MAX_ECM_SIZE 256
#define CCCAM_CW_SIZE 16

// --- Tipos de Leitores ---
typedef enum {
    READER_TYPE_LOCAL = 0,      // Leitor físico (smartcard)
    READER_TYPE_REMOTE = 1,     // Leitor remoto (proxy)
    READER_TYPE_EMU = 2         // Emulação (SoftCam.Key)
} cccam_reader_type_t;

// --- Estado do Leitor ---
typedef enum {
    READER_STATE_DISABLED = 0,
    READER_STATE_OK = 1,
    READER_STATE_ERROR = 2,
    READER_STATE_TIMEOUT = 3,
    READER_STATE_NO_CARD = 4
} cccam_reader_state_t;

// --- Estrutura do Leitor ---
typedef struct {
    uint32_t id;
    char name[CCCAM_READER_NAME_LEN];
    cccam_reader_type_t type;
    cccam_reader_state_t state;
    
    // Dados específicos do leitor
    uint16_t caid;              // CAID suportado (0 = todos)
    uint16_t provid;            // Provider ID (0 = todos)
    uint8_t hop;                // Número de saltos (para leitores remotos)
    uint8_t priority;           // Prioridade (0 = mais alta)
    uint8_t enabled;            // 1 = ativo, 0 = inativo
    
    // Estatísticas
    uint32_t ecm_requests;      // Total de pedidos ECM
    uint32_t ecm_success;       // Pedidos bem-sucedidos
    uint32_t ecm_fail;          // Pedidos falhados
    time_t last_used;           // Última utilização
    time_t last_error;          // Último erro
    int consecutive_failures;   // Falhas consecutivas (backoff)
    time_t retry_after;         // Não usar até esta hora (backoff)
    
    // Para leitores remotos
    char remote_host[256];
    int remote_port;
    char remote_user[64];
    char remote_pass[64];
    int remote_fd;              // Socket para ligação remota
    int remote_logged_in;       // 1 = sessão autenticada no servidor remoto
    cccam_crypto_ctx_t crypto;  // Criptografia da sessão remota
    
    // Para leitores locais (smartcard PC/SC)
    char device[128];           // Nome do leitor PC/SC ("" = primeiro)
    
    struct cccam_reader_t *next;
} cccam_reader_t;

// --- Funções do Card Manager ---

// Inicializa o sistema de gestão de leitores
int cccam_card_manager_init(void);

// Limpa o sistema de gestão de leitores
void cccam_card_manager_cleanup(void);

// Adiciona um leitor à lista
int cccam_card_manager_add_reader(cccam_reader_t *reader);

// Remove um leitor da lista
int cccam_card_manager_remove_reader(uint32_t reader_id);

// Procura um leitor por ID
cccam_reader_t *cccam_card_manager_find_reader(uint32_t reader_id);

// Procura um leitor por nome
cccam_reader_t *cccam_card_manager_find_reader_by_name(const char *name);

// Obtém a CW de um leitor para um determinado ECM
int cccam_card_manager_get_cw(uint16_t caid, uint16_t provid, uint16_t sid,
                               const uint8_t *ecm_data, uint16_t ecm_len,
                               uint8_t *cw, uint8_t *hop, uint32_t *reader_id);

// Envia um EMM aos leitores remotos compatíveis (manutenção de direitos
// dos cartões reais que estão "do outro lado" do share).
// Chamar com o mutex de ECM adquirido (ver cccam_ecm_forward_emm).
int cccam_card_manager_send_emm(uint16_t caid, uint16_t provid,
                                const uint8_t *emm_data, uint16_t emm_len);

// Seleciona o melhor leitor para um determinado CAID/SID
cccam_reader_t *cccam_card_manager_select_reader(uint16_t caid, uint16_t provid, uint16_t sid);

// Atualiza o estado de um leitor
int cccam_card_manager_update_state(uint32_t reader_id, cccam_reader_state_t state);

// Obtém estatísticas dos leitores
void cccam_card_manager_get_stats(int *total_readers, int *active_readers, 
                                  int *local_readers, int *remote_readers);

// Carrega leitores a partir de um ficheiro de configuração
int cccam_card_manager_load_from_config(const char *config_file);

// Define o caminho do ficheiro de leitores (usado no init)
void cccam_card_manager_set_config_file(const char *path);

// Debug - imprime estado dos leitores
void cccam_card_manager_debug_print(void);

#endif // CCCAM3_CARD_MANAGER_H
