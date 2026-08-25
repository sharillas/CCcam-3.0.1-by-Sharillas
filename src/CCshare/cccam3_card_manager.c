#include "cccam3_card_manager.h"
#include "cccam3_logger.h"
#include "cccam3_protocol.h"
#include "cccam3_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// --- Variáveis Globais ---
static cccam_reader_t *g_readers = NULL;
static int g_reader_count = 0;
static uint32_t g_next_reader_id = 1;
static int g_initialized = 0;

// --- Funções Auxiliares Internas ---

// Verifica se um leitor suporta um determinado CAID
static int reader_supports_caid(cccam_reader_t *reader, uint16_t caid) {
    if (!reader || !reader->enabled) return 0;
    if (reader->state == READER_STATE_DISABLED || reader->state == READER_STATE_ERROR) return 0;
    if (reader->caid == 0) return 1; // Suporta todos
    return (reader->caid == caid);
}

// Verifica se um leitor suporta um determinado Provider ID
static int reader_supports_provid(cccam_reader_t *reader, uint16_t provid) {
    if (!reader) return 0;
    if (reader->provid == 0) return 1; // Suporta todos
    return (reader->provid == provid);
}

// Calcula a "pontuação" de um leitor para seleção (quanto menor, melhor)
static int reader_score(cccam_reader_t *reader, uint16_t caid, uint16_t provid) {
    int score = 0;
    
    // Prioridade definida pelo utilizador (0 = mais alta)
    score += reader->priority * 10;
    
    // Preferir leitores com hop menor
    score += reader->hop * 5;
    
    // Preferir leitores locais sobre remotos
    if (reader->type == READER_TYPE_LOCAL) score -= 20;
    if (reader->type == READER_TYPE_EMU) score -= 10;
    if (reader->type == READER_TYPE_REMOTE) score += 10;
    
    // Penalizar leitores que falharam recentemente
    if (reader->state == READER_STATE_TIMEOUT) score += 50;
    if (reader->state == READER_STATE_ERROR) score += 100;
    
    return score;
}

// --- Funções para leitores remotos ---

static int remote_recv_exact(int fd, uint8_t *buffer, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(fd, buffer + received, len - received, 0);
        if (n <= 0) {
            return -1;
        }
        received += (size_t)n;
    }
    return 0;
}

// Lê uma mensagem CCcam completa do servidor remoto
static int remote_read_message(int fd, uint8_t *buffer, size_t buf_size,
                               cccam_msg_header_t *header, uint8_t **payload,
                               size_t *payload_len) {
    uint8_t raw_header[CCCAM_HEADER_SIZE];
    if (remote_recv_exact(fd, raw_header, sizeof(raw_header)) != 0) {
        return -1;
    }

    uint32_t len_net;
    memcpy(&len_net, raw_header + 4, sizeof(len_net));
    uint32_t total = ntohl(len_net);

    if (total < CCCAM_HEADER_SIZE || total > buf_size) {
        return -1;
    }

    memcpy(buffer, raw_header, sizeof(raw_header));
    if (remote_recv_exact(fd, buffer + sizeof(raw_header),
                          total - sizeof(raw_header)) != 0) {
        return -1;
    }

    return cccam_protocol_parse(buffer, (size_t)total, header, payload, payload_len);
}

// Tenta ligar a um leitor remoto
static int remote_connect(cccam_reader_t *reader) {
    if (!reader || reader->type != READER_TYPE_REMOTE) return -1;

    if (reader->remote_fd >= 0) {
        close(reader->remote_fd);
        reader->remote_fd = -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        cccam_log(LOG_ERROR, "CCshare: Falha ao criar socket para %s", reader->name);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)reader->remote_port);
    if (inet_pton(AF_INET, reader->remote_host, &addr.sin_addr) != 1) {
        cccam_log(LOG_ERROR, "CCshare: Endereço remoto inválido: %s", reader->remote_host);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        cccam_log(LOG_WARN, "CCshare: Falha ao ligar a %s:%d (%s)",
                  reader->remote_host, reader->remote_port, strerror(errno));
        close(fd);
        return -1;
    }

    struct timeval rcv_timeout = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));

    reader->remote_fd = fd;
    cccam_log(LOG_INFO, "CCshare: Ligado ao leitor remoto %s (%s:%d)",
              reader->name, reader->remote_host, reader->remote_port);
    return 0;
}

// Obtém CW de um leitor remoto usando o protocolo CCcam
static int remote_get_cw(cccam_reader_t *reader, uint16_t caid, uint16_t provid, 
                          uint16_t sid, const uint8_t *ecm_data, uint16_t ecm_len,
                          uint8_t *cw, uint8_t *hop) {
    if (!reader || reader->type != READER_TYPE_REMOTE) return -1;

    // 1. Login no servidor remoto
    uint8_t login_buf[CCCAM3_BUFFER_SIZE];
    size_t login_len = sizeof(login_buf);
    uint8_t handshake[16] = {0};
    cccam_generate_seed(handshake, sizeof(handshake));

    if (cccam_protocol_build_login(login_buf, &login_len,
                                   reader->remote_user, reader->remote_pass,
                                   301, handshake) != 0) {
        return -1;
    }

    if (send(reader->remote_fd, login_buf, login_len, 0) != (ssize_t)login_len) {
        cccam_log(LOG_WARN, "CCshare: Falha ao enviar login para %s", reader->name);
        return -1;
    }

    // 2. Ler resposta de login (ACK)
    uint8_t resp_buf[CCCAM3_BUFFER_SIZE];
    cccam_msg_header_t header;
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (remote_read_message(reader->remote_fd, resp_buf, sizeof(resp_buf),
                            &header, &payload, &payload_len) != 0) {
        cccam_log(LOG_WARN, "CCshare: Falha ao ler ACK de %s", reader->name);
        return -1;
    }
    free(payload);

    if (header.msg_id != CCCAM_MSG_LOGIN_ACK) {
        cccam_log(LOG_WARN, "CCshare: Resposta inesperada de %s (0x%02X)", reader->name, header.msg_id);
        return -1;
    }

    // 3. Enviar pedido ECM
    uint8_t ecm_buf[CCCAM3_BUFFER_SIZE];
    size_t ecm_msg_len = sizeof(ecm_buf);
    if (cccam_protocol_build_ecm(ecm_buf, &ecm_msg_len, caid, provid, sid,
                                 ecm_data, ecm_len) != 0) {
        return -1;
    }

    if (send(reader->remote_fd, ecm_buf, ecm_msg_len, 0) != (ssize_t)ecm_msg_len) {
        cccam_log(LOG_WARN, "CCshare: Falha ao enviar ECM para %s", reader->name);
        return -1;
    }

    // 4. Ler resposta CW
    payload = NULL;
    payload_len = 0;
    if (remote_read_message(reader->remote_fd, resp_buf, sizeof(resp_buf),
                            &header, &payload, &payload_len) != 0) {
        cccam_log(LOG_WARN, "CCshare: Falha ao ler CW de %s", reader->name);
        return -1;
    }

    if (header.msg_id != CCCAM_MSG_CW || payload_len < 4 + 16 + 1) {
        cccam_log(LOG_WARN, "CCshare: Resposta de CW inválida de %s", reader->name);
        free(payload);
        return -1;
    }

    memcpy(cw, payload + 4, 16);
    *hop = payload[4 + 16];
    free(payload);

    cccam_log(LOG_DEBUG, "CCshare: CW obtida do leitor remoto %s (hop %d)", reader->name, *hop);
    return 0;
}

// --- Funções para leitores locais (smartcards) ---

// Obtém CW de um leitor local
static int local_get_cw(cccam_reader_t *reader, uint16_t caid, uint16_t provid,
                         uint16_t sid, const uint8_t *ecm_data, uint16_t ecm_len,
                         uint8_t *cw, uint8_t *hop) {
    if (!reader || reader->type != READER_TYPE_LOCAL) return -1;
    
    // TODO: Implementar leitura de smartcard físico
    // Por enquanto, simula uma resposta
    
    // Simula sucesso/fracasso (90% sucesso para teste)
    static int counter = 0;
    counter++;
    
    if (counter % 10 == 0) {
        cccam_log(LOG_WARN, "CCshare: Leitor local %s falhou (simulado)", reader->name);
        reader->state = READER_STATE_ERROR;
        return -1;
    }
    
    // CW simulada
    static uint8_t sample_cw[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    memcpy(cw, sample_cw, CCCAM_CW_SIZE);
    *hop = reader->hop;
    
    reader->state = READER_STATE_OK;
    return 0;
}

// --- Funções para leitores de emulação (SoftCam.Key) ---

// Obtém CW de um leitor de emulação
static int emu_get_cw(cccam_reader_t *reader, uint16_t caid, uint16_t provid,
                       uint16_t sid, const uint8_t *ecm_data, uint16_t ecm_len,
                       uint8_t *cw, uint8_t *hop) {
    if (!reader || reader->type != READER_TYPE_EMU) return -1;
    
    // TODO: Implementar emulação real a partir de SoftCam.Key
    // Por enquanto, simula uma resposta
    
    // Simula sucesso (100% para teste)
    static uint8_t sample_cw[16] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30
    };
    memcpy(cw, sample_cw, CCCAM_CW_SIZE);
    *hop = 0; // Hop 0 para emulação
    
    return 0;
}

// --- Implementação das Funções da API ---

int cccam_card_manager_init(void) {
    if (g_initialized) return 0;
    
    g_readers = NULL;
    g_reader_count = 0;
    g_next_reader_id = 1;
    g_initialized = 1;
    
    cccam_log(LOG_INFO, "CCshare: Card Manager inicializado");
    
    // Carregar leitores da configuração
    cccam_card_manager_load_from_config("conf/cccam3.readers");
    
    return 0;
}

void cccam_card_manager_cleanup(void) {
    cccam_reader_t *current = g_readers;
    while (current) {
        cccam_reader_t *next = current->next;
        if (current->type == READER_TYPE_REMOTE && current->remote_fd >= 0) {
            close(current->remote_fd);
        }
        free(current);
        current = next;
    }
    g_readers = NULL;
    g_reader_count = 0;
    g_initialized = 0;
    cccam_log(LOG_INFO, "CCshare: Card Manager limpo");
}

int cccam_card_manager_add_reader(cccam_reader_t *reader) {
    if (!reader) return -1;
    
    // Atribui ID único
    reader->id = g_next_reader_id++;
    
    // Adiciona à lista
    reader->next = g_readers;
    g_readers = reader;
    g_reader_count++;
    
    cccam_log(LOG_INFO, "CCshare: Leitor '%s' adicionado (ID %u, tipo %d)", 
              reader->name, reader->id, reader->type);
    return 0;
}

int cccam_card_manager_remove_reader(uint32_t reader_id) {
    cccam_reader_t *current = g_readers;
    cccam_reader_t *prev = NULL;
    
    while (current) {
        if (current->id == reader_id) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_readers = current->next;
            }
            if (current->type == READER_TYPE_REMOTE && current->remote_fd >= 0) {
                close(current->remote_fd);
            }
            free(current);
            g_reader_count--;
            cccam_log(LOG_INFO, "CCshare: Leitor %u removido", reader_id);
            return 0;
        }
        prev = current;
        current = current->next;
    }
    
    cccam_log(LOG_WARN, "CCshare: Leitor %u não encontrado", reader_id);
    return -1;
}

cccam_reader_t *cccam_card_manager_find_reader(uint32_t reader_id) {
    cccam_reader_t *current = g_readers;
    while (current) {
        if (current->id == reader_id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

cccam_reader_t *cccam_card_manager_find_reader_by_name(const char *name) {
    if (!name) return NULL;
    cccam_reader_t *current = g_readers;
    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Seleciona o melhor leitor para um determinado CAID/SID
cccam_reader_t *cccam_card_manager_select_reader(uint16_t caid, uint16_t provid, uint16_t sid) {
    cccam_reader_t *current = g_readers;
    cccam_reader_t *best = NULL;
    int best_score = 9999;
    
    while (current) {
        if (reader_supports_caid(current, caid) && reader_supports_provid(current, provid)) {
            int score = reader_score(current, caid, provid);
            if (score < best_score) {
                best_score = score;
                best = current;
            }
        }
        current = current->next;
    }
    
    if (best) {
        cccam_log(LOG_DEBUG, "CCshare: Selecionado leitor '%s' (score %d) para CAID %04X", 
                  best->name, best_score, caid);
    } else {
        cccam_log(LOG_DEBUG, "CCshare: Nenhum leitor disponível para CAID %04X", caid);
    }
    
    return best;
}

// Obtém a CW de um leitor para um determinado ECM
int cccam_card_manager_get_cw(uint16_t caid, uint16_t provid, uint16_t sid,
                               const uint8_t *ecm_data, uint16_t ecm_len,
                               uint8_t *cw, uint8_t *hop, uint32_t *reader_id) {
    if (!cw || !hop) return -1;
    
    // Seleciona o melhor leitor
    cccam_reader_t *reader = cccam_card_manager_select_reader(caid, provid, sid);
    if (!reader) {
        cccam_log(LOG_WARN, "CCshare: Sem leitor disponível para CAID %04X SID %04X", caid, sid);
        return -1;
    }
    
    reader->ecm_requests++;
    reader->last_used = time(NULL);
    
    int result = -1;
    
    // Obtém CW do leitor de acordo com o tipo
    switch (reader->type) {
        case READER_TYPE_LOCAL:
            result = local_get_cw(reader, caid, provid, sid, ecm_data, ecm_len, cw, hop);
            break;
        case READER_TYPE_REMOTE:
            // Tenta ligar se necessário
            if (reader->remote_fd < 0) {
                if (remote_connect(reader) != 0) {
                    reader->state = READER_STATE_ERROR;
                    reader->ecm_fail++;
                    cccam_log(LOG_WARN, "CCshare: Falha ao ligar a leitor remoto %s", reader->name);
                    return -1;
                }
            }
            result = remote_get_cw(reader, caid, provid, sid, ecm_data, ecm_len, cw, hop);
            if (result != 0) {
                // Fecha a ligação para tentar religar no próximo pedido
                if (reader->remote_fd >= 0) {
                    close(reader->remote_fd);
                    reader->remote_fd = -1;
                }
            }
            break;
        case READER_TYPE_EMU:
            result = emu_get_cw(reader, caid, provid, sid, ecm_data, ecm_len, cw, hop);
            break;
        default:
            result = -1;
    }
    
    if (result == 0) {
        reader->ecm_success++;
        if (reader_id) *reader_id = reader->id;
        cccam_log(LOG_DEBUG, "CCshare: CW obtida do leitor '%s' (hop %d)", reader->name, *hop);
    } else {
        reader->ecm_fail++;
        reader->state = READER_STATE_ERROR;
        reader->last_error = time(NULL);
        cccam_log(LOG_WARN, "CCshare: Falha ao obter CW do leitor '%s'", reader->name);
    }
    
    return result;
}

// Atualiza o estado de um leitor
int cccam_card_manager_update_state(uint32_t reader_id, cccam_reader_state_t state) {
    cccam_reader_t *reader = cccam_card_manager_find_reader(reader_id);
    if (!reader) return -1;
    
    reader->state = state;
    cccam_log(LOG_DEBUG, "CCshare: Leitor %u estado atualizado para %d", reader_id, state);
    return 0;
}

// Obtém estatísticas dos leitores
void cccam_card_manager_get_stats(int *total_readers, int *active_readers, 
                                  int *local_readers, int *remote_readers) {
    if (total_readers) *total_readers = g_reader_count;
    
    int active = 0, local = 0, remote = 0;
    cccam_reader_t *current = g_readers;
    while (current) {
        if (current->enabled && current->state == READER_STATE_OK) active++;
        if (current->type == READER_TYPE_LOCAL) local++;
        if (current->type == READER_TYPE_REMOTE) remote++;
        current = current->next;
    }
    
    if (active_readers) *active_readers = active;
    if (local_readers) *local_readers = local;
    if (remote_readers) *remote_readers = remote;
}

// Carrega leitores a partir de um ficheiro de configuração
int cccam_card_manager_load_from_config(const char *config_file) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        cccam_log(LOG_WARN, "CCshare: Ficheiro de leitores '%s' não encontrado. Leitores de exemplo criados.", config_file);
        
        // Cria leitores de exemplo para teste
        cccam_reader_t *reader1 = calloc(1, sizeof(cccam_reader_t));
        if (reader1) {
            strcpy(reader1->name, "Local_Reader");
            reader1->type = READER_TYPE_LOCAL;
            reader1->state = READER_STATE_OK;
            reader1->caid = 0x0100;
            reader1->provid = 0x0000;
            reader1->hop = 1;
            reader1->priority = 0;
            reader1->enabled = 1;
            cccam_card_manager_add_reader(reader1);
        }
        
        cccam_reader_t *reader2 = calloc(1, sizeof(cccam_reader_t));
        if (reader2) {
            strcpy(reader2->name, "Remote_Reader");
            reader2->type = READER_TYPE_REMOTE;
            reader2->state = READER_STATE_OK;
            reader2->caid = 0x0500;
            reader2->provid = 0x0000;
            reader2->hop = 2;
            reader2->priority = 1;
            reader2->enabled = 1;
            strcpy(reader2->remote_host, "127.0.0.1");
            reader2->remote_port = 12001;
            strcpy(reader2->remote_user, "user");
            strcpy(reader2->remote_pass, "pass");
            cccam_card_manager_add_reader(reader2);
        }
        
        cccam_reader_t *reader3 = calloc(1, sizeof(cccam_reader_t));
        if (reader3) {
            strcpy(reader3->name, "EMU_Reader");
            reader3->type = READER_TYPE_EMU;
            reader3->state = READER_STATE_OK;
            reader3->caid = 0x0000; // Suporta todos
            reader3->provid = 0x0000;
            reader3->hop = 0;
            reader3->priority = 2;
            reader3->enabled = 1;
            cccam_card_manager_add_reader(reader3);
        }
        
        return 0;
    }
    
    char line[256];
    int line_num = 0;
    cccam_reader_t *reader = NULL;
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *p = line;
        
        // Remove espaços no início
        while (*p == ' ' || *p == '\t') p++;
        
        // Ignora linhas vazias e comentários
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        
        // Remove quebra de linha
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        
        // Verifica início de nova secção
        if (*p == '[') {
            // Finaliza leitor anterior
            if (reader) {
                cccam_card_manager_add_reader(reader);
                reader = NULL;
            }
            
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                char *name = p + 1;
                
                reader = calloc(1, sizeof(cccam_reader_t));
                if (!reader) {
                    cccam_log(LOG_ERROR, "CCshare: Falha ao alocar memória para leitor %s", name);
                    continue;
                }
                strncpy(reader->name, name, CCCAM_READER_NAME_LEN - 1);
                reader->enabled = 1;
                reader->state = READER_STATE_OK;
                reader->hop = 1;
                reader->remote_fd = -1;
            }
            continue;
        }
        
        if (!reader) continue;
        
        // Parsing de key=value
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        
        // Remove espaços
        while (*key == ' ' || *key == '\t') key++;
        char *end_key = key + strlen(key) - 1;
        while (end_key > key && (*end_key == ' ' || *end_key == '\t')) {
            *end_key = '\0';
            end_key--;
        }
        
        while (*value == ' ' || *value == '\t') value++;
        char *end_val = value + strlen(value) - 1;
        while (end_val > value && (*end_val == ' ' || *end_val == '\t')) {
            *end_val = '\0';
            end_val--;
        }
        
        if (strcmp(key, "type") == 0) {
            if (strcmp(value, "local") == 0) reader->type = READER_TYPE_LOCAL;
            else if (strcmp(value, "remote") == 0) reader->type = READER_TYPE_REMOTE;
            else if (strcmp(value, "emu") == 0) reader->type = READER_TYPE_EMU;
        } else if (strcmp(key, "caid") == 0) {
            reader->caid = (uint16_t)strtol(value, NULL, 16);
        } else if (strcmp(key, "provid") == 0) {
            reader->provid = (uint16_t)strtol(value, NULL, 16);
        } else if (strcmp(key, "hop") == 0) {
            reader->hop = (uint8_t)atoi(value);
        } else if (strcmp(key, "priority") == 0) {
            reader->priority = (uint8_t)atoi(value);
        } else if (strcmp(key, "enabled") == 0) {
            reader->enabled = (strcmp(value, "1") == 0 || strcmp(value, "yes") == 0);
        } else if (strcmp(key, "remote_host") == 0) {
            strncpy(reader->remote_host, value, sizeof(reader->remote_host) - 1);
        } else if (strcmp(key, "remote_port") == 0) {
            reader->remote_port = atoi(value);
        } else if (strcmp(key, "remote_user") == 0) {
            strncpy(reader->remote_user, value, sizeof(reader->remote_user) - 1);
        } else if (strcmp(key, "remote_pass") == 0) {
            strncpy(reader->remote_pass, value, sizeof(reader->remote_pass) - 1);
        }
    }
    
    // Adiciona último leitor
    if (reader) {
        cccam_card_manager_add_reader(reader);
    }
    
    fclose(fp);
    cccam_log(LOG_INFO, "CCshare: Leitores carregados de '%s'", config_file);
    return 0;
}

// Debug - imprime estado dos leitores
void cccam_card_manager_debug_print(void) {
    cccam_reader_t *current = g_readers;
    int count = 0;
    
    cccam_log(LOG_INFO, "=== CCshare: Estado dos Leitores ===");
    cccam_log(LOG_INFO, "Total: %d leitores", g_reader_count);
    
    while (current) {
        count++;
        const char *type_str[] = {"Local", "Remoto", "Emulação"};
        const char *state_str[] = {"Desativado", "OK", "Erro", "Timeout", "Sem Cartão"};
        
        cccam_log(LOG_INFO, "[%d] %s", count, current->name);
        cccam_log(LOG_INFO, "    ID: %u", current->id);
        cccam_log(LOG_INFO, "    Tipo: %s", type_str[current->type]);
        cccam_log(LOG_INFO, "    Estado: %s", state_str[current->state]);
        cccam_log(LOG_INFO, "    CAID: %04X, Provid: %04X", current->caid, current->provid);
        cccam_log(LOG_INFO, "    Hop: %d, Prioridade: %d", current->hop, current->priority);
        cccam_log(LOG_INFO, "    Ativo: %s", current->enabled ? "Sim" : "Não");
        cccam_log(LOG_INFO, "    ECM: %d pedidos, %d sucesso, %d falhas", 
                  current->ecm_requests, current->ecm_success, current->ecm_fail);
        
        if (current->type == READER_TYPE_REMOTE) {
            cccam_log(LOG_INFO, "    Remoto: %s:%d", current->remote_host, current->remote_port);
        }
        
        current = current->next;
    }
    cccam_log(LOG_INFO, "=====================================");
}
