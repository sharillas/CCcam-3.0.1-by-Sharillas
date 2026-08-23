#ifndef CCCAM3_STRUCTS_H
#define CCCAM3_STRUCTS_H

#include <stdint.h>
#include <time.h>

// --- Estruturas de Cliente ---
typedef struct {
    int socket_fd;
    uint32_t client_id;
    char username[64];
    char password[64];
    uint32_t version;
    uint8_t crypt_mode;
    uint8_t crypto_key[32];
    size_t crypto_key_len;
    uint8_t handshake_seed[16];
    time_t last_keepalive;
    time_t connected_at;
    int is_authenticated;
    int hop_count;
    uint8_t node_id[8];
} cccam_client_t;

// --- Estruturas de Mensagens ---
typedef struct {
    uint32_t msg_id;
    uint32_t msg_len;
    uint8_t flags;
    uint8_t crypt_mode;
    uint16_t reserved;
} cccam_msg_header_t;

typedef struct {
    uint8_t handshake[16];
    char username[64];
    char password[64];
    uint32_t version;
} cccam_login_msg_t;

typedef struct {
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    uint16_t ecm_len;
    uint8_t ecm_data[256];
} cccam_ecm_msg_t;

typedef struct {
    uint32_t ecm_time;
    uint8_t cw[16];
    uint8_t hop;
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
} cccam_cw_msg_t;

typedef struct {
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    uint8_t hop;
    uint32_t card_id;
    uint16_t data_len;
    uint8_t card_data[128];
} cccam_card_data_t;

// --- Estruturas de Cartão/Leitor ---
typedef struct {
    uint32_t id;
    uint16_t caid;
    uint16_t provid;
    uint8_t hop;
    uint8_t active;
    char reader_name[64];
    time_t last_used;
    uint32_t ecm_count;
    uint32_t cw_count;
} cccam_card_t;

// --- Estruturas de Cache CW ---
typedef struct {
    uint8_t cw[16];
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    time_t timestamp;
    time_t expires_at;
    uint8_t hop;
    uint8_t valid;
} cccam_cache_entry_t;

// --- Estruturas de Configuração ---
typedef struct {
    int listen_port;
    char server_name[64];
    int max_clients;
    int enable_cache;
    int cache_timeout;
    int enable_logging;
    char log_file[256];
    int log_level;
} cccam_config_t;

#endif // CCCAM3_STRUCTS_H
