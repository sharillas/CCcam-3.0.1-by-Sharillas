#ifndef CCCAM3_STRUCTS_H
#define CCCAM3_STRUCTS_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

// --- Contexto de Criptografia por Sessão ---
typedef struct {
    uint8_t mode;              // CCCAM_CRYPT_MODE_*
    uint8_t key[32];
    size_t key_len;
    uint64_t tx_counter;       // Contador de mensagens enviadas (nonce GCM)
    uint64_t rx_counter;       // Contador de mensagens recebidas (nonce GCM)
} cccam_crypto_ctx_t;

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
    int is_newcamd;
    int to_kick;               // Marca para desligar (definido pela API REST)
    time_t ecm_window_start;   // Rate limit de ECMs por cliente
    int ecm_window_count;
    uint32_t ecm_total;        // Total de ECMs pedidos (para o painel)
    uint32_t ecm_ok;           // ECMs com sucesso (CW devolvida)
    uint16_t cur_caid;         // CAID do canal que está a ver agora
    uint16_t cur_sid;          // SID do canal que está a ver agora
    time_t cur_channel_at;     // Quando pediu o último ECM
    uint8_t node_id[8];
    struct sockaddr_in addr;
    cccam_crypto_ctx_t crypto;
    void *ncd_session;         // cccam_newcamd_session_t (sessão Newcamd)
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
    int max_ecm_per_sec;         // Rate limit por cliente (0 = ilimitado)
    int max_login_failures;      // Falhas de login por IP antes de bloquear
    char allow_ips[256];         // Lista de IPs permitidos (vazio = todos)
    char deny_ips[256];          // Lista de IPs bloqueados
    char providers_file[256];    // CCcam.providers (nomes de provedores)
    char channelinfo_file[256];  // CCcam.channelinfo (nomes de canais)
    int enable_cache;
    int cache_timeout;
    int enable_logging;
    char log_file[256];
    int log_level;
    int log_max_mb;              // Rotação do log (0 = desativada)
    char pid_file[128];          // Pidfile do daemon (-d)
    int rest_api_enabled;
    int rest_api_port;
    char rest_api_user[64];      // Autenticação Basic (vazio = desativada)
    char rest_api_password[64];
    int web_interface_enabled;
    char web_path[64];           // Caminho da interface web
    int newcamd_enabled;
    int newcamd_port;
    int newcamd_caid;            // CAID da porta Newcamd (hex, 0 = qualquer)
    char newcamd_des_key[29];    // Chave DES em hex (28 chars = 14 bytes)
    int dvbapi_enabled;
    char dvbapi_socket[256];
    int dvbapi_max_demux;
    int stapi_enabled;
    char stapi_device[128];
    int user_manager_enabled;
    char user_file[256];
    int auto_register;           // Registo automático de utilizadores
    int hop_limit;
    int hop_timeout;
    int block_loops;             // Deteção de loops (informacional)
    uint32_t allowed_crypt_modes;
    char emu_key_file[256];      // Ficheiro SoftCam.Key
    int dvb_enabled;
    int dvb_adapter;
    int dvb_frontend;
    int dvb_demux;
    int dvb_frequency_khz;
    int dvb_symbol_rate;
    int dvb_delivery_system;
    int dvb_modulation;
    int dvb_fec;
    int dvb_inversion;
    int dvb_polarity;
    int dvb_service_id;
    int dvb_bandwidth;           // DVB-T/T2: 6, 7 ou 8 MHz (0 = 8 MHz)
} cccam_config_t;

#endif // CCCAM3_STRUCTS_H
