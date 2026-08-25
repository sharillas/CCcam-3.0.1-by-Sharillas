#ifndef CCCAM3_HOP_CONTROL_H
#define CCCAM3_HOP_CONTROL_H

#include "cccam3_structs.h"
#include <stdint.h>
#include <time.h>

// --- Constantes ---
#define CCCAM_MAX_HOPS 10
#define CCCAM_DEFAULT_HOP_LIMIT 3
#define CCCAM_HOP_TIMEOUT 60  // segundos

// --- Estruturas ---
typedef struct {
    uint16_t caid;
    uint16_t provid;
    uint16_t sid;
    uint8_t hop;              // Hop atual
    time_t timestamp;         // Momento do pedido
    uint32_t client_id;       // Cliente que fez o pedido
    uint8_t blocked;          // 1 = bloqueado, 0 = permitido
} cccam_hop_entry_t;

// --- Funções ---

// Inicializa o sistema de controlo de hops
int cccam_hop_control_init(void);

// Limpa o sistema de controlo de hops
void cccam_hop_control_cleanup(void);

// Verifica se um pedido é permitido com base no hop
int cccam_hop_control_check(uint16_t caid, uint16_t provid, uint16_t sid, 
                            uint8_t hop, uint32_t client_id);

// Regista um pedido para controlo de hops
int cccam_hop_control_register(uint16_t caid, uint16_t provid, uint16_t sid,
                               uint8_t hop, uint32_t client_id);

// Incrementa o hop para um novo pedido
uint8_t cccam_hop_control_increment_hop(uint8_t current_hop);

// Verifica se um hop é válido (não excede o limite)
int cccam_hop_control_is_valid(uint8_t hop);

// Define o limite máximo de hops
void cccam_hop_control_set_limit(uint8_t limit);

// Obtém o limite máximo de hops
uint8_t cccam_hop_control_get_limit(void);

// Define o timeout (segundos) das entradas de hop
void cccam_hop_control_set_timeout(int timeout_seconds);

// Limpa entradas antigas
int cccam_hop_control_clean_expired(void);

// Debug - imprime estado do controlo de hops
void cccam_hop_control_debug_print(void);

#endif // CCCAM3_HOP_CONTROL_H
