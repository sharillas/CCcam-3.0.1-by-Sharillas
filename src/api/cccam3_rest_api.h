#ifndef CCCAM3_REST_API_H
#define CCCAM3_REST_API_H

#include <stdint.h>

// --- Constantes ---
#define REST_API_DEFAULT_PORT 8080
#define REST_API_MAX_BUFFER 8192

// --- Funções ---

// Inicializa a API REST
int cccam_rest_api_init(int port);

// Limpa a API REST
void cccam_rest_api_cleanup(void);

// Verifica se a API REST está em execução
int cccam_rest_api_is_running(void);

// Obtém a porta da API REST
int cccam_rest_api_get_port(void);

#endif // CCCAM3_REST_API_H
