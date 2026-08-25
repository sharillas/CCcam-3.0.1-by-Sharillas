#include "cccam3_handshake_advanced.h"
#include "cccam3_logger.h"
#include <string.h>

int cccam_protocol_handle_login(cccam_login_msg_t *login,
                                uint8_t *response_handshake,
                                size_t response_size) {
    if (!login || !response_handshake || response_size == 0) {
        cccam_log(LOG_ERROR, "CCshare: Handshake - parâmetros inválidos");
        return -1;
    }

    cccam_log(LOG_INFO, "CCshare: Handshake iniciado com cliente %s (versão %u)", 
              login->username, login->version);

    // Verifica se o cliente suporta RSA (através de uma flag na versão ou mensagem)
    // Por enquanto, usa o modo legado por omissão para compatibilidade
    uint8_t client_mode = HANDSHAKE_MODE_LEGACY;
    
    // TODO: Detetar modo do cliente a partir da mensagem de login
    // Se a versão for >= 3.0, assume suporte a RSA
    if (login->version >= 300) {
        client_mode = HANDSHAKE_MODE_RSA_AES;
        cccam_log(LOG_DEBUG, "CCshare: Cliente suporta RSA_AES (versão %u)", login->version);
    }

    // Negocia o melhor modo disponível
    uint8_t mode = cccam_handshake_negotiate_mode(client_mode);

    if (mode >= HANDSHAKE_MODE_RSA_AES) {
        cccam_log(LOG_DEBUG, "CCshare: Usando handshake RSA_AES");
        return cccam_handshake_rsa_server(login, response_handshake, response_size);
    } else {
        cccam_log(LOG_DEBUG, "CCshare: Usando handshake LEGACY (SHA1+RC4)");
        return cccam_handshake_legacy_server(login, response_handshake, response_size);
    }
}

int cccam_protocol_handle_login_response(cccam_login_msg_t *login,
                                         const uint8_t *server_handshake) {
    if (!login || !server_handshake) {
        cccam_log(LOG_ERROR, "CCshare: Handshake response - parâmetros inválidos");
        return -1;
    }

    cccam_log(LOG_INFO, "CCshare: Handshake response recebido do servidor");

    // Verifica se o servidor está a usar RSA (deteta pelo tamanho da resposta)
    // Por enquanto, assume legado
    uint8_t mode = cccam_handshake_get_mode();

    if (mode >= HANDSHAKE_MODE_RSA_AES) {
        return cccam_handshake_rsa_client(login, server_handshake);
    } else {
        return cccam_handshake_legacy_client(login, server_handshake);
    }
}
