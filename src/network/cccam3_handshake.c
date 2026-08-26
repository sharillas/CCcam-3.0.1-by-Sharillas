#include "cccam3_handshake_advanced.h"
#include "cccam3_logger.h"
#include <string.h>

#define RSA_AES_RESPONSE_LEN (16 + 12 + 16 + 16)
#define LEGACY_RESPONSE_LEN  16

int cccam_protocol_handle_login(cccam_login_msg_t *login,
                                uint8_t *response_handshake,
                                size_t response_size) {
    if (!login || !response_handshake || response_size == 0) {
        cccam_log(LOG_ERROR, "CCshare: Handshake - parâmetros inválidos");
        return -1;
    }

    cccam_log(LOG_INFO, "CCshare: Handshake iniciado com cliente %s (versão %u)", 
              login->username, login->version);

    // Clientes com versão >= 300 usam o handshake moderno (PBKDF2 + AES-GCM);
    // clientes antigos usam o legado (SHA1).
    uint8_t client_mode = (login->version >= 300) ? HANDSHAKE_MODE_RSA_AES : HANDSHAKE_MODE_LEGACY;

    uint8_t mode = cccam_handshake_negotiate_mode(client_mode);

    if (mode >= HANDSHAKE_MODE_RSA_AES) {
        cccam_log(LOG_DEBUG, "CCshare: Usando handshake RSA_AES");
        return cccam_handshake_rsa_server(login, response_handshake, response_size);
    }
    cccam_log(LOG_DEBUG, "CCshare: Usando handshake LEGACY (SHA1)");
    return cccam_handshake_legacy_server(login, response_handshake, response_size);
}

int cccam_protocol_handle_login_response(cccam_login_msg_t *login,
                                         const uint8_t *server_handshake,
                                         size_t handshake_len) {
    if (!login || !server_handshake || handshake_len == 0) {
        cccam_log(LOG_ERROR, "CCshare: Handshake response - parâmetros inválidos");
        return -1;
    }

    cccam_log(LOG_INFO, "CCshare: Handshake response recebido do servidor");

    // O tamanho da resposta identifica o modo usado pelo servidor
    if (handshake_len >= RSA_AES_RESPONSE_LEN) {
        return cccam_handshake_rsa_client(login, server_handshake);
    }
    if (handshake_len >= LEGACY_RESPONSE_LEN) {
        return cccam_handshake_legacy_client(login, server_handshake);
    }
    cccam_log(LOG_ERROR, "CCshare: Resposta de handshake com tamanho inválido (%zu)", handshake_len);
    return -1;
}
