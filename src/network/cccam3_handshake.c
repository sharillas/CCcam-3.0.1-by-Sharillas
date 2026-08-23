#include "cccam3_protocol.h"
#include "cccam3_crypto.h"
#include "cccam3_utils.h"
#include "cccam3_logger.h"
#include <string.h>
#include <time.h>

int cccam_protocol_handle_login(cccam_login_msg_t *login,
                                uint8_t *response_handshake) {
    if (!login || !response_handshake) {
        return -1;
    }

    cccam_log(LOG_INFO, "Handshake: Cliente %s (versão %u)", 
              login->username, login->version);

    // 1. Validar credenciais (TODO: integrar com sistema de utilizadores)
    // Por agora, aceita qualquer login para teste

    // 2. Gerar seed de resposta
    cccam_generate_seed(response_handshake, 16);

    // 3. Derivar chave de encriptação
    // SHA1(client_seed + server_seed + password)
    uint8_t combined[16 + 16 + 64];
    memcpy(combined, login->handshake, 16);
    memcpy(combined + 16, response_handshake, 16);
    strcpy((char *)combined + 32, login->password);

    uint8_t crypto_key[20];
    cccam_sha1(combined, 32 + strlen(login->password), crypto_key);

    // 4. Configurar encriptação (RC4 por omissão para compatibilidade)
    cccam_protocol_set_crypto(CCCAM_CRYPT_MODE_RC4, crypto_key, 20);

    cccam_log(LOG_DEBUG, "Handshake concluído, chave de encriptação derivada");
    return 0;
}

int cccam_protocol_handle_login_response(cccam_login_msg_t *login,
                                         const uint8_t *server_handshake) {
    // Cliente: processar resposta do servidor
    // Derivar a mesma chave de encriptação
    uint8_t combined[16 + 16 + 64];
    memcpy(combined, login->handshake, 16);
    memcpy(combined + 16, server_handshake, 16);
    strcpy((char *)combined + 32, login->password);

    uint8_t crypto_key[20];
    cccam_sha1(combined, 32 + strlen(login->password), crypto_key);

    cccam_protocol_set_crypto(CCCAM_CRYPT_MODE_RC4, crypto_key, 20);
    return 0;
}
