// Alvo de fuzzing do parser de mensagens do protocolo próprio.
// Correr: clang -fsanitize=fuzzer,address ... (ver .github/workflows/ci.yml)
#include "cccam3_protocol.h"
#include "cccam3_crypto.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    cccam_crypto_ctx_t crypto;
    cccam_protocol_reset_crypto(&crypto);

    // Contextos com chave real (exercita os caminhos RC4/AES/GCM)
    cccam_crypto_ctx_t ctx_rc4, ctx_aes, ctx_gcm;
    cccam_protocol_reset_crypto(&ctx_rc4);
    cccam_protocol_reset_crypto(&ctx_aes);
    cccam_protocol_reset_crypto(&ctx_gcm);

    uint8_t key16[16], key32[32];
    memset(key16, 0x42, sizeof(key16));
    memset(key32, 0x42, sizeof(key32));
    cccam_protocol_set_crypto(&ctx_rc4, CCCAM_CRYPT_MODE_RC4, key16, 16);
    cccam_protocol_set_crypto(&ctx_aes, CCCAM_CRYPT_MODE_AES, key16, 16);
    cccam_protocol_set_crypto(&ctx_gcm, CCCAM_CRYPT_MODE_AES_GCM, key32, 32);

    cccam_msg_header_t header;
    void *payload = NULL;
    size_t payload_len = 0;

    // parse sem crypto e com os três modos (as falhas de auth GCM são esperadas)
    cccam_protocol_parse(data, size, &header, &payload, &payload_len, &crypto);
    free(payload);
    payload = NULL;

    cccam_protocol_parse(data, size, &header, &payload, &payload_len, &ctx_rc4);
    free(payload);
    payload = NULL;

    cccam_protocol_parse(data, size, &header, &payload, &payload_len, &ctx_aes);
    free(payload);
    payload = NULL;

    cccam_protocol_parse(data, size, &header, &payload, &payload_len, &ctx_gcm);
    free(payload);

    return 0;
}
