// Compatibilidade com clientes CCcam comerciais (2.0.11-2.1.4) - Fase 1.
//
// Protocolo binário CCcam real, portado da referência GPLv3:
//   OSCam module-cccam.c (cc_init_crypt, cc_crypt, cc_xor, cc_cw_crypt)
//   https://github.com/oscam-emu/oscam-patched
//
// Fluxo (servidor):
//   1. envia seed de 16 bytes (14 aleatórios + checksum)
//   2. hash = SHA1(cc_xor(seed)); dec = init(hash); enc = init(cc_crypt(dec,seed))
//   3. recebe eco do hash (20B) e username (20B), encriptados
//   4. verifica a password com "CCcam\0" (6B)
//   5. envia resposta de 20B ("CCcam" + node_id zeros)
//   6. mensagens: header 4B (flag, cmd, len BE) tudo encriptado
//      - pedido ECM (0x02): caid(2) prid(4) card_id(4) srvid(2) len(1) ecm
//      - resposta CW (0x02): 16B com cc_cw_crypt + passo extra de sync
//      - NOK (0xfe/0xff), keepalive (0x06)

#include "cccam3_cc_legacy.h"
#include "cccam3.h"
#include "cccam3_client.h"
#include "cccam3_logger.h"
#include "cccam3_ecm.h"
#include "cccam3_user_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// --- Mensagens ---
#define CCLEGACY_MSG_CLI_DATA    0x01
#define CCLEGACY_MSG_CW_ECM      0x02
#define CCLEGACY_MSG_EMM_ACK     0x03
#define CCLEGACY_MSG_CARD_REMOVED 0x04
#define CCLEGACY_MSG_KEEPALIVE   0x06
#define CCLEGACY_MSG_NEW_CARD    0x07
#define CCLEGACY_MSG_CW_NOK1     0xFE
#define CCLEGACY_MSG_CW_NOK2     0xFF

// --- Cifra CCcrypt (portada do OSCam, GPLv3) ---

static void cc_swapc(uint8_t *a, uint8_t *b) {
    uint8_t tmp = *a;
    *a = *b;
    *b = tmp;
}

static void cc_init_crypt(uint8_t *table, uint8_t *state,
                          int *counter, int *sum,
                          const uint8_t *key, int len) {
    int i;
    uint8_t j = 0;
    for (i = 0; i < 256; i++) {
        table[i] = (uint8_t)i;
    }
    for (i = 0; i < 256; i++) {
        j = (uint8_t)(j + table[i] + key[i % len]);
        cc_swapc(&table[i], &table[j]);
    }
    *state = key[0];
    *counter = 0;
    *sum = 0;
}

// mode: 0 = DECRYPT, 1 = ENCRYPT (afeta a evolução do estado)
static void cc_crypt(uint8_t *table, uint8_t *state,
                     int *counter, int *sum,
                     uint8_t *data, int len, int mode) {
    int i;
    for (i = 0; i < len; i++) {
        uint8_t z = data[i];
        (*counter)++;
        *sum += table[*counter];
        cc_swapc(&table[*counter], &table[*sum]);
        data[i] = (uint8_t)(z ^ table[(table[*counter] + table[*sum]) & 0xff]);
        data[i] ^= *state;
        if (!mode) {
            z = data[i];
        }
        *state = (uint8_t)(*state ^ z);
    }
}

// XOR de preparação do seed (portado do OSCam)
static void cc_xor(uint8_t *buf) {
    static const char cccam[] = "CCcam";
    int i;
    for (i = 0; i < 8; i++) {
        buf[8 + i] = (uint8_t)(i * buf[i]);
        if (i <= 5) {
            buf[i] ^= (uint8_t)cccam[i];
        }
    }
}

// Cifra das CWs com o node id e o card id (portado do OSCam)
static void cc_cw_crypt(uint8_t *cws, uint32_t cardid, const uint8_t *node_id) {
    uint64_t unode_id = 0;
    int i;
    for (i = 0; i < 8; i++) {
        unode_id = (unode_id << 8) | node_id[i];
    }

    if (unode_id > 0x7FFFFFFFFFFFFFFFULL) {
        for (i = 0; i < 16; i++) {
            uint8_t tmp = (uint8_t)(cws[i] ^ (unode_id >> (4 * i)));
            if (i & 1) {
                tmp = (uint8_t)~tmp;
            }
            cws[i] = (uint8_t)((cardid >> (2 * i)) ^ tmp);
        }
    } else {
        int64_t snode_id = (int64_t)unode_id;
        for (i = 0; i < 16; i++) {
            uint8_t tmp = (uint8_t)(cws[i] ^ (snode_id >> (4 * i)));
            if (i & 1) {
                tmp = (uint8_t)~tmp;
            }
            cws[i] = (uint8_t)((cardid >> (2 * i)) ^ tmp);
        }
    }
}

// --- Helpers de I/O ---

static int ccl_recv_exact(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int ccl_send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

// --- Mensagens ---

static int ccl_send_message(int fd, cclegacy_session_t *s,
                            uint8_t cmd, const uint8_t *payload, uint16_t len) {
    uint8_t buf[CCLEGACY_MAX_MSG + 4];
    uint8_t plain[CCLEGACY_MAX_MSG + 4];

    if (len > CCLEGACY_MAX_MSG) return -1;

    plain[0] = 0;                 // flag
    plain[1] = cmd;
    plain[2] = (uint8_t)(len >> 8);
    plain[3] = (uint8_t)(len & 0xFF);
    if (len > 0 && payload) {
        memcpy(plain + 4, payload, len);
    }

    memcpy(buf, plain, 4 + len);
    cc_crypt(s->enc_table, &s->enc_state, &s->enc_counter, &s->enc_sum,
             buf, 4 + (int)len, 1);

    return ccl_send_all(fd, buf, 4 + len);
}

static int ccl_recv_message(int fd, cclegacy_session_t *s,
                            uint8_t *cmd, uint8_t *payload, size_t *payload_len) {
    uint8_t header[4];

    if (ccl_recv_exact(fd, header, 4) != 0) return -1;
    cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
             header, 4, 0);

    uint16_t len = (uint16_t)((header[2] << 8) | header[3]);
    if (len > CCLEGACY_MAX_MSG) return -1;

    if (len > 0) {
        if (ccl_recv_exact(fd, payload, len) != 0) return -1;
        cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
                 payload, len, 0);
    }

    *cmd = header[1];
    *payload_len = len;
    return 0;
}

// --- Handlers ---

static int ccl_handle_ecm(int fd, cclegacy_session_t *s,
                          cccam_client_t *client,
                          const uint8_t *payload, size_t payload_len) {
    if (payload_len < 13) return 0;

    cccam_ecm_request_t request;
    memset(&request, 0, sizeof(request));
    request.caid = (uint16_t)((payload[0] << 8) | payload[1]);
    request.provid = (uint16_t)((payload[2] << 8) | payload[3]);
    uint32_t card_id = ((uint32_t)payload[6] << 24) | ((uint32_t)payload[7] << 16) |
                       ((uint32_t)payload[8] << 8) | payload[9];
    request.sid = (uint16_t)((payload[10] << 8) | payload[11]);
    request.ecm_len = (uint16_t)(payload_len - 13);
    if (request.ecm_len > CCCAM_ECM_MAX_SIZE) {
        request.ecm_len = CCCAM_ECM_MAX_SIZE;
    }
    memcpy(request.ecm_data, payload + 13, request.ecm_len);
    request.client_id = client->client_id;
    request.received_at = time(NULL);

    uint8_t user_max_hops = 0;
    cccam_user_manager_get_max_hops(s->username, &user_max_hops);
    request.hop = user_max_hops;

    cccam_ecm_response_t response;
    int result = cccam_ecm_process(&request, &response);

    if (result == 0 && response.found) {
        uint8_t cw[16];
        memcpy(cw, response.cw, 16);
        cc_cw_crypt(cw, card_id, s->node_id);

        if (ccl_send_message(fd, s, CCLEGACY_MSG_CW_ECM, cw, 16) != 0) {
            return -1;
        }

        // Passo extra de sincronização (clássico): o cliente avança o stream
        // DECRYPT com os 16 bytes da resposta em modo ENCRYPT - espelhar aqui
        cc_crypt(s->enc_table, &s->enc_state, &s->enc_counter, &s->enc_sum,
                 cw, 16, 1);

        cccam_user_manager_register_ecm(s->username, 1);
        return 0;
    }

    cccam_user_manager_register_ecm(s->username, 0);
    return ccl_send_message(fd, s, CCLEGACY_MSG_CW_NOK1, NULL, 0);
}

static int ccl_handle_message(int fd, cclegacy_session_t *s,
                              cccam_client_t *client,
                              uint8_t cmd, const uint8_t *payload, size_t payload_len) {
    switch (cmd) {
        case CCLEGACY_MSG_CW_ECM:
            return ccl_handle_ecm(fd, s, client, payload, payload_len);
        case CCLEGACY_MSG_CLI_DATA:
            // Anúncio de cartões do cliente (cliente como servidor de share):
            // ignorado na Fase 1
            return 0;
        case CCLEGACY_MSG_KEEPALIVE:
            return ccl_send_message(fd, s, CCLEGACY_MSG_KEEPALIVE, NULL, 0);
        case CCLEGACY_MSG_EMM_ACK:
        case CCLEGACY_MSG_CARD_REMOVED:
            return 0;
        default:
            cccam_log(LOG_DEBUG, "CCLegacy: Comando 0x%02X ignorado", cmd);
            return 0;
    }
}

// --- Login clássico ---

static int ccl_login(int fd, cclegacy_session_t *s) {
    uint8_t seed[16];
    uint8_t seed_xor[16];
    uint8_t hash[SHA_DIGEST_LENGTH];
    uint8_t tseed[16];
    uint8_t buf[CCLEGACY_MAX_MSG];
    char password[128] = {0};
    int user_exists = 0, user_enabled = 0;

    // 1. Seed (14 aleatórios + checksum)
    if (RAND_bytes(seed, 14) != 1) {
        for (int i = 0; i < 14; i++) seed[i] = (uint8_t)(rand() & 0xFF);
    }
    uint16_t sum = 0x1234;
    for (int i = 0; i < 14; i++) sum = (uint16_t)(sum + seed[i]);
    seed[14] = (uint8_t)(sum >> 8);
    seed[15] = (uint8_t)(sum & 0xFF);

    if (ccl_send_all(fd, seed, sizeof(seed)) != 0) return -1;

    // 2. Derivação das chaves
    memcpy(seed_xor, seed, sizeof(seed));
    cc_xor(seed_xor);
    SHA1(seed_xor, sizeof(seed_xor), hash);

    cc_init_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
                  hash, sizeof(hash));
    memcpy(tseed, seed, sizeof(seed));
    cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
             tseed, 16, 0);
    cc_init_crypt(s->enc_table, &s->enc_state, &s->enc_counter, &s->enc_sum,
                  tseed, 16);
    cc_crypt(s->enc_table, &s->enc_state, &s->enc_counter, &s->enc_sum,
             hash, sizeof(hash), 0);

    // 3. Eco do hash (20B)
    if (ccl_recv_exact(fd, buf, 20) != 0) return -1;
    cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
             buf, 20, 0);
    if (memcmp(buf, hash, sizeof(hash)) != 0) {
        cccam_log(LOG_WARN, "CCLegacy: Eco do hash inválido (login recusado)");
        return -1;
    }

    // 4. Username (20B)
    if (ccl_recv_exact(fd, buf, 20) != 0) return -1;
    cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
             buf, 20, 0);
    if (buf[19] != '\0') {
        // sem terminação: pode ser nome de 20 bytes exatos
        char tmp[21];
        memcpy(tmp, buf, 20);
        tmp[20] = '\0';
        snprintf(s->username, sizeof(s->username), "%s", tmp);
    } else {
        snprintf(s->username, sizeof(s->username), "%s", (char *)buf);
    }

    // 5. Verificação da password ("CCcam\0")
    cccam_user_manager_lock();
    cccam_user_t *user = cccam_user_manager_get_user(s->username);
    if (user) {
        user_exists = 1;
        user_enabled = user->enabled;
        strncpy(password, user->password, sizeof(password) - 1);
    }
    cccam_user_manager_unlock();

    cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
             (uint8_t *)password, (int)strlen(password), 1);

    uint8_t challenge[6] = { 'C', 'C', 'c', 'a', 'm', '\0' };
    cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
             challenge, 6, 1);
    if (ccl_send_all(fd, challenge, 6) != 0) return -1;

    // O cliente responde com "CCcam\0" encriptado se a password bater
    if (ccl_recv_exact(fd, buf, 6) != 0) return -1;
    cc_crypt(s->dec_table, &s->dec_state, &s->dec_counter, &s->dec_sum,
             buf, 6, 0);
    if (memcmp(buf, "CCcam\0", 6) != 0 || !user_exists || !user_enabled) {
        cccam_log(LOG_WARN, "CCLegacy: Password inválida para '%s'", s->username);
        return -1;
    }

    // 6. Resposta de login (20B: "CCcam" + node_id + padding)
    uint8_t reply[20];
    memset(reply, 0, sizeof(reply));
    memcpy(reply, "CCcam", 5);
    memcpy(reply + 5, s->node_id, 8); // node_id = zeros na Fase 1
    cc_crypt(s->enc_table, &s->enc_state, &s->enc_counter, &s->enc_sum,
             reply, 20, 1);
    if (ccl_send_all(fd, reply, 20) != 0) return -1;

    s->logged_in = 1;
    cccam_log(LOG_INFO, "CCLegacy: Cliente '%s' autenticado (protocolo CCcam real)",
              s->username);
    return 0;
}

// --- Loop principal da sessão ---

int cclegacy_serve(int fd, cccam_client_t *client, cclegacy_session_t *session) {
    uint8_t payload[CCLEGACY_MAX_MSG];
    size_t payload_len;
    uint8_t cmd;

    memset(session, 0, sizeof(*session));
    // node_id de zeros na Fase 1 (login clássico não troca node ids)
    memset(session->node_id, 0, sizeof(session->node_id));

    if (ccl_login(fd, session) != 0) {
        return -1;
    }

    cccam_client_authenticate(client);
    cccam_client_update_keepalive(client);

    while (1) {
        if (__atomic_load_n(&client->to_kick, __ATOMIC_RELAXED)) {
            return 0;
        }
        if (client->zombie) {
            return 0;
        }
        if (cccam_client_is_timeout(client, CCCAM3_CLIENT_TIMEOUT)) {
            return 0;
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        struct timeval tv = {1, 0};
        int activity = select(fd + 1, &read_fds, NULL, NULL, &tv);
        if (activity < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (activity == 0) {
            continue;
        }

        if (ccl_recv_message(fd, session, &cmd, payload, &payload_len) != 0) {
            return -1;
        }
        if (ccl_handle_message(fd, session, client, cmd, payload, payload_len) != 0) {
            return -1;
        }
        cccam_client_update_keepalive(client);
    }
}
