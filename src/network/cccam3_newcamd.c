// Servidor Newcamd (protocolo real newcs/cs357x, NCD_524).
// Implementação baseada no protocolo documentado e no OSCam (GPLv3).
//
// Formato de mensagem (NCD_524):
//   [0..1]  = tamanho total - 2 (em claro, big-endian)
//   [2..]   = encriptado (DES Eurocrypt ECS2 a partir do byte 2):
//     [2..3]  = msgid (big-endian)
//     [4..5]  = sid (big-endian)
//     [6..7]  = 0
//     [8]     = comando (0xE0 login, 0x80/0x81 ECM ...)
//     [9]     = (data_len >> 8) & 0x0F
//     [10]    = data_len & 0xFF
//     [11..]  = dados

#include "cccam3_newcamd.h"
#include "cccam3_logger.h"
#include "cccam3_emu_des.h"
#include "cccam3_ecm.h"
#include "cccam3_user_manager.h"
#include "cccam3_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

// Chave DES clássica do protocolo Newcamd (01 02 ... 0E)
static uint8_t g_ncd_des_key[14] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
};
static uint16_t g_ncd_caid = 0;

void cccam_newcamd_set_des_key(const uint8_t *key14) {
    if (key14) {
        memcpy(g_ncd_des_key, key14, 14);
        cccam_log(LOG_INFO, "Newcamd: Chave DES do servidor definida");
    }
}

void cccam_newcamd_set_caid(uint16_t caid) {
    g_ncd_caid = caid;
    if (caid != 0) {
        cccam_log(LOG_INFO, "Newcamd: CAID %04X atribuído à porta", caid);
    }
}

// --- MD5-crypt ($1$salt$) ---

static void md5_to64(char *s, unsigned long v, int n) {
    static const char itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    while (--n >= 0) {
        *s++ = itoa64[v & 0x3f];
        v >>= 6;
    }
}

static void md5_crypt(const char *pw, const char *salt, char *out) {
    char salt_buf[9];
    const char *magic = "$1$";
    MD5_CTX ctx, ctx1;
    unsigned char digest[MD5_DIGEST_LENGTH];
    unsigned int i, pw_len = (unsigned int)strlen(pw);

    memset(salt_buf, 0, sizeof(salt_buf));
    strncpy(salt_buf, salt, 8);

    MD5_Init(&ctx);
    MD5_Update(&ctx, pw, pw_len);
    MD5_Update(&ctx, magic, 3);
    MD5_Update(&ctx, salt_buf, strlen(salt_buf));

    MD5_Init(&ctx1);
    MD5_Update(&ctx1, pw, pw_len);
    MD5_Update(&ctx1, salt_buf, strlen(salt_buf));
    MD5_Update(&ctx1, pw, pw_len);
    MD5_Final(digest, &ctx1);

    for (i = pw_len; i > 0; i -= 16)
        MD5_Update(&ctx, digest, i > 16 ? 16 : i);

    for (i = pw_len; i > 0; i >>= 1) {
        if (i & 1) MD5_Update(&ctx, "\0", 1);
        else MD5_Update(&ctx, pw, 1);
    }
    MD5_Final(digest, &ctx);

    for (i = 0; i < 1000; i++) {
        MD5_Init(&ctx1);
        if (i & 1) MD5_Update(&ctx1, pw, pw_len);
        else MD5_Update(&ctx1, digest, 16);
        if (i % 3) MD5_Update(&ctx1, salt_buf, strlen(salt_buf));
        if (i % 7) MD5_Update(&ctx1, pw, pw_len);
        if (i & 1) MD5_Update(&ctx1, digest, 16);
        else MD5_Update(&ctx1, pw, pw_len);
        MD5_Final(digest, &ctx1);
    }

    char *p = out;
    p += sprintf(p, "%s%s$", magic, salt_buf);

    unsigned long l;
    l = ((unsigned long)digest[0] << 16) | ((unsigned long)digest[6] << 8) | digest[12];
    md5_to64(p, l, 4); p += 4;
    l = ((unsigned long)digest[1] << 16) | ((unsigned long)digest[7] << 8) | digest[13];
    md5_to64(p, l, 4); p += 4;
    l = ((unsigned long)digest[2] << 16) | ((unsigned long)digest[8] << 8) | digest[14];
    md5_to64(p, l, 4); p += 4;
    l = ((unsigned long)digest[3] << 16) | ((unsigned long)digest[9] << 8) | digest[15];
    md5_to64(p, l, 4); p += 4;
    l = ((unsigned long)digest[4] << 16) | ((unsigned long)digest[10] << 8) | digest[5];
    md5_to64(p, l, 4); p += 4;
    l = digest[11];
    md5_to64(p, l, 2); p += 2;
    *p = '\0';
}

// --- Início de sessão ---

int cccam_newcamd_session_start(int fd, cccam_newcamd_session_t *session) {
    uint8_t init_seq[14];
    uint8_t key[16];

    memset(session, 0, sizeof(*session));

    if (RAND_bytes(init_seq, sizeof(init_seq)) != 1) {
        cccam_generate_seed(init_seq, sizeof(init_seq));
    }

    // Envia a sequência de init em claro (14 bytes)
    size_t sent = 0;
    while (sent < sizeof(init_seq)) {
        ssize_t n = send(fd, init_seq + sent, sizeof(init_seq) - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }

    // Chave de login: spread(init_seq XOR des_key)
    cccam_newcamd_login_key(init_seq, g_ncd_des_key, 14, key);
    memcpy(session->login_key, key, 16);
    memcpy(session->session_key, key, 16);
    session->state = 0;
    cccam_log(LOG_DEBUG, "Newcamd: Sequência de init enviada");
    return 0;
}

void cccam_newcamd_session_reset(cccam_newcamd_session_t *session) {
    if (session) {
        memset(session, 0, sizeof(*session));
    }
}

// --- Construção de mensagens ---

static int ncd_send_message(int fd, cccam_newcamd_session_t *session,
                            uint16_t msg_id, uint8_t cmd, const uint8_t *data,
                            uint16_t data_len, uint16_t sid) {
    uint8_t netbuf[NCD_MAX_MSG];
    int len;

    if (data_len > 0xFFF || (int)data_len + 11 + 8 > NCD_MAX_MSG) return -1;

    memset(netbuf, 0, sizeof(netbuf));
    netbuf[2] = (uint8_t)(msg_id >> 8);
    netbuf[3] = (uint8_t)(msg_id & 0xFF);
    netbuf[4] = (uint8_t)(sid >> 8);
    netbuf[5] = (uint8_t)(sid & 0xFF);
    netbuf[8] = cmd;
    netbuf[9] = (uint8_t)((data_len >> 8) & 0x0F);
    netbuf[10] = (uint8_t)(data_len & 0xFF);
    if (data_len > 0 && data) {
        memcpy(netbuf + 11, data, data_len);
    }

    len = 11 + (int)data_len;
    len = cccam_newcamd_des_encrypt(netbuf, len, session->session_key);
    if (len < 0) return -1;

    netbuf[0] = (uint8_t)((len - 2) >> 8);
    netbuf[1] = (uint8_t)((len - 2) & 0xFF);

    size_t sent = 0;
    while (sent < (size_t)len) {
        ssize_t n = send(fd, netbuf + sent, (size_t)len - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

// --- Decriptação ---

typedef struct {
    uint8_t cmd;
    uint16_t msg_id;
    uint16_t sid;
    const uint8_t *data;
    uint16_t data_len;
} ncd_msg_t;

static int ncd_decrypt_message(const uint8_t *raw, size_t raw_len,
                               const uint8_t *key, ncd_msg_t *msg) {
    uint8_t buf[NCD_MAX_MSG];

    if (raw_len < 16 || raw_len > sizeof(buf)) return -1;
    memcpy(buf, raw, raw_len);

    int len = cccam_newcamd_des_decrypt(buf, (int)raw_len, key);
    if (len < 0) return -1;
    if (len < 11) return -1;

    msg->msg_id = (uint16_t)((buf[2] << 8) | buf[3]);
    msg->sid = (uint16_t)((buf[4] << 8) | buf[5]);
    msg->cmd = buf[8];
    msg->data_len = (uint16_t)(((buf[9] & 0x0F) << 8) | buf[10]);

    if (11 + (int)msg->data_len > len) return -1;
    msg->data = buf + 11;
    return 0;
}

// --- Handlers ---

static int ncd_handle_login(int fd, cccam_newcamd_session_t *session,
                            const ncd_msg_t *msg) {
    char username[64] = {0};
    char password[128] = {0};

    if (msg->data_len < 2) return -1;

    size_t user_len = strnlen((const char *)msg->data, msg->data_len);
    if (user_len == 0 || user_len >= sizeof(username) || user_len >= msg->data_len) {
        return -1;
    }
    memcpy(username, msg->data, user_len);

    size_t pass_off = user_len + 1;
    if (pass_off >= msg->data_len) return -1;
    size_t pass_len = strnlen((const char *)(msg->data + pass_off), msg->data_len - pass_off);
    if (pass_len == 0 || pass_len >= sizeof(password) || pass_len >= msg->data_len - pass_off) {
        return -1;
    }
    memcpy(password, msg->data + pass_off, pass_len);

    // Autenticação: password em claro (newcs/mgcamd) ou MD5-crypt (OSCam)
    cccam_user_t *user = cccam_user_manager_get_user(username);
    int auth_ok = 0;
    char md5_expected[128];

    if (user && user->enabled) {
        if (strcmp(user->password, password) == 0) {
            auth_ok = 1;
        } else {
            md5_crypt(user->password, "abcdefgh", md5_expected);
            if (strcmp(md5_expected, password) == 0) {
                auth_ok = 1;
            }
        }
    }

    if (!auth_ok && cccam_user_manager_auto_register_enabled() && user == NULL) {
        // Registo automático: cria o utilizador com a password recebida
        if (cccam_user_manager_auto_register(username, password, &user) == 0) {
            auth_ok = 1;
            cccam_log(LOG_INFO, "Newcamd: Utilizador '%s' registado automaticamente", username);
        }
    }

    if (!auth_ok) {
        if (user) {
            cccam_log(LOG_WARN, "Newcamd: Password inválida para '%s'", username);
        } else {
            cccam_log(LOG_WARN, "Newcamd: Utilizador '%s' não existe", username);
        }
        ncd_send_message(fd, session, msg->msg_id, NCD_MSG_LOGIN_NAK, NULL, 0, 0);
        return -1;
    }

    // ACK com a chave de login
    if (ncd_send_message(fd, session, msg->msg_id, NCD_MSG_LOGIN_ACK, NULL, 0, 0) != 0) {
        return -1;
    }

    // Chaves de sessão: derivadas da DES key + password (ou MD5-crypt)
    md5_crypt(user->password, "abcdefgh", md5_expected);
    cccam_newcamd_login_key(g_ncd_des_key, (const uint8_t *)user->password,
                            (int)strlen(user->password), session->session_key);
    cccam_newcamd_login_key(g_ncd_des_key, (const uint8_t *)md5_expected,
                            (int)strlen(md5_expected), session->session_key_alt);
    session->key_mode = 0;
    session->state = 1;
    snprintf(session->username, sizeof(session->username), "%s", username);
    session->last_keepalive = time(NULL);

    cccam_log(LOG_INFO, "Newcamd: Cliente '%s' autenticado (nível %d)", username, user->level);
    return 0;
}

static int ncd_handle_card_req(int fd, cccam_newcamd_session_t *session,
                               const ncd_msg_t *msg) {
    // MSG_CARD_DATA: [userid][caid 2][0 0][serial 6][nprov] (nprov = 0)
    uint8_t card[10];
    memset(card, 0, sizeof(card));
    card[0] = 1;                        // userid
    card[1] = (uint8_t)(g_ncd_caid >> 8);
    card[2] = (uint8_t)(g_ncd_caid & 0xFF);
    card[9] = 0x00;                     // nprov = 0

    return ncd_send_message(fd, session, msg->msg_id, NCD_MSG_CARD_DATA,
                            card, sizeof(card), 0);
}

static int ncd_handle_ecm(int fd, cccam_newcamd_session_t *session,
                          const ncd_msg_t *msg) {
    cccam_ecm_request_t request;
    cccam_ecm_response_t response;
    uint8_t reply[16];
    uint16_t table_id = msg->cmd;   // 0x80 (par) ou 0x81 (ímpar)

    if (msg->data_len < 8 || msg->data_len > CCCAM_ECM_MAX_SIZE) {
        return 0;
    }

    // Reconstrói a secção completa: [table][len][payload]
    uint16_t sec_len = (uint16_t)(msg->data_len + 1);
    uint8_t section[CCCAM_ECM_MAX_SIZE + 3];
    section[0] = (uint8_t)table_id;
    section[1] = (uint8_t)(0x30 | ((sec_len >> 8) & 0x0F));
    section[2] = (uint8_t)(sec_len & 0xFF);
    memcpy(section + 3, msg->data, msg->data_len);

    memset(&request, 0, sizeof(request));
    request.caid = g_ncd_caid;
    request.provid = 0;
    request.sid = msg->sid;
    request.ecm_len = (uint16_t)(msg->data_len + 3);
    memcpy(request.ecm_data, section, request.ecm_len);
    request.received_at = time(NULL);
    request.client_id = 0;

    // Limite de hops do utilizador (0 = ilimitado)
    cccam_user_t *user = cccam_user_manager_get_user(session->username);
    request.hop = user ? user->max_hops : 3;

    int result = cccam_ecm_process(&request, &response);

    if (result == 0 && response.found) {
        memcpy(reply, response.cw, 16);
        cccam_user_manager_register_ecm(session->username, 1);
        return ncd_send_message(fd, session, msg->msg_id, table_id,
                                reply, 16, 0);
    }

    cccam_user_manager_register_ecm(session->username, 0);
    return ncd_send_message(fd, session, msg->msg_id, table_id, NULL, 0, 0);
}

// Processa uma mensagem completa (os 2 bytes de comprimento já foram lidos)
int cccam_newcamd_process(int fd, cccam_newcamd_session_t *session,
                          uint8_t *raw, size_t raw_len) {
    ncd_msg_t msg;
    int rc;

    if (session->state == 0) {
        rc = ncd_decrypt_message(raw, raw_len, session->login_key, &msg);
    } else {
        rc = ncd_decrypt_message(raw, raw_len, session->session_key, &msg);
        if (rc != 0 && session->key_mode == 0) {
            rc = ncd_decrypt_message(raw, raw_len, session->session_key_alt, &msg);
            if (rc == 0) {
                session->key_mode = 1;
                cccam_log(LOG_DEBUG, "Newcamd: Cliente '%s' usa MD5-crypt", session->username);
            }
        }
    }

    if (rc != 0) {
        cccam_log(LOG_WARN, "Newcamd: Falha ao decriptar mensagem (chave errada?)");
        return -1;
    }

    session->msg_id = msg.msg_id;

    switch (msg.cmd) {
        case NCD_MSG_LOGIN:
            return ncd_handle_login(fd, session, &msg);
        case NCD_MSG_CARD_REQ:
            if (session->state != 1) return -1;
            return ncd_handle_card_req(fd, session, &msg);
        case 0x80:
        case 0x81:
            if (session->state != 1) return -1;
            return ncd_handle_ecm(fd, session, &msg);
        case NCD_MSG_KEEPALIVE:
            session->last_keepalive = time(NULL);
            return ncd_send_message(fd, session, msg.msg_id, NCD_MSG_KEEPALIVE_ACK,
                                    NULL, 0, 0);
        case 0xEB:
            // EMM do cliente Newcamd: reencaminhar para os leitores remotos
            if (session->state == 1 && msg.data_len >= 3) {
                cccam_ecm_forward_emm(g_ncd_caid, 0, msg.data, msg.data_len);
            }
            return ncd_send_message(fd, session, msg.msg_id, 0xEB, NULL, 0, 0);
        default:
            cccam_log(LOG_DEBUG, "Newcamd: Comando 0x%02X ignorado", msg.cmd);
            return 0;
    }
}
