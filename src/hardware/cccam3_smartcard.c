#include "cccam3_smartcard.h"
#include "cccam3_logger.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef USE_PCSC

#include <winscard.h>
#include <unistd.h>

static SCARDCONTEXT g_sc_context = 0;
static int g_sc_initialized = 0;

int cccam_smartcard_init(void) {
    LONG rc;
    if (g_sc_initialized) return 0;

    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_sc_context);
    if (rc != SCARD_S_SUCCESS) {
        cccam_log(LOG_WARN, "SMARTCARD: Falha ao estabelecer contexto PC/SC (0x%08lX)", (unsigned long)rc);
        return -1;
    }
    g_sc_initialized = 1;
    cccam_log(LOG_INFO, "SMARTCARD: Contexto PC/SC inicializado");
    return 0;
}

void cccam_smartcard_cleanup(void) {
    if (g_sc_initialized) {
        SCardReleaseContext(g_sc_context);
        g_sc_context = 0;
        g_sc_initialized = 0;
        cccam_log(LOG_INFO, "SMARTCARD: Contexto PC/SC libertado");
    }
}

int cccam_smartcard_available(void) {
    return g_sc_initialized;
}

// --- Transmissão de APDUs ---

// Resposta do cartão: dados + SW1/SW2
typedef struct {
    uint8_t data[300];
    size_t data_len;
    uint8_t sw1;
    uint8_t sw2;
} sc_response_t;

static int sc_transmit(SCARDHANDLE card, const uint8_t *apdu, size_t apdu_len,
                       sc_response_t *resp) {
    uint8_t recv_buf[512];
    DWORD recv_len = sizeof(recv_buf);
    LONG rc;

    memset(recv_buf, 0, sizeof(recv_buf));
    rc = SCardTransmit(card, SCARD_PCI_T0, apdu, (DWORD)apdu_len,
                       NULL, recv_buf, &recv_len);
    if (rc != SCARD_S_SUCCESS) {
        cccam_log(LOG_WARN, "SMARTCARD: SCardTransmit falhou (0x%08lX)", (unsigned long)rc);
        return -1;
    }

    if (recv_len < 2) {
        cccam_log(LOG_WARN, "SMARTCARD: Resposta do cartão demasiado curta (%lu bytes)", (unsigned long)recv_len);
        return -1;
    }

    resp->data_len = (size_t)recv_len - 2;
    if (resp->data_len > sizeof(resp->data)) {
        resp->data_len = sizeof(resp->data);
    }
    memcpy(resp->data, recv_buf, resp->data_len);
    resp->sw1 = recv_buf[recv_len - 2];
    resp->sw2 = recv_buf[recv_len - 1];
    return 0;
}

static int sc_status_ok(const sc_response_t *resp) {
    return (resp->sw1 == 0x90 && resp->sw2 == 0x00);
}

// --- Ligação ao cartão ---

static SCARDHANDLE sc_connect(const char *reader_name) {
    SCARDHANDLE card = 0;
    DWORD active_proto = 0;
    LONG rc;
    char reader_sel[128];

    if (reader_name && reader_name[0] != '\0') {
        snprintf(reader_sel, sizeof(reader_sel), "%s", reader_name);
    } else {
        // Lista os leitores e usa o primeiro disponível
        char readers[2048];
        DWORD readers_len = sizeof(readers);
        rc = SCardListReaders(g_sc_context, NULL, readers, &readers_len);
        if (rc != SCARD_S_SUCCESS || readers_len == 0 || readers[0] == '\0') {
            cccam_log(LOG_WARN, "SMARTCARD: Nenhum leitor PC/SC disponível");
            return 0;
        }
        snprintf(reader_sel, sizeof(reader_sel), "%s", readers);
    }

    rc = SCardConnect(g_sc_context, reader_sel, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &active_proto);
    if (rc != SCARD_S_SUCCESS) {
        cccam_log(LOG_WARN, "SMARTCARD: Falha ao ligar ao cartão '%s' (0x%08lX)",
                  reader_sel, (unsigned long)rc);
        return 0;
    }

    cccam_log(LOG_DEBUG, "SMARTCARD: Ligado ao cartão em '%s'", reader_sel);
    return card;
}

// --- Drivers de CAID ---

// Seca/Mediaguard (0x0100): enumera providers com CA A4, envia o ECM com
// C1 3C e lê a CW com C1 3A (mesma sequência do OSCam reader-seca.c).
static int sc_seca_ecm(SCARDHANDLE card, uint16_t provid,
                       const uint8_t *ecm, uint16_t ecm_len, uint8_t *cw) {
    sc_response_t resp;
    int provider_index = -1;

    // 1. Enumerar providers: CA A4 00 00 00
    const uint8_t ins_a4[] = { 0xCA, 0xA4, 0x00, 0x00, 0x00 };
    if (sc_transmit(card, ins_a4, sizeof(ins_a4), &resp) != 0) {
        return -1;
    }

    // A resposta contém entradas de 8 bytes: 3 bytes de provid + 5 de dados
    for (size_t i = 0; i + 8 <= resp.data_len; i += 8) {
        uint32_t p = ((uint32_t)resp.data[i] << 16) |
                     ((uint32_t)resp.data[i + 1] << 8) | resp.data[i + 2];
        if ((provid == 0 || p == provid) && provider_index < 0) {
            provider_index = (int)(i / 8);
        }
    }

    if (provider_index < 0) {
        // Alguns cartões devolvem apenas os providers válidos sem index fixo;
        // tentamos o índice 0 como fallback apenas se houver dados
        if (resp.data_len >= 8 && (resp.sw1 == 0x90 || resp.sw1 == 0x9F)) {
            provider_index = 0;
        } else {
            cccam_log(LOG_WARN, "SMARTCARD Seca: Provider %04X não encontrado no cartão", provid);
            return -1;
        }
    }

    if (ecm_len < 8) {
        cccam_log(LOG_WARN, "SMARTCARD Seca: ECM demasiado curto (%u bytes)", ecm_len);
        return -1;
    }

    // 2. Enviar ECM: C1 3C 00 <idx> <keynr> <len> + dados
    uint16_t sec_len = (uint16_t)(((ecm[1] & 0x0F) << 8) | ecm[2]);
    if (sec_len < 5 || sec_len - 5 > ecm_len - 8) {
        cccam_log(LOG_WARN, "SMARTCARD Seca: Comprimento de secção inválido (%u)", sec_len);
        return -1;
    }
    uint8_t data_len = (uint8_t)(sec_len - 5);
    if (data_len > 0xFF) data_len = 0xFF;

    uint8_t ins_3c[5 + 256];
    ins_3c[0] = 0xC1;
    ins_3c[1] = 0x3C;
    ins_3c[2] = 0x00;
    ins_3c[3] = (uint8_t)provider_index;
    ins_3c[4] = ecm[7]; // key nr
    ins_3c[5] = data_len;
    memcpy(ins_3c + 6, ecm + 8, data_len);

    if (sc_transmit(card, ins_3c, 6 + data_len, &resp) != 0) {
        return -1;
    }

    // SW 90 1A: cartão pede token
    if (resp.sw1 == 0x90 && resp.sw2 == 0x1A) {
        const uint8_t ins_30[] = { 0xC1, 0x30, 0x00, 0x02, 0x09 };
        const uint8_t ins_30_data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };
        if (sc_transmit(card, ins_30, sizeof(ins_30), &resp) != 0) return -1;
        if (sc_transmit(card, ins_30_data, sizeof(ins_30_data), &resp) != 0) return -1;
        if (sc_transmit(card, ins_3c, 6 + data_len, &resp) != 0) return -1;
    }

    // SW 96 00 (ECM falso) e 93 02 (não subscrito) → falha
    if ((resp.sw1 == 0x96 && resp.sw2 == 0x00) ||
        (resp.sw1 == 0x93 && resp.sw2 == 0x02)) {
        cccam_log(LOG_DEBUG, "SMARTCARD Seca: ECM rejeitado (SW %02X %02X)", resp.sw1, resp.sw2);
        return -1;
    }

    // 3. Ler CW: C1 3A 00 00 10
    const uint8_t ins_3a[] = { 0xC1, 0x3A, 0x00, 0x00, 0x10 };
    if (sc_transmit(card, ins_3a, sizeof(ins_3a), &resp) != 0) {
        return -1;
    }
    if (resp.data_len < 16 || !sc_status_ok(&resp)) {
        cccam_log(LOG_WARN, "SMARTCARD Seca: Resposta de CW inválida (SW %02X %02X)",
                  resp.sw1, resp.sw2);
        return -1;
    }

    memcpy(cw, resp.data, 16);
    return 0;
}

// Conax (0x0B00): DD A2 com o ECM, DD CA para ler a CW (OSCam reader-conax.c).
static int sc_conax_ecm(SCARDHANDLE card, const uint8_t *ecm, uint16_t ecm_len,
                        uint8_t *cw) {
    sc_response_t resp;
    uint8_t buf[256];

    // DD A2 00 00 <len> + [0x14, len+1, 0x00] + ecm
    if (ecm_len > 250) {
        cccam_log(LOG_WARN, "SMARTCARD Conax: ECM demasiado grande (%u bytes)", ecm_len);
        return -1;
    }

    buf[0] = 0x14;
    buf[1] = (uint8_t)(ecm_len + 1);
    buf[2] = 0x00; // sem rotação de emparelhamento
    memcpy(buf + 3, ecm, ecm_len);

    uint8_t ins_a2[5];
    ins_a2[0] = 0xDD;
    ins_a2[1] = 0xA2;
    ins_a2[2] = 0x00;
    ins_a2[3] = 0x00;
    ins_a2[4] = (uint8_t)(ecm_len + 3);

    if (sc_transmit(card, ins_a2, sizeof(ins_a2), &resp) != 0) return -1;
    if (sc_transmit(card, buf, ecm_len + 3, &resp) != 0) return -1;

    // Lê a resposta enquanto o cartão pedir (SW1 = 0x98)
    int found_cw = 0;
    uint8_t cw_idx0 = 0, cw_idx1 = 0;
    uint8_t cw0[8], cw1[8];

    while (resp.sw1 == 0x98 && resp.sw2 != 0xFF) {
        uint8_t ins_ca[5];
        ins_ca[0] = 0xDD;
        ins_ca[1] = 0xCA;
        ins_ca[2] = 0x00;
        ins_ca[3] = 0x00;
        ins_ca[4] = resp.sw2;

        if (sc_transmit(card, ins_ca, sizeof(ins_ca), &resp) != 0) return -1;

        if (resp.sw1 == 0x98 || resp.sw1 == 0x90) {
            for (size_t i = 0; i + 2 <= resp.data_len; ) {
                size_t entry_len = (size_t)resp.data[i + 1] + 2;
                if (i + entry_len > resp.data_len) break;

                if (resp.data[i] == 0x25 && resp.data[i + 1] >= 0x0D) {
                    uint8_t n = resp.data[i + 4];
                    if (n == 0) {
                        memcpy(cw0, resp.data + i + 7, 8);
                        cw_idx0 = 1;
                    } else if (n == 1) {
                        memcpy(cw1, resp.data + i + 7, 8);
                        cw_idx1 = 1;
                    }
                }
                i += entry_len;
            }
        }
    }

    if (cw_idx0) memcpy(cw, cw0, 8);
    if (cw_idx1) memcpy(cw + 8, cw1, 8);
    found_cw = cw_idx0 && cw_idx1;

    if (!found_cw) {
        cccam_log(LOG_DEBUG, "SMARTCARD Conax: CW não obtida (SW %02X %02X)", resp.sw1, resp.sw2);
        return -1;
    }
    return 0;
}

// --- Interface pública ---

int cccam_smartcard_ecm(const char *reader_name, uint16_t caid, uint16_t provid,
                        const uint8_t *ecm, uint16_t ecm_len, uint8_t *cw) {
    SCARDHANDLE card;
    int result = -1;

    if (!g_sc_initialized) {
        cccam_log(LOG_WARN, "SMARTCARD: PC/SC não inicializado");
        return -1;
    }

    if (!ecm || !cw || ecm_len < 8) {
        return -1;
    }

    card = sc_connect(reader_name);
    if (!card) {
        return -1;
    }

    switch (caid & 0xFF00) {
        case 0x0100:
            result = sc_seca_ecm(card, provid, ecm, ecm_len, cw);
            break;
        case 0x0B00:
            result = sc_conax_ecm(card, ecm, ecm_len, cw);
            break;
        default:
            cccam_log(LOG_DEBUG, "SMARTCARD: CAID %04X não suportado no leitor local", caid);
            result = -1;
            break;
    }

    SCardDisconnect(card, SCARD_LEAVE_CARD);
    return result;
}

#else // USE_PCSC

int cccam_smartcard_init(void) {
    cccam_log(LOG_WARN, "SMARTCARD: Compilado sem suporte PC/SC (USE_PCSC não definido)");
    return -1;
}

void cccam_smartcard_cleanup(void) {
}

int cccam_smartcard_available(void) {
    return 0;
}

int cccam_smartcard_ecm(const char *reader_name, uint16_t caid, uint16_t provid,
                        const uint8_t *ecm, uint16_t ecm_len, uint8_t *cw) {
    (void)reader_name;
    (void)caid;
    (void)provid;
    (void)ecm;
    (void)ecm_len;
    (void)cw;
    cccam_log(LOG_WARN, "SMARTCARD: Sem suporte PC/SC - use um leitor remoto ou compile com USE_PCSC");
    return -1;
}

#endif // USE_PCSC
