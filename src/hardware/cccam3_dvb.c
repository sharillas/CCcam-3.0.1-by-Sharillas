#include "cccam3_dvb.h"
#include "cccam3_logger.h"
#include "cccam3_ecm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/dvb/frontend.h>
#include <linux/dvb/dmx.h>

// Descrambler do demux: presente apenas em kernels de STBs (ex.: Dreambox/VU+).
// Definição local compatível para sistemas sem o patch no header.
struct cccam3_dmx_descr {
    int index;
    int flags;
    uint8_t cw[16];
};

#ifndef DMX_SET_DESCRAMBLER
#define DMX_SET_DESCRAMBLER _IOW('o', 47, struct cccam3_dmx_descr)
#endif

#ifndef DMX_DESCRAMBLER_KEY_ODD
#define DMX_DESCRAMBLER_KEY_ODD 1
#define DMX_DESCRAMBLER_KEY_EVEN 2
#endif

#ifndef SYS_DVBC2
#define SYS_DVBC2 19
#endif

// --- Estado ---
static int g_running = 0;
static pthread_t g_thread;
static pthread_mutex_t g_chan_mutex = PTHREAD_MUTEX_INITIALIZER;
static cccam_dvb_config_t g_config;
static int g_frontend_fd = -1;
static int g_demux_fd = -1;
static int g_pes_demux_fd = -1;
static cccam_dvb_channel_t g_channels[CCCAM3_DVB_MAX_CHANNELS];
static int g_channel_count = 0;
static uint16_t g_service_id = 0;
static uint16_t g_ecm_pid = 0;
static uint16_t g_caid = 0;
static uint16_t g_video_pid = 0;
static uint32_t g_total_ecm = 0;
static uint32_t g_total_cw = 0;
static uint8_t g_section_buf[4096];

// --- Mapeamentos de configuração ---

static fe_modulation_t dvb_modulation(void) {
    switch (g_config.modulation) {
        case CCCAM3_DVB_MOD_QPSK: return QPSK;
        case CCCAM3_DVB_MOD_PSK8: return PSK_8;
        case CCCAM3_DVB_MOD_QAM16: return QAM_16;
        case CCCAM3_DVB_MOD_QAM32: return QAM_32;
        case CCCAM3_DVB_MOD_QAM64: return QAM_64;
        case CCCAM3_DVB_MOD_QAM128: return QAM_128;
        case CCCAM3_DVB_MOD_QAM256: return QAM_256;
        default: return QAM_AUTO;
    }
}

static fe_code_rate_t dvb_fec(void) {
    switch (g_config.fec) {
        case CCCAM3_DVB_FEC_1_2: return FEC_1_2;
        case CCCAM3_DVB_FEC_2_3: return FEC_2_3;
        case CCCAM3_DVB_FEC_3_4: return FEC_3_4;
        case CCCAM3_DVB_FEC_5_6: return FEC_5_6;
        case CCCAM3_DVB_FEC_7_8: return FEC_7_8;
        case CCCAM3_DVB_FEC_8_9: return FEC_8_9;
        case CCCAM3_DVB_FEC_9_10: return FEC_9_10;
        default: return FEC_AUTO;
    }
}

static fe_spectral_inversion_t dvb_inversion(void) {
    switch (g_config.inversion) {
        case CCCAM3_DVB_INV_ON: return INVERSION_ON;
        case CCCAM3_DVB_INV_OFF: return INVERSION_OFF;
        default: return INVERSION_AUTO;
    }
}

static fe_delivery_system_t dvb_delivery_system(void) {
    switch (g_config.delivery_system) {
        case CCCAM3_DVB_DELIVERY_S: return SYS_DVBS;
        case CCCAM3_DVB_DELIVERY_S2: return SYS_DVBS2;
        case CCCAM3_DVB_DELIVERY_C: return SYS_DVBC_ANNEX_A;
        case CCCAM3_DVB_DELIVERY_C2: return SYS_DVBC2;
        case CCCAM3_DVB_DELIVERY_T: return SYS_DVBT;
        case CCCAM3_DVB_DELIVERY_T2: return SYS_DVBT2;
        default: {
            struct dvb_frontend_info info;
            if (ioctl(g_frontend_fd, FE_GET_INFO, &info) == 0) {
                if (info.type == FE_QAM) return SYS_DVBC_ANNEX_A;
                if (info.type == FE_QPSK) return SYS_DVBS2;
                if (info.type == FE_OFDM) return SYS_DVBT2;
            }
            return SYS_DVBS2;
        }
    }
}

// --- Parsing de tabelas MPEG ---

static int dvb_parse_pat(const uint8_t *buf, int len) {
    if (len < 8 || buf[0] != 0x00) return -1;
    int section_length = ((buf[1] & 0x0F) << 8) | buf[2];
    if (section_length + 3 > len || section_length < 9) return -1;
    int end = 3 + section_length - 4;
    int off = 8;
    int count = 0;

    while (off + 4 <= end && count < CCCAM3_DVB_MAX_CHANNELS) {
        uint16_t program = (uint16_t)((buf[off] << 8) | buf[off + 1]);
        uint16_t pid = (uint16_t)(((buf[off + 2] & 0x1F) << 8) | buf[off + 3]);
        off += 4;
        if (program == 0) continue;

        cccam_dvb_channel_t *ch = &g_channels[count];
        memset(ch, 0, sizeof(*ch));
        ch->sid = program;
        ch->pmt_pid = pid;
        snprintf(ch->name, sizeof(ch->name), "SID %04X", program);
        count++;
    }

    return count;
}

static void dvb_parse_sdt(const uint8_t *buf, int len) {
    if (len < 11 || buf[0] != 0x42) return;
    int section_length = ((buf[1] & 0x0F) << 8) | buf[2];
    if (section_length + 3 > len) return;
    int end = 3 + section_length - 4;
    int off = 11;

    while (off + 5 <= end) {
        uint16_t sid = (uint16_t)((buf[off] << 8) | buf[off + 1]);
        uint16_t desc_len = (uint16_t)(((buf[off + 3] & 0x0F) << 8) | buf[off + 4]);
        off += 5;
        if (off + desc_len > end) break;

        int d = off;
        int dend = off + desc_len;
        while (d + 2 <= dend) {
            uint8_t tag = buf[d];
            uint8_t dlen = buf[d + 1];
            if (d + 2 + dlen > dend) break;
            if (tag == 0x48 && dlen >= 3) {
                int provider_len = buf[d + 3];
                int name_pos = d + 4 + provider_len + 1;
                if (name_pos < d + 2 + dlen) {
                    int name_len = buf[name_pos - 1];
                    if (name_pos + name_len <= d + 2 + dlen && name_len > 0 && name_len < 64) {
                        for (int i = 0; i < g_channel_count; i++) {
                            if (g_channels[i].sid == sid) {
                                memcpy(g_channels[i].name, buf + name_pos, name_len);
                                g_channels[i].name[name_len] = '\0';
                                break;
                            }
                        }
                    }
                }
            }
            d += 2 + dlen;
        }
        off = dend;
    }
}

static int dvb_parse_pmt(const uint8_t *buf, int len,
                         uint16_t *ecm_pid, uint16_t *caid, uint16_t *video_pid) {
    if (len < 12 || buf[0] != 0x02) return -1;
    int section_length = ((buf[1] & 0x0F) << 8) | buf[2];
    if (section_length + 3 > len) return -1;
    int end = 3 + section_length - 4;

    uint16_t prog_info_len = (uint16_t)(((buf[10] & 0x0F) << 8) | buf[11]);
    int off = 12;
    if (off > end) return -1;
    if (off + prog_info_len > end) return -1;

    int d = off;
    int dend = off + prog_info_len;
    while (d + 2 <= dend) {
        uint8_t tag = buf[d];
        uint8_t dlen = buf[d + 1];
        if (d + 2 + dlen > dend) break;
        if (tag == 0x09 && dlen >= 4) {
            *caid = (uint16_t)((buf[d + 2] << 8) | buf[d + 3]);
            *ecm_pid = (uint16_t)(((buf[d + 4] & 0x1F) << 8) | buf[d + 5]);
        }
        d += 2 + dlen;
    }

    off = dend;
    while (off + 5 <= end) {
        uint8_t stream_type = buf[off];
        uint16_t elem_pid = (uint16_t)(((buf[off + 1] & 0x1F) << 8) | buf[off + 2]);
        uint16_t es_info_len = (uint16_t)(((buf[off + 3] & 0x0F) << 8) | buf[off + 4]);
        off += 5;
        if (off + es_info_len > end) break;
        if (*video_pid == 0 &&
            (stream_type == 0x01 || stream_type == 0x02 || stream_type == 0x10 ||
             stream_type == 0x1B || stream_type == 0x24)) {
            *video_pid = elem_pid;
        }
        off += es_info_len;
    }

    return 0;
}

// --- Demux ---

static int dvb_set_section_filter(int fd, uint16_t pid, uint8_t table_id, uint8_t mask) {
    struct dmx_sct_filter_params sct;
    memset(&sct, 0, sizeof(sct));
    sct.pid = pid;
    sct.timeout = 0;
    sct.flags = DMX_CHECK_CRC | DMX_IMMEDIATE_START;
    sct.filter.filter[0] = table_id;
    sct.filter.mask[0] = mask;

    if (ioctl(fd, DMX_SET_FILTER, &sct) < 0) {
        cccam_log(LOG_ERROR, "DVB: DMX_SET_FILTER (pid 0x%04X) falhou: %s", pid, strerror(errno));
        return -1;
    }
    return 0;
}

static int dvb_read_section(int fd, uint8_t *buf, size_t size, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int r = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return -1;

    ssize_t n = read(fd, buf, size);
    if (n <= 0) return -1;
    return (int)n;
}

// --- Sintonia ---

static int dvb_tune(void) {
    struct dtv_property props[12];
    struct dtv_properties cmdseq;
    memset(props, 0, sizeof(props));
    int i = 0;

    fe_delivery_system_t sys = dvb_delivery_system();
    props[i].cmd = DTV_DELIVERY_SYSTEM;
    props[i].u.data = (uint32_t)sys;
    i++;

    props[i].cmd = DTV_FREQUENCY;
    props[i].u.data = (uint32_t)g_config.frequency_khz * 1000U;
    i++;

    if (g_config.symbol_rate > 0) {
        props[i].cmd = DTV_SYMBOL_RATE;
        props[i].u.data = (uint32_t)g_config.symbol_rate;
        i++;
    }

    props[i].cmd = DTV_INVERSION;
    props[i].u.data = (uint32_t)dvb_inversion();
    i++;

    props[i].cmd = DTV_MODULATION;
    props[i].u.data = (uint32_t)dvb_modulation();
    i++;

    props[i].cmd = DTV_INNER_FEC;
    props[i].u.data = (uint32_t)dvb_fec();
    i++;

    if (sys == SYS_DVBS || sys == SYS_DVBS2) {
        props[i].cmd = DTV_VOLTAGE;
        props[i].u.data = (g_config.polarity == CCCAM3_DVB_POL_H) ? SEC_VOLTAGE_18 : SEC_VOLTAGE_13;
        i++;
        props[i].cmd = DTV_TONE;
        props[i].u.data = SEC_TONE_OFF;
        i++;
    }

    if (sys == SYS_DVBT || sys == SYS_DVBT2) {
        // Largura de banda do canal (6/7/8 MHz; 0 = 8 MHz)
        uint32_t bw = 8000000;
        if (g_config.bandwidth == 6) bw = 6000000;
        else if (g_config.bandwidth == 7) bw = 7000000;
        props[i].cmd = DTV_BANDWIDTH_HZ;
        props[i].u.data = bw;
        i++;
    }

    props[i].cmd = DTV_TUNE;
    i++;

    cmdseq.num = i;
    cmdseq.props = props;

    if (ioctl(g_frontend_fd, FE_SET_PROPERTY, &cmdseq) < 0) {
        cccam_log(LOG_ERROR, "DVB: FE_SET_PROPERTY falhou: %s", strerror(errno));
        return -1;
    }

    for (int t = 0; t < 50; t++) {
        fe_status_t status = 0;
        if (ioctl(g_frontend_fd, FE_READ_STATUS, &status) == 0 && (status & FE_HAS_LOCK)) {
            return 0;
        }
        usleep(100000);
    }
    return -1;
}

// --- Injeção de CW ---

static void dvb_write_cw(const uint8_t *cw, int parity) {
    if (g_pes_demux_fd < 0) {
        return;
    }

    struct cccam3_dmx_descr descr;
    memset(&descr, 0, sizeof(descr));
    descr.index = parity ? 1 : 0;
    descr.flags = parity ? DMX_DESCRAMBLER_KEY_ODD : DMX_DESCRAMBLER_KEY_EVEN;
    memcpy(descr.cw, cw, 16);

    if (ioctl(g_pes_demux_fd, DMX_SET_DESCRAMBLER, &descr) < 0) {
        cccam_log(LOG_DEBUG, "DVB: DMX_SET_DESCRAMBLER falhou: %s", strerror(errno));
    } else {
        cccam_log(LOG_DEBUG, "DVB: CW (%s) injetada no descrambler", parity ? "ímpar" : "par");
    }
}

// --- Gestão de serviço ---

static void dvb_select_channel(int idx) {
    cccam_dvb_channel_t *ch = &g_channels[idx];
    g_service_id = ch->sid;
    g_ecm_pid = ch->ecm_pid;
    g_caid = ch->caid;
    g_video_pid = ch->video_pid;

    cccam_log(LOG_INFO, "DVB: Serviço selecionado: SID %04X (%s) | CAID %04X | ECM PID 0x%04X",
              g_service_id, ch->name, g_caid, g_ecm_pid);

    if (g_ecm_pid != 0) {
        dvb_set_section_filter(g_demux_fd, g_ecm_pid, 0x80, 0xF0);
    }

    if (g_pes_demux_fd >= 0 && g_video_pid != 0) {
        struct dmx_pes_filter_params pes;
        memset(&pes, 0, sizeof(pes));
        pes.pid = g_video_pid;
        pes.input = DMX_IN_FRONTEND;
        pes.output = DMX_OUT_DECODER;
        pes.pes_type = DMX_PES_OTHER;
        pes.flags = 0;

        if (ioctl(g_pes_demux_fd, DMX_SET_PES_FILTER, &pes) < 0) {
            cccam_log(LOG_WARN, "DVB: DMX_SET_PES_FILTER falhou: %s", strerror(errno));
        } else {
            ioctl(g_pes_demux_fd, DMX_START);
        }
    }
}

static void dvb_scan_channels(void) {
    int n;

    pthread_mutex_lock(&g_chan_mutex);
    g_channel_count = 0;
    g_service_id = 0;
    g_ecm_pid = 0;
    g_caid = 0;
    g_video_pid = 0;
    pthread_mutex_unlock(&g_chan_mutex);

    // PAT
    if (dvb_set_section_filter(g_demux_fd, 0x0000, 0x00, 0xFF) != 0) return;
    n = dvb_read_section(g_demux_fd, g_section_buf, sizeof(g_section_buf), 3000);
    if (n <= 0) {
        cccam_log(LOG_WARN, "DVB: Falha ao obter PAT");
        return;
    }
    pthread_mutex_lock(&g_chan_mutex);
    g_channel_count = dvb_parse_pat(g_section_buf, n);
    pthread_mutex_unlock(&g_chan_mutex);
    if (g_channel_count <= 0) {
        cccam_log(LOG_WARN, "DVB: PAT sem serviços");
        return;
    }

    // SDT (nomes dos serviços)
    if (dvb_set_section_filter(g_demux_fd, 0x0011, 0x42, 0xFF) == 0) {
        n = dvb_read_section(g_demux_fd, g_section_buf, sizeof(g_section_buf), 3000);
        if (n > 0) {
            pthread_mutex_lock(&g_chan_mutex);
            dvb_parse_sdt(g_section_buf, n);
            pthread_mutex_unlock(&g_chan_mutex);
        }
    }

    // PMT de cada serviço
    for (int i = 0; i < g_channel_count; i++) {
        if (dvb_set_section_filter(g_demux_fd, g_channels[i].pmt_pid, 0x02, 0xFF) != 0) continue;
        n = dvb_read_section(g_demux_fd, g_section_buf, sizeof(g_section_buf), 1500);
        if (n > 0) {
            pthread_mutex_lock(&g_chan_mutex);
            dvb_parse_pmt(g_section_buf, n, &g_channels[i].ecm_pid,
                          &g_channels[i].caid, &g_channels[i].video_pid);
            pthread_mutex_unlock(&g_chan_mutex);
        }
    }

    // Escolher serviço: configurado, senão o primeiro com ECM
    int selected = -1;
    if (g_config.service_id > 0) {
        for (int i = 0; i < g_channel_count; i++) {
            if (g_channels[i].sid == (uint16_t)g_config.service_id) {
                selected = i;
                break;
            }
        }
    }
    if (selected < 0) {
        for (int i = 0; i < g_channel_count; i++) {
            if (g_channels[i].ecm_pid != 0) {
                selected = i;
                break;
            }
        }
    }

    cccam_log(LOG_INFO, "DVB: %d serviços no transponder:", g_channel_count);
    for (int i = 0; i < g_channel_count; i++) {
        cccam_log(LOG_INFO, "DVB:   SID %04X | PMT 0x%04X | ECM 0x%04X | CAID %04X | %s",
                  g_channels[i].sid, g_channels[i].pmt_pid, g_channels[i].ecm_pid,
                  g_channels[i].caid, g_channels[i].name);
    }

    if (selected >= 0) {
        dvb_select_channel(selected);
    } else {
        cccam_log(LOG_WARN, "DVB: Nenhum serviço com ECM encontrado");
    }
}

// --- Processamento de ECM ---

static void dvb_handle_ecm(const uint8_t *sec, int len) {
    if (len < 8) return;
    int parity = (sec[0] == 0x80) ? 0 : 1;

    cccam_ecm_request_t req;
    memset(&req, 0, sizeof(req));
    req.caid = g_caid;
    req.provid = 0;
    req.sid = g_service_id;
    req.ecm_len = (uint16_t)(len > CCCAM_ECM_MAX_SIZE ? CCCAM_ECM_MAX_SIZE : len);
    memcpy(req.ecm_data, sec, req.ecm_len);
    req.received_at = time(NULL);
    req.client_id = 0;
    req.hop = 1;

    cccam_ecm_response_t resp;
    int result = cccam_ecm_process(&req, &resp);
    g_total_ecm++;

    if (result == 0 && resp.found) {
        g_total_cw++;
        dvb_write_cw(resp.cw, parity);
    } else {
        cccam_log(LOG_DEBUG, "DVB: ECM não resolvido (SID %04X, CAID %04X)", g_service_id, g_caid);
    }
}

// --- EMM (manutenção de direitos dos cartões do share) ---

static int g_emm_demux_fd = -1;
static uint16_t g_emm_pid = 0;

// Lê o CAT (PID 0x0001), encontra o EMM PID do CAID sintonizado e filtra-o
static int dvb_setup_emm(void) {
    uint8_t buf[4096];

    if (g_emm_demux_fd < 0) return -1;
    if (dvb_set_section_filter(g_emm_demux_fd, 0x0001, 0x01, 0xFF) != 0) return -1;

    int n = dvb_read_section(g_emm_demux_fd, buf, sizeof(buf), 1500);
    if (n <= 0 || buf[0] != 0x01) return -1;

    int section_length = ((buf[1] & 0x0F) << 8) | buf[2];
    if (section_length + 3 > n) return -1;
    int end = 3 + section_length - 4;

    for (int off = 8; off + 2 <= end; ) {
        uint8_t tag = buf[off];
        uint8_t dlen = buf[off + 1];
        if (off + 2 + dlen > end) break;

        if (tag == 0x09 && dlen >= 4) {
            uint16_t caid = (uint16_t)((buf[off + 2] << 8) | buf[off + 3]);
            uint16_t pid = (uint16_t)(((buf[off + 4] & 0x1F) << 8) | buf[off + 5]);
            if (caid == g_caid) {
                g_emm_pid = pid;
                break;
            }
        }
        off += 2 + dlen;
    }

    if (g_emm_pid == 0) {
        cccam_log(LOG_DEBUG, "DVB: Sem EMM PID para CAID %04X no CAT", g_caid);
        return -1;
    }

    cccam_log(LOG_INFO, "DVB: EMM PID %04X (CAID %04X) - a encaminhar para os leitores remotos",
              g_emm_pid, g_caid);
    return dvb_set_section_filter(g_emm_demux_fd, g_emm_pid, 0x80, 0xF0);
}

// Reencaminha EMMs (tabelas 0x82-0x8F) para os leitores remotos
static void dvb_handle_emm(void) {
    uint8_t buf[4096];
    int n = dvb_read_section(g_emm_demux_fd, buf, sizeof(buf), 100);
    if (n <= 0) return;

    if (buf[0] >= 0x82 && buf[0] <= 0x8F) {
        cccam_ecm_forward_emm(g_caid, 0, buf, (uint16_t)n);
        cccam_log(LOG_DEBUG, "DVB: EMM (%d bytes) encaminhado", n);
    }
}

// --- Thread principal ---

static void *dvb_thread_func(void *arg) {
    (void)arg;
    int locked = 0;

    while (g_running) {
        if (!locked) {
            if (dvb_tune() != 0) {
                cccam_log(LOG_WARN, "DVB: Sem sinal ou falha de sintonia - nova tentativa em 3s");
                sleep(3);
                continue;
            }
            locked = 1;
            cccam_log(LOG_INFO, "DVB: Sintonizado (lock OK)");
            dvb_scan_channels();
            if (g_service_id == 0) {
                locked = 0;
                sleep(3);
                continue;
            }
            dvb_setup_emm();
        }

        int n = dvb_read_section(g_demux_fd, g_section_buf, sizeof(g_section_buf), 1000);
        if (n > 0) {
            if (g_section_buf[0] == 0x80 || g_section_buf[0] == 0x81) {
                dvb_handle_ecm(g_section_buf, n);
            }
        } else {
            fe_status_t status = 0;
            if (ioctl(g_frontend_fd, FE_READ_STATUS, &status) != 0 || !(status & FE_HAS_LOCK)) {
                cccam_log(LOG_WARN, "DVB: Sinal perdido - a ressintonizar");
                locked = 0;
            }
        }

        // EMMs do transponder (sem bloquear o processamento de ECMs)
        if (g_emm_pid != 0) {
            dvb_handle_emm();
        }
    }

    return NULL;
}

// --- API Pública ---

int cccam_dvb_init(cccam_dvb_config_t *config) {
    if (g_running) return 0;
    if (!config || !config->enabled) {
        return -1;
    }

    g_config = *config;

    char path[64];
    snprintf(path, sizeof(path), "/dev/dvb/adapter%d/frontend%d",
             g_config.adapter, g_config.frontend);
    g_frontend_fd = open(path, O_RDWR | O_NONBLOCK);
    if (g_frontend_fd < 0) {
        cccam_log(LOG_ERROR, "DVB: Falha ao abrir %s: %s", path, strerror(errno));
        return -1;
    }

    struct dvb_frontend_info info;
    if (ioctl(g_frontend_fd, FE_GET_INFO, &info) == 0) {
        cccam_log(LOG_INFO, "DVB: Frontend: %s", info.name);
    }

    snprintf(path, sizeof(path), "/dev/dvb/adapter%d/demux%d",
             g_config.adapter, g_config.demux);
    g_demux_fd = open(path, O_RDWR | O_NONBLOCK);
    if (g_demux_fd < 0) {
        cccam_log(LOG_ERROR, "DVB: Falha ao abrir %s: %s", path, strerror(errno));
        close(g_frontend_fd);
        g_frontend_fd = -1;
        return -1;
    }

    snprintf(path, sizeof(path), "/dev/dvb/adapter%d/demux%d",
             g_config.adapter, g_config.demux + 1);
    g_pes_demux_fd = open(path, O_RDWR | O_NONBLOCK);
    if (g_pes_demux_fd < 0) {
        cccam_log(LOG_WARN, "DVB: Sem demux de descodificação (%s) - CWs não serão injetadas", path);
    }

    // Demux extra para CAT/EMM (opcional)
    snprintf(path, sizeof(path), "/dev/dvb/adapter%d/demux%d",
             g_config.adapter, g_config.demux + 2);
    g_emm_demux_fd = open(path, O_RDWR | O_NONBLOCK);
    if (g_emm_demux_fd < 0) {
        cccam_log(LOG_DEBUG, "DVB: Sem demux extra para EMM (%s)", path);
    }

    g_running = 1;
    if (pthread_create(&g_thread, NULL, dvb_thread_func, NULL) != 0) {
        cccam_log(LOG_ERROR, "DVB: Falha ao criar thread");
        g_running = 0;
        if (g_pes_demux_fd >= 0) { close(g_pes_demux_fd); g_pes_demux_fd = -1; }
        if (g_demux_fd >= 0) { close(g_demux_fd); g_demux_fd = -1; }
        if (g_frontend_fd >= 0) { close(g_frontend_fd); g_frontend_fd = -1; }
        return -1;
    }

    cccam_log(LOG_INFO, "DVB: Leitor de hardware iniciado (adapter %d, frontend %d, %d kHz, SR %d)",
              g_config.adapter, g_config.frontend, g_config.frequency_khz, g_config.symbol_rate);
    return 0;
}

void cccam_dvb_cleanup(void) {
    if (!g_running) return;

    g_running = 0;
    pthread_join(g_thread, NULL);

    if (g_pes_demux_fd >= 0) { close(g_pes_demux_fd); g_pes_demux_fd = -1; }
    if (g_emm_demux_fd >= 0) { close(g_emm_demux_fd); g_emm_demux_fd = -1; }
    if (g_demux_fd >= 0) { close(g_demux_fd); g_demux_fd = -1; }
    if (g_frontend_fd >= 0) { close(g_frontend_fd); g_frontend_fd = -1; }

    cccam_log(LOG_INFO, "DVB: Leitor de hardware encerrado (ECMs: %u, CWs: %u)",
              g_total_ecm, g_total_cw);
}

int cccam_dvb_is_running(void) {
    return g_running;
}

int cccam_dvb_get_channels(cccam_dvb_channel_t *channels, int max_channels) {
    if (!channels || max_channels <= 0) return 0;

    pthread_mutex_lock(&g_chan_mutex);
    int count = g_channel_count < max_channels ? g_channel_count : max_channels;
    memcpy(channels, g_channels, (size_t)count * sizeof(cccam_dvb_channel_t));
    pthread_mutex_unlock(&g_chan_mutex);

    return count;
}
