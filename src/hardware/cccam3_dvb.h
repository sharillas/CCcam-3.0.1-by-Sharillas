#ifndef CCCAM3_DVB_H
#define CCCAM3_DVB_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define CCCAM3_DVB_MAX_CHANNELS 256

typedef enum {
    CCCAM3_DVB_DELIVERY_AUTO = 0,
    CCCAM3_DVB_DELIVERY_S = 1,
    CCCAM3_DVB_DELIVERY_S2 = 2,
    CCCAM3_DVB_DELIVERY_C = 3,
    CCCAM3_DVB_DELIVERY_C2 = 4,
    CCCAM3_DVB_DELIVERY_T = 5,
    CCCAM3_DVB_DELIVERY_T2 = 6
} cccam3_dvb_delivery_t;

typedef enum {
    CCCAM3_DVB_MOD_AUTO = 0,
    CCCAM3_DVB_MOD_QPSK = 1,
    CCCAM3_DVB_MOD_PSK8 = 2,
    CCCAM3_DVB_MOD_QAM16 = 3,
    CCCAM3_DVB_MOD_QAM32 = 4,
    CCCAM3_DVB_MOD_QAM64 = 5,
    CCCAM3_DVB_MOD_QAM128 = 6,
    CCCAM3_DVB_MOD_QAM256 = 7
} cccam3_dvb_modulation_t;

typedef enum {
    CCCAM3_DVB_FEC_AUTO = 0,
    CCCAM3_DVB_FEC_1_2 = 1,
    CCCAM3_DVB_FEC_2_3 = 2,
    CCCAM3_DVB_FEC_3_4 = 3,
    CCCAM3_DVB_FEC_5_6 = 4,
    CCCAM3_DVB_FEC_7_8 = 5,
    CCCAM3_DVB_FEC_8_9 = 6,
    CCCAM3_DVB_FEC_9_10 = 7
} cccam3_dvb_fec_t;

typedef enum {
    CCCAM3_DVB_INV_AUTO = 0,
    CCCAM3_DVB_INV_ON = 1,
    CCCAM3_DVB_INV_OFF = 2
} cccam3_dvb_inversion_t;

typedef enum {
    CCCAM3_DVB_POL_AUTO = 0,
    CCCAM3_DVB_POL_H = 1,
    CCCAM3_DVB_POL_V = 2
} cccam3_dvb_polarity_t;

typedef struct {
    int enabled;
    int adapter;
    int frontend;
    int demux;
    int frequency_khz;
    int symbol_rate;
    int delivery_system;
    int modulation;
    int fec;
    int inversion;
    int polarity;
    int service_id;
    int bandwidth;          // DVB-T/T2: 6, 7 ou 8 MHz (0 = 8 MHz)
} cccam_dvb_config_t;

typedef struct {
    uint16_t sid;
    uint16_t pmt_pid;
    uint16_t caid;
    uint16_t ecm_pid;
    uint16_t video_pid;
    char name[64];
} cccam_dvb_channel_t;

int cccam_dvb_init(cccam_dvb_config_t *config);
void cccam_dvb_cleanup(void);
int cccam_dvb_is_running(void);
int cccam_dvb_get_channels(cccam_dvb_channel_t *channels, int max_channels);

#endif // CCCAM3_DVB_H
