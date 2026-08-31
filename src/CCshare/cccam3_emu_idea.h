#ifndef CCCAM3_EMU_IDEA_H
#define CCCAM3_EMU_IDEA_H

// IDEA (Eric Young, eay@cryptsoft.com) - portado do cscrypt do OSCam

#include <stdint.h>

#define IDEA_INT unsigned int
#define IDEA_ENCRYPT    1
#define IDEA_DECRYPT    0
#define IDEA_BLOCK  8
#define IDEA_KEY_LENGTH 16

typedef struct idea_key_st {
    IDEA_INT data[9][6];
} IDEA_KEY_SCHEDULE;

void cccam_emu_idea_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks);
void cccam_emu_idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk);
void cccam_emu_idea_cbc_encrypt(const unsigned char *in, unsigned char *out,
                                long length, IDEA_KEY_SCHEDULE *ks,
                                unsigned char *iv, int enc);
void cccam_emu_idea_encrypt(unsigned long *in, IDEA_KEY_SCHEDULE *ks);

#endif // CCCAM3_EMU_IDEA_H
