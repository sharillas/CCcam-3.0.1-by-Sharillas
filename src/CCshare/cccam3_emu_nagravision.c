// Nagra2 EMU - portado de OSCam-emu (GPLv3) module-emulator-nagravision.c
// Usa OpenSSL BN para o RSA e o IDEA do cscrypt do OSCam.

#include "cccam3_emu.h"
#include "cccam3_emu_des.h"
#include "cccam3_emu_idea.h"
#include "cccam3_logger.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>

static void nagra_reverse_mem(uint8_t *in, int32_t len)
{
	uint8_t temp;
	int32_t i;

	for (i = 0; i < (len / 2); i++)
	{
		temp = in[i];
		in[i] = in[len - i - 1];
		in[len - i - 1] = temp;
	}
}

static void nagra_reverse_mem_in_out(uint8_t *out, const uint8_t *in, int32_t n)
{
	if (n > 0)
	{
		out += n;
		do
		{
			*(--out) = *(in++);
		}
		while (--n);
	}
}

static int nagra_rsa_input(BIGNUM *d, const uint8_t *in, int32_t n, int le)
{
	int result = 0;

	if (le)
	{
		uint8_t *tmp = (uint8_t *)malloc(sizeof(uint8_t) * n);

		if (tmp == NULL)
		{
			return 0;
		}

		nagra_reverse_mem_in_out(tmp, in, n);
		result = BN_bin2bn(tmp, n, d) != 0;
		free(tmp);
	}
	else
	{
		result = BN_bin2bn(in, n, d) != 0;
	}

	return result;
}

static int32_t nagra_rsa_output(uint8_t *out, int32_t n, BIGNUM *r, int le)
{
	int32_t s = BN_num_bytes(r);

	if (s > n)
	{
		uint8_t *buff = (uint8_t *)malloc(sizeof(uint8_t) * s);

		if (buff == NULL)
		{
			return 0;
		}

		BN_bn2bin(r, buff);
		memcpy(out, buff + s - n, n);
		free(buff);
	}
	else if (s < n)
	{
		int32_t l = n - s;

		memset(out, 0, l);
		BN_bn2bin(r, out + l);
	}
	else
	{
		BN_bn2bin(r, out);
	}

	if (le)
	{
		nagra_reverse_mem(out, n);
	}

	return s;
}

static int32_t nagra_rsa(uint8_t *out, const uint8_t *in, int32_t n,
                         BIGNUM *exp, BIGNUM *mod, int le)
{
	BN_CTX *ctx;
	BIGNUM *r, *d;
	int32_t result = 0;

	ctx = BN_CTX_new();
	r = BN_new();
	d = BN_new();

	if (nagra_rsa_input(d, in, n, le) && BN_mod_exp(r, d, exp, mod, ctx))
	{
		result = nagra_rsa_output(out, n, r, le);
	}

	BN_free(d);
	BN_free(r);
	BN_CTX_free(ctx);

	return result;
}

// --- Pesquisa de Chaves ('N' no SoftCam.Key) ---

static int nagra_get_key(uint8_t *buf, uint32_t ident, char key_name,
                         uint32_t key_index, uint32_t key_length)
{
	char key_str[8];
	snprintf(key_str, sizeof(key_str), "%c%X", key_name, (unsigned int)key_index);

	if (cccam_emu_find_key('N', ident, key_str, 0, buf, key_length) >= (int)key_length)
	{
		return 1;
	}

	return 0;
}

static int nagra2_signature(const uint8_t *vkey, const uint8_t *sig,
                            const uint8_t *msg, int32_t len)
{
	uint8_t buff[16], iv[8];
	int32_t i, j;

	memcpy(buff, vkey, sizeof(buff));

	for (i = 0; i + 7 < len; i += 8)
	{
		IDEA_KEY_SCHEDULE ek;

		cccam_emu_idea_set_encrypt_key(buff, &ek);
		memcpy(buff, buff + 8, 8);
		memset(iv, 0, sizeof(iv));
		cccam_emu_idea_cbc_encrypt(msg + i, buff + 8, 8, &ek, iv, IDEA_ENCRYPT);

		for (j = 7; j >= 0; j--)
		{
			buff[j + 8] ^= msg[i + j];
		}
	}

	buff[8] &= 0x7F;

	return (memcmp(sig, buff + 8, 8) == 0);
}

static int nagra_decrypt_ecm(uint8_t *in, uint8_t *out, const uint8_t *key,
                             int32_t len, const uint8_t *vkey, uint8_t *keyM)
{
	BIGNUM *exp, *mod;
	uint8_t iv[8];
	int32_t i = 0, sign = in[0] & 0x80;
	uint8_t binExp = 3;
	int result = 1;

	exp = BN_new();
	mod = BN_new();
	BN_bin2bn(&binExp, 1, exp);
	BN_bin2bn(keyM, 64, mod);

	if (nagra_rsa(out, in + 1, 64, exp, mod, 1) <= 0)
	{
		BN_free(exp);
		BN_free(mod);
		return 0;
	}

	out[63] |= sign;

	if (len > 64)
	{
		memcpy(out + 64, in + 65, len - 64);
	}

	memset(iv, 0, sizeof(iv));

	if (in[0] & 0x04)
	{
		uint8_t key1[8], key2[8];

		nagra_reverse_mem_in_out(key1, &key[0], 8);
		nagra_reverse_mem_in_out(key2, &key[8], 8);

		for (i = 7; i >= 0; i--)
		{
			nagra_reverse_mem(out + 8 * i, 8);
		}

		cccam_emu_des_ede2_cbc_decrypt(out, iv, key1, key2, len);

		for (i = 7; i >= 0; i--)
		{
			nagra_reverse_mem(out + 8 * i, 8);
		}
	}
	else
	{
		IDEA_KEY_SCHEDULE ek;

		cccam_emu_idea_set_encrypt_key(key, &ek);
		cccam_emu_idea_cbc_encrypt(out, out, len & ~7, &ek, iv, IDEA_DECRYPT);
	}

	nagra_reverse_mem(out, 64);

	if (result && nagra_rsa(out, out, 64, exp, mod, 0) <= 0)
	{
		result = 0;
	}

	if (result && vkey && !nagra2_signature(vkey, out, out + 8, len - 8))
	{
		result = 0;
	}

	BN_free(exp);
	BN_free(mod);
	return result;
}

static uint16_t nagra_sct_len(const uint8_t *ecm)
{
	return (uint16_t)(((ecm[1] & 0x0F) << 8) | ecm[2]);
}

int cccam_emu_nagravision_ecm(uint16_t caid, uint8_t *ecm, uint8_t *dw)
{
	int useVerifyKey = 0;
	int32_t l = 0, s;

	uint8_t cmdLen, ideaKeyNr, *dec, ideaKey[16], vKey[16], m1Key[64], mecmAlgo = 0;
	uint16_t i = 0, ecmLen = nagra_sct_len(ecm);
	uint32_t ident, identMask, tmp1, tmp2, tmp3;

	(void)caid;

	if (ecmLen < 8)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	cmdLen = ecm[4] - 5;
	ident = (uint32_t)((ecm[5] << 8) + ecm[6]);
	ideaKeyNr = (ecm[7] & 0x10) >> 4;

	if (ideaKeyNr)
	{
		ideaKeyNr = 1;
	}

	if (ident == 1283 || ident == 1285 || ident == 1297)
	{
		ident = 1281;
	}

	if (cmdLen <= 63 || ecmLen < cmdLen + 10)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	if (!nagra_get_key(ideaKey, ident, '0', ideaKeyNr, 16))
	{
		return CCCAM_EMU_KEY_NOT_FOUND;
	}

	if (nagra_get_key(vKey, ident, 'V', 0, 16))
	{
		useVerifyKey = 1;
	}

	if (!nagra_get_key(m1Key, ident, 'M', 1, 64))
	{
		return CCCAM_EMU_KEY_NOT_FOUND;
	}

	nagra_reverse_mem(m1Key, 64);

	dec = (uint8_t *)malloc(sizeof(uint8_t) * cmdLen);
	if (dec == NULL)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	if (!nagra_decrypt_ecm(ecm + 9, dec, ideaKey, cmdLen, useVerifyKey ? vKey : NULL, m1Key))
	{
		free(dec);
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	for (i = (dec[14] & 0x10) ? 16 : 20; i < cmdLen && l != 3; )
	{
		switch (dec[i])
		{
			case 0x10:
			case 0x11:
				if (i + 10 < cmdLen && dec[i + 1] == 0x09)
				{
					s = (~dec[i]) & 1;
					mecmAlgo = dec[i + 2] & 0x60;
					memcpy(dw + (s << 3), &dec[i + 3], 8);
					i += 11;
					l |= (s + 1);
				}
				else
				{
					i++;
				}
				break;

			case 0x00:
				i += 2;
				break;

			case 0x30:
			case 0x31:
			case 0x32:
			case 0x33:
			case 0x34:
			case 0x35:
			case 0x36:
			case 0xB0:
				if (i + 1 < cmdLen)
				{
					i += dec[i + 1] + 2;
				}
				else
				{
					i++;
				}
				break;

			default:
				i++;
				continue;
		}
	}

	free(dec);

	if (l != 3)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	if (mecmAlgo > 0)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	identMask = ident & 0xFF00;

	if (identMask == 0x1100 || identMask == 0x500 || identMask == 0x3100)
	{
		memcpy(&tmp1, dw, 4);
		memcpy(&tmp2, dw + 4, 4);
		memcpy(&tmp3, dw + 12, 4);
		memcpy(dw, dw + 8, 4);
		memcpy(dw + 4, &tmp3, 4);
		memcpy(dw + 8, &tmp1, 4);
		memcpy(dw + 12, &tmp2, 4);
	}

	cccam_log(LOG_DEBUG, "EMU Nagra: CW obtida (ident %06X, chave %02X)", ident, ideaKeyNr);
	return CCCAM_EMU_OK;
}
