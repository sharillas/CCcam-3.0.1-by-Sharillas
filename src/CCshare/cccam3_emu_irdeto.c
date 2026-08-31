// Irdeto2 EMU - portado de OSCam-emu (GPLv3) module-emulator-irdeto.c
// Inclui o processamento de EMMs (atualização de chaves OP/PMK).

#include "cccam3_emu.h"
#include "cccam3_emu_des.h"
#include "cccam3_logger.h"
#include <string.h>
#include <stdio.h>

#define IRD_ECM_MAX 512
#define IRD_EMM_MAX 1024

static void ird_xxor(uint8_t *data, int32_t len, const uint8_t *v1, const uint8_t *v2)
{
	uint32_t i;

	switch (len)
	{
		case 16:
			for (i = 0; i < 16; ++i)
			{
				data[i] = v1[i] ^ v2[i];
			}
			break;

		case 8:
			for (i = 0; i < 8; ++i)
			{
				data[i] = v1[i] ^ v2[i];
			}
			break;

		default:
			while (len--)
			{
				*data++ = *v1++ ^ *v2++;
			}
			break;
	}
}

static int ird_get_key(uint8_t *buf, uint32_t ident, char key_name, uint32_t key_index)
{
	char key_str[8];
	snprintf(key_str, sizeof(key_str), "%c%X", key_name, (unsigned int)key_index);

	if (cccam_emu_find_key('I', ident, key_str, 0, buf, 16) >= 16)
	{
		return 1;
	}

	return 0;
}

static void irdeto2_encrypt(uint8_t *data, const uint8_t *seed, const uint8_t *key, int32_t len)
{
	int32_t i;
	const uint8_t *tmp = seed;
	uint32_t ks1[32], ks2[32];

	cccam_emu_des_set_key(key, ks1);
	cccam_emu_des_set_key(key + 8, ks2);

	len &= ~7;

	for (i = 0; i + 7 < len; i += 8)
	{
		ird_xxor(&data[i], 8, &data[i], tmp);
		tmp = &data[i];
		cccam_emu_des(&data[i], ks1, 1);
		cccam_emu_des(&data[i], ks2, 0);
		cccam_emu_des(&data[i], ks1, 1);
	}
}

static void irdeto2_decrypt(uint8_t *data, const uint8_t *seed, const uint8_t *key, int32_t len)
{
	int32_t i, n = 0;
	uint8_t buf[2][8];
	uint32_t ks1[32], ks2[32];

	cccam_emu_des_set_key(key, ks1);
	cccam_emu_des_set_key(key + 8, ks2);

	len &= ~7;

	memcpy(buf[n], seed, 8);

	for (i = 0; i + 7 < len; i += 8, data += 8, n ^= 1)
	{
		memcpy(buf[1 - n], data, 8);
		cccam_emu_des(data, ks1, 0);
		cccam_emu_des(data, ks2, 1);
		cccam_emu_des(data, ks1, 0);
		ird_xxor(data, 8, data, buf[n]);
	}
}

static int ird_calculate_hash(const uint8_t *key, const uint8_t *iv,
                              const uint8_t *data, int32_t len)
{
	int32_t l, y;
	uint8_t cbuff[8];
	uint32_t ks1[32], ks2[32];

	cccam_emu_des_set_key(key, ks1);
	cccam_emu_des_set_key(key + 8, ks2);

	memset(cbuff, 0, sizeof(cbuff));

	len -= 8;

	for (y = 0; y < len; y += 8)
	{
		if (y < len - 8)
		{
			ird_xxor(cbuff, 8, cbuff, &data[y]);
		}
		else
		{
			l = len - y;
			ird_xxor(cbuff, l, cbuff, &data[y]);
			ird_xxor(cbuff + l, 8 - l, cbuff + l, iv + 8);
		}

		cccam_emu_des(cbuff, ks1, 1);
		cccam_emu_des(cbuff, ks2, 0);
		cccam_emu_des(cbuff, ks1, 1);
	}

	return memcmp(cbuff, &data[len], 8) == 0;
}

static uint16_t ird_sct_len(const uint8_t *ecm)
{
	return (uint16_t)(((ecm[1] & 0x0F) << 8) | ecm[2]);
}

int cccam_emu_irdeto_ecm(uint16_t caid, uint8_t *oecm, uint8_t *dw)
{
	uint8_t keyNr = 0, length, end, key[16], okeySeed[16], keySeed[16], keyIV[16], tmp[16];
	uint8_t ecmCopy[IRD_ECM_MAX], *ecm = oecm;
	uint16_t ecmLen = ird_sct_len(ecm);
	uint32_t ident, i, j, l;

	if (ecmLen < 12 || ecmLen > sizeof(ecmCopy))
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	length = ecm[11];
	keyNr = ecm[9];
	ident = ecm[8] | ((uint32_t)caid << 8);

	if (ecmLen < length + 12)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	if (!ird_get_key(key, ident, '0', keyNr))
	{
		return CCCAM_EMU_KEY_NOT_FOUND;
	}

	if (!ird_get_key(okeySeed, ident, 'M', 1))
	{
		return CCCAM_EMU_KEY_NOT_FOUND;
	}

	if (!ird_get_key(keyIV, ident, 'M', 2))
	{
		return CCCAM_EMU_KEY_NOT_FOUND;
	}

	memcpy(keySeed, okeySeed, 16);
	memcpy(ecmCopy, oecm, ecmLen);

	ecm = ecmCopy;
	memset(tmp, 0, 16);
	irdeto2_encrypt(keySeed, tmp, key, 16);

	ecm += 12;
	irdeto2_decrypt(ecm, keyIV, keySeed, length);

	i = (ecm[0] & 7) + 1;
	end = length - 8 < 0 ? 0 : length - 8;

	while (i < end)
	{
		l = ecm[i + 1] ? (ecm[i + 1] & 0x3F) + 2 : 1;

		switch (ecm[i])
		{
			case 0x10:
			case 0x50:
				if (l == 0x13 && i <= length - 8 - l)
				{
					irdeto2_decrypt(&ecm[i + 3], keyIV, key, 16);
				}
				break;

			case 0x78:
				if (l == 0x14 && i <= length - 8 - l)
				{
					irdeto2_decrypt(&ecm[i + 4], keyIV, key, 16);
				}
				break;

			default:
				break;
		}
		i += l;
	}

	i = (ecm[0] & 7) + 1;

	if (ird_calculate_hash(keySeed, keyIV, ecm - 6, length + 6))
	{
		while (i < end)
		{
			l = ecm[i + 1] ? (ecm[i + 1] & 0x3F) + 2 : 1;

			switch (ecm[i])
			{
				case 0x78:
				{
					if (l == 0x14 && i <= length - 8 - l)
					{
						memcpy(dw, &ecm[i + 4], 16);

						for (j = 0; j < 16; j += 4)
						{
							dw[j + 3] = (dw[j] + dw[j + 1] + dw[j + 2]) & 0xFF;
						}
						cccam_log(LOG_DEBUG, "EMU Irdeto: CW obtida (ident %06X, chave %02X)",
								  ident, keyNr);
						return CCCAM_EMU_OK;
					}
				}
				break;

				default:
					break;
			}
			i += l;
		}
	}

	return CCCAM_EMU_NOT_SUPPORTED;
}

// --- EMM (atualização de chaves OP/PMK) ---

static const uint8_t ird_fausto_xor[16] =
{
	0x22, 0x58, 0xBD, 0x85, 0x2E, 0x8E, 0x52, 0x80,
	0xA3, 0x79, 0x98, 0x69, 0x68, 0xE2, 0xD8, 0x4D
};

static int ird_do_emm_type_op(uint32_t ident, uint8_t *emm, uint8_t *keySeed,
                              uint8_t *keyIV, uint8_t *keyPMK, uint16_t emmLen,
                              uint8_t startOffset, uint8_t length, int *keysAdded)
{
	uint8_t tmp[16];
	uint32_t end, i, l;
	char keyName[8], keyValue[36];

	memset(tmp, 0, 16);
	irdeto2_encrypt(keySeed, tmp, keyPMK, 16);
	irdeto2_decrypt(&emm[startOffset], keyIV, keySeed, length);

	i = 16;
	end = startOffset + (length - 8 < 0 ? 0 : length - 8);

	while (i < end)
	{
		l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

		switch (emm[i])
		{
			case 0x10:
			case 0x50:
				if (l == 0x13 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 3], keyIV, keyPMK, 16);
				}
				break;

			case 0x78:
				if (l == 0x14 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 4], keyIV, keyPMK, 16);
				}
				break;

			default:
				break;
		}
		i += l;
	}

	memmove(emm + 6, emm + 7, emmLen - 7);

	i = 15;
	end = startOffset + (length - 9 < 0 ? 0 : length - 9);

	if (ird_calculate_hash(keySeed, keyIV, emm + 3, emmLen - 4))
	{
		while (i < end)
		{
			l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

			switch (emm[i])
			{
				case 0x10:
				case 0x50:
				{
					if (l == 0x13 && i <= startOffset + length - 9 - l)
					{
						snprintf(keyName, sizeof(keyName), "%02X", emm[i + 2] >> 2);
						cccam_emu_add_runtime_key('I', ident, keyName, &emm[i + 3], 16, 1);

						(*keysAdded)++;
						for (uint32_t k = 0; k < 16; k++) {
							sprintf(keyValue + 2 * k, "%02X", emm[i + 3 + k]);
						}
						cccam_log(LOG_INFO, "EMU Irdeto: Chave do EMM: I %06X %s %s",
								  ident, keyName, keyValue);
					}
				}
				break;

				default:
					break;
			}
			i += l;
		}

		if (*keysAdded > 0)
		{
			return 0;
		}
	}

	return 1;
}

static int ird_do_emm_type_pmk(uint32_t ident, uint8_t *emm, uint8_t *keySeed,
                               uint8_t *keyIV, uint8_t *keyPMK, uint16_t emmLen,
                               uint8_t startOffset, uint8_t length, int *keysAdded)
{
	uint32_t end, i, j, l;
	char keyName[8], keyValue[36];

	irdeto2_decrypt(&emm[startOffset], keyIV, keySeed, length);

	i = 13;
	end = startOffset + (length - 8 < 0 ? 0 : length - 8);

	while (i < end)
	{
		l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

		switch (emm[i])
		{
			case 0x10:
			case 0x50:
				if (l == 0x13 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 3], keyIV, keyPMK, 16);
				}
				break;

			case 0x78:
				if (l == 0x14 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 4], keyIV, keyPMK, 16);
				}
				break;

			case 0x68:
				if (l == 0x26 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 3], keyIV, keyPMK, 16 * 2);
				}
				break;

			default:
				break;
		}
		i += l;
	}

	memmove(emm + 7, emm + 9, emmLen - 9);

	i = 11;
	end = startOffset + (length - 10 < 0 ? 0 : length - 10);

	if (ird_calculate_hash(keySeed, keyIV, emm + 3, emmLen - 5))
	{
		while (i < end)
		{
			l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

			switch (emm[i])
			{
				case 0x68:
				{
					if (l == 0x26 && i <= startOffset + length - 10 - l)
					{
						for (j = 0; j < 2; j++)
						{
							snprintf(keyName, sizeof(keyName), "M%01X", 3 + j);
							cccam_emu_add_runtime_key('I', ident, keyName, &emm[i + 3 + j * 16], 16, 1);

							(*keysAdded)++;
							for (uint32_t k = 0; k < 16; k++) {
								sprintf(keyValue + 2 * k, "%02X", emm[i + 3 + j * 16 + k]);
							}
							cccam_log(LOG_INFO, "EMU Irdeto: Chave do EMM: I %06X %s %s",
									  ident, keyName, keyValue);
						}
					}
				}
				break;

				default:
					break;
			}
			i += l;
		}

		if (*keysAdded > 0)
		{
			return 0;
		}
	}

	return 1;
}

int cccam_emu_irdeto_emm(uint16_t caid, const uint8_t *oemm, uint16_t emm_in_len)
{
	uint8_t length, okeySeed[16], keySeed[16], keyIV[16], keyPMK[16], startOffset, emmType;
	uint8_t emmCopy[IRD_EMM_MAX], *emm = (uint8_t *)oemm;
	uint16_t emmLen = ird_sct_len(emm);
	uint32_t ident;
	int keysAdded = 0;

	if (emmLen < 11 || emmLen > sizeof(emmCopy) || emm_in_len < emmLen)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	if (emm[3] == 0xC3 || emm[3] == 0xCB)
	{
		emmType = 2;
		startOffset = 11;
	}
	else
	{
		emmType = 1;
		startOffset = 10;
	}

	ident = emm[startOffset - 2] | ((uint32_t)caid << 8);
	length = emm[startOffset - 1];

	if (emmLen < length + startOffset)
	{
		return CCCAM_EMU_NOT_SUPPORTED;
	}

	if (!ird_get_key(okeySeed, ident, 'M', emmType == 1 ? 0 : 0xA))
	{
		return CCCAM_EMU_KEY_NOT_FOUND;
	}

	if (!ird_get_key(keyIV, ident, 'M', 2))
	{
		return CCCAM_EMU_KEY_NOT_FOUND;
	}

	uint8_t pmk_names[] = { 3, 4, 5, 6, 0xB };
	for (uint32_t p = 0; p < sizeof(pmk_names); p++)
	{
		if (emmType == 1 && p == 4) continue; // 0xB é só para tipo 2
		if (emmType == 2 && p < 4) continue;  // 3-6 são só para tipo 1
		if (!ird_get_key(keyPMK, ident, 'M', pmk_names[p]))
		{
			continue;
		}

		memcpy(keySeed, okeySeed, 16);
		memcpy(emmCopy, oemm, emmLen);
		emm = emmCopy;

		int rc;
		if (emmType == 1)
		{
			if (pmk_names[p] >= 5)
			{
				ird_xxor(keyPMK, 16, keyPMK, ird_fausto_xor);
			}
			rc = ird_do_emm_type_op(ident, emm, keySeed, keyIV, keyPMK, emmLen,
			                        startOffset, length, &keysAdded);
		}
		else
		{
			rc = ird_do_emm_type_pmk(ident, emm, keySeed, keyIV, keyPMK, emmLen,
			                         startOffset, length, &keysAdded);
		}

		if (rc == 0)
		{
			return CCCAM_EMU_OK;
		}
	}

	return keysAdded > 0 ? CCCAM_EMU_OK : CCCAM_EMU_NOT_SUPPORTED;
}
