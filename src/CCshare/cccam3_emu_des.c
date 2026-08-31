// Implementações DES usadas pelo motor de emulação (Viaccess).
// Portado de OSCam (GPLv3): cscrypt/des.c e module-newcamd-des.c.

#include "cccam3_emu_des.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

// ===================== nc_des (Viaccess Eurocrypt) =====================

#define DES_IP              1
#define DES_IP_1            2
#define DES_RIGHT           4
#define DES_HASH            8

#define TestBit(addr, bit) ((addr) & (1 << bit))

static const unsigned char nc_PC2[8][6] =
{
	{ 14, 17, 11, 24,  1,  5 },
	{  3, 28, 15,  6, 21, 10 },
	{ 23, 19, 12,  4, 26,  8 },
	{ 16,  7, 27, 20, 13,  2 },
	{ 41, 52, 31, 37, 47, 55 },
	{ 30, 40, 51, 45, 33, 48 },
	{ 44, 49, 39, 56, 34, 53 },
	{ 46, 42, 50, 36, 29, 32 }
};

static const unsigned char nc_E[8][6] =
{
	{ 32,  1,  2,  3,  4,  5 },
	{  4,  5,  6,  7,  8,  9 },
	{  8,  9, 10, 11, 12, 13 },
	{ 12, 13, 14, 15, 16, 17 },
	{ 16, 17, 18, 19, 20, 21 },
	{ 20, 21, 22, 23, 24, 25 },
	{ 24, 25, 26, 27, 28, 29 },
	{ 28, 29, 30, 31, 32,  1 }
};

static const unsigned char nc_P[32] =
{
	16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
	2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const unsigned char nc_SBOXES[4][64] =
{
	{
		0x2e, 0xe0, 0xc4, 0xbf, 0x4d, 0x27, 0x11, 0xc4,
		0x72, 0x4e, 0xaf, 0x72, 0xbb, 0xdd, 0x68, 0x11,
		0x83, 0x5a, 0x5a, 0x06, 0x36, 0xfc, 0xfc, 0xab,
		0xd5, 0x39, 0x09, 0x95, 0xe0, 0x83, 0x97, 0x68,
		0x44, 0xbf, 0x21, 0x8c, 0x1e, 0xc8, 0xb8, 0x72,
		0xad, 0x14, 0xd6, 0xe9, 0x72, 0x21, 0x8b, 0xd7,
		0xff, 0x65, 0x9c, 0xfb, 0xc9, 0x03, 0x57, 0x9e,
		0x63, 0xaa, 0x3a, 0x40, 0x05, 0x56, 0xe0, 0x3d
	},
	{
		0xcf, 0xa3, 0x11, 0xfd, 0xa8, 0x44, 0xfe, 0x27,
		0x96, 0x7f, 0x2b, 0xc2, 0x63, 0x98, 0x84, 0x5e,
		0x09, 0x6c, 0xd7, 0x10, 0x32, 0xd1, 0x4d, 0xea,
		0xec, 0x06, 0x70, 0xb9, 0x55, 0x3b, 0xba, 0x85,
		0x90, 0x4d, 0xee, 0x38, 0xf7, 0x2a, 0x5b, 0xc1,
		0x2a, 0x93, 0x84, 0x5f, 0xcd, 0xf4, 0x31, 0xa2,
		0x75, 0xbb, 0x08, 0xe6, 0x4c, 0x17, 0xa6, 0x7c,
		0x19, 0x60, 0xd3, 0x05, 0xb2, 0x8e, 0x6f, 0xd9
	},
	{
		0x4a, 0xdd, 0xb0, 0x07, 0x29, 0xb0, 0xee, 0x79,
		0xf6, 0x43, 0x03, 0x94, 0x8f, 0x16, 0xd5, 0xaa,
		0x31, 0xe2, 0xcd, 0x38, 0x9c, 0x55, 0x77, 0xce,
		0x5b, 0x2c, 0xa4, 0xfb, 0x62, 0x8f, 0x18, 0x61,
		0x1d, 0x61, 0x46, 0xba, 0xb4, 0xdd, 0xd9, 0x80,
		0xc8, 0x16, 0x3f, 0x49, 0x73, 0xa8, 0xe0, 0x77,
		0xab, 0x94, 0xf1, 0x5f, 0x62, 0x0e, 0x8c, 0xf3,
		0x05, 0xeb, 0x5a, 0x25, 0x9e, 0x32, 0x27, 0xcc
	},
	{
		0xd7, 0x1d, 0x2d, 0xf8, 0x8e, 0xdb, 0x43, 0x85,
		0x60, 0xa6, 0xf6, 0x3f, 0xb9, 0x70, 0x1a, 0x43,
		0xa1, 0xc4, 0x92, 0x57, 0x38, 0x62, 0xe5, 0xbc,
		0x5b, 0x01, 0x0c, 0xea, 0xc4, 0x9e, 0x7f, 0x29,
		0x7a, 0x23, 0xb6, 0x1f, 0x49, 0xe0, 0x10, 0x76,
		0x9c, 0x4a, 0xcb, 0xa1, 0xe7, 0x8d, 0x2d, 0xd8,
		0x0f, 0xf9, 0x61, 0xc4, 0xa3, 0x95, 0xde, 0x0b,
		0xf5, 0x3c, 0x32, 0x57, 0x58, 0x62, 0x84, 0xbe
	}
};

static const unsigned char nc_PC1[][8] =
{
	{57, 49, 41, 33, 25, 17,  9, 1},
	{58, 50, 42, 34, 26, 18, 10, 2},
	{59, 51, 43, 35, 27, 19, 11, 3},
	{60, 52, 44, 36, 63, 55, 47, 39},
	{31, 23, 15,  7, 62, 54, 46, 38},
	{30, 22, 14,  6, 61, 53, 45, 37},
	{29, 21, 13,  5, 28, 20, 12, 4}
};

static void nc_doPC1(unsigned char data[])
{
	unsigned char buf[8];
	unsigned char i, j;

	memset(buf, 0, 8);

	for (j = 0; j < 7; j++)
	{
		for (i = 0; i < 8; i++)
		{
			unsigned char lookup = nc_PC1[j][i];
			buf[j] |= ((data[(lookup >> 3)] >> (8 - (lookup & 7))) & 1) << (7 - i);
		}
	}

	memcpy(data, buf, 8);
}

static void nc_doIp(unsigned char data[])
{
	unsigned char j, k;
	unsigned char val;
	unsigned char buf[8];
	unsigned char *p;
	unsigned char i = 8;
	memset(buf, 0, sizeof(buf));

	for (i = 0; i < 8; i++)
	{
		val = data[i];
		p = &buf[3];
		j = 4;

		do
		{
			for (k = 0; k <= 4; k += 4)
			{
				p[k] >>= 1;
				if (val & 1) { p[k] |= 0x80; }
				val >>= 1;
			}
			p--;
		}
		while (--j);
	}

	memcpy(data, buf, 8);
}

static void nc_doIp_1(unsigned char data[])
{
	unsigned char j, k;
	unsigned char r = 0;
	unsigned char buf[8];
	unsigned char *p;
	unsigned char i = 8;

	for (i = 0; i < 8; i++)
	{
		p = &data[3];
		j = 4;

		do
		{
			for (k = 0; k <= 4; k += 4)
			{
				r >>= 1;
				if (p[k] & 1) { r |= 0x80; }
				p[k] >>= 1;
			}
			p--;
		}
		while (--j);
		buf[i] = r;
	}

	memcpy(data, buf, 8);
}

static void nc_makeK(unsigned char *left, unsigned char *right, unsigned char *K)
{
	unsigned char i, j;
	unsigned char bit, val;
	unsigned char *p;

	for (i = 0; i < 8; i++)
	{
		val = 0;
		for (j = 0; j < 6; j++)
		{
			bit = nc_PC2[i][j];
			if (bit < 29)
			{
				bit = 28 - bit;
				p   = left;
			}
			else
			{
				bit = 56 - bit;
				p   = right;
			}
			val <<= 1;
			if (p[bit >> 3] & (1 << (bit & 7))) { val |= 1; }
		}
		*K = val;
		K++;
	}
}

static void nc_rightRot(unsigned char key[])
{
	unsigned char *p     = key;
	unsigned char  i     = 3;
	unsigned char  carry = 0;

	carry = 0;

	if (*p & 1) { carry = 0x08; }

	do
	{
		*p = (*p >> 1) | ((p[1] & 1) ? 0x80 : 0);
		p++;
	}
	while (--i);

	*p = (*p >> 1) | carry;
}

static void nc_rightRotKeys(unsigned char left[], unsigned char right[])
{
	nc_rightRot(left);
	nc_rightRot(right);
}

static void nc_leftRot(unsigned char key[])
{
	unsigned char i = 27;

	do
	{
		nc_rightRot(key);
	}
	while (--i);
}

static void nc_leftRotKeys(unsigned char left[], unsigned char right[])
{
	nc_leftRot(left);
	nc_leftRot(right);
}

static void nc_desCore(unsigned char data[], unsigned char K[], unsigned char result[])
{
	unsigned char i, j;
	unsigned char bit, val;

	memset(result, 0, 4);

	for (i = 0; i < 8; i++)
	{
		val = 0;
		for (j = 0; j < 6; j++)
		{
			bit = 32 - nc_E[i][j];
			val <<= 1;
			if (data[3 - (bit >> 3)] & (1 << (bit & 7))) { val |= 1; }
		}
		val ^= K[i];
		val  = nc_SBOXES[i & 3][val];
		if (i > 3)
		{
			val >>= 4;
		}
		val &= 0x0f;
		result[i >> 1] |= (i & 1) ? val : (val << 4);
	}
}

static void nc_permut32(unsigned char data[])
{
	unsigned char i, j;
	unsigned char bit;
	unsigned char r[4] = {0};
	unsigned char *p;

	for (i = 0; i < 32; i++)
	{
		bit = 32 - nc_P[i];
		p = r;
		for (j = 0; j < 3; j++)
		{
			*p = (*p << 1) | ((p[1] & 0x80) ? 1 : 0);
			p++;
		}
		*p <<= 1;
		if (data[3 - (bit >> 3)] & (1 << (bit & 7))) { *p |= 1; }
	}

	memcpy(data, r, 4);
}

static void nc_swap(unsigned char left[], unsigned char right[])
{
	unsigned char x[4];

	memcpy(x, right, 4);
	memcpy(right, left, 4);
	memcpy(left, x, 4);
}

static void nc_desRound(unsigned char left[], unsigned char right[], unsigned char data[], unsigned char mode, unsigned char k8)
{
	unsigned char i;
	unsigned char K[8];
	unsigned char r[4];
	unsigned char tempr[4];
	unsigned short temp;

	memcpy(tempr, data + 4, 4);

	/* Viaccess */
	temp = (unsigned short)((unsigned short)k8 * (unsigned short)tempr[0] +
	                        (unsigned short)k8 + (unsigned short)tempr[0]);
	tempr[0] = (temp & 0xff) - ((temp >> 8) & 0xff);
	if ((temp & 0xff) - (temp >> 8) < 0)
		{ tempr[0]++; }

	nc_makeK(left, right, K);
	nc_desCore(tempr, K, r);
	nc_permut32(r);

	if (mode & DES_HASH)
	{
		i    = r[0];
		r[0] = r[1];
		r[1] = i;
	}

	for (i = 0; i < 4; i++)
	{
		*data ^= r[i];
		data++;
	}

	nc_swap(data - 4, data);
}

void cccam_emu_nc_des(uint8_t *key, uint8_t mode, uint8_t *data)
{
	unsigned char i;
	unsigned char left[8];
	unsigned char right[8];
	unsigned char *p = left;

	short DESShift = (mode & DES_RIGHT) ? 0x8103 : 0xc081;

	for (i = 3; i > 0; i--)
	{
		*p = (key[i - 1] << 4) | (key[i] >> 4);
		p++;
	}
	left[3] =  key[0] >> 4;
	right[0] = key[6];
	right[1] = key[5];
	right[2] = key[4];
	right[3] = key[3] & 0x0f;

	if (mode & DES_IP) { nc_doIp(data); }

	do
	{
		if (!(mode & DES_RIGHT))
		{
			nc_leftRotKeys(left, right);
			if (!(DESShift & 0x8000)) { nc_leftRotKeys(left, right); }
		}
		nc_desRound(left, right, data, mode, key[7]);

		if (mode & DES_RIGHT)
		{
			nc_rightRotKeys(left, right);
			if (!(DESShift & 0x8000)) { nc_rightRotKeys(left, right); }
		}
		DESShift <<= 1;
	}
	while (DESShift);

	nc_swap(data, data + 4);
	if (mode & DES_IP_1) { nc_doIp_1(data); }
}

// ===================== DES standard (esquema de bytes OSCam) =====================

static const uint8_t emu_shifts2[16] = {0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};

static const uint32_t emu_des_skb[8][64] =
{
	{
		0x00000000,0x00000010,0x20000000,0x20000010,
		0x00010000,0x00010010,0x20010000,0x20010010,
		0x00000800,0x00000810,0x20000800,0x20000810,
		0x00010800,0x00010810,0x20010800,0x20010810,
		0x00000020,0x00000030,0x20000020,0x20000030,
		0x00010020,0x00010030,0x20010020,0x20010030,
		0x00000820,0x00000830,0x20000820,0x20000830,
		0x00010820,0x00010830,0x20010820,0x20010830,
		0x00080000,0x00080010,0x20080000,0x20080010,
		0x00090000,0x00090010,0x20090000,0x20090010,
		0x00080800,0x00080810,0x20080800,0x20080810,
		0x00090800,0x00090810,0x20090800,0x20090810,
		0x00080020,0x00080030,0x20080020,0x20080030,
		0x00090020,0x00090030,0x20090020,0x20090030,
		0x00080820,0x00080830,0x20080820,0x20080830,
		0x00090820,0x00090830,0x20090820,0x20090830,
	},{
		0x00000000,0x02000000,0x00002000,0x02002000,
		0x00200000,0x02200000,0x00202000,0x02202000,
		0x00000004,0x02000004,0x00002004,0x02002004,
		0x00200004,0x02200004,0x00202004,0x02202004,
		0x00000400,0x02000400,0x00002400,0x02002400,
		0x00200400,0x02200400,0x00202400,0x02202400,
		0x00000404,0x02000404,0x00002404,0x02002404,
		0x00200404,0x02200404,0x00202404,0x02202404,
		0x10000000,0x12000000,0x10002000,0x12002000,
		0x10200000,0x12200000,0x10202000,0x12202000,
		0x10000004,0x12000004,0x10002004,0x12002004,
		0x10200004,0x12200004,0x10202004,0x12202004,
		0x10000400,0x12000400,0x10002400,0x12002400,
		0x10200400,0x12200400,0x10202400,0x12202400,
		0x10000404,0x12000404,0x10002404,0x12002404,
		0x10200404,0x12200404,0x10202404,0x12202404,
	},{
		0x00000000,0x00000001,0x00040000,0x00040001,
		0x01000000,0x01000001,0x01040000,0x01040001,
		0x00000002,0x00000003,0x00040002,0x00040003,
		0x01000002,0x01000003,0x01040002,0x01040003,
		0x00000200,0x00000201,0x00040200,0x00040201,
		0x01000200,0x01000201,0x01040200,0x01040201,
		0x00000202,0x00000203,0x00040202,0x00040203,
		0x01000202,0x01000203,0x01040202,0x01040203,
		0x08000000,0x08000001,0x08040000,0x08040001,
		0x09000000,0x09000001,0x09040000,0x09040001,
		0x08000002,0x08000003,0x08040002,0x08040003,
		0x09000002,0x09000003,0x09040002,0x09040003,
		0x08000200,0x08000201,0x08040200,0x08040201,
		0x09000200,0x09000201,0x09040200,0x09040201,
		0x08000202,0x08000203,0x08040202,0x08040203,
		0x09000202,0x09000203,0x09040202,0x09040203,
	},{
		0x00000000,0x00100000,0x00000100,0x00100100,
		0x00000008,0x00100008,0x00000108,0x00100108,
		0x00001000,0x00101000,0x00001100,0x00101100,
		0x00001008,0x00101008,0x00001108,0x00101108,
		0x04000000,0x04100000,0x04000100,0x04100100,
		0x04000008,0x04100008,0x04000108,0x04100108,
		0x04001000,0x04101000,0x04001100,0x04101100,
		0x04001008,0x04101008,0x04001108,0x04101108,
		0x00020000,0x00120000,0x00020100,0x00120100,
		0x00020008,0x00120008,0x00020108,0x00120108,
		0x00021000,0x00121000,0x00021100,0x00121100,
		0x00021008,0x00121008,0x00021108,0x00121108,
		0x04020000,0x04120000,0x04020100,0x04120100,
		0x04020008,0x04120008,0x04020108,0x04120108,
		0x04021000,0x04121000,0x04021100,0x04121100,
		0x04021008,0x04121008,0x04021108,0x04121108,
	},{
		0x00000000,0x10000000,0x00010000,0x10010000,
		0x00000004,0x10000004,0x00010004,0x10010004,
		0x20000000,0x30000000,0x20010000,0x30010000,
		0x20000004,0x30000004,0x20010004,0x30010004,
		0x00100000,0x10100000,0x00110000,0x10110000,
		0x00100004,0x10100004,0x00110004,0x10110004,
		0x20100000,0x30100000,0x20110000,0x30110000,
		0x20100004,0x30100004,0x20110004,0x30110004,
		0x00001000,0x10001000,0x00011000,0x10011000,
		0x00001004,0x10001004,0x00011004,0x10011004,
		0x20001000,0x30001000,0x20011000,0x30011000,
		0x20001004,0x30001004,0x20011004,0x30011004,
		0x00101000,0x10101000,0x00111000,0x10111000,
		0x00101004,0x10101004,0x00111004,0x10111004,
		0x20101000,0x30101000,0x20111000,0x30111000,
		0x20101004,0x30101004,0x20111004,0x30111004,
	},{
		0x00000000,0x08000000,0x00000008,0x08000008,
		0x00000400,0x08000400,0x00000408,0x08000408,
		0x00020000,0x08020000,0x00020008,0x08020008,
		0x00020400,0x08020400,0x00020408,0x08020408,
		0x00000001,0x08000001,0x00000009,0x08000009,
		0x00000401,0x08000401,0x00000409,0x08000409,
		0x00020001,0x08020001,0x00020009,0x08020009,
		0x00020401,0x08020401,0x00020409,0x08020409,
		0x02000000,0x0A000000,0x02000008,0x0A000008,
		0x02000400,0x0A000400,0x02000408,0x0A000408,
		0x02020000,0x0A020000,0x02020008,0x0A020008,
		0x02020400,0x0A020400,0x02020408,0x0A020408,
		0x02000001,0x0A000001,0x02000009,0x0A000009,
		0x02000401,0x0A000401,0x02000409,0x0A000409,
		0x02020001,0x0A020001,0x02020009,0x0A020009,
		0x02020401,0x0A020401,0x02020409,0x0A020409,
	},{
		0x00000000,0x00000100,0x00080000,0x00080100,
		0x01000000,0x01000100,0x01080000,0x01080100,
		0x00000010,0x00000110,0x00080010,0x00080110,
		0x01000010,0x01000110,0x01080010,0x01080110,
		0x00200000,0x00200100,0x00280000,0x00280100,
		0x01200000,0x01200100,0x01280000,0x01280100,
		0x00200010,0x00200110,0x00280010,0x00280110,
		0x01200010,0x01200110,0x01280010,0x01280110,
		0x00000200,0x00000300,0x00080200,0x00080300,
		0x01000200,0x01000300,0x01080200,0x01080300,
		0x00000210,0x00000310,0x00080210,0x00080310,
		0x01000210,0x01000310,0x01080210,0x01080310,
		0x00200200,0x00200300,0x00280200,0x00280300,
		0x01200200,0x01200300,0x01280200,0x01280300,
		0x00200210,0x00200310,0x00280210,0x00280310,
		0x01200210,0x01200310,0x01280210,0x01280310,
	},{
		0x00000000,0x04000000,0x00040000,0x04040000,
		0x00000002,0x04000002,0x00040002,0x04040002,
		0x00002000,0x04002000,0x00042000,0x04042000,
		0x00002002,0x04002002,0x00042002,0x04042002,
		0x00000020,0x04000020,0x00040020,0x04040020,
		0x00000022,0x04000022,0x00040022,0x04040022,
		0x00002020,0x04002020,0x00042020,0x04042020,
		0x00002022,0x04002022,0x00042022,0x04042022,
		0x00000800,0x04000800,0x00040800,0x04040800,
		0x00000802,0x04000802,0x00040802,0x04040802,
		0x00002800,0x04002800,0x00042800,0x04042800,
		0x00002802,0x04002802,0x00042802,0x04042802,
		0x00000820,0x04000820,0x00040820,0x04040820,
		0x00000822,0x04000822,0x00040822,0x04040822,
		0x00002820,0x04002820,0x00042820,0x04042820,
		0x00002822,0x04002822,0x00042822,0x04042822,
	}
};

static const uint32_t emu_des_SPtrans[8][64] =
{
	{
		0x00820200, 0x00020000, 0x80800000, 0x80820200,
		0x00800000, 0x80020200, 0x80020000, 0x80800000,
		0x80020200, 0x00820200, 0x00820000, 0x80000200,
		0x80800200, 0x00800000, 0x00000000, 0x80020000,
		0x00020000, 0x80000000, 0x00800200, 0x00020200,
		0x80820200, 0x00820000, 0x80000200, 0x00800200,
		0x80000000, 0x00000200, 0x00020200, 0x80820000,
		0x00000200, 0x80800200, 0x80820000, 0x00000000,
		0x00000000, 0x80820200, 0x00800200, 0x80020000,
		0x00820200, 0x00020000, 0x80000200, 0x00800200,
		0x80820000, 0x00000200, 0x00020200, 0x80800000,
		0x80020200, 0x80000000, 0x80800000, 0x00820000,
		0x80820200, 0x00020200, 0x00820000, 0x80800200,
		0x00800000, 0x80000200, 0x80020000, 0x00000000,
		0x00020000, 0x00800000, 0x80800200, 0x00820200,
		0x80000000, 0x80820000, 0x00000200, 0x80020200,
	},{
		0x10042004, 0x00000000, 0x00042000, 0x10040000,
		0x10000004, 0x00002004, 0x10002000, 0x00042000,
		0x00002000, 0x10040004, 0x00000004, 0x10002000,
		0x00040004, 0x10042000, 0x10040000, 0x00000004,
		0x00040000, 0x10002004, 0x10040004, 0x00002000,
		0x00042004, 0x10000000, 0x00000000, 0x00040004,
		0x10002004, 0x00042004, 0x10042000, 0x10000004,
		0x10000000, 0x00040000, 0x00002004, 0x10042004,
		0x00040004, 0x10042000, 0x10002000, 0x00042004,
		0x10042004, 0x00040004, 0x10000004, 0x00000000,
		0x10000000, 0x00002004, 0x00040000, 0x10040004,
		0x00002000, 0x10000000, 0x00042004, 0x10002004,
		0x10042000, 0x00002000, 0x00000000, 0x10000004,
		0x00000004, 0x10042004, 0x00042000, 0x10040000,
		0x10040004, 0x00040000, 0x00002004, 0x10002000,
		0x10002004, 0x00000004, 0x10040000, 0x00042000,
	},{
		0x41000000, 0x01010040, 0x00000040, 0x41000040,
		0x40010000, 0x01000000, 0x41000040, 0x00010040,
		0x01000040, 0x00010000, 0x01010000, 0x40000000,
		0x41010040, 0x40000040, 0x40000000, 0x41010000,
		0x00000000, 0x40010000, 0x01010040, 0x00000040,
		0x40000040, 0x41010040, 0x00010000, 0x41000000,
		0x41010000, 0x01000040, 0x40010040, 0x01010000,
		0x00010040, 0x00000000, 0x01000000, 0x40010040,
		0x01010040, 0x00000040, 0x40000000, 0x00010000,
		0x40000040, 0x40010000, 0x01010000, 0x41000040,
		0x00000000, 0x01010040, 0x00010040, 0x41010000,
		0x40010000, 0x01000000, 0x41010040, 0x40000000,
		0x40010040, 0x41000000, 0x01000000, 0x41010040,
		0x00010000, 0x01000040, 0x41000040, 0x00010040,
		0x01000040, 0x00000000, 0x41010000, 0x40000040,
		0x41000000, 0x40010040, 0x00000040, 0x01010000,
	},{
		0x00100402, 0x04000400, 0x00000002, 0x04100402,
		0x00000000, 0x04100000, 0x04000402, 0x00100002,
		0x04100400, 0x04000002, 0x04000000, 0x00000402,
		0x04000002, 0x00100402, 0x00100000, 0x04000000,
		0x04100002, 0x00100400, 0x00000400, 0x00000002,
		0x00100400, 0x04000402, 0x04100000, 0x00000400,
		0x00000402, 0x00000000, 0x00100002, 0x04100400,
		0x04000400, 0x04100002, 0x04100402, 0x00100000,
		0x04100002, 0x00000402, 0x00100000, 0x04000002,
		0x00100400, 0x04000400, 0x00000002, 0x04100000,
		0x04000402, 0x00000000, 0x00000400, 0x00100002,
		0x00000000, 0x04100002, 0x04100400, 0x00000400,
		0x04000000, 0x04100402, 0x00100402, 0x00100000,
		0x04100402, 0x00000002, 0x04000400, 0x00100402,
		0x00100002, 0x00100400, 0x04100000, 0x04000402,
		0x00000402, 0x04000000, 0x04000002, 0x04100400,
	},{
		0x02000000, 0x00004000, 0x00000100, 0x02004108,
		0x02004008, 0x02000100, 0x00004108, 0x02004000,
		0x00004000, 0x00000008, 0x02000008, 0x00004100,
		0x02000108, 0x02004008, 0x02004100, 0x00000000,
		0x00004100, 0x02000000, 0x00004008, 0x00000108,
		0x02000100, 0x00004108, 0x00000000, 0x02000008,
		0x00000008, 0x02000108, 0x02004108, 0x00004008,
		0x02004000, 0x00000100, 0x00000108, 0x02004100,
		0x02004100, 0x02000108, 0x00004008, 0x02004000,
		0x00004000, 0x00000008, 0x02000008, 0x02000100,
		0x02000000, 0x00004100, 0x02004108, 0x00000000,
		0x00004108, 0x02000000, 0x00000100, 0x00004008,
		0x02000108, 0x00000100, 0x00000000, 0x02004108,
		0x02004008, 0x02004100, 0x00000108, 0x00004000,
		0x00004100, 0x02004008, 0x02000100, 0x00000108,
		0x00000008, 0x00004108, 0x02004000, 0x02000008,
	},{
		0x20000010, 0x00080010, 0x00000000, 0x20080800,
		0x00080010, 0x00000800, 0x20000810, 0x00080000,
		0x00000810, 0x20080810, 0x00080800, 0x20000000,
		0x20000800, 0x20000010, 0x20080000, 0x00080810,
		0x00080000, 0x20000810, 0x20080010, 0x00000000,
		0x00000800, 0x00000010, 0x20080800, 0x20080010,
		0x20080810, 0x20080000, 0x20000000, 0x00000810,
		0x00000010, 0x00080800, 0x00080810, 0x20000800,
		0x00000810, 0x20000000, 0x20000800, 0x00080810,
		0x20080800, 0x00080010, 0x00000000, 0x20000800,
		0x20000000, 0x00000800, 0x20080010, 0x00080000,
		0x00080010, 0x20080810, 0x00080800, 0x00000010,
		0x20080810, 0x00080800, 0x00080000, 0x20000810,
		0x20000010, 0x20080000, 0x00080810, 0x00000000,
		0x00000800, 0x20000010, 0x20000810, 0x20080800,
		0x20080000, 0x00000810, 0x00000010, 0x20080010,
	},{
		0x00001000, 0x00000080, 0x00400080, 0x00400001,
		0x00401081, 0x00001001, 0x00001080, 0x00000000,
		0x00400000, 0x00400081, 0x00000081, 0x00401000,
		0x00000001, 0x00401080, 0x00401000, 0x00000081,
		0x00400081, 0x00001000, 0x00001001, 0x00401081,
		0x00000000, 0x00400080, 0x00400001, 0x00001080,
		0x00401001, 0x00001081, 0x00401080, 0x00000001,
		0x00001081, 0x00401001, 0x00000080, 0x00400000,
		0x00001081, 0x00401000, 0x00401001, 0x00000081,
		0x00001000, 0x00000080, 0x00400000, 0x00401001,
		0x00400081, 0x00001081, 0x00001080, 0x00000000,
		0x00000080, 0x00400001, 0x00000001, 0x00400080,
		0x00000000, 0x00400081, 0x00400080, 0x00001080,
		0x00000081, 0x00001000, 0x00401081, 0x00400000,
		0x00401080, 0x00000001, 0x00001001, 0x00401081,
		0x00400001, 0x00401080, 0x00401000, 0x00001001,
	},{
		0x08200020, 0x08208000, 0x00008020, 0x00000000,
		0x08008000, 0x00200020, 0x08200000, 0x08208020,
		0x00000020, 0x08000000, 0x00208000, 0x00008020,
		0x00208020, 0x08008020, 0x08000020, 0x08200000,
		0x00008000, 0x00208020, 0x00200020, 0x08008000,
		0x08208020, 0x08000020, 0x00000000, 0x00208000,
		0x08000000, 0x00200000, 0x08008020, 0x08200020,
		0x00200000, 0x00008000, 0x08208000, 0x00000020,
		0x00200000, 0x00008000, 0x08000020, 0x08208020,
		0x00008020, 0x08000000, 0x00000000, 0x00208000,
		0x08200020, 0x08008020, 0x08008000, 0x00200020,
		0x08208000, 0x00000020, 0x00200020, 0x08008000,
		0x08208020, 0x00200000, 0x08200000, 0x08000020,
		0x00208000, 0x00008020, 0x08008020, 0x08200000,
		0x00000020, 0x08208000, 0x00208020, 0x00000000,
		0x08000000, 0x08200020, 0x00008000, 0x00208020,
	}
};

static uint32_t emu_Get32bits(const uint8_t *key, int kindex)
{
	return (((uint32_t)(key[kindex+3]&0xff)<<24) + ((uint32_t)(key[kindex+2]&0xff)<<16) +
	        ((uint32_t)(key[kindex+1]&0xff)<<8) + (key[kindex]&0xff));
}

int cccam_emu_des_set_key(const uint8_t *key, uint32_t *schedule)
{
	uint32_t c, d, t, s;
	int i;
	int kIndex;

	c = emu_Get32bits(key, 0);
	d = emu_Get32bits(key, 4);
	t = (((d>>4)^c)&0x0f0f0f0f);
	c ^= t;
	d ^= (t<<4);
	t = (((c<<18)^c)&0xcccc0000);
	c = c^t^(t>>18);
	t = ((d<<18)^d)&0xcccc0000;
	d = d^t^(t>>18);
	t = ((d>>1)^c)&0x55555555;
	c ^= t;
	d ^= (t<<1);
	t = ((c>>8)^d)&0x00ff00ff;
	d ^= t;
	c ^= (t<<8);
	t = ((d>>1)^c)&0x55555555;
	c ^= t;
	d ^= (t<<1);
	d = (((d&0x000000ff)<<16)| (d&0x0000ff00) |((d&0x00ff0000)>>16)|((c&0xf0000000)>>4));
	c &= 0x0fffffff;

	kIndex = 0;
	for (i = 0; i < 16; i++)
	{
		if (emu_shifts2[i])
		{
			c = ((c>>2)|(c<<26));
			d = ((d>>2)|(d<<26));
		}
		else
		{
			c = ((c>>1)|(c<<27));
			d = ((d>>1)|(d<<27));
		}
		c &= 0x0fffffff;
		d &= 0x0fffffff;
		s = emu_des_skb[0][ (c    )&0x3f                ]|
			emu_des_skb[1][((c>> 6)&0x03)|((c>> 7)&0x3c)]|
			emu_des_skb[2][((c>>13)&0x0f)|((c>>14)&0x30)]|
			emu_des_skb[3][((c>>20)&0x01)|((c>>21)&0x06) |
						  ((c>>22)&0x38)];
		t = emu_des_skb[4][ (d    )&0x3f                ]|
			emu_des_skb[5][((d>> 7)&0x03)|((d>> 8)&0x3c)]|
			emu_des_skb[6][ (d>>15)&0x3f                ]|
			emu_des_skb[7][((d>>21)&0x0f)|((d>>22)&0x30)];
		schedule[kIndex++] = ((t<<16)|(s&0x0000ffff))&0xffffffff;
		s = ((s>>16)|(t&0xffff0000));
		s = (s<<4)|(s>>28);
		schedule[kIndex++] = s&0xffffffff;
	}
	return 1;
}

static uint32_t emu_lrotr(uint32_t i)
{
	return ((i>>4) | ((i&0xff)<<28));
}

static void emu_des_encrypt_int(uint32_t *data, const uint32_t *ks, int do_encrypt)
{
	uint32_t l, r, t, u;
	int i;

	u = data[0];
	r = data[1];

	{
		uint32_t tt;

		tt = ((r>>4)^u)&0x0f0f0f0f;
		u ^= tt;
		r ^= (tt<<4);
		tt = (((u>>16)^r)&0x0000ffff);
		r ^= tt;
		u ^= (tt<<16);
		tt = (((r>>2)^u)&0x33333333);
		u ^= tt;
		r ^= (tt<<2);
		tt = (((u>>8)^r)&0x00ff00ff);
		r ^= tt;
		u ^= (tt<<8);
		tt = (((r>>1)^u)&0x55555555);
		u ^= tt;
		r ^= (tt<<1);
	}

	l = (r<<1)|(r>>31);
	r = (u<<1)|(u>>31);

	l &= 0xffffffff;
	r &= 0xffffffff;

	if (do_encrypt)
	{
		for (i = 0; i < 32; i += 8)
		{
			u = (r^ks[i+0]);
			t = r^ks[i+0+1];
			t = emu_lrotr(t);
			l ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
			u = (l^ks[i+2]);
			t = l^ks[i+2+1];
			t = emu_lrotr(t);
			r ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
			u = (r^ks[i+4]);
			t = r^ks[i+4+1];
			t = emu_lrotr(t);
			l ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
			u = (l^ks[i+6]);
			t = l^ks[i+6+1];
			t = emu_lrotr(t);
			r ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
		}
	}
	else
	{
		for (i = 30; i > 0; i -= 8)
		{
			u = (r^ks[i-0]);
			t = r^ks[i-0+1];
			t = emu_lrotr(t);
			l ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
			u = (l^ks[i-2]);
			t = l^ks[i-2+1];
			t = emu_lrotr(t);
			r ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
			u = (r^ks[i-4]);
			t = r^ks[i-4+1];
			t = emu_lrotr(t);
			l ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
			u = (l^ks[i-6]);
			t = l^ks[i-6+1];
			t = emu_lrotr(t);
			r ^= emu_des_SPtrans[1][(t )&0x3f]| emu_des_SPtrans[3][(t>> 8)&0x3f]| emu_des_SPtrans[5][(t>>16)&0x3f]| emu_des_SPtrans[7][(t>>24)&0x3f]| emu_des_SPtrans[0][(u )&0x3f]| emu_des_SPtrans[2][(u>> 8)&0x3f]| emu_des_SPtrans[4][(u>>16)&0x3f]| emu_des_SPtrans[6][(u>>24)&0x3f];
		}
	}

	l = (l>>1)|(l<<31);
	r = (r>>1)|(r<<31);

	l &= 0xffffffff;
	r &= 0xffffffff;

	{
		uint32_t tt;

		tt = (((r>>1)^l)&0x55555555);
		l ^= tt;
		r ^= (tt<<1);
		tt = (((l>>8)^r)&0x00ff00ff);
		r ^= tt;
		l ^= (tt<<8);
		tt = (((r>>2)^l)&0x33333333);
		l ^= tt;
		r ^= (tt<<2);
		tt = (((l>>16)^r)&0x0000ffff);
		r ^= tt;
		l ^= (tt<<16);
		tt = (((r>>4)^l)&0x0f0f0f0f);
		l ^= tt;
		r ^= (tt<<4);
	}

	data[0] = l;
	data[1] = r;
}

void cccam_emu_des(uint8_t *data, const uint32_t *schedule, int do_encrypt)
{
	uint32_t l, ll[2];

	l = emu_Get32bits(data, 0);
	ll[0] = l;

	l = emu_Get32bits(data, 4);
	ll[1] = l;

	emu_des_encrypt_int(ll, schedule, do_encrypt);

	l = ll[0];

	data[0] = (l&0xff);
	data[1] = ((l>>8)&0xff);
	data[2] = ((l>>16)&0xff);
	data[3] = ((l>>24)&0xff);
	l = ll[1];
	data[4] = (l&0xff);
	data[5] = ((l>>8)&0xff);
	data[6] = ((l>>16)&0xff);
	data[7] = ((l>>24)&0xff);
}

void cccam_emu_aes_decrypt_block(uint8_t *data, const uint8_t *key)
{
	AES_KEY aes_key;
	AES_set_decrypt_key(key, 128, &aes_key);
	AES_decrypt(data, data, &aes_key);
}

void cccam_emu_des_ecb3_decrypt(uint8_t *data, const uint8_t *key)
{
	uint32_t ks1[32], ks2[32];

	cccam_emu_des_set_key(key, ks1);
	cccam_emu_des_set_key(key + 8, ks2);
	cccam_emu_des(data, ks1, 0);
	cccam_emu_des(data, ks2, 1);
	cccam_emu_des(data, ks1, 0);
}

int cccam_emu_is_valid_dcw(const uint8_t *cw)
{
	return cw[3] == (uint8_t)(cw[0] + cw[1] + cw[2]);
}

// ===================== DES Newcamd (newcs/cs357x) =====================
// Portado de OSCam module-newcamd-des.c (GPLv3)

#define F_EURO_S2       0
#define F_TRIPLE_DES    1

#define DES_ECS2_DECRYPT    (DES_IP | DES_IP_1 | DES_RIGHT)
#define DES_ECS2_CRYPT      (DES_IP | DES_IP_1)

static void ncd_des_key_parity_adjust(uint8_t *key, uint8_t len)
{
	uint8_t i, j, parity;

	for (i = 0; i < len; i++)
	{
		parity = 1;
		for (j = 1; j < 8; j++) if ((key[i] >> j) & 0x1) { parity = ~parity & 0x01; }
		key[i] |= parity;
	}
}

static uint8_t *ncd_des_key_spread(const uint8_t *normal, uint8_t *spread)
{
	spread[ 0] = normal[ 0] & 0xfe;
	spread[ 1] = ((normal[ 0] << 7) | (normal[ 1] >> 1)) & 0xfe;
	spread[ 2] = ((normal[ 1] << 6) | (normal[ 2] >> 2)) & 0xfe;
	spread[ 3] = ((normal[ 2] << 5) | (normal[ 3] >> 3)) & 0xfe;
	spread[ 4] = ((normal[ 3] << 4) | (normal[ 4] >> 4)) & 0xfe;
	spread[ 5] = ((normal[ 4] << 3) | (normal[ 5] >> 5)) & 0xfe;
	spread[ 6] = ((normal[ 5] << 2) | (normal[ 6] >> 6)) & 0xfe;
	spread[ 7] = normal[ 6] << 1;
	spread[ 8] = normal[ 7] & 0xfe;
	spread[ 9] = ((normal[ 7] << 7) | (normal[ 8] >> 1)) & 0xfe;
	spread[10] = ((normal[ 8] << 6) | (normal[ 9] >> 2)) & 0xfe;
	spread[11] = ((normal[ 9] << 5) | (normal[10] >> 3)) & 0xfe;
	spread[12] = ((normal[10] << 4) | (normal[11] >> 4)) & 0xfe;
	spread[13] = ((normal[11] << 3) | (normal[12] >> 5)) & 0xfe;
	spread[14] = ((normal[12] << 2) | (normal[13] >> 6)) & 0xfe;
	spread[15] = normal[13] << 1;

	ncd_des_key_parity_adjust(spread, 16);
	return spread;
}

static void ncd_des_random_get(uint8_t *buffer, uint8_t len)
{
	for (uint8_t idx = 0; idx < len; idx++)
	{
		buffer[idx] = (uint8_t)(rand() & 0xff);
	}
}

static uint8_t ncd_getmask(uint8_t *OutData, uint8_t *Mask, uint8_t I, uint8_t J)
{
	uint8_t K, B, M, M1, D, DI, MI;

	K = I ^ J;
	DI = 7;
	if ((K & 4) == 4)
	{
		K ^= 7;
		DI ^= 7;
	}
	MI = 3;
	MI &= J;
	K ^= MI;
	K += MI;
	if ((K & 4) == 4)
	{
		return 0;
	}
	DI ^= J;
	D = OutData[DI];
	MI = 0;
	MI += J;
	M1 = Mask[MI];
	MI ^= 4;
	M = Mask[MI];
	B = 0;
	for (K = 0; K <= 7; K++)
	{
		if ((D & 1) == 1) { B += M; }
		D = (D >> 1) + ((B & 1) << 7);
		B = B >> 1;
	}
	return D ^ M1;
}

static void ncd_v2mask(uint8_t *cw, uint8_t *mask)
{
	int i, j;

	for (i = 7; i >= 0; i--)
		for (j = 7; j >= 4; j--)
			{ cw[i] ^= ncd_getmask(cw, mask, i, j); }
	for (i = 0; i <= 7; i++)
		for (j = 0; j <= 3; j++)
			{ cw[i] ^= ncd_getmask(cw, mask, i, j); }
}

static void ncd_EuroDes(const uint8_t key1[], const uint8_t key2[], uint8_t desMode, uint8_t operatingMode, uint8_t data[])
{
	uint8_t mode;

	if (key1[7])   /* Viaccess */
	{
		mode = (operatingMode == NC_DES_ECM_HASH) ? NC_DES_ECM_HASH : NC_DES_ECM_CRYPT;

		if (key2 != NULL)
			{ ncd_v2mask(data, (uint8_t *)key2); }
		cccam_emu_nc_des((uint8_t *)key1, mode, data);
		if (key2 != NULL)
			{ ncd_v2mask(data, (uint8_t *)key2); }
	}
	else if (TestBit(desMode, F_TRIPLE_DES))
	{
		/* Eurocrypt 3-DES */
		mode = (operatingMode == NC_DES_ECM_HASH) ? 0 : DES_RIGHT;
		cccam_emu_nc_des((uint8_t *)key1, (uint8_t)(DES_IP | mode), data);

		mode ^= DES_RIGHT;
		cccam_emu_nc_des((uint8_t *)key2, mode, data);

		mode ^= DES_RIGHT;
		cccam_emu_nc_des((uint8_t *)key1, (uint8_t)(mode | DES_IP_1), data);
	}
	else
	{
		if (TestBit(desMode, F_EURO_S2))
		{
			/* Eurocrypt S2 */
			mode = (operatingMode == NC_DES_ECM_HASH) ? DES_ECS2_CRYPT : DES_ECS2_DECRYPT;
		}
		else
		{
			/* Eurocrypt M */
			mode = (operatingMode == NC_DES_ECM_HASH) ? NC_DES_ECM_HASH : NC_DES_ECM_CRYPT;
		}
		cccam_emu_nc_des((uint8_t *)key1, mode, data);
	}
}

int cccam_newcamd_des_encrypt(uint8_t *buffer, int len, const uint8_t *deskey)
{
	uint8_t checksum = 0;
	uint8_t noPadBytes;
	uint8_t padBytes[7];
	uint8_t ivec[8];
	short i;

	if (!deskey) { return len; }
	noPadBytes = (uint8_t)((8 - ((len - 1) % 8)) % 8);
	if (len + noPadBytes + 1 >= 1024 - 8) { return -1; }
	ncd_des_random_get(padBytes, noPadBytes);
	for (i = 0; i < noPadBytes; i++) { buffer[len++] = padBytes[i]; }
	for (i = 2; i < len; i++) { checksum ^= buffer[i]; }
	buffer[len++] = checksum;
	ncd_des_random_get(ivec, 8);
	memcpy(buffer + len, ivec, 8);
	for (i = 2; i < len; i += 8)
	{
		uint8_t j;
		const uint8_t flags = (uint8_t)((1 << F_EURO_S2) | (1 << F_TRIPLE_DES));
		for (j = 0; j < 8; j++) { buffer[i + j] ^= ivec[j]; }
		ncd_EuroDes(deskey, deskey + 8, flags, NC_DES_ECM_HASH, buffer + i);
		memcpy(ivec, buffer + i, 8);
	}
	len += 8;
	return len;
}

int cccam_newcamd_des_decrypt(uint8_t *buffer, int len, const uint8_t *deskey)
{
	uint8_t ivec[8];
	uint8_t nextIvec[8];
	int i;
	uint8_t checksum = 0;

	if (!deskey) { return len; }
	if ((len - 2) % 8 || (len - 2) < 16) { return -1; }
	len -= 8;
	memcpy(nextIvec, buffer + len, 8);
	for (i = 2; i < len; i += 8)
	{
		uint8_t j;
		const uint8_t flags = (uint8_t)((1 << F_EURO_S2) | (1 << F_TRIPLE_DES));

		memcpy(ivec, nextIvec, 8);
		memcpy(nextIvec, buffer + i, 8);
		ncd_EuroDes(deskey, deskey + 8, flags, NC_DES_ECM_CRYPT, buffer + i);
		for (j = 0; j < 8; j++)
			{ buffer[i + j] ^= ivec[j]; }
	}
	for (i = 2; i < len; i++) { checksum ^= buffer[i]; }
	if (checksum) { return -1; }
	return len;
}

void cccam_newcamd_login_key(const uint8_t *key1, const uint8_t *key2,
                             int len, uint8_t *des16)
{
	uint8_t des14[14];
	int i;

	memcpy(des14, key1, sizeof(des14));
	for (i = 0; i < len; i++) { des14[i % 14] ^= key2[i]; }
	ncd_des_key_spread(des14, des16);
	nc_doPC1(des16);
	nc_doPC1(des16 + 8);
}
