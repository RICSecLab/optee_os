// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 RICSec
 */

#include <drivers/imx_ocotp.h>
#include <string.h>
#include <util.h>

#include "platform.h"

/* SRK hash: OCOTP banks 6 and 7, four words each, 256 bits in total */
#define OCOTP_SRK_BANK_FIRST	6
#define OCOTP_SRK_BANK_LAST	7
#define OCOTP_WORDS_PER_BANK	4

/* SEC_CONFIG[1]: bank 1 word 3 bit 25, set once the device is closed */
#define OCOTP_SEC_CONFIG_BANK	1
#define OCOTP_SEC_CONFIG_WORD	3
#define OCOTP_SEC_CONFIG_CLOSED	BIT32(25)

/* PSA security lifecycle states */
#define PSA_LIFECYCLE_ASSEMBLY_AND_TEST	0x1000
#define PSA_LIFECYCLE_PSA_ROT_PROVISIONING	0x2000
#define PSA_LIFECYCLE_SECURED		0x3000

static bool all_zero(const uint8_t *buf, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		if (buf[i])
			return false;

	return true;
}

TEE_Result platform_get_signer_id(uint8_t signer_id[SIGNER_ID_LEN])
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int bank = 0;
	unsigned int word = 0;
	uint32_t val = 0;
	size_t i = 0;

	for (bank = OCOTP_SRK_BANK_FIRST; bank <= OCOTP_SRK_BANK_LAST; bank++) {
		for (word = 0; word < OCOTP_WORDS_PER_BANK; word++) {
			res = imx_ocotp_read(bank, word, &val);
			if (res != TEE_SUCCESS)
				return res;

			signer_id[i++] = val >> 24;
			signer_id[i++] = val >> 16;
			signer_id[i++] = val >> 8;
			signer_id[i++] = val;
		}
	}

	return TEE_SUCCESS;
}

/*
 * The SRK fuses and the SEC_CONFIG fuse say how far the device has come:
 * no SRK hash means it is still being assembled and tested, an SRK hash
 * on an open device means the root of trust is being provisioned, and a
 * closed device only boots signed images.
 */
TEE_Result platform_get_lifecycle(int *lifecycle)
{
	uint8_t srk[SIGNER_ID_LEN] = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t sec_config = 0;

	res = platform_get_signer_id(srk);
	if (res != TEE_SUCCESS)
		return res;

	res = imx_ocotp_read(OCOTP_SEC_CONFIG_BANK, OCOTP_SEC_CONFIG_WORD,
			     &sec_config);
	if (res != TEE_SUCCESS)
		return res;

	if (all_zero(srk, sizeof(srk)))
		*lifecycle = PSA_LIFECYCLE_ASSEMBLY_AND_TEST;
	else if (!(sec_config & OCOTP_SEC_CONFIG_CLOSED))
		*lifecycle = PSA_LIFECYCLE_PSA_ROT_PROVISIONING;
	else
		*lifecycle = PSA_LIFECYCLE_SECURED;

	return TEE_SUCCESS;
}
