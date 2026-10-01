/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#ifndef __PTA_VERAISON_ATTESTATION_H
#define __PTA_VERAISON_ATTESTATION_H

#define PTA_VERAISON_ATTESTATION_UUID                                  \
	{                                                              \
		0xa77955f9, 0xeea1, 0x44fd,                            \
		{                                                      \
			0xad, 0xd5, 0x4a, 0x9d, 0x96, 0x2a, 0xfc, 0xf5 \
		}                                                      \
	}

/*
 * Return a CBOR(COSE) evidence
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        Output buffer
 * [in]     memref[2]        Implementation ID
 * [in]     memref[3]        (optional) Signing key: public key X (32 bytes),
 *                           public key Y (32 bytes), then the private key
 *                           as a serialized CAAM key, that is a CAAM black
 *                           key blob, never a plain scalar. Only accepted
 *                           when CFG_NXP_CAAM=y. Without it the embedded
 *                           test key (CFG_VERAISON_ATTESTATION_PTA_TEST_KEY)
 *                           signs. The PSA instance-id is derived from the
 *                           public key of the key in use.
 *
 * Main return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED   - Caller is not a user space TA
 * TEE_ERROR_BAD_PARAMETERS  - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER    - Output buffer size less than required
 * TEE_ERROR_NOT_IMPLEMENTED - Command not implemented
 */
#define PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE 0x0

#endif /* __PTA_VERAISON_ATTESTATION_H */
