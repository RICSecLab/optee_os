// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#include <base64.h>
#include <config.h>
#include <kernel/pseudo_ta.h>
#include <mempool.h>
#include <pta_veraison_attestation.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"
#include "hash.h"
#include "sign.h"

#define PTA_NAME "veraison_attestation.pta"

#define MAX_KEY_SIZE 4096
#define MAX_NONCE_SIZE 64
#define TEE_SHA256_HASH_SIZE 32

#define EAT_PROFILE "http://arm.com/psa/2.0.0"
#define CLIENT_ID 1
#define LIFECYCLE 12288
#define MEASURMENT_TYPE "PRoT"
#define SIGNER_ID_LEN 32

/* clang-format off */
#define SIGNER_ID {                                                \
		0xac, 0xbb, 0x11, 0xc7, 0xe4, 0xda, 0x21, 0x72,    \
		0x05, 0x52, 0x3c, 0xe4, 0xce, 0x1a, 0x24, 0x5a,    \
		0xe1, 0xa2, 0x39, 0xae, 0x3c, 0x6b, 0xfd, 0x9e,    \
		0x78, 0x71, 0xf7, 0xe5, 0xd8, 0xba, 0xe8, 0x6b     \
	}
/* clang-format on */

/*
 * Signing key handed in by the caller (memref[3]):
 * public key X || public key Y || serialized CAAM private key.
 */
#define KEY_PARAM_HEADER_SIZE (2 * SIGNING_KEY_COORD_SIZE)

static TEE_Result get_signing_key(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS],
				  struct signing_key *skey)
{
	const uint8_t *buf = params[3].memref.buffer;
	size_t len = params[3].memref.size;

	if (TEE_PARAM_TYPE_GET(param_types, 3) == TEE_PARAM_TYPE_NONE)
		return get_test_signing_key(skey);

	if (!IS_ENABLED(CFG_NXP_CAAM))
		return TEE_ERROR_NOT_SUPPORTED;

	if (!buf || len <= KEY_PARAM_HEADER_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	*skey = (struct signing_key){
		.pub_x = buf,
		.pub_y = buf + SIGNING_KEY_COORD_SIZE,
		.priv = buf + KEY_PARAM_HEADER_SIZE,
		.priv_len = len - KEY_PARAM_HEADER_SIZE,
	};

	return TEE_SUCCESS;
}

static TEE_Result cmd_get_cbor_evidence(uint32_t param_types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint8_t *nonce = params[0].memref.buffer;
	const size_t nonce_sz = params[0].memref.size;
	uint8_t *output_buffer = params[1].memref.buffer;
	size_t *output_buffer_len = &params[1].memref.size;
	const uint8_t *psa_implementation_id = params[2].memref.buffer;
	const size_t psa_implementation_id_len = params[2].memref.size;
	TEE_Result status = TEE_SUCCESS;

	const char eat_profile[] = EAT_PROFILE;
	const int psa_client_id = CLIENT_ID;
	const int psa_security_lifecycle = LIFECYCLE;
	const char measurement_type[] = MEASURMENT_TYPE;
	const uint8_t signer_id[SIGNER_ID_LEN] = SIGNER_ID;
	uint8_t psa_instance_id[INSTANCE_ID_LEN] = { };
	struct signing_key skey = { };

	uint8_t measurement_value[TEE_SHA256_HASH_SIZE] = { 0 };
	size_t b64_measurement_value_len = TEE_SHA256_HASH_SIZE * 2;
	char b64_measurement_value[TEE_SHA256_HASH_SIZE * 2] = { 0 };

	UsefulBufC ubc_cbor_evidence = { NULL, 0 };
	UsefulBufC ubc_cose_evidence = { NULL, 0 };

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE) &&
	    param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!nonce || !nonce_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!output_buffer && *output_buffer_len)
		return TEE_ERROR_BAD_PARAMETERS;

	status = get_signing_key(param_types, params, &skey);
	if (status != TEE_SUCCESS)
		return status;

	status = compute_instance_id(&skey, psa_instance_id);
	if (status != TEE_SUCCESS)
		return status;

	/* Calculate measurement hash of memory */
	status = get_hash_ta_memory(measurement_value);
	if (status != TEE_SUCCESS)
		return status;

	/* Encode measurement_value to base64 */
	if (!base64_enc(measurement_value, TEE_SHA256_HASH_SIZE,
			b64_measurement_value,
			&b64_measurement_value_len)) {
		DMSG("Failed to encode measurement_value to base64");
		return TEE_ERROR_GENERIC;
	}
	DMSG("b64_measurement_value: %s", b64_measurement_value);

	/* Encode evidence to CBOR */
	ubc_cbor_evidence = generate_cbor_evidence(eat_profile,
						   psa_client_id,
						   psa_security_lifecycle,
						   psa_implementation_id,
						   psa_implementation_id_len,
						   measurement_type,
						   signer_id,
						   SIGNER_ID_LEN,
						   psa_instance_id,
						   INSTANCE_ID_LEN,
						   nonce,
						   nonce_sz,
						   measurement_value,
						   TEE_SHA256_HASH_SIZE);
	if (UsefulBuf_IsNULLC(ubc_cbor_evidence)) {
		DMSG("Failed to encode evidence to CBOR");
		return TEE_ERROR_GENERIC;
	}

	/* Sign the CBOR and generate a COSE evidence */
	ubc_cose_evidence = generate_cose_evidence(ubc_cbor_evidence, &skey);
	if (UsefulBuf_IsNULLC(ubc_cose_evidence)) {
		DMSG("Failed to encode CBOR to COSE");
		status = TEE_ERROR_GENERIC;
		goto free_ubc_cbor_evidence;
	}

	/* Copy COSE evidence for return buffer */
	if (ubc_cose_evidence.len > *output_buffer_len) {
		*output_buffer_len = ubc_cose_evidence.len;
		status = TEE_ERROR_SHORT_BUFFER;
		goto free_ubc_cose_evidence;
	}
	memcpy(output_buffer, ubc_cose_evidence.ptr, ubc_cose_evidence.len);
	*output_buffer_len = ubc_cose_evidence.len;

	/* Free mempool allocation before returning to the caller */
free_ubc_cose_evidence:
	mempool_free(mempool_default, (void *)ubc_cose_evidence.ptr);
free_ubc_cbor_evidence:
	mempool_free(mempool_default, (void *)ubc_cbor_evidence.ptr);

	return status;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE:
		return cmd_get_cbor_evidence(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_VERAISON_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
