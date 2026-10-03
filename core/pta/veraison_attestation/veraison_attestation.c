// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#include <config.h>
#include <crypto/crypto.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_manager.h>
#include <kernel/user_ta.h>
#include <mempool.h>
#include <pta_veraison_attestation.h>
#include <stdlib.h>
#include <string.h>
#include <tee/uuid.h>
#include <util.h>

#ifdef CFG_NXP_CAAM
#include <drivers/caam_extension.h>
#endif

#include "cbor.h"
#include "hash.h"
#include "platform.h"
#include "sign.h"

#define PTA_NAME "veraison_attestation.pta"

#define MAX_KEY_SIZE 4096
#define MAX_NONCE_SIZE 64
#define TEE_SHA256_HASH_SIZE 32

#define EAT_PROFILE "http://arm.com/psa/2.0.0"
#define LIFECYCLE 12288
#define TA_MEASUREMENT_TYPE "ARoT"
#define TEE_MEASUREMENT_TYPE "PRoT"
#define TEE_VERSION_MAX_LEN 32

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

/*
 * The PSA client-id names the caller the evidence is about. Derive it from
 * the UUID of the calling TA: the low 31 bits of the SHA-256 of the UUID
 * in its RFC 4122 octet form, which keeps it positive, the value range the
 * PSA token reserves for callers in the secure world.
 */
static TEE_Result get_client_id(int *client_id)
{
	uint8_t hash[TEE_SHA256_HASH_SIZE] = { };
	uint8_t octets[sizeof(TEE_UUID)] = { };
	struct ts_session *s = NULL;
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;
	uint32_t v = 0;

	s = ts_get_calling_session();
	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;
	tee_uuid_to_octets(octets, &s->ctx->uuid);

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res != TEE_SUCCESS)
		return res;
	res = crypto_hash_init(ctx);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_update(ctx, octets, sizeof(octets));
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_final(ctx, hash, sizeof(hash));
	if (res != TEE_SUCCESS)
		goto out;

	v = ((uint32_t)hash[28] << 24) | ((uint32_t)hash[29] << 16) |
	    ((uint32_t)hash[30] << 8) | hash[31];
	*client_id = v & 0x7fffffff;
out:
	crypto_hash_free_ctx(ctx);

	return res;
}

/*
 * Version of the TEE core: the first word of the core version string, that
 * is TEE_IMPL_VERSION (for instance "4.6.0" or "4.6.0-12-gabcdef0-dev"),
 * without the compiler, build count and date that follow it.
 */
static void get_tee_version(char *out, size_t out_len)
{
	size_t n = 0;

	while (n < out_len - 1 && core_v_str[n] && core_v_str[n] != ' ')
		n++;
	memcpy(out, core_v_str, n);
	out[n] = '\0';
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
	int psa_client_id = 0;
	int psa_security_lifecycle = LIFECYCLE;
	uint8_t signer_id[SIGNER_ID_LEN] = SIGNER_ID;
	uint8_t psa_instance_id[INSTANCE_ID_LEN] = { };
	struct signing_key skey = { };

	uint8_t ta_measurement[TEE_SHA256_HASH_SIZE] = { };
	uint8_t tee_measurement[TEE_SHA256_HASH_SIZE] = { };
	char tee_version[TEE_VERSION_MAX_LEN] = { };
	struct psa_sw_component components[2] = {
		{
			.measurement_type = TA_MEASUREMENT_TYPE,
			.measurement_value = ta_measurement,
			.measurement_value_len = sizeof(ta_measurement),
			.signer_id = signer_id,
			.signer_id_len = sizeof(signer_id),
		},
		{
			.measurement_type = TEE_MEASUREMENT_TYPE,
			.measurement_value = tee_measurement,
			.measurement_value_len = sizeof(tee_measurement),
			.version = tee_version,
			.signer_id = signer_id,
			.signer_id_len = sizeof(signer_id),
		},
	};

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

	status = get_client_id(&psa_client_id);
	if (status != TEE_SUCCESS)
		return status;

	status = get_signing_key(param_types, params, &skey);
	if (status != TEE_SUCCESS)
		return status;

	status = compute_instance_id(&skey, psa_instance_id);
	if (status != TEE_SUCCESS)
		return status;

	if (IS_ENABLED(CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS)) {
		status = platform_get_signer_id(signer_id);
		if (status != TEE_SUCCESS)
			return status;
		status = platform_get_lifecycle(&psa_security_lifecycle);
		if (status != TEE_SUCCESS)
			return status;
	}

	/* Measure the calling TA and the TEE core */
	status = get_hash_ta_memory(ta_measurement);
	if (status != TEE_SUCCESS)
		return status;
	status = get_hash_tee_memory(tee_measurement);
	if (status != TEE_SUCCESS)
		return status;
	get_tee_version(tee_version, sizeof(tee_version));
	DHEXDUMP(ta_measurement, sizeof(ta_measurement));
	DHEXDUMP(tee_measurement, sizeof(tee_measurement));
	DMSG("TEE version: %s", tee_version);

	/* Encode evidence to CBOR */
	ubc_cbor_evidence = generate_cbor_evidence(eat_profile,
						   psa_client_id,
						   psa_security_lifecycle,
						   psa_implementation_id,
						   psa_implementation_id_len,
						   components,
						   ARRAY_SIZE(components),
						   psa_instance_id,
						   INSTANCE_ID_LEN,
						   nonce,
						   nonce_sz);
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

#ifdef CFG_NXP_CAAM
/* Export a bignum as a fixed-size big-endian field, zero padded */
static TEE_Result export_coord(struct bignum *bn, uint8_t *out, size_t size)
{
	size_t len = crypto_bignum_num_bytes(bn);

	if (len > size)
		return TEE_ERROR_GENERIC;

	memset(out, 0, size);
	crypto_bignum_bn2bin(bn, out + size - len);

	return TEE_SUCCESS;
}

static TEE_Result cmd_generate_key(uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	struct ecc_keypair key = { };
	TEE_Result res = TEE_SUCCESS;
	size_t priv_len = 0;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_acipher_alloc_ecc_keypair(&key, TEE_TYPE_ECDSA_KEYPAIR,
					       SIGNING_KEY_COORD_SIZE * 8);
	if (res != TEE_SUCCESS)
		return res;
	key.curve = TEE_ECC_CURVE_NIST_P256;

	/*
	 * With the CAAM crypto driver the private key is generated as a
	 * black key and key.d holds its serialized form (a blob), so the
	 * plain key is never available here.
	 */
	res = crypto_acipher_gen_ecc_key(&key, SIGNING_KEY_COORD_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto out;

	priv_len = crypto_bignum_num_bytes(key.d);
	if (params[0].memref.size < priv_len ||
	    params[1].memref.size < SIGNING_KEY_COORD_SIZE ||
	    params[2].memref.size < SIGNING_KEY_COORD_SIZE) {
		params[0].memref.size = priv_len;
		params[1].memref.size = SIGNING_KEY_COORD_SIZE;
		params[2].memref.size = SIGNING_KEY_COORD_SIZE;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	if (!params[0].memref.buffer || !params[1].memref.buffer ||
	    !params[2].memref.buffer) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	crypto_bignum_bn2bin(key.d, params[0].memref.buffer);
	params[0].memref.size = priv_len;
	res = export_coord(key.x, params[1].memref.buffer,
			   SIGNING_KEY_COORD_SIZE);
	if (res != TEE_SUCCESS)
		goto out;
	params[1].memref.size = SIGNING_KEY_COORD_SIZE;
	res = export_coord(key.y, params[2].memref.buffer,
			   SIGNING_KEY_COORD_SIZE);
	if (res != TEE_SUCCESS)
		goto out;
	params[2].memref.size = SIGNING_KEY_COORD_SIZE;

out:
	crypto_bignum_free(&key.d);
	crypto_bignum_free(&key.x);
	crypto_bignum_free(&key.y);

	return res;
}

static TEE_Result cmd_wrap_key(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	size_t out_size = params[1].memref.size;
	TEE_Result res = TEE_SUCCESS;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer ||
	    params[0].memref.size != SIGNING_KEY_COORD_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = caam_key_wrap_black(params[0].memref.buffer,
				  params[0].memref.size,
				  params[1].memref.buffer, &out_size);
	params[1].memref.size = out_size;

	return res;
}
#endif /* CFG_NXP_CAAM */

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE:
		return cmd_get_cbor_evidence(param_types, params);
#ifdef CFG_NXP_CAAM
	case PTA_VERAISON_ATTESTATION_GENERATE_KEY:
		return cmd_generate_key(param_types, params);
	case PTA_VERAISON_ATTESTATION_WRAP_KEY:
		return cmd_wrap_key(param_types, params);
#endif
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_VERAISON_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
