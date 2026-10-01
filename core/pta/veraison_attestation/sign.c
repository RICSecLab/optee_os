// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib_ext.h>
#include <string.h>
#include <utee_defines.h>

#include "sign.h"

#define KEY_SIZE 32
#define KEY_SIZE_BIT (KEY_SIZE * 8)

static struct ecc_keypair *key;
static struct ecc_public_key *pubkey;

#ifdef CFG_VERAISON_ATTESTATION_PTA_TEST_KEY
/*
 * FIXME: Currently, keys are directly embedded within the code. From a security
 * standpoint these keys should be stored in a secure location and properly
 * loaded during program execution in a production environment.
 * The key information has been extracted using the command:
 *   $ echo "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4=" | base64 -d | xxd -p
 * (and similar steps for obtaining the x, y, d values).
 *
 * {
 *   "kty": "EC",
 *   "crv": "P-256",
 *   "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
 * }
 */

/* clang-format off */
#define PUBLIC_KEY_X {                                             \
		0x30, 0xa0, 0x42, 0x4c, 0xd2, 0x1c, 0x29, 0x44,    \
		0x83, 0x8a, 0x2d, 0x75, 0xc9, 0x2b, 0x37, 0xe7,    \
		0x6e, 0xa2, 0x0d, 0x9f, 0x00, 0x89, 0x3a, 0x3b,    \
		0x4e, 0xee, 0x8a, 0x3c, 0x0a, 0xaf, 0xec, 0x3e     \
	}
#define PUBLIC_KEY_Y {                                             \
		0xe0, 0x4b, 0x65, 0xe9, 0x24, 0x56, 0xd9, 0x88,    \
		0x8b, 0x52, 0xb3, 0x79, 0xbd, 0xfb, 0xd5, 0x1e,    \
		0xe8, 0x69, 0xef, 0x1f, 0x0f, 0xc6, 0x5b, 0x66,    \
		0x59, 0x69, 0x5b, 0x6c, 0xce, 0x08, 0x17, 0x23     \
	}
#define PRIVATE_KEY {                                              \
		0xf3, 0xbd, 0x0c, 0x07, 0xa8, 0x1f, 0xb9, 0x32,    \
		0x78, 0x1e, 0xd5, 0x27, 0x52, 0xf6, 0x0c, 0xc8,    \
		0x9a, 0x6b, 0xe5, 0xe5, 0x19, 0x34, 0xfe, 0x01,    \
		0x93, 0x8d, 0xdb, 0x55, 0xd8, 0xf7, 0x78, 0x01     \
	}
/* clang-format on */

static const uint8_t test_public_key_x[] = PUBLIC_KEY_X;
static const uint8_t test_public_key_y[] = PUBLIC_KEY_Y;
static const uint8_t test_private_key[] = PRIVATE_KEY;
#elif !defined(CFG_NXP_CAAM)
#error "This is experimental code, requires " \
	"CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=y"
#endif

TEE_Result get_test_signing_key(struct signing_key *skey)
{
#ifdef CFG_VERAISON_ATTESTATION_PTA_TEST_KEY
	*skey = (struct signing_key){
		.pub_x = test_public_key_x,
		.pub_y = test_public_key_y,
		.priv = NULL,
		.priv_len = 0,
	};

	return TEE_SUCCESS;
#else
	*skey = (struct signing_key){ };

	return TEE_ERROR_NOT_SUPPORTED;
#endif
}

static TEE_Result hash_sha256(const uint8_t *msg, size_t msg_len, uint8_t *hash)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res != TEE_SUCCESS)
		return res;
	res = crypto_hash_init(ctx);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_update(ctx, msg, msg_len);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_final(ctx, hash, TEE_SHA256_HASH_SIZE);

out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static void free_keypair(void)
{
	if (!key)
		return;

	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->x);
	crypto_bignum_free(&key->y);

	free_wipe(key);
	key = NULL;
}

static void free_pubkey(void)
{
	if (!pubkey)
		return;

	crypto_bignum_free(&pubkey->x);
	crypto_bignum_free(&pubkey->y);

	free_wipe(pubkey);
	pubkey = NULL;
}

static TEE_Result generate_key(const struct signing_key *skey)
{
	TEE_Result res = TEE_SUCCESS;

	/* Allocate a private key storage */
	assert(!key);
	key = calloc(1, sizeof(*key));
	if (!key)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = crypto_acipher_alloc_ecc_keypair(key, TEE_TYPE_ECDSA_KEYPAIR,
					       KEY_SIZE_BIT);
	if (res != TEE_SUCCESS)
		goto free_keypair;
	key->curve = TEE_ECC_CURVE_NIST_P256;

	/*
	 * Copy the private key. A serialized CAAM key is longer than the
	 * scalar; the CAAM crypto driver sizes the bignum for it and unwraps
	 * it when the key is used.
	 */
	if (skey->priv)
		res = crypto_bignum_bin2bn(skey->priv, skey->priv_len, key->d);
#ifdef CFG_VERAISON_ATTESTATION_PTA_TEST_KEY
	else
		res = crypto_bignum_bin2bn(test_private_key, KEY_SIZE, key->d);
#else
	else
		res = TEE_ERROR_BAD_PARAMETERS;
#endif
	if (res != TEE_SUCCESS)
		goto free_keypair;

	/* Allocate a public key storage */
	assert(!pubkey);
	pubkey = calloc(1, sizeof(*pubkey));
	if (!pubkey) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto free_keypair;
	}
	res = crypto_acipher_alloc_ecc_public_key(pubkey,
						  TEE_TYPE_ECDSA_PUBLIC_KEY,
						  KEY_SIZE_BIT);
	if (res != TEE_SUCCESS)
		goto free_pubkey;
	pubkey->curve = TEE_ECC_CURVE_NIST_P256;

	/* Copy the public key */
	res = crypto_bignum_bin2bn(skey->pub_x, KEY_SIZE, pubkey->x);
	if (res != TEE_SUCCESS)
		goto free_pubkey;

	res = crypto_bignum_bin2bn(skey->pub_y, KEY_SIZE, pubkey->y);
	if (res != TEE_SUCCESS)
		goto free_pubkey;

	return TEE_SUCCESS;

free_pubkey:
	free_pubkey();
free_keypair:
	free_keypair();

	return res;
}

TEE_Result compute_instance_id(const struct signing_key *skey,
			       uint8_t instance_id[INSTANCE_ID_LEN])
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;
	const uint8_t uncompressed_point = 0x04;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res != TEE_SUCCESS)
		return res;
	res = crypto_hash_init(ctx);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_update(ctx, &uncompressed_point, 1);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_update(ctx, skey->pub_x, KEY_SIZE);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_update(ctx, skey->pub_y, KEY_SIZE);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_hash_final(ctx, instance_id + 1, TEE_SHA256_HASH_SIZE);
	if (res != TEE_SUCCESS)
		goto out;

	/* EAT UEID type byte: hash of a public key */
	instance_id[0] = 0x01;

out:
	crypto_hash_free_ctx(ctx);
	return res;
}

TEE_Result sign_ecdsa_sha256(const struct signing_key *skey,
			     const uint8_t *msg, size_t msg_len, uint8_t *sig,
			     size_t *sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t hash_msg[TEE_SHA256_HASH_SIZE] = { };

	/* Allocate the key pair*/
	res = generate_key(skey);
	if (res != TEE_SUCCESS)
		return res;

	/* Hash the msg */
	res = hash_sha256(msg, msg_len, hash_msg);
	if (res != TEE_SUCCESS)
		goto free;

	/* Sign the hashed msg by the key pair*/
	res = crypto_acipher_ecc_sign(TEE_ALG_ECDSA_SHA256, key, hash_msg,
				      TEE_SHA256_HASH_SIZE, sig, sig_len);
	if (res != TEE_SUCCESS)
		goto free;

	/* Verify the signature */
	res = crypto_acipher_ecc_verify(TEE_ALG_ECDSA_SHA256, pubkey, hash_msg,
					TEE_SHA256_HASH_SIZE, sig, *sig_len);
	if (res == TEE_SUCCESS)
		DMSG("Success to verify");
	else
		DMSG("Failed to verify");

free:
	free_pubkey();
	assert(!pubkey);
	free_keypair();
	assert(!key);

	return res;
}
