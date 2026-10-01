/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 RICSec
 */

#ifndef PTA_VERAISON_ATTESTATION_PLATFORM_H
#define PTA_VERAISON_ATTESTATION_PLATFORM_H

#include <stdint.h>
#include <tee_api_types.h>

#define SIGNER_ID_LEN 32

/*
 * Platform values of the PSA token. A platform provides them from its
 * hardware (CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS=y); otherwise
 * the fixed test values are used.
 */

/* The hash of the key that verifies the boot firmware, SIGNER_ID_LEN bytes */
TEE_Result platform_get_signer_id(uint8_t signer_id[SIGNER_ID_LEN]);

/* The PSA security lifecycle state */
TEE_Result platform_get_lifecycle(int *lifecycle);

#endif /* PTA_VERAISON_ATTESTATION_PLATFORM_H */
