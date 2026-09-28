/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 RICSec
 */

#ifndef __TEE_RPMB_DEV_H
#define __TEE_RPMB_DEV_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/* eMMC CID, the device identity the RPMB FS binds its key to */
#define RPMB_DEV_CID_SIZE	16

/* One RPMB data frame, as defined by JEDEC JESD84 */
#define RPMB_DEV_FRAME_SIZE	512

/*
 * A device driver in the core that moves RPMB frames to and from an eMMC,
 * so that the RPMB FS (CFG_RPMB_FS) works without tee-supplicant when
 * CFG_RPMB_CORE_DRIVER=y.
 *
 * The RPMB protocol (frame layout, MAC, write counter, nonce) is handled by
 * the RPMB FS; the driver only carries complete frames. Every write is a
 * request that the caller follows with a read of the response, so a driver
 * may keep the device on the RPMB partition between calls.
 */
struct rpmb_dev_ops {
	/*
	 * Identify the device: its CID, the RPMB size in 128 KiB units
	 * (EXT_CSD[168]) and the reliable write sector count (EXT_CSD[222]).
	 */
	TEE_Result (*get_dev_info)(uint8_t cid[RPMB_DEV_CID_SIZE],
				   uint8_t *rpmb_size_mult,
				   uint8_t *rel_wr_sec_c);
	/* Write @nframes request frames to the RPMB partition */
	TEE_Result (*write)(const void *frames, size_t nframes);
	/* Read @nframes response frames from the RPMB partition */
	TEE_Result (*read)(void *frames, size_t nframes);
};

/*
 * Register the (single) RPMB device driver. Must be called before the
 * first RPMB access, typically from an initcall of the driver.
 */
TEE_Result rpmb_dev_register(const struct rpmb_dev_ops *ops);

#endif /* __TEE_RPMB_DEV_H */
