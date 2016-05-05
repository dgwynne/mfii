/*
 * Copyright (c) 2016 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define __packed	__attribute__((__packed__))
#define __aligned(x)	__attribute__((__aligned__(x)))

#include "mpiireg.h"
#include "mfireg.h"

#define MFII_PCI_VEN_LSI	0x1000

#define MFII_PCI_DEV_2208	0x005b
#define MFII_PCI_DEV_3108	0x005d
#define MFII_PCI_DEV_3008	0x005f

#define PCI_ID(_v, _p)		((_v) | ((_p) << 16))

#define MFII_PCI_ID_2208	PCI_ID(MFII_PCI_VEN_LSI, MFII_PCI_DEV_2208)
#define MFII_PCI_ID_3108	PCI_ID(MFII_PCI_VEN_LSI, MFII_PCI_DEV_3108)
#define MFII_PCI_ID_3008	PCI_ID(MFII_PCI_VEN_LSI, MFII_PCI_DEV_3008)

#define MFII_PCI_BAR		PCI_CONF_BASE1

#define MFII_MAX_SGL_LEN 256

#define MFII_OSTS_INTR_VALID	0x00000009
#define MFII_RPI		0x6c /* reply post host index */

#define MFII_REQ_TYPE_SCSI	MPII_REQ_DESCR_SCSI_IO
#define MFII_REQ_TYPE_LDIO	(0x7 << 1)
#define MFII_REQ_TYPE_MFA	(0x1 << 1)
#define MFII_REQ_TYPE_NO_LOCK	(0x2 << 1)
#define MFII_REQ_TYPE_HI_PRI	(0x6 << 1)

#define MFII_REQ_MFA(_a)	LE_64((_a) | MFII_REQ_TYPE_MFA)

#define MFII_FUNCTION_LDIO_REQUEST (0xf1)

struct mfii_request_descr {
	uint8_t		flags;
	uint8_t		msix_index;
	uint16_t	smid;

	uint16_t	lmid;
	uint16_t	dev_handle;
} __packed;

#define MFII_RAID_CTX_IO_TYPE_SYSPD	(0x1 << 4)
#define MFII_RAID_CTX_TYPE_CUDA		(0x2 << 4)

struct mfii_raid_context {
	uint8_t		type_nseg;
	uint8_t		_reserved1;
	uint16_t	timeout_value;

	uint8_t		reg_lock_flags;
#define MFII_RAID_CTX_RL_FLAGS_SEQNO_EN (0x08)
#define MFII_RAID_CTX_RL_FLAGS_CPU0     (0x00)
#define MFII_RAID_CTX_RL_FLAGS_CPU1     (0x10)
#define MFII_RAID_CTX_RL_FLAGS_CUDA     (0x80)
	uint8_t		_reserved2;
	uint16_t	virtual_disk_target_id;

	uint64_t	reg_lock_row_lba;

	uint32_t	reg_lock_length;

	uint16_t	next_lm_id;
	uint8_t		ex_status;
	uint8_t		status;

	uint8_t		raid_flags;
	uint8_t		num_sge;
	uint16_t	config_seq_num;

	uint8_t		span_arm;
	uint8_t		_reserved3[3];
} __packed;

struct mfii_sge {
	uint64_t	sg_addr;
	uint32_t	sg_len;
	uint16_t	_reserved;
	uint8_t		sg_next_chain_offset;
	uint8_t		sg_flags;
} __packed;

#define MFII_SGE_ADDR_MASK		(0x03)
#define MFII_SGE_ADDR_SYSTEM		(0x00)
#define MFII_SGE_ADDR_IOCDDR		(0x01)
#define MFII_SGE_ADDR_IOCPLB		(0x02)
#define MFII_SGE_ADDR_IOCPLBNTA		(0x03)
#define MFII_SGE_END_OF_LIST		(0x40)
#define MFII_SGE_CHAIN_ELEMENT		(0x80)

#define MFII_REQUEST_SIZE	256

#define MR_DCMD_LD_MAP_GET_INFO		0x0300e101

#define MFII_MAX_ROW		32
#define MFII_MAX_ARRAY		128

struct mfii_array_map {
	uint16_t		mam_pd[MFII_MAX_ROW];
} __packed;

struct mfii_dev_handle {
	uint16_t		mdh_cur_handle;
	uint8_t			mdh_valid;
	uint8_t			mdh_reserved;
	uint16_t		mdh_handle[2];
} __packed;

struct mfii_ld_map {
	uint32_t		mlm_total_size;
	uint32_t		mlm_reserved1[5];
	uint32_t		mlm_num_lds;
	uint32_t		mlm_reserved2;
	uint8_t			mlm_tgtid_to_ld[2 * MFI_MAX_LD];
	uint8_t			mlm_pd_timeout;
	uint8_t			mlm_reserved3[7];
	struct mfii_array_map	mlm_am[MFII_MAX_ARRAY];
	struct mfii_dev_handle	mlm_dev_handle[MFI_MAX_PD];
} __packed;
