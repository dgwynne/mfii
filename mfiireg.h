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

#define MFII_PCI_VEN_ID_LSI	0x1000

#define MFII_PCI_DEV_ID_2008	0x005b
#define MFII_PCI_DEV_ID_3108	0x005d
#define MFII_PCI_DEV_ID_3008	0x005f

#define PCI_ID(_v, _p)		((_v) | ((_p) << 16))

#define MFII_PCI_ID_2008	PCI_ID(MFII_PCI_VEN_LSI, MFII_PCI_DEV_2008)
#define MFII_PCI_ID_3108	PCI_ID(MFII_PCI_VEN_LSI, MFII_PCI_DEV_3108)
#define MFII_PCI_ID_3008	PCI_ID(MFII_PCI_VEN_LSI, MFII_PCI_DEV_3008)

#define MFII_PCI_BAR		PCI_CONF_BASE1

struct mfii_request_descr {
	uint8_t		flags;
	uint8_t		msix_index;
	uint16_t	smid;

	uint16_t	lmid;
	uint16_t	dev_handle;
} __packed;

#define MFII_MAX_SGL_LEN 256

#include "mpiireg.h"
#include "mfireg.h"
