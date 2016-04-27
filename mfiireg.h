

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
