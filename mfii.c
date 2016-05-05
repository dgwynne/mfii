/* $Id$ */

/*
 * Copyright (c) 2016 The University of Queensland
 * Copyright (c) 2012 David Gwynne <dlg@openbsd.org>
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

/*
 * This code was written by David Gwynne <dlg@uq.edu.au> as part of the
 * IT Infrastructure Group in the Faculty of Engineering, Architecture
 * and Information Technology.
 */

#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/byteorder.h>
#include <sys/pci.h>
#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/queue.h>

#include "mfiireg.h"

char _depends_on[] = "misc/scsi";

static int		mfii_attach(dev_info_t *, ddi_attach_cmd_t);
static int		mfii_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops mfii_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* refcnt */
	nodev,		/* info */
	nulldev,	/* identify */
	nulldev,	/* probe */
	mfii_attach,	/* attach */
	mfii_detach,	/* detach */
	nodev,		/* reset */
	NULL,		/* driver ops */
	NULL,		/* bus ops */
	0		/* power */
};

static void *mfii_softc_p;

static struct modldrv mfii_modldrv = {
	&mod_driverops,
	"MegaRAID SAS Fusion",
	&mfii_ops
};

static struct modlinkage mfii_modlinkage = {
	MODREV_1,
	&mfii_modldrv,
	NULL
};

struct mfii_dmamem {
	ddi_dma_handle_t	mdm_dma_handle;
	ddi_acc_handle_t	mdm_mem_handle;
	ddi_dma_cookie_t	mdm_dma_cookie;
	caddr_t			mdm_kva;
	size_t			mdm_len;
	size_t			mdm_rlen;
};
#define MFII_DMA_KVA(_mdm) ((void *)(_mdm)->mdm_kva)
#define MFII_DMA_DVA(_mdm) ((uint64_t)(_mdm)->mdm_dma_cookie.dmac_laddress)
#define MFII_DMA_LEN(_mdm) ((_mdm)->mdm_len)
#define MFII_DMA_HANDLE(_mdm) ((_mdm)->mdm_dma_handle)

struct mfii_softc;
struct mfii_pkt;

struct mfii_ccb {
	void			*ccb_request;
	uint64_t		ccb_request_dva;
	off_t			ccb_request_offset;

	struct mfi_sense	*ccb_sense;
	uint32_t		ccb_sense_dva;
	off_t			ccb_sense_offset;

	struct mfii_sge		*ccb_sgl;
	uint64_t		ccb_sgl_dva;
	off_t			ccb_sgl_offset;
	uint_t			ccb_sgl_len;

	struct mfii_request_descr
				ccb_req;

	int			ccb_direction;
#define MFII_DATA_NONE			0
#define MFII_DATA_IN			1
#define MFII_DATA_OUT			2

	void			*ccb_cookie;
	void			(*ccb_done)(struct mfii_softc *,
				    struct mfii_ccb *);

	uint_t			ccb_smid;
	SIMPLEQ_ENTRY(mfii_ccb)	ccb_entry;
};
SIMPLEQ_HEAD(mfii_ccb_list, mfii_ccb);

struct mfii_pkt {
	struct mfii_ccb		*mp_ccb;
	struct scsi_pkt		*mp_pkt;
};

struct mfii_iop {
	uint8_t			ldio_req_type;
	uint8_t			ldio_ctx_type_nseg;
	uint8_t			ldio_ctx_reg_lock_flags;
	uint8_t			sge_flag_chain;
	uint8_t			sge_flag_eol;
};

struct mfii_softc {
	dev_info_t		*sc_dev;
	ddi_iblock_cookie_t	sc_iblock_cookie;

	const struct mfii_iop	*sc_iop;

	ddi_acc_handle_t	sc_reg_space;
	caddr_t			sc_reg_baseaddr;

	ddi_acc_handle_t	sc_iqp_space;
	u_long			*sc_iqp;
	kmutex_t		sc_iqp_mtx;

	uint_t			sc_max_cmds;
	uint_t			sc_max_sgl;

	ddi_dma_attr_t		sc_io_dma_attr;

	uint_t			sc_reply_postq_depth;
	uint_t			sc_reply_postq_index;
	struct mfii_dmamem	*sc_reply_postq;

	struct mfii_dmamem	*sc_requests;
	struct mfii_dmamem	*sc_sense;
	struct mfii_dmamem	*sc_sgl;

	struct mfii_ccb		*sc_ccbs;
	struct mfii_ccb_list	sc_ccb_list;
	kmutex_t		sc_ccb_mtx;

	scsi_hba_tran_t		*sc_tran;

	struct mfi_ctrl_info	sc_info;
};

static uint_t		mfii_intr(caddr_t);

#define mfii_read(_s, _r) ddi_get32((_s)->sc_reg_space, \
    (uint32_t *)((_s)->sc_reg_baseaddr + (_r)))
#define mfii_write(_s, _r, _v) ddi_put32((_s)->sc_reg_space, \
    (uint32_t *)((_s)->sc_reg_baseaddr + (_r)), (_v))

#define mfii_fw_state(_sc) mfii_read((_sc), MFI_OSP)

static struct mfii_dmamem *
			mfii_dmamem_alloc(struct mfii_softc *,
			    ddi_dma_attr_t *, size_t, size_t, uint_t);
static void		mfii_dmamem_free(struct mfii_softc *,
			    struct mfii_dmamem *);

static int		mfii_pci_cfg(struct mfii_softc *);
static int		mfii_fw_transition(struct mfii_softc *);
static int		mfii_fw_init(struct mfii_softc *);
static int		mfii_fw_info(struct mfii_softc *);

static int		mfii_ccbs_ctor(struct mfii_softc *);
static struct mfii_ccb *
			mfii_ccb_get(struct mfii_softc *);
static void
			mfii_ccb_put(struct mfii_softc *, struct mfii_ccb *);
static void		mfii_ccbs_dtor(struct mfii_softc *);

static void		mfii_start(struct mfii_softc *, struct mfii_ccb *);
static int		mfii_dcmd(struct mfii_softc *, struct mfii_ccb *,
			    uint32_t, struct mfii_dmamem *);
static int		mfii_mfa_poll(struct mfii_softc *, struct mfii_ccb *);
static void		mfii_done(struct mfii_softc *, struct mfii_ccb *);

static int		mfii_hba_attach(struct mfii_softc *);
static void		mfii_hba_detach(struct mfii_softc *);

static int		mfii_iport_attach(dev_info_t *, ddi_attach_cmd_t);

static int		mfii_tran_tgt_init(dev_info_t *, dev_info_t *,
			    scsi_hba_tran_t *, struct scsi_device *);
static int		mfii_tran_start(struct scsi_address *,
			    struct scsi_pkt *);

static int		mfii_tran_getcap(struct scsi_address *, char *, int);
static int		mfii_tran_setcap(struct scsi_address *, char *,
			    int, int);

static int		mfii_tran_setup_pkt(struct scsi_pkt *,
			    int (*)(caddr_t), caddr_t);
static void		mfii_tran_teardown_pkt(struct scsi_pkt *);

static int		mfii_ld_tran_tgt_init(dev_info_t *, dev_info_t *,
			    scsi_hba_tran_t *, struct scsi_device *);
static int		mfii_ld_tran_start(struct scsi_address *,
			    struct scsi_pkt *);
static void		mfii_ld_io(struct mfii_softc *,
			    struct scsi_address *, struct scsi_pkt *);
static void		mfii_ld_scsi(struct mfii_softc *,
			    struct scsi_address *, struct scsi_pkt *);

static int		mfii_pd_tran_tgt_init(dev_info_t *, dev_info_t *,
			    scsi_hba_tran_t *, struct scsi_device *);
static int		mfii_pd_tran_start(struct scsi_address *,
			    struct scsi_pkt *);

static void		mfii_tran_done(struct mfii_softc *, struct mfii_ccb *);

static ddi_dma_attr_t mfii_req_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffull,		/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	8,			/* alignment */
	0x7,			/* burst sizes */
	1,			/* minimum transfer */
	0xffffffffull,		/* maximum transfer */
	0xffffffffull,		/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0			/* flags (reserved) */
};

static ddi_dma_attr_t mfii_rep_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xfffffffful,		/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	64,			/* alignment */
	1,			/* burst sizes */
	1,			/* minimum transfer */
	0xffffffffull,		/* maximum transfer */
	0xffffffffull,		/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0			/* flags (reserved) */
};

static ddi_dma_attr_t mfii_cmd_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffull,		/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	64,			/* alignment */
	1,			/* burst sizes */
	1,			/* minimum transfer */
	0xffffffffull,		/* maximum transfer */
	0xffffffffull,		/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0			/* flags (reserved) */
};

static const ddi_dma_attr_t mfii_io_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffull,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment */
	0x7,			/* burst sizes */
	1,			/* minimum transfer */
	0xffffffffull,		/* maximum transfer */
	0xffffffffull,		/* maximum segment length */
	0x50,			/* maximum number of segments */
	512,			/* granularity */
	0			/* flags (reserved) */
};

const struct mfii_iop mfii_iop_thunderbolt = {
	MFII_REQ_TYPE_LDIO,
	0,
	0,
	MFII_SGE_CHAIN_ELEMENT | MFII_SGE_ADDR_IOCPLBNTA,
	0
};

/*
 * a lot of these values depend on us not implementing fastpath yet.
 */
const struct mfii_iop mfii_iop_25 = {
	MFII_REQ_TYPE_NO_LOCK,
	MFII_RAID_CTX_TYPE_CUDA | 0x1,
	MFII_RAID_CTX_RL_FLAGS_CPU0, /* | MFII_RAID_CTX_RL_FLAGS_SEQNO_EN */
	MFII_SGE_CHAIN_ELEMENT,
	MFII_SGE_END_OF_LIST
};

int
_init(void)
{
	int			error;

	error = ddi_soft_state_init(&mfii_softc_p,
	    sizeof(struct mfii_softc), 1);
	if (error != 0)
		goto err;

	error = scsi_hba_init(&mfii_modlinkage);
	if (error != 0)
		goto state_fini;

	error = mod_install(&mfii_modlinkage);
	if (error != 0)
		goto hba_fini;

	return (error);

hba_fini:
	scsi_hba_fini(&mfii_modlinkage);
state_fini:
	ddi_soft_state_fini(mfii_softc_p);
err:
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mfii_modlinkage, modinfop));
}

int
_fini(void)
{
	int			error;

	error = mod_remove(&mfii_modlinkage);
	if (error)
		return (error);

	scsi_hba_fini(&mfii_modlinkage);

	ddi_soft_state_fini(&mfii_softc_p);

	return (error);
}

/* how to access the register space */
static ddi_device_acc_attr_t mfii_reg_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC,
};

static ddi_device_acc_attr_t mfii_iqp_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC,
};

static ddi_device_acc_attr_t mfii_mem_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_NEVERSWAP_ACC,
	DDI_UNORDERED_OK_ACC,
	DDI_DEFAULT_ACC,
};

static int
mfii_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct mfii_softc *sc;
	int instance;
	uint32_t status;

	if (scsi_hba_iport_unit_address(dip) != NULL)
		return (mfii_iport_attach(dip, cmd));

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(mfii_softc_p, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to alloc softc");
		goto err;
	}
	sc = ddi_get_soft_state(mfii_softc_p, instance);
	sc->sc_dev = dip;

	if (mfii_pci_cfg(sc) != DDI_SUCCESS) {
		/* error printed by mfii_pci_cfg */
		goto free_sc;
	}

	if (ddi_regs_map_setup(dip, 2, &sc->sc_reg_baseaddr, 0, 0,
	    &mfii_reg_attr, &sc->sc_reg_space) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to map register space");
		goto free_sc;
	}

	/* get a different mapping for the iqp */
	if (ddi_regs_map_setup(dip, 2, (caddr_t *)&sc->sc_iqp,
	    MFI_IQPL, sizeof(struct mfii_request_descr),
	    &mfii_iqp_attr, &sc->sc_iqp_space) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to map register space");
		goto free_regs;
	}

	/* hook up interrupt */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		dev_err(dip, CE_WARN, "high level interrupt is not supported");
		goto free_iqp;
	}

	if (ddi_get_iblock_cookie(dip, 0,
	    &sc->sc_iblock_cookie) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to get iblock cookie");
		goto free_sc;
	}

	mutex_init(&sc->sc_iqp_mtx, NULL, MUTEX_DRIVER,
	    sc->sc_iblock_cookie);
	mutex_init(&sc->sc_ccb_mtx, NULL, MUTEX_DRIVER,
	    sc->sc_iblock_cookie);

	/* disable interrupts */
	mfii_write(sc, MFI_OMSK, 0xffffffff);

	if (mfii_fw_transition(sc) != DDI_SUCCESS) {
		/* error printed by mfi_fw_transition */
		goto unmutex;
	}

	status = mfii_fw_state(sc);
	sc->sc_max_cmds = status & MFI_STATE_MAXCMD_MASK;
	sc->sc_max_sgl = (status & MFI_STATE_MAXSGL_MASK) >> 16;

	sc->sc_io_dma_attr = mfii_io_attr;
	sc->sc_io_dma_attr.dma_attr_sgllen = sc->sc_max_sgl;

	/* sense memory */
	sc->sc_sense = mfii_dmamem_alloc(sc, &mfii_cmd_attr,
	    sc->sc_max_cmds, sizeof(struct mfi_sense),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	if (sc->sc_sense == NULL) {
		dev_err(dip, CE_WARN, "unable to allocate sense memory");
		goto unmutex;
	}

	sc->sc_reply_postq_depth = roundup(sc->sc_max_cmds, 16);

	sc->sc_reply_postq = mfii_dmamem_alloc(sc, &mfii_rep_attr,
	    sc->sc_reply_postq_depth, sizeof(struct mpii_reply_descr),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	if (sc->sc_reply_postq == NULL) {
		dev_err(dip, CE_WARN, "unable to allocate post queue");
		goto free_sense;
	}

	memset(MFII_DMA_KVA(sc->sc_reply_postq), 0xff,
	    MFII_DMA_LEN(sc->sc_reply_postq));

	sc->sc_requests = mfii_dmamem_alloc(sc, &mfii_req_attr,
	    (sc->sc_max_cmds + 1), MFII_REQUEST_SIZE,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT);
	if (sc->sc_requests == NULL) {
		dev_err(dip, CE_WARN, "unable to allocate request queue");
		goto free_reply_postq;
	}

	sc->sc_sgl = mfii_dmamem_alloc(sc, &mfii_cmd_attr,
	    sc->sc_max_cmds, sizeof(struct mfii_sge) * sc->sc_max_sgl,
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	if (sc->sc_sgl == NULL) {
		dev_err(dip, CE_WARN,
		    "unable to allocate scatter gather lists");
		goto free_requests;
	}

	if (mfii_ccbs_ctor(sc) != 0) {
		dev_err(dip, CE_WARN, "unable to initialise control blocks");
		goto free_sgls;
	}

	/* kickstart firmware with all addresses and pointers */
	if (mfii_fw_init(sc) != 0) {
		dev_err(dip, CE_WARN, "unable to initialise firmware");
		goto ccb_dtor;
	}

	if (ddi_add_intr(sc->sc_dev, 0, &sc->sc_iblock_cookie, NULL,
	    mfii_intr, (caddr_t)sc) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "unable to establish interrupt");
		goto ccb_dtor;
	}

	/* enable interrupts */
	mfii_write(sc, MFI_OSTS, 0xffffffff);
	mfii_write(sc, MFI_OMSK, ~MFII_OSTS_INTR_VALID);

	if (mfii_fw_info(sc) != 0) {
		dev_err(dip, CE_WARN,
		    "unable to retrieve controller information");
		goto del_intr;
	}

	dev_err(dip, CE_NOTE, "\"%s\", firmware %s",
	    sc->sc_info.mci_product_name, sc->sc_info.mci_package_version);
	if (LE_16(sc->sc_info.mci_memory_size) > 0) {
		cmn_err(CE_CONT, " %uMB cache",
		    LE_16(sc->sc_info.mci_memory_size));
	}

	if (scsi_hba_iport_register(dip, "v0") != DDI_SUCCESS)
		goto del_intr;
	if (scsi_hba_iport_register(dip, "p0") != DDI_SUCCESS)
		goto del_intr;

	if (mfii_hba_attach(sc) != DDI_SUCCESS)
		goto del_intr;

	return (DDI_SUCCESS);
del_intr:
	ddi_remove_intr(sc->sc_dev, 0, sc->sc_iblock_cookie);
ccb_dtor:
	mfii_ccbs_dtor(sc);
free_sgls:
	mfii_dmamem_free(sc, sc->sc_sgl);
free_requests:
	mfii_dmamem_free(sc, sc->sc_requests);
free_reply_postq:
	mfii_dmamem_free(sc, sc->sc_reply_postq);
free_sense:
	mfii_dmamem_free(sc, sc->sc_sense);
unmutex:
	mutex_destroy(&sc->sc_ccb_mtx);
	mutex_destroy(&sc->sc_iqp_mtx);
free_iqp:
	ddi_regs_map_free(&sc->sc_iqp_space);
free_regs:
	ddi_regs_map_free(&sc->sc_reg_space);
free_sc:
	ddi_soft_state_free(mfii_softc_p, instance);
err:
	return (DDI_FAILURE);
}

static int
mfii_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct mfii_softc	*sc;
	int			instance;

	if (scsi_hba_iport_unit_address(dip) != NULL)
		return (DDI_SUCCESS);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(mfii_softc_p, instance);

	mfii_hba_detach(sc);
	ddi_remove_intr(sc->sc_dev, 0, sc->sc_iblock_cookie);
	mfii_ccbs_dtor(sc);
	mfii_dmamem_free(sc, sc->sc_sgl);
	mfii_dmamem_free(sc, sc->sc_requests);
	mfii_dmamem_free(sc, sc->sc_reply_postq);
	mfii_dmamem_free(sc, sc->sc_sense);
	mutex_destroy(&sc->sc_ccb_mtx);
	mutex_destroy(&sc->sc_iqp_mtx);
	ddi_regs_map_free(&sc->sc_iqp_space);
	ddi_regs_map_free(&sc->sc_reg_space);
	ddi_soft_state_free(mfii_softc_p, instance);

	return (DDI_SUCCESS);
}

static inline int
mfii_my_intr(struct mfii_softc *sc)
{
	uint32_t status;

	status = mfii_read(sc, MFI_OSTS);
	if (status & 0x1) {
		mfii_write(sc, MFI_OSTS, status);
		return (1);
	}

	return (status & MFII_OSTS_INTR_VALID);
}

static uint_t
mfii_intr(caddr_t arg)
{
	struct mfii_softc *sc = (struct mfii_softc *)arg;
	struct mpii_reply_descr *postq = MFII_DMA_KVA(sc->sc_reply_postq);
	struct mpii_reply_descr *rdp;
	struct mfii_ccb *ccb;
	int rpi = 0;

	if (!mfii_my_intr(sc))
		return (DDI_INTR_UNCLAIMED);

	ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_reply_postq), 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	for (;;) {
		rdp = &postq[sc->sc_reply_postq_index];
		if ((rdp->reply_flags & MPII_REPLY_DESCR_TYPE_MASK) ==
		    MPII_REPLY_DESCR_UNUSED)
			break;
		if (rdp->data == 0xffffffff) {
			/*
			 * ioc is still writing to the reply post queue
			 * race condition - bail!
			 */
			break;
		}

		ccb = &sc->sc_ccbs[LE_16(rdp->smid) - 1];
		mfii_done(sc, ccb);
		memset(rdp, 0xff, sizeof(*rdp));

		if (++sc->sc_reply_postq_index >= sc->sc_reply_postq_depth)
			sc->sc_reply_postq_index = 0;
		rpi = 1;
	}

	if (rpi)
		mfii_write(sc, MFII_RPI, sc->sc_reply_postq_index);

	return (DDI_INTR_CLAIMED);
}

static void
mfii_done(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_requests),
	    ccb->ccb_request_offset, MFII_REQUEST_SIZE,
	    DDI_DMA_SYNC_FORKERNEL);

	ccb->ccb_done(sc, ccb);
}

static int
mfii_pci_cfg(struct mfii_softc *sc)
{
	dev_info_t *dip = sc->sc_dev;
	ddi_acc_handle_t pci_conf;
	uint16_t command;
	uint32_t id;
	int rv = DDI_SUCCESS;

	if (pci_config_setup(dip, &pci_conf) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "unable to map pci config space");
		return (DDI_FAILURE);
	}

	/* force the busmaster enable bit on */
	command = pci_config_get16(pci_conf, PCI_CONF_COMM);
	if ((command & PCI_COMM_ME) == 0) {
		command |= PCI_COMM_ME;
		pci_config_put16(pci_conf, PCI_CONF_COMM, command);

		/* check if it is enabled */
		command = pci_config_get16(pci_conf, PCI_CONF_COMM);
		if ((command & PCI_COMM_ME) == 0) {
			cmn_err(CE_WARN, "unable to enable bus mastering");
			rv = DDI_FAILURE;
			goto fail;
		}
	}

	id = pci_config_get32(pci_conf, PCI_CONF_VENID);
	switch (id) {
	case MFII_PCI_ID_2208:
		sc->sc_iop = &mfii_iop_thunderbolt;
		break;
	case MFII_PCI_ID_3008:
	case MFII_PCI_ID_3108:
		sc->sc_iop = &mfii_iop_25;
		break;
	default:
		dev_err(sc->sc_dev, CE_WARN, "unknown chip 0x%08x", id);
		rv = DDI_FAILURE;
		goto fail;
	}

fail:
	pci_config_teardown(&pci_conf);
	return (rv);
}

static int
mfii_fw_transition(struct mfii_softc *sc)
{
	int32_t fw_state, cur_state;
	int max_wait, i;

	fw_state = mfii_fw_state(sc) & MFI_STATE_MASK;

	while (fw_state != MFI_STATE_READY) {
		switch (fw_state) {
		case MFI_STATE_FAULT:
			cmn_err(CE_WARN, "firmware fault");
			return (DDI_FAILURE);
		case MFI_STATE_WAIT_HANDSHAKE:
			mfii_write(sc, MFI_SKINNY_IDB,
			    MFI_INIT_CLEAR_HANDSHAKE);
			max_wait = 2;
			break;
		case MFI_STATE_OPERATIONAL:
			mfii_write(sc, MFI_SKINNY_IDB, MFI_INIT_READY);
			max_wait = 10;
			break;
		case MFI_STATE_UNDEFINED:
		case MFI_STATE_BB_INIT:
			max_wait = 2;
			break;
		case MFI_STATE_FW_INIT:
		case MFI_STATE_DEVICE_SCAN:
		case MFI_STATE_FLUSH_CACHE:
			max_wait = 20;
			break;
		default:
			cmn_err(CE_WARN, "unknown firmware state 0x%08x",
			    fw_state);
			return (DDI_FAILURE);
		}

		cur_state = fw_state;
		for (i = 0; i < (max_wait * 10); i++) {
			fw_state = mfii_fw_state(sc) & MFI_STATE_MASK;
			if (fw_state != cur_state)
				break;

			delay(drv_usectohz(100000));
		}

		if (fw_state == cur_state) {
			cmn_err(CE_WARN, "firmware stuck in state 0x%08x",
			    fw_state);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static int
mfii_fw_init(struct mfii_softc *sc)
{
	struct mpii_msg_iocinit_request *iiq;
	struct mfii_dmamem *m;
	struct mfii_ccb *ccb;
	struct mfi_init_frame *init;
	int rv;

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1, sizeof(*iiq),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	if (m == NULL)
		return (DDI_FAILURE);

	iiq = MFII_DMA_KVA(m);
	memset(iiq, 0, sizeof(*iiq));

	iiq->function = MPII_FUNCTION_IOC_INIT;
	iiq->whoinit = MPII_WHOINIT_HOST_DRIVER;

	/* magic! */
	iiq->msg_version_maj = 0x02;
	iiq->msg_version_min = 0x00;
	iiq->hdr_version_unit = 0x10;
	iiq->hdr_version_dev = 0x0;

	iiq->system_request_frame_size = LE_16(MFII_REQUEST_SIZE / 4);

	iiq->reply_descriptor_post_queue_depth =
	    LE_16(sc->sc_reply_postq_depth);
	iiq->reply_free_queue_depth = LE_16(0);

	iiq->sense_buffer_address_high =
	    LE_32(MFII_DMA_DVA(sc->sc_sense) >> 32);

	iiq->reply_descriptor_post_queue_address_lo = 
	    LE_32(MFII_DMA_DVA(sc->sc_reply_postq));
	iiq->reply_descriptor_post_queue_address_hi =
	    LE_32(MFII_DMA_DVA(sc->sc_reply_postq) >> 32);

	iiq->system_request_frame_base_address_lo =
	    LE_32(MFII_DMA_DVA(sc->sc_requests));
	iiq->system_request_frame_base_address_hi =
	    LE_32(MFII_DMA_DVA(sc->sc_requests) >> 32);

	iiq->timestamp = LE_64(gethrtime() / 1000000);

	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORDEV);

	ccb = mfii_ccb_get(sc);
	VERIFY(ccb != NULL);
	init = ccb->ccb_request;

	init->mif_header.mfh_cmd = MFI_CMD_INIT;
	init->mif_header.mfh_data_len = LE_32(sizeof(*iiq));
	init->mif_qinfo_new_addr = LE_64(MFII_DMA_DVA(m));

	rv = mfii_mfa_poll(sc, ccb);

	mfii_ccb_put(sc, ccb);
	mfii_dmamem_free(sc, m);

	return (rv);
}

static int
mfii_fw_info(struct mfii_softc *sc)
{
	struct mfii_dmamem *m;
	struct mfii_ccb *ccb;
	int rv;

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1, sizeof(sc->sc_info),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	ccb = mfii_ccb_get(sc);
	VERIFY(ccb != NULL);

	rv = mfii_dcmd(sc, ccb, MR_DCMD_CTRL_GET_INFO, m);
	if (rv != DDI_SUCCESS)
		goto done;

	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORKERNEL);
	memcpy(&sc->sc_info, MFII_DMA_KVA(m), sizeof(sc->sc_info));

done:
	mfii_ccb_put(sc, ccb);
	mfii_dmamem_free(sc, m);

	return (rv);
}

static int
mfii_dcmd(struct mfii_softc *sc, struct mfii_ccb *ccb, uint32_t opc,
    struct mfii_dmamem *m)
{
	struct mfi_dcmd_frame *dcmd = ccb->ccb_request;
	struct mfi_frame_header *hdr = &dcmd->mdf_header;

	memset(dcmd, 0, sizeof(*dcmd));

	hdr->mfh_cmd =  MFI_CMD_DCMD;
	hdr->mfh_context = ccb->ccb_smid;
	hdr->mfh_data_len = LE_32(MFII_DMA_LEN(m));
	hdr->mfh_sg_count = 1;
	hdr->mfh_flags = LE_16(MFI_FRAME_SGL64);

	dcmd->mdf_opcode = LE_32(opc);
	dcmd->mdf_sgl.sg64[0].addr = LE_64(MFII_DMA_DVA(m));
	dcmd->mdf_sgl.sg64[0].len = LE_32(MFII_DMA_LEN(m));

	mfii_mfa_poll(sc, ccb);

	return ((hdr->mfh_cmd_status == MFI_STAT_OK) ?
	    DDI_SUCCESS : DDI_FAILURE);
}

static int
mfii_mfa_poll(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	struct mfi_frame_header *hdr = ccb->ccb_request;
	uint64_t r;
	int to = 0;
	int rv = DDI_SUCCESS;

	hdr->mfh_context = ccb->ccb_smid;
	hdr->mfh_cmd_status = 0xff;
	hdr->mfh_flags |= LE_16(MFI_FRAME_DONT_POST_IN_REPLY_QUEUE);

	r = MFII_REQ_MFA(ccb->ccb_request_dva);
	memcpy(&ccb->ccb_req, &r, sizeof(ccb->ccb_req));

	mfii_start(sc, ccb);

	for (;;) {
		ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_requests),
		    ccb->ccb_request_offset, MFII_REQUEST_SIZE,
		    DDI_DMA_SYNC_FORKERNEL);

		if (hdr->mfh_cmd_status != 0xff)
			break;

		if (to++ > 5000) { /* XXX 5 seconds busywait sucks */
			cmn_err(CE_WARN, "timeout on ccb %u", ccb->ccb_smid);
			rv = DDI_FAILURE;
			break;
		}

		delay(drv_usectohz(1000));
	}

	return (rv);
}


static int
mfii_hba_attach(struct mfii_softc *sc)
{
	scsi_hba_tran_t	*tran;
	int flags;

	tran = scsi_hba_tran_alloc(sc->sc_dev, SCSI_HBA_CANSLEEP);
	if (tran == NULL)
		return (DDI_FAILURE);

	tran->tran_hba_private = sc;

	tran->tran_tgt_init = mfii_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;

	tran->tran_start = mfii_tran_start;
	//tran->tran_reset = mfii_tran_reset;

	tran->tran_getcap = mfii_tran_getcap;
	tran->tran_setcap = mfii_tran_setcap;

	tran->tran_setup_pkt = mfii_tran_setup_pkt;
	tran->tran_teardown_pkt = mfii_tran_teardown_pkt;
	tran->tran_hba_len = sizeof(struct mfii_pkt);

	flags = SCSI_HBA_HBA | SCSI_HBA_TRAN_CLONE |
	    SCSI_HBA_TRAN_CDB | SCSI_HBA_TRAN_SCB;

	if (scsi_hba_attach_setup(sc->sc_dev, &sc->sc_io_dma_attr, tran,
	    flags) != DDI_SUCCESS)
		goto tran_free;

	sc->sc_tran = tran;

	return (DDI_SUCCESS);

tran_free:
	scsi_hba_tran_free(tran);
	return (DDI_FAILURE);
}

static void
mfii_hba_detach(struct mfii_softc *sc)
{
	scsi_hba_detach(sc->sc_dev);
	scsi_hba_tran_free(sc->sc_tran);
}

static int
mfii_iport_attach(dev_info_t *iport_dip, ddi_attach_cmd_t cmd)
{
	struct mfii_softc *sc;
	scsi_hba_tran_t *tran;
	dev_info_t *dip;
	int instance;
	const char *addr;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	addr = scsi_hba_iport_unit_address(iport_dip);
	VERIFY(addr != NULL);

	dip = ddi_get_parent(iport_dip);
	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(mfii_softc_p, instance);
	VERIFY(sc != NULL);

	tran = ddi_get_driver_private(iport_dip);

	if (strcmp(addr, "v0") == 0) {
		tran->tran_tgt_init = mfii_ld_tran_tgt_init;
		tran->tran_start = mfii_ld_tran_start;
	} else if (strcmp(addr, "p0") == 0) {
		tran->tran_tgt_init = mfii_pd_tran_tgt_init;
		tran->tran_start = mfii_pd_tran_start;
	} else
		return (DDI_FAILURE);

	tran->tran_hba_private = sc;

	return (DDI_SUCCESS);
}

static int
mfii_tran_tgt_init(dev_info_t *dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	/* we only attach on iports */
	return (DDI_FAILURE);
}

int
mfii_ld_tran_tgt_init(dev_info_t *dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;

	VERIFY(scsi_hba_iport_unit_address(dip) != NULL);

	if (sd->sd_address.a_target > sc->sc_info.mci_max_lds)
		return (DDI_FAILURE);

	/* ld read/write dont take a lun, so only 0 is supported */
	if (sd->sd_address.a_lun != 0)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
mfii_pd_tran_tgt_init(dev_info_t *dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	return (DDI_SUCCESS);
}

static int
mfii_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int index;

	index = scsi_hba_lookup_capstr(cap);
	if (index == DDI_FAILURE)
		return (-1);

	//DTRACE_PROBE1(getcap_index, int, index);

	if (cap == NULL || whom == 0)
		return (-1);

	switch (index) {
	case SCSI_CAP_ARQ:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
	default:
		break;
	}

	return (-1);
}

static int
mfii_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int index;

	index = scsi_hba_lookup_capstr(cap);
	if (index == DDI_FAILURE)
		return (-1);

	//DTRACE_PROBE1(setcap_index, int, index);

	if (cap == NULL || whom == 0)
		return (-1);

	switch (index) {
	case SCSI_CAP_ARQ:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
mfii_tran_setup_pkt(struct scsi_pkt *pkt, int (*callback)(caddr_t),
    caddr_t arg)
{
	scsi_hba_tran_t *tran = pkt->pkt_address.a_hba_tran;
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;
	struct mfii_pkt *mp = (struct mfii_pkt *)pkt->pkt_ha_private;
	struct mfii_ccb *ccb;
	//int kmflags = callback == SLEEP_FUNC ? KM_SLEEP : KM_NOSLEEP;

	if (pkt->pkt_cdblen > MPII_CDB_LEN)
		return (-1);
	if (pkt->pkt_scblen > sizeof(*ccb->ccb_sense))
		return (-1);

	ccb = mfii_ccb_get(sc);
	if (ccb == NULL)
		return (-1);

	ccb->ccb_cookie = mp;
	mp->mp_ccb = ccb;
	mp->mp_pkt = pkt;

	return (0);
}

static void
mfii_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	scsi_hba_tran_t *tran = pkt->pkt_address.a_hba_tran;
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;
	struct mfii_pkt *mp = (struct mfii_pkt *)pkt->pkt_ha_private;
	struct mfii_ccb *ccb = mp->mp_ccb;

	mp->mp_ccb = NULL;
	mp->mp_pkt = NULL;

	mfii_ccb_put(sc, ccb);
}

static size_t
mfii_sgl(struct mfii_softc *sc, struct mfii_ccb *ccb, void *sglp,
    ddi_dma_cookie_t *cookies, uint_t ncookies)
{
	struct mpii_msg_request *req = ccb->ccb_request;
	struct mfii_sge *sge = NULL, *nsge = sglp;
	struct mfii_sge *ce = NULL;
	size_t datalen = 0;
	u_int space;
	uint_t i;

        if (ncookies == 0)
                return (0);

	space = (MFII_REQUEST_SIZE - ((uint8_t *)nsge - (uint8_t *)req)) /
            sizeof(*nsge);
        if (ncookies > space) {
		space--;

		ccb->ccb_sgl_len = (ncookies - space) * sizeof(*nsge);
		memset(ccb->ccb_sgl, 0, ccb->ccb_sgl_len);

		ce = nsge + space;
		ce->sg_addr = LE_64(ccb->ccb_sgl_dva);
		ce->sg_len = LE_32(ccb->ccb_sgl_len);
		ce->sg_flags = sc->sc_iop->sge_flag_chain;

		req->chain_offset = ((uint8_t *)ce - (uint8_t *)req) / 16;
	}

	for (i = 0; i < ncookies; i++) {
		if (nsge == ce)
			nsge = ccb->ccb_sgl;

		sge = nsge;

		sge->sg_addr = LE_64(cookies[i].dmac_laddress);
                sge->sg_len = LE_32(cookies[i].dmac_size);
		sge->sg_flags = MFII_SGE_ADDR_SYSTEM;

		nsge = sge + 1;

		datalen += cookies[i].dmac_size;
        }
	sge->sg_flags |= sc->sc_iop->sge_flag_eol;

	if (ccb->ccb_sgl_len > 0) {
		ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_sgl),
		    ccb->ccb_sgl_offset, ccb->ccb_sgl_len,
		    DDI_DMA_SYNC_FORDEV);
	}

	return (datalen);
}

static int
mfii_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsi_hba_tran_t *tran = pkt->pkt_address.a_hba_tran;
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;

	return (TRAN_BADPKT);
}

static int
mfii_ld_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsi_hba_tran_t *tran = pkt->pkt_address.a_hba_tran;
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;
	struct mfii_pkt *mp = (struct mfii_pkt *)pkt->pkt_ha_private;
	struct mfii_ccb *ccb = mp->mp_ccb;
	union scsi_cdb *cdb;

	if (pkt->pkt_numcookies > sc->sc_max_sgl)
		return (TRAN_BADPKT);

	memset(ccb->ccb_request, 0, MFII_REQUEST_SIZE);
	ccb->ccb_done = mfii_tran_done;

	cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	switch (cdb->scc_cmd) {
        case SCMD_READ:
	case SCMD_READ_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE:
	case SCMD_WRITE_G1:
	case SCMD_WRITE_G4:
		/* G5 READS AND WRITES? */
		mfii_ld_io(sc, ap, pkt);
		break;

	default:
		mfii_ld_scsi(sc, ap, pkt);
		break;
	}

	pkt->pkt_resid = 0;
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_statistics = 0;
	pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;

	if (pkt->pkt_flags & FLAG_NOINTR) {
		if (mfii_mfa_poll(sc, ccb) != DDI_SUCCESS)
			return (TRAN_FATAL_ERROR);
	} else
		mfii_start(sc, ccb);

	return (TRAN_ACCEPT);
}

static int
mfii_pd_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsi_hba_tran_t *tran = pkt->pkt_address.a_hba_tran;
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;

	return (TRAN_BADPKT);
}

static void
mfii_ld_io(struct mfii_softc *sc, struct scsi_address *ap,
    struct scsi_pkt *pkt)
{
	struct mfii_pkt *mp = (struct mfii_pkt *)pkt->pkt_ha_private;
	struct mfii_ccb *ccb = mp->mp_ccb;
	struct mpii_msg_scsi_io *io = ccb->ccb_request;
	struct mfii_raid_context *ctx = (struct mfii_raid_context *)(io + 1);
	size_t datalen;

	datalen = mfii_sgl(sc, ccb, ctx + 1,
	    pkt->pkt_cookies, pkt->pkt_numcookies);

	io->dev_handle = LE_16(ap->a_target);
	io->function = MFII_FUNCTION_LDIO_REQUEST;
	io->sense_buffer_low_address = LE_32(ccb->ccb_sense_dva);
	io->sgl_flags = LE_16(MFI_FRAME_SGL64);
	io->sense_buffer_length = sizeof(*ccb->ccb_sense);
	io->sgl_offset0 = (sizeof(*io) + sizeof(*ctx)) / 4;
	io->data_length = LE_32(datalen);
	io->io_flags = LE_16(pkt->pkt_cdblen);
	memcpy(io->cdb, pkt->pkt_cdbp, pkt->pkt_cdblen);

	io->direction = MPII_SCSIIO_DIR_NONE;
	if (datalen > 0) {
		if (pkt->pkt_dma_flags & DDI_DMA_READ)
			io->direction = MPII_SCSIIO_DIR_READ;
		else if (pkt->pkt_dma_flags & DDI_DMA_WRITE)
			io->direction = MPII_SCSIIO_DIR_WRITE;
	}

	ctx->type_nseg = sc->sc_iop->ldio_ctx_type_nseg;
	ctx->timeout_value = LE_16(pkt->pkt_time);
	ctx->reg_lock_flags = sc->sc_iop->ldio_ctx_reg_lock_flags;
	ctx->virtual_disk_target_id = LE_16(ap->a_target);
	ctx->num_sge = pkt->pkt_numcookies;

	memset(&ccb->ccb_req, 0, sizeof(ccb->ccb_req));
	ccb->ccb_req.flags = sc->sc_iop->ldio_req_type;
	ccb->ccb_req.smid = LE_16(ccb->ccb_smid);
}

static void
mfii_ld_scsi(struct mfii_softc *sc, struct scsi_address *ap,
    struct scsi_pkt *pkt)
{
	struct mfii_pkt *mp = (struct mfii_pkt *)pkt->pkt_ha_private;
	struct mfii_ccb *ccb = mp->mp_ccb;
	struct mpii_msg_scsi_io *io = ccb->ccb_request;
	struct mfii_raid_context *ctx = (struct mfii_raid_context *)(io + 1);
	size_t datalen;

	datalen = mfii_sgl(sc, ccb, ctx + 1,
	    pkt->pkt_cookies, pkt->pkt_numcookies);

	io->dev_handle = LE_16(ap->a_target);
	io->function = MFII_FUNCTION_LDIO_REQUEST;
	io->sense_buffer_low_address = LE_32(ccb->ccb_sense_dva);
	io->sgl_flags = LE_16(MFI_FRAME_SGL64);
	io->sense_buffer_length = sizeof(*ccb->ccb_sense);
	io->sgl_offset0 = (sizeof(*io) + sizeof(*ctx)) / 4;
	io->data_length = LE_32(datalen);
	io->io_flags = LE_16(pkt->pkt_cdblen);
	memcpy(io->cdb, pkt->pkt_cdbp, pkt->pkt_cdblen);

	io->direction = MPII_SCSIIO_DIR_NONE;
	if (datalen > 0) {
		if (pkt->pkt_dma_flags & DDI_DMA_READ)
			io->direction = MPII_SCSIIO_DIR_READ;
		else if (pkt->pkt_dma_flags & DDI_DMA_WRITE)
			io->direction = MPII_SCSIIO_DIR_WRITE;
	}

	ctx->virtual_disk_target_id = LE_16(ap->a_target);
	ctx->num_sge = pkt->pkt_numcookies;

	memset(&ccb->ccb_req, 0, sizeof(ccb->ccb_req));
	ccb->ccb_req.flags = MFII_REQ_TYPE_SCSI;
	ccb->ccb_req.smid = LE_16(ccb->ccb_smid);
}

static void
mfii_tran_done(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	struct mfii_pkt *mp = ccb->ccb_cookie;
	struct scsi_pkt *pkt = mp->mp_pkt;
	struct mpii_msg_scsi_io *io = ccb->ccb_request;
	struct mfii_raid_context *ctx = (struct mfii_raid_context *)(io + 1);
	struct scsi_arq_status *arqstat;

	switch (ctx->status) {
	case MFI_STAT_SCSI_DONE_WITH_ERROR:
		pkt->pkt_state |= STATE_GOT_STATUS | STATE_ARQ_DONE;

		arqstat = (struct scsi_arq_status *)pkt->pkt_scbp;
		arqstat->sts_rqpkt_reason = CMD_CMPLT;
		arqstat->sts_rqpkt_resid = 0;
		arqstat->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA;
		arqstat->sts_rqpkt_statistics = 0;

		memcpy(&arqstat->sts_sensedata, ccb->ccb_sense,
		    sizeof(arqstat->sts_sensedata));

		/* FALLTHROUGH */
	case MFI_STAT_OK:
	case MFI_STAT_LD_CC_IN_PROGRESS:
	case MFI_STAT_LD_RECON_IN_PROGRESS:
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= STATE_XFERRED_DATA;
		pkt->pkt_resid = 0;
		break;

	case MFI_STAT_LD_OFFLINE:
	case MFI_STAT_DEVICE_NOT_FOUND:
		pkt->pkt_reason = CMD_DEV_GONE;
		break;

	default:
		pkt->pkt_reason = CMD_TRAN_ERR;
                break;
        }

	pkt->pkt_comp(pkt);
}

static void
mfii_start(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	u_long *r = (u_long *)&ccb->ccb_req;
 
	ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_requests),
	    ccb->ccb_request_offset, MFII_REQUEST_SIZE,
	    DDI_DMA_SYNC_FORDEV);

#if defined(__LP64__)
	ddi_put64(sc->sc_iqp_space, (uint64_t *)sc->sc_iqp, *r);
#else
	mutex_enter(&sc->sc_iqp_mutex);
	ddi_put32(sc->sc_iqp_space, 0, r[0]);
	ddi_put32(sc->sc_iqp_space, MFI_IQPH - MFI_IQPH, r[1]);
	mutex_leave(&sc->sc_iqp_mtx);
#endif
}

int
mfii_ccbs_ctor(struct mfii_softc *sc)
{
	struct mfii_ccb *ccb;
	uint8_t *request = MFII_DMA_KVA(sc->sc_requests);
	struct mfi_sense *sense = MFII_DMA_KVA(sc->sc_sense);
	uint8_t *sgl = MFII_DMA_KVA(sc->sc_sgl);
	uint_t i;

	sc->sc_ccbs = kmem_zalloc(sc->sc_max_cmds * sizeof(*ccb), KM_SLEEP);

	for (i = 0; i < sc->sc_max_cmds; i++) {
		ccb = &sc->sc_ccbs[i];

		/* select i + 1'th request. 0 is reserved for events */
		ccb->ccb_smid = i + 1;
		ccb->ccb_request_offset = MFII_REQUEST_SIZE * (i + 1);
		ccb->ccb_request = request + ccb->ccb_request_offset;
		ccb->ccb_request_dva = MFII_DMA_DVA(sc->sc_requests) +
		    ccb->ccb_request_offset;

		/* select i'th sense */
		ccb->ccb_sense_offset = sizeof(*ccb->ccb_sense) * i;
		ccb->ccb_sense = &sense[i];
		ccb->ccb_sense_dva = (uint32_t)(MFII_DMA_DVA(sc->sc_sense) +
		    ccb->ccb_sense_offset);

		/* select i'th sgl */
		ccb->ccb_sgl_offset = sizeof(struct mfii_sge) *
		    sc->sc_max_sgl * i;
		ccb->ccb_sgl = (struct mfii_sge *)(sgl + ccb->ccb_sgl_offset);
		ccb->ccb_sgl_dva = MFII_DMA_DVA(sc->sc_sgl) +
		    ccb->ccb_sgl_offset;

		/* add ccb to queue */
		mfii_ccb_put(sc, ccb);
	}

	return (DDI_SUCCESS);
}

static void
mfii_ccbs_dtor(struct mfii_softc *sc)
{
	struct mfii_ccb *ccb;

	kmem_free(sc->sc_ccbs, sc->sc_max_cmds * sizeof(*ccb));
}

static struct mfii_ccb *
mfii_ccb_get(struct mfii_softc *sc)
{
	struct mfii_ccb *ccb;

	mutex_enter(&sc->sc_ccb_mtx);
	ccb = SIMPLEQ_FIRST(&sc->sc_ccb_list);
	if (ccb != NULL)
		SIMPLEQ_REMOVE_HEAD(&sc->sc_ccb_list, ccb_entry);
	mutex_exit(&sc->sc_ccb_mtx);

	return (ccb);
}

static void
mfii_ccb_put(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	mutex_enter(&sc->sc_ccb_mtx);
	SIMPLEQ_INSERT_HEAD(&sc->sc_ccb_list, ccb, ccb_entry);
	mutex_exit(&sc->sc_ccb_mtx);
}

static struct mfii_dmamem *
mfii_dmamem_alloc(struct mfii_softc *sc, ddi_dma_attr_t *attr,
    size_t n, size_t e, uint_t flags)
{
	struct mfii_dmamem *mdm;
	size_t len;
	uint_t ncookies;

	mdm = kmem_zalloc(sizeof(*mdm), KM_SLEEP);
	len = n * e; /* XXX check for overflow */

	if (ddi_dma_alloc_handle(sc->sc_dev, attr, DDI_DMA_SLEEP, NULL,
	    &mdm->mdm_dma_handle) != DDI_SUCCESS)
		goto err;

	if (ddi_dma_mem_alloc(mdm->mdm_dma_handle, len, &mfii_mem_attr, flags,
	    DDI_DMA_SLEEP, NULL, &mdm->mdm_kva, &mdm->mdm_rlen,
	    &mdm->mdm_mem_handle) != DDI_SUCCESS)
		goto free_dma;

	if (ddi_dma_addr_bind_handle(mdm->mdm_dma_handle, NULL,
	    mdm->mdm_kva, len, flags, DDI_DMA_SLEEP, NULL,
	    &mdm->mdm_dma_cookie, &ncookies) != DDI_DMA_MAPPED)
		goto free_mem;

	if (ncookies != 1)
		goto unbind_handle;

	mdm->mdm_len = len;

	return (mdm);

unbind_handle:
	ddi_dma_unbind_handle(mdm->mdm_dma_handle);
free_mem:
	ddi_dma_mem_free(&mdm->mdm_mem_handle);
free_dma:
	ddi_dma_free_handle(&mdm->mdm_dma_handle);
err:
	kmem_free(mdm, sizeof(*mdm));
	return (NULL);
}

static void
mfii_dmamem_free(struct mfii_softc *sc, struct mfii_dmamem *mdm)
{
	ddi_dma_unbind_handle(mdm->mdm_dma_handle);
	ddi_dma_mem_free(&mdm->mdm_mem_handle);
	ddi_dma_free_handle(&mdm->mdm_dma_handle);
	kmem_free(mdm, sizeof(*mdm));
}
