/* $Id$ */

/*
 * Copyright (c) 2016, 2017 The University of Queensland
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
#include <sys/ksynch.h>
#include <sys/queue.h>
#include <sys/atomic.h>

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

struct refcnt {
	unsigned int		refs;
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
struct mfii_ccb_sleep;

struct mfii_ccb {
	void			*ccb_request;
	uint64_t		ccb_request_dva;
	off_t			ccb_request_offset;

	struct mfi_sense	*ccb_sense;
	uint64_t		ccb_sense_dva;
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

struct mfii_pd_tgt {
	struct refcnt		ptgt_refcnt;
	TAILQ_ENTRY(mfii_pd_tgt)
				ptgt_entry;

	uint64_t		ptgt_wwn;

	uint16_t		ptgt_id;
	uint16_t		ptgt_handle;
};

struct mfii_pd_lu {
	struct mfii_pd_tgt	*plu_tgt;
	uint64_t		plu_lun;
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
	kmutex_t		sc_mfa_mtx;

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
	TAILQ_HEAD(, mfii_ccb_sleep)
				sc_ccb_sleepers;

	scsi_hba_tran_t		*sc_tran;

	scsi_hba_tgtmap_t	*sc_ld_map;
	scsi_hba_tgtmap_t	*sc_pd_map;

	ddi_soft_state_bystr	*sc_ptgt_lus;
	kmutex_t		sc_ptgt_mtx;
	TAILQ_HEAD(, mfii_pd_tgt)
				sc_ptgt_list;

	ddi_taskq_t		*sc_taskq;

	struct mfii_ccb		*sc_aen_ccb;

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

static int		mfii_aen_register(struct mfii_softc *);
static void		mfii_aen_start(struct mfii_softc *,
			    struct mfii_ccb *, struct mfii_dmamem *, uint32_t);
static void		mfii_aen_done(struct mfii_softc *,
			    struct mfii_ccb *);
static void		mfii_aen_task(void *);
static void		mfii_aen_pd_inserted(struct mfii_softc *,
			    struct mfii_ccb *ccb,
			    const struct mfi_evtarg_pd_address *);
static void		mfii_aen_pd_removed(struct mfii_softc *,
			    struct mfii_ccb *ccb,
			    const struct mfi_evtarg_pd_address *);

static int		mfii_pci_cfg(struct mfii_softc *);
static int		mfii_fw_transition(struct mfii_softc *);
static int		mfii_fw_init(struct mfii_softc *);
static int		mfii_fw_info(struct mfii_softc *);

static int		mfii_ccbs_ctor(struct mfii_softc *);
static struct mfii_ccb *
			mfii_ccb_get(struct mfii_softc *, int);
static void
			mfii_ccb_put(struct mfii_softc *, struct mfii_ccb *);
static void		mfii_ccbs_dtor(struct mfii_softc *);

static void		mfii_start(struct mfii_softc *, struct mfii_ccb *);
static int		mfii_dcmd(struct mfii_softc *, struct mfii_ccb *,
			    uint32_t, const union mfi_mbox *,
			    struct mfii_dmamem *);
static int		mfii_mfa_poll(struct mfii_softc *, struct mfii_ccb *);

static void		mfii_dcmd_start(struct mfii_softc *,
			    struct mfii_ccb *);

static int		mfii_hba_attach(struct mfii_softc *);
static void		mfii_hba_detach(struct mfii_softc *);

static int		mfii_ld_probe(struct mfii_softc *);
static int		mfii_pd_probe(struct mfii_softc *);

static int		mfii_iport_attach(dev_info_t *, ddi_attach_cmd_t);
static int		mfii_iport_detach(dev_info_t *, ddi_detach_cmd_t);

static void		mfii_tgtmap_activate_cb(void *, char *,
			    scsi_tgtmap_tgt_type_t, void **);
static boolean_t	mfii_tgtmap_deactivate_cb(void *, char *,
			    scsi_tgtmap_tgt_type_t, void *,
			    scsi_tgtmap_deact_rsn_t);

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
static void		mfii_pd_tran_tgt_free(dev_info_t *, dev_info_t *,
			    scsi_hba_tran_t *, struct scsi_device *);
static int		mfii_pd_tran_start(struct scsi_address *,
			    struct scsi_pkt *);
static int		mfii_pd_tran_getcap(struct scsi_address *, char *, int);

static void		mfii_tran_done(struct mfii_softc *, struct mfii_ccb *);

static void		mfii_pd_tgt_add(struct mfii_softc *,
			    struct mfii_ccb *, uint16_t, const uint64_t *);
static int		mfii_pd_tgt_insert(struct mfii_softc *, uint64_t,
			    uint16_t, uint16_t);
static void		mfii_pd_tgt_rele(struct mfii_pd_tgt *);
static struct mfii_pd_tgt *
			mfii_pd_tgt_lookup(struct mfii_softc *, const char *);
static int		mfii_pd_detail(struct mfii_softc *,
			    struct mfii_ccb *, uint16_t);
static uint16_t		mfii_pd_dev_handle(struct mfii_softc *,
			    struct mfii_ccb *, uint16_t);

static inline void
refcnt_init(struct refcnt *r)
{
	r->refs = 1;
}

static inline void
refcnt_take(struct refcnt *r)
{
	atomic_inc_uint(&r->refs);
}

static inline int
refcnt_rele(struct refcnt *r)
{
	return (atomic_dec_uint_nv(&r->refs) == 0);
}

static inline void
mfii_dcmd_zero(struct mfii_ccb *ccb)
{
	memset(ccb->ccb_sense, 0, sizeof(*ccb->ccb_sense));
}

static inline struct mfi_dcmd_frame *
mfii_dcmd_frame(struct mfii_ccb *ccb)
{
	return ((struct mfi_dcmd_frame *)ccb->ccb_sense);
}

static inline void
mfii_dcmd_sync(struct mfii_softc *sc, struct mfii_ccb *ccb, uint_t type)
{
	ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_sense),
	    ccb->ccb_sense_offset, sizeof(*ccb->ccb_sense),
	    DDI_DMA_SYNC_FORKERNEL);
}

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

	SIMPLEQ_INIT(&sc->sc_ccb_list);
	TAILQ_INIT(&sc->sc_ptgt_list);
	TAILQ_INIT(&sc->sc_ccb_sleepers);
	if (ddi_soft_state_bystr_init(&sc->sc_ptgt_lus,
	    sizeof(struct mfii_pd_lu), 16) != 0)
		goto free_sc;

	if (mfii_pci_cfg(sc) != DDI_SUCCESS) {
		/* error printed by mfii_pci_cfg */
		goto free_lu;
	}

	if (ddi_regs_map_setup(dip, 2, &sc->sc_reg_baseaddr, 0, 0,
	    &mfii_reg_attr, &sc->sc_reg_space) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to map register space");
		goto free_lu;
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
	mutex_init(&sc->sc_mfa_mtx, NULL, MUTEX_DRIVER,
	    sc->sc_iblock_cookie);
	mutex_init(&sc->sc_ccb_mtx, NULL, MUTEX_DRIVER,
	    sc->sc_iblock_cookie);
	mutex_init(&sc->sc_ptgt_mtx, NULL, MUTEX_DRIVER,
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

	sc->sc_taskq = ddi_taskq_create(sc->sc_dev, "mfiitq", 1,
	    TASKQ_DEFAULTPRI, 0);
	if (sc->sc_taskq == NULL) {
		cmn_err(CE_NOTE, "unable to create taskq");
		goto ccb_dtor;
	}

	if (ddi_add_intr(sc->sc_dev, 0, &sc->sc_iblock_cookie, NULL,
	    mfii_intr, (caddr_t)sc) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "unable to establish interrupt");
		goto taskq_dtor;
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

	if (scsi_hba_iport_register(dip, "v0") != DDI_SUCCESS)
		goto del_intr;
	if (scsi_hba_iport_register(dip, "p0") != DDI_SUCCESS)
		goto del_intr;

	if (mfii_hba_attach(sc) != DDI_SUCCESS)
		goto del_intr;

	if (mfii_aen_register(sc) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "unable to registers aen");
		goto hba_detach;
	}

	return (DDI_SUCCESS);
hba_detach:
	mfii_hba_detach(sc);
del_intr:
	ddi_remove_intr(sc->sc_dev, 0, sc->sc_iblock_cookie);
taskq_dtor:
	ddi_taskq_destroy(sc->sc_taskq);
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
	mutex_destroy(&sc->sc_ptgt_mtx);
	mutex_destroy(&sc->sc_ccb_mtx);
	mutex_destroy(&sc->sc_mfa_mtx);
	mutex_destroy(&sc->sc_iqp_mtx);
free_iqp:
	ddi_regs_map_free(&sc->sc_iqp_space);
free_regs:
	ddi_regs_map_free(&sc->sc_reg_space);
free_lu:
	ddi_soft_state_bystr_fini(&sc->sc_ptgt_lus);
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
		return (mfii_iport_detach(dip, cmd));

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
	ddi_taskq_destroy(sc->sc_taskq);
	ddi_remove_intr(sc->sc_dev, 0, sc->sc_iblock_cookie);
	mfii_ccbs_dtor(sc);
	mfii_dmamem_free(sc, sc->sc_sgl);
	mfii_dmamem_free(sc, sc->sc_requests);
	mfii_dmamem_free(sc, sc->sc_reply_postq);
	mfii_dmamem_free(sc, sc->sc_sense);
	mutex_destroy(&sc->sc_ptgt_mtx);
	mutex_destroy(&sc->sc_ccb_mtx);
	mutex_destroy(&sc->sc_mfa_mtx);
	mutex_destroy(&sc->sc_iqp_mtx);
	ddi_regs_map_free(&sc->sc_iqp_space);
	ddi_regs_map_free(&sc->sc_reg_space);
	ddi_soft_state_bystr_fini(&sc->sc_ptgt_lus);
	ddi_soft_state_free(mfii_softc_p, instance);

	return (DDI_SUCCESS);
}

static int
mfii_aen_register(struct mfii_softc *sc)
{
	struct mfii_dmamem *m; /* use this for the counters and event data */
	struct mfi_evt_log_info *mel;
	struct mfii_ccb *ccb;
	uint32_t seq;
	int rv;

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1, sizeof(*mel),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	if (m == NULL)
		return (DDI_FAILURE);
	ccb = mfii_ccb_get(sc, KM_SLEEP);

	memset(MFII_DMA_KVA(m), 0, MFII_DMA_LEN(m));

	rv = mfii_dcmd(sc, ccb, MR_DCMD_CTRL_EVENT_GET_INFO, NULL, m);
	if (rv != DDI_SUCCESS)
		goto freem;

	mel = MFII_DMA_KVA(m);
	seq = LE_32(mel->mel_boot_seq_num);
	mfii_dmamem_free(sc, m);

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1,
	    sizeof(struct mfi_evt_detail), DDI_DMA_READ | DDI_DMA_CONSISTENT);
	if (m == NULL)
		goto freeccb;

	sc->sc_aen_ccb = ccb;
	mfii_aen_start(sc, ccb, m, seq);

	return (DDI_SUCCESS);
freem:
	mfii_dmamem_free(sc, m);
freeccb:
	mfii_ccb_put(sc, ccb);
	return (DDI_FAILURE);
}

static void
mfii_aen_start(struct mfii_softc *sc, struct mfii_ccb *ccb,
    struct mfii_dmamem *m, uint32_t seq)
{
	struct mfi_dcmd_frame *dcmd = mfii_dcmd_frame(ccb);
	struct mfi_frame_header *hdr = &dcmd->mdf_header;
	union mfi_sgl *sgl = &dcmd->mdf_sgl;
	union mfi_evt_class_locale mec;

	mfii_dcmd_zero(ccb);
	memset(MFII_DMA_KVA(m), 0, MFII_DMA_LEN(m));

	ccb->ccb_cookie = m;
	ccb->ccb_done = mfii_aen_done;

	mec.mec_members.class = MFI_EVT_CLASS_DEBUG;
	mec.mec_members.reserved = 0;
	mec.mec_members.locale = LE_16(MFI_EVT_LOCALE_ALL);

	hdr->mfh_cmd = MFI_CMD_DCMD;
	hdr->mfh_sg_count = 1;
	hdr->mfh_flags = LE_16(MFI_FRAME_DIR_READ);
	hdr->mfh_data_len = LE_32(MFII_DMA_LEN(m));
	hdr->mfh_flags = LE_16(MFI_FRAME_SGL64);
	dcmd->mdf_opcode = LE_32(MR_DCMD_CTRL_EVENT_WAIT);
	dcmd->mdf_mbox.w[0] = LE_32(seq);
	dcmd->mdf_mbox.w[1] = LE_32(mec.mec_word);
	sgl->sg64[0].addr = LE_64(MFII_DMA_DVA(m));
	sgl->sg64[0].len = LE_32(MFII_DMA_LEN(m));

	mfii_dcmd_sync(sc, ccb, DDI_DMA_SYNC_FORDEV);
	mfii_dcmd_start(sc, ccb);
}

static void
mfii_aen_done(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	(void)ddi_taskq_dispatch(sc->sc_taskq, mfii_aen_task, sc, DDI_SLEEP);
}

static void
mfii_aen_task(void *xsc)
{
	struct mfii_softc *sc = xsc;
	struct mfii_ccb *ccb = sc->sc_aen_ccb;
	struct mfii_dmamem *m = ccb->ccb_cookie;
	const struct mfi_evt_detail *med = MFII_DMA_KVA(m);
	uint32_t seq;

	mfii_dcmd_sync(sc, ccb, DDI_DMA_SYNC_FORKERNEL);
	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORKERNEL);

	seq = LE_32(med->med_seq_num);
	dev_err(sc->sc_dev, CE_NOTE, "%s", med->med_description);

	switch (LE_32(med->med_code)) {
	case MFI_EVT_PD_INSERTED_EXT:
		if (med->med_arg_type != MFI_EVT_ARGS_PD_ADDRESS)
			break;

		mfii_aen_pd_inserted(sc, ccb, &med->args.pd_address);
		break;
	case MFI_EVT_PD_REMOVED_EXT:
		if (med->med_arg_type != MFI_EVT_ARGS_PD_ADDRESS)
			break;

		mfii_aen_pd_removed(sc, ccb, &med->args.pd_address);
		break;

	default:
		break;
	}

	mfii_aen_start(sc, ccb, m, seq + 1);
}

static void
mfii_aen_pd_inserted(struct mfii_softc *sc, struct mfii_ccb *ccb,
    const struct mfi_evtarg_pd_address *pd)
{
	mfii_pd_tgt_add(sc, ccb, pd->device_id, pd->sas_addr);
}

static void
mfii_aen_pd_removed(struct mfii_softc *sc, struct mfii_ccb *ccb,
    const struct mfi_evtarg_pd_address *pd)
{
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
		memset(rdp, 0xff, sizeof(*rdp));

		ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_requests),
		    ccb->ccb_request_offset, MFII_REQUEST_SIZE,
		    DDI_DMA_SYNC_FORKERNEL);
		ccb->ccb_done(sc, ccb);

		if (++sc->sc_reply_postq_index >= sc->sc_reply_postq_depth)
			sc->sc_reply_postq_index = 0;
		rpi = 1;
	}

	if (rpi)
		mfii_write(sc, MFII_RPI, sc->sc_reply_postq_index);

	return (DDI_INTR_CLAIMED);
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

	ccb = mfii_ccb_get(sc, KM_SLEEP);
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
	ccb = mfii_ccb_get(sc, KM_SLEEP);
	VERIFY(ccb != NULL);

	rv = mfii_dcmd(sc, ccb, MR_DCMD_CTRL_GET_INFO, NULL, m);
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
mfii_ld_probe(struct mfii_softc *sc)
{
	struct mfii_dmamem *m;
	struct mfii_ccb *ccb;
	struct mfi_ld_list *l;
	char name[SCSI_MAXNAMELEN];
	int i, n;
	int rv;

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1, sizeof(*l),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	ccb = mfii_ccb_get(sc, KM_SLEEP);
	VERIFY(ccb != NULL);

	rv = mfii_dcmd(sc, ccb, MR_DCMD_LD_GET_LIST, NULL, m);
	if (rv != DDI_SUCCESS)
		goto done;

	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORKERNEL);
	l = MFII_DMA_KVA(m);

	n = LE_32(l->mll_no_ld);
	for (i = 0; i < n; i++) {
		snprintf(name, sizeof(name), "%x",
		    l->mll_list[i].mll_ld.mld_target);
		if (scsi_hba_tgtmap_tgt_add(sc->sc_ld_map,
		    SCSI_TGT_SCSI_DEVICE, name, NULL) != DDI_SUCCESS) {
			dev_err(sc->sc_dev, CE_WARN,
			    "failed to add %s on v0", name);
		}
	}

done:
	mfii_ccb_put(sc, ccb);
	mfii_dmamem_free(sc, m);

	return (rv);
}

static uint16_t
mfii_pd_dev_handle(struct mfii_softc *sc, struct mfii_ccb *ccb, uint16_t tgt)
{
	struct mfii_dmamem *m;
	struct mfii_ld_map *ldm;
	uint16_t handle = LE_16(0xffff);;
	int rv;

	tgt = LE_16(tgt);
	if (tgt >= MFI_MAX_PD)
		return handle;

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1, sizeof(*ldm),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);

	rv = mfii_dcmd(sc, ccb, MR_DCMD_LD_MAP_GET_INFO, NULL, m);
	if (rv != DDI_SUCCESS)
		goto done;

	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORKERNEL);
	ldm = MFII_DMA_KVA(m);
	handle = ldm->mlm_dev_handle[tgt].mdh_cur_handle;

done:
	mfii_dmamem_free(sc, m);

	return (handle);
}

static int
mfii_pd_detail(struct mfii_softc *sc, struct mfii_ccb *ccb, uint16_t tgt)
{
	struct mfii_dmamem *m;
	struct mfi_pd_details *pd;
	union mfi_mbox mbox;
	int rv;

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1, sizeof(*pd),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);

	memset(&mbox, 0, sizeof(mbox));
	mbox.s[0] = LE_16(tgt);

	rv = mfii_dcmd(sc, ccb, MR_DCMD_PD_GET_INFO, &mbox, m);
	if (rv != DDI_SUCCESS)
		goto done;

	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORKERNEL);
	pd = MFII_DMA_KVA(m);

	if (pd->mpd_fw_state != LE_16(MFI_PD_SYSTEM)) {
		rv = DDI_FAILURE;
		goto done;
	}

done:
	mfii_dmamem_free(sc, m);
	return (rv);
}

static int
mfii_pd_probe(struct mfii_softc *sc)
{
	struct mfii_dmamem *m;
	struct mfi_pd_list *pdl;
	struct mfii_ccb *ccb;
	int i, n;
	int rv;

	m = mfii_dmamem_alloc(sc, &mfii_cmd_attr, 1, sizeof(*pdl),
	    DDI_DMA_READ | DDI_DMA_CONSISTENT);
	ccb = mfii_ccb_get(sc, KM_SLEEP);
	VERIFY(ccb != NULL);

	rv = mfii_dcmd(sc, ccb, MR_DCMD_PD_GET_LIST, NULL, m);
	if (rv != DDI_SUCCESS)
		goto done;

	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORKERNEL);
	pdl = MFII_DMA_KVA(m);

	n = LE_32(pdl->mpl_no_pd);
	for (i = 0; i < n; i++) {
		struct mfi_pd_address *mpa = &pdl->mpl_address[i];

		mfii_pd_tgt_add(sc, ccb, mpa->mpa_pd_id, mpa->mpa_sas_address);
	}

done:
	mfii_ccb_put(sc, ccb);
	mfii_dmamem_free(sc, m);

	return (rv);
}

static void
mfii_pd_tgt_add(struct mfii_softc *sc, struct mfii_ccb *ccb,
    uint16_t target, const uint64_t *sas_addrs)
{
	uint64_t wwpn;
	scsi_hba_tgtmap_t *map;
	char name[SCSI_MAXNAMELEN];
	uint16_t handle;

	map = sc->sc_pd_map;
	if (map == NULL)
		return;

	wwpn = LE_64(sas_addrs[0]);
	if (wwpn == 0) {
		wwpn = LE_64(sas_addrs[1]);
		if (wwpn == 0)
			return;
	}

	if (mfii_pd_detail(sc, ccb, target) != DDI_SUCCESS)
		return;

	handle = mfii_pd_dev_handle(sc, ccb, target);
	if (handle == LE_16(0xffff))
		return;

	scsi_wwn_to_wwnstr(wwpn, 1, name);

	if (mfii_pd_tgt_insert(sc, wwpn, target, handle) != DDI_SUCCESS)
		return;

	(void)scsi_hba_tgtmap_tgt_add(map, SCSI_TGT_SCSI_DEVICE, name, NULL);
}

static int
mfii_dcmd(struct mfii_softc *sc, struct mfii_ccb *ccb, uint32_t opc,
    const union mfi_mbox *mbox, struct mfii_dmamem *m)
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
	if (mbox != NULL)
		memcpy(&dcmd->mdf_mbox, mbox, sizeof(dcmd->mdf_mbox));

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

	mutex_enter(&sc->sc_mfa_mtx);
	mfii_start(sc, ccb);

	for (;;) {
		ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_requests),
		    ccb->ccb_request_offset, MFII_REQUEST_SIZE,
		    DDI_DMA_SYNC_FORKERNEL);

		if (hdr->mfh_cmd_status != 0xff)
			break;

		if (to++ > 5000) { /* XXX 5 seconds busywait sucks */
			dev_err(sc->sc_dev, CE_WARN, "timeout on ccb %u (%x)",
			    ccb->ccb_smid, hdr->mfh_cmd);
			rv = DDI_FAILURE;
			break;
		}

		delay(drv_usectohz(1000));
	}
	mutex_exit(&sc->sc_mfa_mtx);

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

	flags = SCSI_HBA_HBA | SCSI_HBA_TRAN_CDB | SCSI_HBA_TRAN_SCB;

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
	scsi_hba_tgtmap_t **map;
	int (*probe)(struct mfii_softc *) = NULL;

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
		map = &sc->sc_ld_map;
		tran->tran_tgt_init = mfii_ld_tran_tgt_init;
		tran->tran_start = mfii_ld_tran_start;

		probe = mfii_ld_probe;
	} else if (strcmp(addr, "p0") == 0) {
		map = &sc->sc_pd_map;
		tran->tran_tgt_init = mfii_pd_tran_tgt_init;
		tran->tran_tgt_free = mfii_pd_tran_tgt_free;
		tran->tran_getcap = mfii_pd_tran_getcap;
		tran->tran_start = mfii_pd_tran_start;
		tran->tran_interconnect_type = INTERCONNECT_SAS;
		/* XXX not sure if this is kosher */
		tran->tran_hba_flags |= SCSI_HBA_ADDR_COMPLEX;

		probe = mfii_pd_probe;
	} else
		return (DDI_FAILURE);

	if (scsi_hba_tgtmap_create(iport_dip, SCSI_TM_PERADDR,
	    MICROSEC, MICROSEC * 2, sc,
	    mfii_tgtmap_activate_cb, mfii_tgtmap_deactivate_cb,
	    map) != DDI_SUCCESS)
		return (DDI_FAILURE);

	tran->tran_hba_private = sc;

	if ((*probe)(sc) != DDI_SUCCESS)
		goto destroy;

	return (DDI_SUCCESS);

destroy:
	scsi_hba_tgtmap_destroy(*map);
	return (DDI_FAILURE);
}

static int
mfii_iport_detach(dev_info_t *iport_dip, ddi_detach_cmd_t cmd)
{
	struct mfii_softc *sc;
	scsi_hba_tran_t *tran;
	scsi_hba_tgtmap_t *map;
	const char *addr;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	addr = scsi_hba_iport_unit_address(iport_dip);
	VERIFY(addr != NULL);

	tran = ddi_get_driver_private(iport_dip);
	sc = tran->tran_hba_private;

	if (strcmp(addr, "v0") == 0)
		map = sc->sc_ld_map;
	else if (strcmp(addr, "p0") == 0)
		map = sc->sc_pd_map;
	else
		return (DDI_FAILURE);

	scsi_hba_tgtmap_destroy(map);

	return (DDI_SUCCESS);
}

static void
mfii_tgtmap_activate_cb(void *tgtmap_priv, char *tgt_addr,
    scsi_tgtmap_tgt_type_t tgt_type, void **tgt_privp)
{
}

static boolean_t
mfii_tgtmap_deactivate_cb(void *tgtmap_priv, char *tgt_addr,
    scsi_tgtmap_tgt_type_t tgt_type, void *tgt_priv,
    scsi_tgtmap_deact_rsn_t tgt_deact_rsn)
{
	return (B_TRUE);
}

static int
mfii_tran_tgt_init(dev_info_t *dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	/* we only attach on iports */
	return (DDI_FAILURE);
}

static int
mfii_hexdigit(int ch)
{
	if (ch >= '0' && ch <= '9')
		return (ch - '0');
	if (ch >= 'a' && ch <= 'f')
		return (10 + (ch - 'a'));
	return (-1);
}

static int
mfii_parse_ua(const char *ua, ushort_t *tgtp, uchar_t *lunp)
{
	int tgt = 0, lun = 0;
	const char *p = ua;
	int ch;

	/* we expect a ua to be in the form T,L */

	ch = mfii_hexdigit(*p++);
	if (ch == -1)
		return (DDI_FAILURE);

	for (;;) {
		tgt *= 0x10;
		tgt += ch;

		if (tgt >= 0x10000) /* USHRT_MAX */
			return (DDI_FAILURE);

		if (*p == ',')
			break;

		ch = mfii_hexdigit(*p++);
		if (ch == -1)
			return (DDI_FAILURE);
	}

	p++; /* move past the comma */
	ch = mfii_hexdigit(*p++);
	if (ch == -1)
		return (DDI_FAILURE);

	for (;;) {
		lun *= 0x10;
		lun += ch;

		if (lun >= 0x100) /* UCHAR_MAX */
			return (DDI_FAILURE);

		if (*p == '\0')
			break;

		ch = mfii_hexdigit(*p++);
		if (ch == -1)
			return (DDI_FAILURE);
	}

	*tgtp = tgt;
	*lunp = lun;

	return (DDI_SUCCESS);
}

int
mfii_ld_tran_tgt_init(dev_info_t *dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;
	const char *ua;
	ushort_t tgt;
	uchar_t lun;

	VERIFY(scsi_hba_iport_unit_address(dip) != NULL);

	ua = scsi_device_unit_address(sd);
	if (ua == NULL)
		return (DDI_FAILURE);

	if (mfii_parse_ua(ua, &tgt, &lun) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (tgt > sc->sc_info.mci_max_lds || lun != 0)
		return (DDI_FAILURE);

	sd->sd_address.a_target = tgt;
	sd->sd_address.a_lun = lun;

	return (DDI_SUCCESS);
}

static int
mfii_pd_tgt_insert(struct mfii_softc *sc, uint64_t wwpn,
    uint16_t pd_id, uint16_t pd_handle)
{
	struct mfii_pd_tgt *ptgt;
	struct mfii_pd_tgt *optgt;

	ptgt = kmem_zalloc(sizeof(*ptgt), KM_SLEEP);

	refcnt_init(&ptgt->ptgt_refcnt);
	ptgt->ptgt_wwn = wwpn;
	ptgt->ptgt_id = pd_id;
	ptgt->ptgt_handle = pd_handle;

	mutex_enter(&sc->sc_ptgt_mtx);
	TAILQ_FOREACH(optgt, &sc->sc_ptgt_list, ptgt_entry) {
		if (ptgt->ptgt_id == optgt->ptgt_id)
			break;
	}

	/* existing target wasnt found */
	if (optgt == NULL) {
		/* give ref to the list */
		TAILQ_INSERT_TAIL(&sc->sc_ptgt_list, ptgt, ptgt_entry);
	}
	mutex_exit(&sc->sc_ptgt_mtx);

	if (optgt != NULL) {
		kmem_free(ptgt, sizeof(*ptgt));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static inline struct mfii_pd_tgt *
mfii_pd_tgt_take(struct mfii_pd_tgt *ptgt)
{
	refcnt_take(&ptgt->ptgt_refcnt);
	return (ptgt);
}

static inline struct mfii_pd_tgt *
mfii_pd_tgt_lookup(struct mfii_softc *sc, const char *ua)
{
	char name[SCSI_MAXNAMELEN];
	struct mfii_pd_tgt *ptgt;

	mutex_enter(&sc->sc_ptgt_mtx);
	TAILQ_FOREACH(ptgt, &sc->sc_ptgt_list, ptgt_entry) {
		scsi_wwn_to_wwnstr(ptgt->ptgt_wwn, 1, name);
		if (memcmp(ua, name, strlen(name)) == 0) {
			mfii_pd_tgt_take(ptgt);
			break;
		}
	}
	mutex_exit(&sc->sc_ptgt_mtx);

	return (ptgt);
}

static void
mfii_pd_tgt_rele(struct mfii_pd_tgt *ptgt)
{
	if (refcnt_rele(&ptgt->ptgt_refcnt))
		kmem_free(ptgt, sizeof(*ptgt));
}

static int
mfii_pd_tran_tgt_init(dev_info_t *dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;
	struct mfii_pd_tgt *ptgt;
	struct mfii_pd_lu *plu;
	const char *ua;
	uint64_t lun;

	VERIFY(scsi_hba_iport_unit_address(dip) != NULL);

	ua = scsi_device_unit_address(sd);
	if (ua == NULL)
		return (DDI_FAILURE);

	lun = scsi_device_prop_get_int64(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_LUN64, SCSI_LUN64_ILLEGAL);
	if (lun == SCSI_LUN64_ILLEGAL)
		return (DDI_FAILURE);

	ptgt = mfii_pd_tgt_lookup(sc, ua);
	if (ptgt == NULL)
		return (DDI_FAILURE);

	if (ddi_soft_state_bystr_zalloc(sc->sc_ptgt_lus, ua) != DDI_SUCCESS)
		goto rele;

	plu = ddi_soft_state_bystr_get(sc->sc_ptgt_lus, ua);
	if (plu == NULL)
		goto rele;

	plu->plu_tgt = ptgt; /* give ref to plu */
	plu->plu_lun = lun;

	scsi_device_hba_private_set(sd, plu);

	return (DDI_SUCCESS);

rele:
	mfii_pd_tgt_rele(ptgt);
	return (DDI_FAILURE);
}

static void
mfii_pd_tran_tgt_free(dev_info_t *dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;
	struct mfii_pd_lu *plu;
	const char *ua;

	ua = scsi_device_unit_address(sd);
	plu = scsi_device_hba_private_get(sd);

	mfii_pd_tgt_rele(plu->plu_tgt);

	ddi_soft_state_bystr_free(sc->sc_ptgt_lus, ua);
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
	case SCSI_CAP_CDB_LEN:
		return (MPII_CDB_LEN);
	default:
		break;
	}

	return (-1);
}

static int
mfii_pd_tran_getcap(struct scsi_address *ap, char *cap, int whom)
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
	case SCSI_CAP_CDB_LEN:
		return (MPII_CDB_LEN);
	case SCSI_CAP_INTERCONNECT_TYPE:
		return (INTERCONNECT_SAS);
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
	int kmflags = callback == SLEEP_FUNC ? KM_SLEEP : KM_NOSLEEP;

	ccb = mfii_ccb_get(sc, kmflags);
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

	if (pkt->pkt_cdblen > MPII_CDB_LEN)
		return (TRAN_BADPKT);
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

	case SCMD_SYNCHRONIZE_CACHE:
		pkt->pkt_resid = 0;
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_scbp[0] = STATUS_GOOD;
		pkt->pkt_statistics = 0;
		pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA;

		pkt->pkt_comp(pkt);
		return (TRAN_ACCEPT);

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
	struct scsi_device *sd;
	struct mfii_softc *sc = (struct mfii_softc *)tran->tran_hba_private;
	struct mfii_pkt *mp = (struct mfii_pkt *)pkt->pkt_ha_private;
	struct mfii_ccb *ccb = mp->mp_ccb;
	struct mfii_pd_lu *plu;
	struct mfii_pd_tgt *ptgt;
	struct mpii_msg_scsi_io *io = ccb->ccb_request;
	struct mfii_raid_context *ctx = (struct mfii_raid_context *)(io + 1);
	size_t datalen;

	sd = scsi_address_device(ap);
	VERIFY(sd != NULL);
	plu = scsi_device_hba_private_get(sd);
	VERIFY(plu != NULL);
	ptgt = plu->plu_tgt;
	VERIFY(ptgt != NULL);

	if (pkt->pkt_cdblen > MPII_CDB_LEN)
		return (TRAN_BADPKT);
	if (pkt->pkt_numcookies > sc->sc_max_sgl)
		return (TRAN_BADPKT);

	memset(ccb->ccb_request, 0, MFII_REQUEST_SIZE);
	ccb->ccb_done = mfii_tran_done;

	datalen = mfii_sgl(sc, ccb, ctx + 1,
	    pkt->pkt_cookies, pkt->pkt_numcookies);

	io->dev_handle = ptgt->ptgt_handle;
	io->function = 0;
	io->sense_buffer_low_address = LE_32(ccb->ccb_sense_dva);
	io->sgl_flags = LE_16(MFI_FRAME_SGL64);
	io->sense_buffer_length = sizeof(*ccb->ccb_sense);
	io->sgl_offset0 = (sizeof(*io) + sizeof(*ctx)) / 4;
	io->data_length = LE_32(datalen);
	io->io_flags = LE_16(pkt->pkt_cdblen);
	memcpy(io->lun, &plu->plu_lun, sizeof(io->lun));
	memcpy(io->cdb, pkt->pkt_cdbp, pkt->pkt_cdblen);

	io->direction = MPII_SCSIIO_DIR_NONE;
	if (datalen > 0) {
		if (pkt->pkt_dma_flags & DDI_DMA_READ)
			io->direction = MPII_SCSIIO_DIR_READ;
		else if (pkt->pkt_dma_flags & DDI_DMA_WRITE)
			io->direction = MPII_SCSIIO_DIR_WRITE;
	}

	ctx->virtual_disk_target_id = ptgt->ptgt_id;
	ctx->raid_flags = MFII_RAID_CTX_IO_TYPE_SYSPD;
	ctx->timeout_value = LE_16(pkt->pkt_time);
	ctx->num_sge = pkt->pkt_numcookies;

	memset(&ccb->ccb_req, 0, sizeof(ccb->ccb_req));
	ccb->ccb_req.flags = MFII_REQ_TYPE_HI_PRI;
	ccb->ccb_req.smid = LE_16(ccb->ccb_smid);
	ccb->ccb_req.dev_handle = ptgt->ptgt_handle;

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
	struct scsi_arq_status *arq;

	switch (ctx->status) {
	case MFI_STAT_SCSI_DONE_WITH_ERROR:
		if (pkt->pkt_scblen >= sizeof(*arq)) {
			pkt->pkt_state |= STATE_GOT_STATUS | STATE_ARQ_DONE;

			arq = (struct scsi_arq_status *)pkt->pkt_scbp;
			arq->sts_rqpkt_reason = CMD_CMPLT;
			arq->sts_rqpkt_resid = 0;
			arq->sts_rqpkt_state = STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA;
			arq->sts_rqpkt_statistics = 0;

			memcpy(&arq->sts_sensedata, ccb->ccb_sense,
			    sizeof(arq->sts_sensedata));
		}

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

	case MFI_STAT_SCSI_IO_FAILED:
		pkt->pkt_reason = CMD_TRAN_ERR;
		break;

	default:
		dev_err(sc->sc_dev, CE_WARN, "%s: status 0x%x", __func__,
		    ctx->status);
		pkt->pkt_reason = CMD_TRAN_ERR;
		break;
	}

	pkt->pkt_comp(pkt);
}

static void
mfii_dcmd_start(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	struct mpii_msg_scsi_io *io = ccb->ccb_request;
	struct mfii_raid_context *ctx = (struct mfii_raid_context *)(io + 1);
	struct mfii_sge *sge = (struct mfii_sge *)(ctx + 1);

	memset(ccb->ccb_request, 0, MFII_REQUEST_SIZE);
	io->function = MFII_FUNCTION_PASSTHRU_IO;
	io->sgl_offset0 = (uint32_t *)sge - (uint32_t *)io;
	io->chain_offset = io->sgl_offset0 / 4;
	sge->sg_addr = LE_64(ccb->ccb_sense_dva);
	sge->sg_len = LE_32(sizeof(*ccb->ccb_sense));
	sge->sg_flags = MFII_SGE_CHAIN_ELEMENT | MFII_SGE_ADDR_IOCPLBNTA;

	memset(&ccb->ccb_req, 0, sizeof(ccb->ccb_req));
	ccb->ccb_req.flags = MFII_REQ_TYPE_SCSI;
	ccb->ccb_req.smid = LE_16(ccb->ccb_smid);

	mfii_start(sc, ccb);
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
	mutex_exit(&sc->sc_iqp_mtx);
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
		ccb->ccb_sense_dva = (MFII_DMA_DVA(sc->sc_sense) +
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

struct mfii_ccb_sleep {
	kcondvar_t			s_cv;
	struct mfii_ccb			*s_ccb;
	TAILQ_ENTRY(mfii_ccb_sleep)	s_entry;
};

static struct mfii_ccb *
mfii_ccb_get(struct mfii_softc *sc, int sleep)
{
	struct mfii_ccb *ccb;

	mutex_enter(&sc->sc_ccb_mtx);
	ccb = SIMPLEQ_FIRST(&sc->sc_ccb_list);
	if (ccb != NULL)
		SIMPLEQ_REMOVE_HEAD(&sc->sc_ccb_list, ccb_entry);
	else if (sleep == KM_SLEEP) {
		struct mfii_ccb_sleep s;

		cv_init(&s.s_cv, "mfiiccb", CV_DRIVER, NULL);
		s.s_ccb = NULL;

		TAILQ_INSERT_TAIL(&sc->sc_ccb_sleepers, &s, s_entry);

		do
			cv_wait(&s.s_cv, &sc->sc_ccb_mtx);
		while (s.s_ccb == NULL);

		cv_destroy(&s.s_cv);

		ccb = s.s_ccb;
	}
	mutex_exit(&sc->sc_ccb_mtx);

	return (ccb);
}

static void
mfii_ccb_put(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	struct mfii_ccb_sleep *s;

	mutex_enter(&sc->sc_ccb_mtx);
	s = TAILQ_FIRST(&sc->sc_ccb_sleepers);
	if (s != NULL) {
		TAILQ_REMOVE(&sc->sc_ccb_sleepers, s, s_entry);
		s->s_ccb = ccb;
		cv_signal(&s->s_cv);
	} else
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
