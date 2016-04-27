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
};
#define MFII_DMA_KVA(_mdm) ((void *)(_mdm)->mdm_kva)
#define MFII_DMA_DVA(_mdm) ((uint64_t)(_mdm)->mdm_mdm_dma_cookie.dmac_laddress)
#define MFII_DMA_HANDLE(_mdm) ((_mdm)->mdm_dma_handle);

static inline void
mfii_put8(struct mfii_dmamem *mdm, uint8_t *p, uint8_t v)
{
	ddi_put8(mdm->mdm_mem_handle, p, v);
}

static inline void
mfii_put16(struct mfii_dmamem *mdm, uint16_t *p, uint16_t v)
{
	ddi_put16(mdm->mdm_mem_handle, p, v);
}

static inline void
mfii_put32(struct mfii_dmamem *mdm, uint32_t *p, uint32_t v)
{
	ddi_put32(mdm->mdm_mem_handle, p, v);
}

static inline uint8_t
mfii_get8(struct mfii_dmamem *mdm, uint8_t *p)
{
	return ddi_get8(mdm->mdm_mem_handle, p);
}

static inline uint16_t
mfii_get16(struct mfii_dmamem *mdm, uint16_t *p)
{
	return ddi_get16(mdm->mdm_mem_handle, p);
}

static inline uint32_t
mfii_get32(struct mfii_dmamem *mdm, uint32_t *p)
{
	return ddi_get32(mdm->mdm_mem_handle, p);
}

struct mfii_softc;
struct mfii_pkt_data;

struct mfii_ccb {
	struct mfii_softc	*ccb_sc;
	struct mfii_pkt_data	*ccb_mpd;
	void			(*ccb_done)(struct mfii_ccb *);

	uint32_t		ccb_context;

	ddi_acc_handle_t	ccb_acc_handle;
	ddi_dma_handle_t	ccb_dma_handle;
#define MFI_CCB_CMDLEN			(MFI_FRAME_SIZE * MFI_FRAME_COUNT)
#define MFI_CCB_EXTRALEN		32 /* mostly for sense data */
#define MFI_CCB_BUFLEN			(MFI_CCB_CMDLEN + MFI_CCB_EXTRALEN)
	uint8_t			*ccb_cmd;
	uint64_t		ccb_cmd_dva;
	uint8_t			*ccb_extra;
	uint64_t		ccb_extra_dva;

	struct {
		uint64_t		sg_addr;
		size_t			sg_len;
	}			ccb_sgl[MFII_MAX_SGL_LEN];
	u_int			ccb_sgllen;
	u_int			ccb_datalen;

	int			ccb_extra_frames;

	SIMPLEQ_ENTRY(mfii_ccb)	ccb_entry;
};
SIMPLEQ_HEAD(mfii_ccb_list, mfii_ccb);

struct mfii_pkt_data {
	struct mfii_ccb		*mpd_ccb;
	struct scsi_pkt		*mpd_pkt;

	ddi_dma_handle_t	mpd_dma_handle;
	ddi_dma_cookie_t	mpd_cookies;
	uint_t			mpd_ncookies;
	uint_t			mpd_curcookie;
	uint_t			mpd_window;
	uint_t			mpd_datalen;

	int			mpd_dma_mapped;
	int			mpd_read;
	int			mpd_cdblen;
	int			mpd_senselen;
};

struct mfii_softc {
	dev_info_t		*sc_dev;
	ddi_iblock_cookie_t	sc_iblock_cookie;

	ddi_acc_handle_t	sc_reg_space;
	caddr_t			sc_reg_baseaddr;

	ddi_acc_handle_t	sc_iqp_space;
	u_long			*sc_iqp;
	kmutex_t		sc_iqp_mtx;

	uint_t			sc_max_cmds;
	uint_t			sc_max_sgl;

	uint_t			sc_reply_postq_depth;
	uint_t			sc_reply_postq_index;
	kmutex_t		sc_reply_postq_mtx;
	struct mfii_dmamem	*sc_reply_postq;

	struct mfii_dmamem	*sc_requests;
	struct mfii_dmamem	*sc_sense;
	struct mfii_dmamem	*sc_sgl;

	struct mfii_ccb		*sc_ccbs;
	struct mfii_ccb_list	sc_ccb_list;
	kmutex_t		sc_ccb_mtx;

	scsi_hba_tran_t		*sc_ld_tran;
	scsi_hba_tran_t		*sc_pd_tran;

	struct mfi_ctrl_info	sc_info;
};

static uint_t		mfii_intr(caddr_t);

#define mfii_read(_s, _r) ddi_get32((_s)->sc_reg_space, \
    (uint32_t *)((_s)->sc_reg_baseaddr + (_r)))
#define mfii_write(_s, _r, _v) ddi_put32((_s)->sc_reg_space, \
    (uint32_t *)((_s)->sc_reg_baseaddr + (_r)), (_v))

#define mfii_fw_state(_sc) mfii_read((_sc), MFI_OSP)

static mfii_dmamem	*mfii_dmamem_alloc(struct mfii_softc *,
			    ddi_dma_attr_t *, size_t, size_t, uint_t);
static void		mfii_dmamem_free(struct mfii_softc *,
			    struct mfii_dmamem *);

static int		mfii_pci_cfg(struct mfii_softc *);
static int		mfii_transition_firmware(struct mfi_softc *);
static int		mfii_init_firmware(struct mfi_softc *);

static int		mfi_alloc_pcq(struct mfi_softc *);
static void		mfi_free_pcq(struct mfi_softc *);

static int		mfi_alloc_ccbs(struct mfi_softc *);
static void		mfi_free_ccbs(struct mfi_softc *);
static struct mfi_ccb	*mfi_alloc_ccb(struct mfi_softc *);
static void		mfi_free_ccb(struct mfi_softc *, struct mfi_ccb *);
static struct mfi_ccb	*mfi_get_ccb(struct mfi_softc *);
static void		mfi_put_ccb(struct mfi_softc *, struct mfi_ccb *);

static int		mfi_alloc_cmdbuf(struct mfi_softc *, struct mfi_ccb *);
static void		mfi_free_cmdbuf(struct mfi_softc *, struct mfi_ccb *);

static void		mfi_post(struct mfi_softc *, struct mfi_ccb *);
static int		mfi_poll(struct mfi_softc *, struct mfi_ccb *, u_int);

static void		mfi_done(struct mfi_ccb *);


static int		mfi_dma_map(struct mfi_pkt_data *, struct buf *, int,
			    int	(*)(caddr_t));
static void		mfi_load_sgl(struct mfi_ccb *, struct mfi_sge32 *);
static void		mfi_start_io(struct mfi_softc *, struct scsi_address *,
			    struct mfi_pkt_data *);
static void		mfi_start_scsi(struct mfi_softc *,
			    struct scsi_address *, struct mfi_pkt_data *);
static void		mfi_done_tran(struct mfi_ccb *);

static int		mfi_hba_attach(struct mfi_softc *);
static void		mfi_hba_detach(struct mfi_softc *);

static int		mfi_tran_tgt_init(dev_info_t *, dev_info_t *,
			    scsi_hba_tran_t *, struct scsi_device *);
static int		mfi_tran_start(struct scsi_address *,
			    struct scsi_pkt *);
static int		mfi_tran_reset(struct scsi_address *, int);
static int		mfi_tran_getcap(struct scsi_address *, char *, int);
static int		mfi_tran_setcap(struct scsi_address *, char *,
			    int, int);
static struct scsi_pkt	*mfi_tran_init_pkt(struct scsi_address *,
			    struct scsi_pkt *, struct buf *, int, int, int,
			    int, int (*)(), caddr_t);
static void		mfi_tran_destroy_pkt(struct scsi_address *,
			    struct scsi_pkt *);
static void		mfi_tran_dmafree(struct scsi_address *,
			    struct scsi_pkt *);
static void		mfi_tran_sync_pkt(struct scsi_address *,
			    struct scsi_pkt *);

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

	error = scsi_hba_init(&ml);
	if (error != 0)
		goto state_fini;

	error = mod_install(&ml);
	if (error != 0)
		goto hba_fini;

	return (error);

hba_fini:
	scsi_hba_fini(&ml);
state_fini:
	ddi_soft_state_fini(mfi_softc_p);
err:
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int			error;

	error = mod_remove(&ml);
	if (error)
		return (error);

	scsi_hba_fini(&ml);

	ddi_soft_state_fini(&mfi_softc_p);

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

static int
mfii_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct mfii_softc *sc;
	int instance;

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
	sc->sc_io_dma_attr = io_dma_attr;

	if (mfii_pci_cfg(sc) != DDI_SUCCESS) {
		/* error printed by mfii_pci_cfg */
		goto free_sc;
	}

	if (ddi_regs_map_setup(dip, 1, &sc->sc_reg_baseaddr, 0, 0,
	    &mfii_acc_attr, &sc->sc_reg_space) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to map register space");
		goto free_sc;
	}

	/* get a different mapping for the iqp */
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&sc->sc_iqp,
	    MFI_IQPL, sizeof(struct mfii_request_descr),
	    &mfii_iqp_attr, &sc->sc_iqp_space) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to map register space");
		goto free_sc;
	}

	/* hook up interrupt */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		dev_err(dip, CE_WARN, "high level interrupt is not supported");
		goto free_sc;
	}

	if (ddi_get_iblock_cookie(dip, 0,
	    &sc->sc_iblock_cookie) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to get iblock cookie");
		goto free_sc;
	}

	mutex_init(&sc->sc_post_mutex, NULL, MUTEX_DRIVER,
	    sc->sc_iblock_cookie);
	mutex_init(&sc->sc_ccb_mutex, NULL, MUTEX_DRIVER,
	    sc->sc_iblock_cookie);

	/* disable interrupts */
	mfii_write(sc, MFI_OMSK, 0xffffffff);

	if (mfii_transition_firmware(sc) != DDI_SUCCESS) {
		/* error printed by mfi_transition_firmware */
		goto unmutex;
	}

	status = mfii_fw_state(sc);
	sc->sc_max_cmds = status & MFI_STATE_MAXCMD_MASK;
	sc->sc_max_sgl = (status & MFI_STATE_MAXSGL_MASK) >> 16;

	/* sense memory */
	sc->sc_sense = mfii_dmamem_alloc(sc, &mfii_sense_attr,
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

	if (mfii_ccb_init(sc) != 0) {
		dev_err(dip, CE_WARN, "unable to initialise control blocks");
		goto free_sgl;
	}

	/* kickstart firmware with all addresses and pointers */
	if (mfii_initialise_firmware(sc) != 0) {
		dev_err(dip, CE_WARN, "unable to initialise firmware");
		goto free_sgl;
	}

	if (mfii_get_info(sc) != 0) {
		dev_err(dip, CE_WARN,
		    "unable to retrieve controller information");
		goto free_sgl;
	}

	dev_err(dip, CE_NOTE, "\"%s\", firmware %s",
	    sc->sc_info.mci_product_name, sc->sc_info.mci_package_version);
	if (LE_16(sc->sc_info.mci_memory_size) > 0) {
		cmn_err(CE_CONT, %uMB cache",
		    LE_16(sc->sc_info.mci_memory_size));
	}

	if (ddi_add_intr(sc->sc_dev, 0, &sc->sc_iblock_cookie, NULL,
	    mfii_intr, (caddr_t)sc) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "unable to establish interrupt");
		goto free_sgl;
	}

	/* enable interrupts */
	mfii_write(sc, MFI_OSTS, 0xffffffff);
	mfii_write(sc, MFI_OMSK, ~MFII_OSTS_INTR_VALID);

	if (mfii_ld_attach(sc) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "unable to attach logical device bus");
		goto del_intr;
	}

	if (mfii_pd_attach(sc) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "unable to attach physical device bus");
		goto ld_detach
	}

	return (DDI_SUCCESS);

del_intr:
	ddi_remove_intr(sc->sc_dev, 0, sc->sc_iblock_cookie);
free_ccbs:
	mfi_free_ccbs(sc);
free_pcq:
	mfi_free_pcq(sc);
unmutex:
	mutex_destroy(&sc->sc_replyq_mutex);
	mutex_destroy(&sc->sc_post_mutex);
free_sc:
	ddi_soft_state_free(mfi_softc_p, instance);
err:
	return (DDI_FAILURE);
}

static int
mfi_detach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct mfi_softc	*sc;
	int			instance;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(mfi_softc_p, instance);

	mfi_hba_detach(sc);

	ddi_remove_intr(sc->sc_dev, 0, sc->sc_iblock_cookie);

	mfi_free_ccbs(sc);

	mfi_free_pcq(sc);

	mutex_destroy(&sc->sc_replyq_mutex);
	mutex_destroy(&sc->sc_post_mutex);

	ddi_regs_map_free(&sc->sc_reg_space);

	ddi_soft_state_free(mfi_softc_p, instance);

	return (DDI_SUCCESS);
}

static uint_t
mfi_intr(caddr_t arg)
{
	struct mfi_softc	*sc = (struct mfi_softc *)arg;
	struct mfi_ccb		*ccb;
	uint32_t		status, producer, consumer, context;
	uint_t			rv = DDI_INTR_UNCLAIMED;

	mutex_enter(&sc->sc_replyq_mutex);

	status = mfi_read(sc, MFI_OSTS);
	if (status & MFI_OSTS_INTR_VALID) {
		mfi_write(sc, MFI_OSTS, status);
		rv = DDI_INTR_CLAIMED;

		ddi_dma_sync(sc->sc_pcq_dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);
		producer = sc->sc_pc->producer;
		consumer = sc->sc_pc->consumer;

		while (consumer != producer) {
			context = sc->sc_replyq[consumer];
			sc->sc_replyq[consumer] = 0xffffffff;
			/* XXX check consumer is < ncmds */
			if (context != 0xffffffff) {
				ccb = &sc->sc_ccbs[context];
				ddi_dma_sync(ccb->ccb_dma_handle, 0, 0,
				    DDI_DMA_SYNC_FORCPU);
				ccb->ccb_done(ccb);
			}

			consumer++;
			consumer %= sc->sc_ncmds + 1;
		}

		sc->sc_pc->consumer = consumer;
		ddi_dma_sync(sc->sc_pcq_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);
	}

	mutex_exit(&sc->sc_replyq_mutex);

	return (rv);
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

	switch (pci_config_get32(pci_conf, PCI_CONF_VENID)) {
	case MFII_PCI_ID_2008:
		sc->sc_iop = &mfii_iop_thunderbolt;
		break;
	case MFII_PCI_ID_3008:
	case MFII_PCI_ID_3108:
		sc->sc_iop = &mfii_iop_25;
		break;
	default:
		cnm_err(CE_WARN, "unknown chip");
		error = DDI_FAILURE;
		goto fail:
	}

fail:
	pci_config_teardown(&pci_conf);
	return (rv);
}

static int
mfi_transition_firmware(struct mfi_softc *sc)
{
	int32_t                 fw_state, cur_state;
	int                     max_wait, i;

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
mfii_initialise_firmware(struct mfii_softc *sc)
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

	mfii_put8(m, &iiq->function, MPII_FUNCTION_IOC_INIT);
	mfii_put8(m, &iiq->whoinit, MPII_WHOINIT_HOST_DRIVER);

	/* magic! */
	mfii_put8(m, &iiq->msg_version_maj, 0x02);
	mfii_put8(m, &iiq->msg_version_min, 0x00);
	mfii_put8(m, &iiq->hdr_version_unit, 0x10);
	mfii_put8(m, &iiq->hdr_version_dev, 0x0);

	mfii_put16(m, &iiq->system_request_frame_size, MFII_REQUEST_SIZE / 4);

	mfii_put16(m, &iiq->reply_descriptor_post_queue_depth,
	    sc->sc_reply_postq_depth);
	mfii_put16(m, &iiq->reply_free_queue_depth, 0);

	mfii_put32(m, &iiq->sense_buffer_address_high, 
	    MFII_DMA_DVA(sc->sc_sense) >> 32);

	mfii_put32(m, &iiq->reply_descriptor_post_queue_address_lo,
	    MFII_DMA_DVA(sc->sc_reply_postq));
	mfii_put32(m, &iiq->reply_descriptor_post_queue_address_hi,
	    MFII_DMA_DVA(sc->sc_reply_postq) >> 32);

	mfii_put32(m, &iiq->system_request_frame_base_address_lo,
	    MFII_DMA_DVA(sc->sc_requests));
	mfii_put32(m, &iiq->system_request_frame_base_address_hi,
	    MFII_DMA_DVA(sc->sc_requests) >> 32);

	mfii_put64(m, iiq->timestamp, gethrtime() / 1000000);

	ccb = mfii_ccb_get(sc);
	VERIFY(ccb != NULL);
	mfii_ccb_scrub(ccb);
	init = ccb->ccb_request;

	mfii_put8(&sc->sc_requests, &init->mif_header.mfh_cmd, MFI_CMD_INIT);
	mfii_put32(&sc->sc_requests, &init->mif_header.mfh_data_len,
	    sizeof(*iiq));
	mfii_put64(&sc->sc_requests, &init->mif_qinfo_new_addr,
	    MFII_DMA_DVA(m));

	ddi_dma_sync(MFII_DMA_HANDLE(m), 0, 0, DDI_DMA_SYNC_FORDEV);

	rv = mfii_mfa_poll(sc, ccb);

	mfii_ccb_put(sc, ccb);
	mfii_dmamem_free(sc, m);

	return (rv);
}

int
mfii_mfa_poll(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	struct mfi_frame_header *hdr = ccb->ccb_request;
	uint64_t r;
	int to = 0;
	rv = DDI_SUCCESS;

	VERIFY(ccb->ccb_cookie != NULL);
	VERIFY(ccb->ccb_done != NULL);

	mfii_put8(sc->sc_requests, &hdr->mfh_context, ccb->ccb_smid);
	mfii_put8(sc->sc_requests, &hdr->mfh_cmd_status, 0xff);
	mfii_put16(sc->sc_requests, &hdr->mfh_flags,
	    mfii_get16(sc->sc_requests, &hdr->mfh_flags) |
	    MFI_FRAME_DONT_POST_IN_REPLY_QUEUE);

	r = MFII_REQ_MFA(ccb->ccb_request_dva);
	memcpy(&ccb->ccb_req, &r, sizeof(ccb->ccb_req));

	mfii_start(sc, ccb);

	for (;;) {
		ddi_dma_sync(MFII_DMA_HANDLE(sc->sc_requests),
		    ccb->ccb_request_offset, MFII_REQUEST_SIZE,
		    DDI_DMA_SYNC_FORKERNEL);

		if (ddi_get8(sc->sc_requests, &hdr->mfh_cmd_status) != 0xff)
			break;

		if (to++ > 5000) { /* XXX 5 seconds busywait sucks */
			cmn_err(CE_WARN, "timeout on ccb %u", ccb->ccb_smid);
			ccb->ccb_flags |= MFI_CCB_F_ERR;
			rv = DDI_FAILURE;
			break;
		}

		delay(drv_usectohz(1000));
	}

	return (rv);
}

static int
mfii_ld_attach(struct mfii_softc *sc)
{
	scsi_hba_tran_t			*tran;

	tran = scsi_hba_tran_alloc(sc->sc_dev, SCSI_HBA_CANSLEEP);
	if (tran == NULL)
		return (DDI_FAILURE);

	tran->tran_hba_private = sc;
	tran->tran_tgt_private = NULL;
	tran->tran_tgt_init = mfi_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;
	/* tran->tran_tgt_free */

	tran->tran_start = mfi_ld_tran_start;
	tran->tran_reset = mfi_tran_reset;
	tran->tran_getcap = mfi_tran_getcap;
	tran->tran_setcap = mfi_tran_setcap;
	tran->tran_init_pkt = mfi_tran_init_pkt;
	tran->tran_destroy_pkt = mfi_tran_destroy_pkt;
	tran->tran_dmafree = mfi_tran_dmafree;
	tran->tran_sync_pkt = mfi_tran_sync_pkt;

	tran->tran_abort = NULL;
	tran->tran_tgt_free = NULL;
	tran->tran_quiesce = NULL;
	tran->tran_unquiesce = NULL;
	tran->tran_sd = NULL;

	if (scsi_hba_attach_setup(sc->sc_dev, &mfii_io_attr, tran,
	    SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS)
		goto tran_free;

	sc->sc_ld_tran = tran;

	return (DDI_SUCCESS);

tran_free:
	scsi_hba_tran_free(tran);
err:
	return (DDI_FAILURE);
}

static void
mfii_ld_detach(struct mfii_softc *sc)
{
	scsi_hba_detach(sc->sc_ld_dev);
	scsi_hba_tran_free(sc->sc_ld_tran);
}

static int
mfii_pd_attach(struct mfii_softc *sc)
{
	scsi_hba_tran_t			*tran;

	tran = scsi_hba_tran_alloc(sc->sc_dev, SCSI_HBA_CANSLEEP);
	if (tran == NULL)
		return (DDI_FAILURE);

	tran->tran_hba_private = sc;
	tran->tran_tgt_private = NULL;
	tran->tran_tgt_init = mfii_pd_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;
	/* tran->tran_tgt_free */

	tran->tran_start = mfi_tran_start;
	tran->tran_reset = mfi_tran_reset;
	tran->tran_getcap = mfi_tran_getcap;
	tran->tran_setcap = mfi_tran_setcap;
	tran->tran_init_pkt = mfi_tran_init_pkt;
	tran->tran_destroy_pkt = mfi_tran_destroy_pkt;
	tran->tran_dmafree = mfi_tran_dmafree;
	tran->tran_sync_pkt = mfi_tran_sync_pkt;

	tran->tran_abort = NULL;
	tran->tran_tgt_free = NULL;
	tran->tran_quiesce = NULL;
	tran->tran_unquiesce = NULL;
	tran->tran_sd = NULL;

	if (scsi_hba_attach_setup(sc->sc_dev, &mfii_io_attr, tran,
	    SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS)
		goto tran_free;

	sc->sc_pd_tran = tran;

	return (DDI_SUCCESS);

tran_free:
	scsi_hba_tran_free(tran);
err:
	return (DDI_FAILURE);
}


static int
mfi_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	/* ld read/write dont take a lun, so only 0 is supported */
	if (sd->sd_address.a_lun != 0)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
mfi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct mfi_softc		*sc;
	struct mfi_ccb			*ccb;
	struct mfi_pkt_data		*mpd;
	union scsi_cdb			*cdb;

	sc = (struct mfi_softc *)ap->a_hba_tran->tran_hba_private;
	mpd = (struct mfi_pkt_data *)pkt->pkt_ha_private;
	ccb = mpd->mpd_ccb;
	bzero(ccb->ccb_cmd, MFI_CCB_BUFLEN);
	ccb->ccb_done = mfi_done_tran;

	cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	switch (cdb->scc_cmd) {
	case SCMD_READ:
	case SCMD_READ_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE:
	case SCMD_WRITE_G1:
	case SCMD_WRITE_G4:
		/* G5 READS AND WRITES? */
		mfi_start_io(sc, ap, mpd);
		break;

	default:
		mfi_start_scsi(sc, ap, mpd);
		break;
	}

	pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;


	if (pkt->pkt_flags & FLAG_NOINTR) {
		if (mfi_poll(sc, ccb, 10000) != DDI_SUCCESS)
			return (TRAN_FATAL_ERROR);
	} else
		mfi_post(sc, ccb);

	return (TRAN_ACCEPT);
}

static void
mfi_start_scsi(struct mfi_softc *sc, struct scsi_address *ap,
    struct mfi_pkt_data *mpd)
{
	struct scsi_pkt			*pkt = mpd->mpd_pkt;
	struct mfi_ccb			*ccb = mpd->mpd_ccb;
	struct mfi_cmd_scsi		*io;
	struct mfi_sge32		*sgl;

	io = (struct mfi_cmd_scsi *)ccb->ccb_cmd;
	sgl = (struct mfi_sge32 *)(ccb->ccb_cmd + sizeof(struct mfi_cmd_scsi));

	io->cmd = MFI_CMD_LD_SCSI;
	io->sense_len = MFI_CCB_EXTRALEN;

	io->target = ap->a_target;
	io->lun = 0; /* always lun 0 */
	io->cdb_len = mpd->mpd_cdblen;
	io->nsge = ccb->ccb_sgllen;

	io->context = ccb->ccb_context;

	io->flags |= mpd->mpd_read ? MFI_CMD_FLAG_READ : MFI_CMD_FLAG_WRITE;

	io->datalen = ccb->ccb_datalen;

	io->sense_lo = (uint32_t)ccb->ccb_extra_dva;
	io->sense_hi = (uint32_t)(ccb->ccb_extra_dva >> 32);

	memcpy(io->cdb, pkt->pkt_cdbp, mpd->mpd_cdblen);

	mfi_load_sgl(ccb, sgl);

	DPRINTF(MFI_D_HBA, "ccb 0x%08x >> cmd: 0x%02x sense_len: %d "
	    "status: 0x%02x scsi_status: 0x%02x", ccb->ccb_context, io->cmd,
	    io->sense_len, io->status, io->scsi_status);
	DPRINTF(MFI_D_HBA, "  target: %d lun: %d cdb_len: %d nsge: %d",
	    io->target, io->lun, io->cdb_len, io->nsge);
	DPRINTF(MFI_D_HBA, "  context: 0x%08x", io->context);
	DPRINTF(MFI_D_HBA, "  flags: 0x%04x timeout: 0x%04x", io->flags,
	    io->timeout);
	DPRINTF(MFI_D_HBA, "  datalen: %d", io->datalen);
	DPRINTF(MFI_D_HBA, "  sense: 0x%08x %08x", io->sense_lo, io->sense_hi);
	DPRINTF(MFI_D_HBA, "  cdb[0]: 0x%02x", io->cdb[0]);
}

static void
mfi_start_io(struct mfi_softc *sc, struct scsi_address *ap,
    struct mfi_pkt_data *mpd)
{
	struct scsi_pkt			*pkt = mpd->mpd_pkt;
	struct mfi_ccb			*ccb = mpd->mpd_ccb;
	struct mfi_cmd_io		*io;
	struct mfi_sge32		*sgl;
	union scsi_cdb			*cdb;

	io = (struct mfi_cmd_io *)ccb->ccb_cmd;
	sgl = (struct mfi_sge32 *)(ccb->ccb_cmd + sizeof(struct mfi_cmd_io));

	io->cmd = mpd->mpd_read ? MFI_CMD_LD_READ : MFI_CMD_LD_WRITE;
	io->sense_len = MFI_CCB_EXTRALEN;

	io->target = ap->a_target;
	io->nsge = ccb->ccb_sgllen;

	io->context = ccb->ccb_context;

	io->flags |= mpd->mpd_read ? MFI_CMD_FLAG_READ : MFI_CMD_FLAG_WRITE;

	io->sense_lo = (uint32_t)ccb->ccb_extra_dva;
	io->sense_hi = (uint32_t)(ccb->ccb_extra_dva >> 32);

	cdb = (union scsi_cdb *)pkt->pkt_cdbp;
	switch (cdb->scc_cmd) {
	case SCMD_READ:
	case SCMD_WRITE:
		io->block_lo = GETG0ADDR(cdb);
		break;
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
		io->block_lo = GETG1ADDR(cdb);
		break;
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
		io->block_lo = GETG4ADDRTL(cdb);
		io->block_hi = GETG4ADDR(cdb);
		break;
	}

	mfi_load_sgl(ccb, sgl);
	io->nblocks = (ccb->ccb_datalen + 512 - 1) / 512; /* XXX magic */
}

static void
mfi_load_sgl(struct mfi_ccb *ccb, struct mfi_sge32 *sgl)
{
	int				i;

	for (i = 0; i < ccb->ccb_sgllen; i++) {
		sgl[i].len = ccb->ccb_sgl[i].sg_len;
		sgl[i].addr = ccb->ccb_sgl[i].sg_addr;
	}
}

static void
mfi_done_tran(struct mfi_ccb *ccb)
{
	struct mfi_softc		*sc = ccb->ccb_sc;
	struct mfi_pkt_data		*mpd = ccb->ccb_mpd;
	struct mfi_cmd_hdr		*io;
	struct scsi_pkt			*pkt = mpd->mpd_pkt;
	struct scsi_arq_status		*arqstat;

	io = (struct mfi_cmd_hdr *)ccb->ccb_cmd;

	DPRINTF(MFI_D_HBA, "ccb 0x%08x << cmd: 0x%02x sense_len: %d "
	    "status: 0x%02x scsi_status: 0x%02x", ccb->ccb_context, io->cmd,
	    io->sense_len, io->status, io->scsi_status);

	switch (io->status) {
	case MFI_STAT_SCSI_DONE_WITH_ERROR:
		pkt->pkt_state |= STATE_GOT_STATUS;
		pkt->pkt_scbp[0] = io->scsi_status;

		if (io->scsi_status == STATUS_CHECK) {
			pkt->pkt_state |= STATE_ARQ_DONE;
			arqstat = (struct scsi_arq_status *)pkt->pkt_scbp;
			arqstat->sts_rqpkt_reason = CMD_CMPLT;
			arqstat->sts_rqpkt_resid = 0;
			arqstat->sts_rqpkt_state = STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA;
			arqstat->sts_rqpkt_statistics = 0;

			memcpy(&arqstat->sts_sensedata, ccb->ccb_extra,
			    sizeof(arqstat->sts_sensedata));
		}

		/* FALLTHROUGH */
	case MFI_STAT_OK:
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= STATE_XFERRED_DATA;
		pkt->pkt_resid = 0;
		break;

	default:
		cmn_err(CE_NOTE, "%s: %d", __func__, io->status);
		break;
	/* XXX deal with other values */
	}

	pkt->pkt_comp(pkt);
}

static int
mfi_tran_reset(struct scsi_address *ap, int level)
{
#if 0
	cmn_err(CE_NOTE, "mfi_tran_reset");
#endif
	return (0);
}

static int
mfii_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	struct mfi_softc		*sc;

	if (cap == NULL || whom == 0)
		return (-1);

	sc = (struct mfi_softc *)ap->a_hba_tran->tran_hba_private;

	DPRINTF(MFI_D_CAP, "getcap: %s", cap);

	switch (scsi_hba_lookup_capstr(cap)) {
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
	struct mfi_softc		*sc;

	if (cap == NULL || whom == 0)
		return (-1);

	sc = (struct mfi_softc *)ap->a_hba_tran->tran_hba_private;

	DPRINTF(MFI_D_CAP, "setcap: %s", cap);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
#if 0
	case SCSI_CAP_TOTAL_SECTORS:
		return (1);
	case SCSI_CAP_SECTOR_SIZE:
		return (1);
#endif
	default:
		break;
	}

	return (0);
}

static struct scsi_pkt *
mfi_tran_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback)(caddr_t), caddr_t arg)
{
	struct mfi_softc		*sc;
	struct mfi_ccb			*ccb;
	struct mfi_pkt_data		*mpd;
	struct scsi_pkt			*npkt = NULL;
	int				(*cb)(caddr_t);
	int				i;

	sc = (struct mfi_softc *)ap->a_hba_tran->tran_hba_private;
	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	DPRINTF(MFI_D_HBA, "init_pkt(%d,%d): pkt: %p buf: %p buflen: %d "
	    "cmdlen: %d statuslen: %d tgtlen: %d flags: 0x%08x",
	    ap->a_target, ap->a_lun, pkt, bp, (bp == NULL) ? 0 : bp->b_bcount,
	    cmdlen, statuslen, tgtlen, flags);

	/* step 1: packet allocation */
	if (pkt == NULL) {
		if (cmdlen > MFI_CMD_SCSI_CDBLEN ||
		    statuslen > MFI_CCB_EXTRALEN)
			return (NULL);

		ccb = mfi_get_ccb(sc);
		if (ccb == NULL)
			return (NULL);

		DPRINTF(MFI_D_HBA, "ccb: 0x%08x", ccb->ccb_context);

		pkt = scsi_hba_pkt_alloc(sc->sc_dev, ap, cmdlen, statuslen,
		    tgtlen, sizeof(struct mfi_pkt_data), callback, arg);
		if (pkt == NULL) {
			mfi_put_ccb(sc, ccb);
			return (NULL);
		}

		mpd = (struct mfi_pkt_data *)pkt->pkt_ha_private;
		ccb->ccb_mpd = mpd;

		mpd->mpd_ccb = ccb;
		mpd->mpd_pkt = pkt;
		mpd->mpd_dma_mapped = 0;
		mpd->mpd_cdblen = cmdlen;
		mpd->mpd_senselen = statuslen;

		if (ddi_dma_alloc_handle(sc->sc_dev, &sc->sc_io_dma_attr, cb,
		    NULL, &mpd->mpd_dma_handle) != DDI_SUCCESS) {
			scsi_hba_pkt_free(ap, pkt);
			mfi_put_ccb(sc, ccb);
			return (NULL);
		}

		pkt->pkt_address = *ap;
		pkt->pkt_comp = (void (*)(struct scsi_pkt *))NULL;
		pkt->pkt_flags = 0;
		pkt->pkt_time = 0;
		pkt->pkt_resid = 0;
		pkt->pkt_statistics = 0;
		pkt->pkt_reason = 0;

		npkt = pkt;
	} else {
		mpd = pkt->pkt_ha_private;
		ccb = mpd->mpd_ccb;
	}

	ccb->ccb_sgllen = 0;
	ccb->ccb_datalen = 0;

	/* step 2: dma allocation */
	if (bp == NULL || bp->b_bcount == 0)
		return (pkt);

	if (mfi_dma_map(mpd, bp, flags, cb) != DDI_SUCCESS) {
		if (npkt != NULL) {
			ddi_dma_free_handle(&mpd->mpd_dma_handle);
			scsi_hba_pkt_free(ap, pkt);
			mfi_put_ccb(sc, ccb);
		}
		return (NULL);
	}

	pkt->pkt_resid = bp->b_bcount - mpd->mpd_datalen;

	return (pkt);
}

static int
mfi_dma_map(struct mfi_pkt_data *mpd, struct buf *bp, int flags,
    int (*cb)(caddr_t))
{
	struct mfi_ccb			*ccb = mpd->mpd_ccb;
	int				dma_flags;
	int				rv;
	int				i;

	if (!mpd->mpd_dma_mapped) {
		if (bp->b_flags & B_READ) {
			dma_flags = DDI_DMA_READ;
			mpd->mpd_read = 1;
		} else {
			dma_flags = DDI_DMA_WRITE;
			mpd->mpd_read = 0;
		}

		if (flags & PKT_CONSISTENT)
			dma_flags |= DDI_DMA_CONSISTENT;
		if (flags & PKT_DMA_PARTIAL)
			dma_flags |= DDI_DMA_PARTIAL;

		rv = ddi_dma_buf_bind_handle(mpd->mpd_dma_handle,
		    bp, dma_flags, cb, NULL,
		    &mpd->mpd_cookies, &mpd->mpd_ncookies);
		switch (rv) {
		case DDI_DMA_MAPPED:
		case DDI_DMA_PARTIAL_MAP:
			break;

		case DDI_DMA_NORESOURCES:
			bioerror(bp, 0);
			return (DDI_FAILURE);
		case DDI_DMA_NOMAPPING:
			bioerror(bp, EFAULT);
			return (DDI_FAILURE);
		case DDI_DMA_TOOBIG:
			bioerror(bp, EINVAL);
			return (DDI_FAILURE);
		case DDI_DMA_INUSE:
			cmn_err(CE_PANIC, "ddi_dma_buf_bind_handle: "
			    "DDI_DMA_INUSE can't happen");
			/* NOTREACHED */
		default:
			cmn_err(CE_PANIC, "ddi_dma_buf_bind_handle: "
			    "unknown rv: 0x%x", rv);
			/* NOTREACHED */
		}

		mpd->mpd_window = 0;
		mpd->mpd_datalen = 0;
		mpd->mpd_curcookie = 0;
		mpd->mpd_dma_mapped = 1;
	} else if (mpd->mpd_curcookie == mpd->mpd_ncookies) {
		off_t off;
		size_t len;

		/* next window */
		mpd->mpd_window++;
		mpd->mpd_curcookie = 0;
		rv = ddi_dma_getwin(mpd->mpd_dma_handle, mpd->mpd_window,
		    &off, &len, &mpd->mpd_cookies, &mpd->mpd_ncookies);
		if (rv != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	for (i = 0; i < MFI_MAX_SGL_LEN; i++) {
		if (mpd->mpd_curcookie == mpd->mpd_ncookies)
			break;

		ccb->ccb_sgl[i].sg_len = mpd->mpd_cookies.dmac_size;
		ccb->ccb_sgl[i].sg_addr = mpd->mpd_cookies.dmac_address;
		ccb->ccb_datalen += mpd->mpd_cookies.dmac_size;

		ddi_dma_nextcookie(mpd->mpd_dma_handle, &mpd->mpd_cookies);
		mpd->mpd_curcookie++;
	}
	ccb->ccb_sgllen = i;
	mpd->mpd_datalen += ccb->ccb_datalen;

	return (DDI_SUCCESS);
}

static void
mfi_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct mfi_softc		*sc;
	struct mfi_ccb			*ccb;
	struct mfi_pkt_data		*mpd;

	sc = (struct mfi_softc *)ap->a_hba_tran->tran_hba_private;
	mpd = (struct mfi_pkt_data *)pkt->pkt_ha_private;
	ccb = mpd->mpd_ccb;

#if 0
	cmn_err(CE_NOTE, "mfi_tran_destroy_pkt");
#endif

	if (mpd->mpd_dma_mapped)
		ddi_dma_unbind_handle(mpd->mpd_dma_handle);

	ddi_dma_free_handle(&mpd->mpd_dma_handle);
	scsi_hba_pkt_free(ap, pkt);
	mfi_put_ccb(sc, ccb);
}

static void
mfi_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct mfi_softc		*sc;
	struct mfi_pkt_data		*mpd;

	sc = (struct mfi_softc *)ap->a_hba_tran->tran_hba_private;
	mpd = (struct mfi_pkt_data *)pkt->pkt_ha_private;

#if 0
	cmn_err(CE_NOTE, "mfi_tran_dmafree");
#endif

	if (mpd->mpd_dma_mapped) {
		ddi_dma_unbind_handle(mpd->mpd_dma_handle);
		mpd->mpd_dma_mapped = 0;
	}
}

static void
mfi_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct mfi_softc		*sc;
	struct mfi_pkt_data		*mpd;

	sc = (struct mfi_softc *)ap->a_hba_tran->tran_hba_private;
	mpd = (struct mfi_pkt_data *)pkt->pkt_ha_private;

	if (!mpd->mpd_dma_mapped)
		return;

	ddi_dma_sync(mpd->mpd_dma_handle, 0, 0,
	    mpd->mpd_read ? DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
}

static void
mfii_start(struct mfi_softc *sc, struct mfi_ccb *ccb)
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

static void
mfi_done(struct mfi_ccb *ccb)
{
	/* empty handler handler */
}

int
mfii_ccbs_ctor(struct mfii_softc *sc)
{
	struct mfii_ccb *ccb;
	uint8_t *request = MFII_DMA_KVA(sc->sc_requests);
	struct mfi_sense *sense = MFII_DMA_KVA(sc->sc_sense);
	uint8_t *sgl = MFII_DMA_KVA(sc->sc_sgl);
	uint_t i;
	int error;

	sc->sc_ccb = kmem_zalloc(sc->sc_max_cmds * sizeof(*ccb), KM_SLEEP);

	for (i = 0; i < sc->sc_max_cmds; i++) {
		ccb = &sc->sc_ccb[i];

		/* create a dma map for transfer */
		if (ddi_dma_alloc_handle(sc->sc_dev, &sc->sc_dma_attr,
		    DDI_DMA_SLEEP, NULL,
		    &ccb->ccb_dma_handle) != DDI_SUCCESS) {
			dev_err(sc->sc_dev, CE_WARN,
			    "unable to allocate dma handle for command %d", i);
			goto destroy;
		}

		/* select i + 1'th request. 0 is reserved for events */
		ccb->ccb_smid = i + 1;
		ccb->ccb_request_offset = MFII_REQUEST_SIZE * (i + 1);
		ccb->ccb_request = request + ccb->ccb_request_offset;
		ccb->ccb_request_dva = MFII_DMA_DVA(sc->sc_requests) +
		    ccb->ccb_request_offset;

		/* select i'th sense */
		ccb->ccb_sense_offset = sizeof(*ccb->ccb_sense) * i;
		ccb->ccb_sense = &sense[i];
		ccb->ccb_sense_dva = (u_int32_t)(MFII_DMA_DVA(sc->sc_sense) +
		    ccb->ccb_sense_offset);

		/* select i'th sgl */
		ccb->ccb_sgl_offset = sizeof(struct mfii_sge) *
		    sc->sc_max_sgl * i;
		ccb->ccb_sgl = (struct mfii_sge *)(sgl + ccb->ccb_sgl_offset);
		ccb->ccb_sgl_dva = MFII_DMA_DVA(sc->sc_sgl) +
		    ccb->ccb_sgl_offset;

		/* add ccb to queue */
		mfii_put_ccb(sc, ccb);
	}

	return (DDI_SUCCESS);

destroy:
	mfii_ccbs_dtor(sc);
	return (DDI_FAILURE);
}

static void
mfi_ccbs_dtor(struct mfii_softc *sc)
{
	struct mfii_ccb *ccb;

	while ((ccb = mfii_ccb_get(sc)) != NULL)
		ddi_dma_free_handle(&ccb->ccb_dma_handle);

	kmem_free(sc->sc_ccbs, sc->sc_max_cmds * sizeof(*ccb));
}

static struct mfii_ccb *
mfii_ccb_get(struct mfii_softc *sc)
{
	mutex_enter(&sc->sc_ccb_mtx);
	ccb = SIMPLQ_FIRST(&sc->sc_ccb_list);
	if (ccb != NULL)
		SIMPLQ_REMOVE_HEAD(&sc->ccb_list, ccb_entry);
	mutex_leave(&sc->sc_ccb_mtx);

	return (ccb);
}

static void
mfii_ccb_put(struct mfii_softc *sc, struct mfii_ccb *ccb)
{
	mutex_enter(&sc->sc_ccb_mtx);
	SIMPLEQ_INSERT_HEAD(&sc->sc_ccb_list, ccb, ccb_entry);
	mutex_leave(&sc->sc_ccb_mtx);
}

static struct mfii_dmamem *
mfii_dmamem_alloc(struct mfi_softc *sc, ddi_dma_attr_t *attr,
    size_t n, size_t e, uint_t flags)
{
	struct mfii_dmamem *mdm;
	size_t len;
	uint_t ncookies;

	mdm = kmem_zalloc(sizeof(*mdm), KM_SLEEP);
	len = n * e;

	if (ddi_dma_alloc_handle(sc->sc_dev, attr, DDI_DMA_SLEEP, NULL,
	    &mdm->mdm_dma_handle) != DDI_SUCCESS)
		goto err;

	if (ddi_dma_mem_alloc(mdm->mdm_dma_handle, len, attr, flags,
	    DDI_DMA_SLEEP, NULL, &mdm->mdm_kva, &mdm->mdm_len,
	    &mdm->mdm_mem_handle) != DDI_SUCCESS)
		goto free_dma;

	if (ddi_dma_addr_bind_handle(mdm->mem_dma_handle, NULL,
	    mdm->mdm_kva, len, flags, DDI_DMA_SLEEP, NULL,
	    &mdm->mdm_dma_cookie, &ncookies) != DDI_DMA_MAPPED)
		goto free_mem;

	if (ncookies != 1)
		goto unbind_handle;

	return (DDI_SUCCESS);

unbind_handle:
	ddi_dma_unbind_handle(mdm->mdm_dma_handle);
free_mem:
	ddi_dma_mem_free(&mdm->mdm_mem_handle);
free_dma:
	ddi_dma_free_handle(&mdm->mdm_dma_handle);
err:
	kmem_free(mdm, sizeof(*mdm));
	return (DDI_FAILURE);
}

static void
mfii_dmamem_free(struct mfii_softc *sc, struct mfii_dmamem *mdm)
{
	ddi_dma_unbind_handle(mdm->mdm_dma_handle);
	ddi_dma_mem_free(&mdm->mdm_mem_handle);
	ddi_dma_free_handle(&mdm->mdm_dma_handle);
	kmem_free(mdm, sizeof(*mdm));
}
