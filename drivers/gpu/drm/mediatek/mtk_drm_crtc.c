/*
 * Copyright (c) 2015 MediaTek Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/barrier.h>
#include <drm/drmP.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_plane_helper.h>
#include <linux/clk.h>
#include <linux/pm_runtime.h>
#include <soc/mediatek/cmdq.h>
#include <soc/mediatek/smi.h>

#include "mtk_drm_drv.h"
#include "mtk_drm_crtc.h"
#include "mtk_drm_ddp.h"
#include "mtk_drm_ddp_comp.h"
#include "mtk_drm_fb.h"
#include "mtk_drm_gem.h"
#include "mtk_drm_plane.h"

/**
 * struct mtk_drm_crtc - MediaTek specific crtc structure.
 * @base: crtc object.
 * @enabled: records whether crtc_enable succeeded
 * @planes: array of 4 drm_plane structures, one for each overlay plane
 * @config_regs: memory mapped mmsys configuration register space
 * @mutex: handle to one of the ten disp_mutex streams
 * @ddp_comp_nr: number of components in ddp_comp
 * @ddp_comp: array of pointers the mtk_ddp_comp structures used by this crtc
 */
struct mtk_drm_crtc {
	struct drm_crtc			base;
	bool				enabled;

	bool				pending_needs_vblank;
	struct drm_pending_vblank_event	*event;
	struct completion		completion;
	bool				cmdq_needs_event;
	struct drm_pending_vblank_event	*cmdq_vblank_event;

	bool				cmdq_busy;
	bool				cmdq_flush;
	u64				cmdq_engine_flag;
	int				cmdq_event;
	struct work_struct		cmdq_work;
	struct mtk_plane_pending_state	cmdq_pending[OVL_LAYER_NR];
	struct mutex			cmdq_pending_lock;

	struct work_struct		unreference_work;
	struct drm_framebuffer		*new_fb[OVL_LAYER_NR];
	struct drm_framebuffer		*onscreen_fb[OVL_LAYER_NR];
	struct drm_framebuffer		*old_fb[OVL_LAYER_NR];

	struct drm_plane		planes[OVL_LAYER_NR];

	void __iomem			*config_regs;
	struct mtk_disp_mutex		*mutex;
	unsigned int			ddp_comp_nr;
	struct mtk_ddp_comp		**ddp_comp;
	struct mtk_ddp_comp		*rdma;
};

struct mtk_crtc_state {
	struct drm_crtc_state		base;

	bool				pending_config;
	unsigned int			pending_width;
	unsigned int			pending_height;
	unsigned int			pending_vrefresh;
	bool				cmdq_pending_config;
	unsigned int			cmdq_pending_width;
	unsigned int			cmdq_pending_height;
	unsigned int			cmdq_pending_vrefresh;
};

static inline struct mtk_drm_crtc *to_mtk_crtc(struct drm_crtc *c)
{
	return container_of(c, struct mtk_drm_crtc, base);
}

static inline struct mtk_crtc_state *to_mtk_crtc_state(struct drm_crtc_state *s)
{
	return container_of(s, struct mtk_crtc_state, base);
}

static void mtk_drm_crtc_finish_page_flip(struct mtk_drm_crtc *mtk_crtc)
{
	struct drm_crtc *crtc = &mtk_crtc->base;
	unsigned long flags;

	spin_lock_irqsave(&crtc->dev->event_lock, flags);
	drm_crtc_send_vblank_event(crtc, mtk_crtc->cmdq_vblank_event);
	drm_crtc_vblank_put(crtc);
	mtk_crtc->cmdq_vblank_event = NULL;
	spin_unlock_irqrestore(&crtc->dev->event_lock, flags);
}

static void mtk_drm_crtc_destroy(struct drm_crtc *crtc)
{
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);
	int i;

	for (i = 0; i < mtk_crtc->ddp_comp_nr; i++)
		clk_unprepare(mtk_crtc->ddp_comp[i]->clk);

	mtk_disp_mutex_put(mtk_crtc->mutex);

	drm_crtc_cleanup(crtc);
}

static void mtk_drm_crtc_reset(struct drm_crtc *crtc)
{
	struct mtk_crtc_state *state;

	if (crtc->state) {
		__drm_atomic_helper_crtc_destroy_state(crtc, crtc->state);

		state = to_mtk_crtc_state(crtc->state);
		memset(state, 0, sizeof(*state));
	} else {
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return;
		crtc->state = &state->base;
	}

	state->base.crtc = crtc;
}

static struct drm_crtc_state *mtk_drm_crtc_duplicate_state(struct drm_crtc *crtc)
{
	struct mtk_crtc_state *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	__drm_atomic_helper_crtc_duplicate_state(crtc, &state->base);

	WARN_ON(state->base.crtc != crtc);
	state->base.crtc = crtc;

	return &state->base;
}

static void mtk_drm_crtc_destroy_state(struct drm_crtc *crtc,
				       struct drm_crtc_state *state)
{
	__drm_atomic_helper_crtc_destroy_state(crtc, state);
	kfree(to_mtk_crtc_state(state));
}

static bool mtk_drm_crtc_mode_fixup(struct drm_crtc *crtc,
				    const struct drm_display_mode *mode,
				    struct drm_display_mode *adjusted_mode)
{
	/* Nothing to do here, but this callback is mandatory. */
	return true;
}

int mtk_drm_crtc_enable_vblank(struct drm_device *drm, unsigned int pipe)
{
	struct mtk_drm_private *priv = drm->dev_private;
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(priv->crtc[pipe]);
	struct mtk_ddp_comp *ovl = mtk_crtc->ddp_comp[0];

	mtk_ddp_comp_enable_vblank(ovl, &mtk_crtc->base, NULL);

	return 0;
}

void mtk_drm_crtc_disable_vblank(struct drm_device *drm, unsigned int pipe)
{
	struct mtk_drm_private *priv = drm->dev_private;
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(priv->crtc[pipe]);
	struct mtk_ddp_comp *ovl = mtk_crtc->ddp_comp[0];

	mtk_ddp_comp_disable_vblank(ovl, NULL);
}

static int mtk_crtc_ddp_clk_enable(struct mtk_drm_crtc *mtk_crtc)
{
	int ret;
	int i;

	DRM_DEBUG_DRIVER("%s\n", __func__);
	for (i = 0; i < mtk_crtc->ddp_comp_nr; i++) {
		ret = clk_enable(mtk_crtc->ddp_comp[i]->clk);
		if (ret) {
			DRM_ERROR("Failed to enable clock %d: %d\n", i, ret);
			goto err;
		}
	}

	return 0;
err:
	while (--i >= 0)
		clk_disable(mtk_crtc->ddp_comp[i]->clk);
	return ret;
}

static void mtk_crtc_ddp_clk_disable(struct mtk_drm_crtc *mtk_crtc)
{
	int i;

	DRM_DEBUG_DRIVER("%s\n", __func__);
	for (i = 0; i < mtk_crtc->ddp_comp_nr; i++)
		clk_disable(mtk_crtc->ddp_comp[i]->clk);
}

static int ddp_cmdq_cb(void *data)
{
	struct drm_crtc *crtc = data;
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);

	complete(&mtk_crtc->completion);

	if (mtk_crtc->cmdq_needs_event) {
		mtk_drm_crtc_finish_page_flip(mtk_crtc);
		mtk_crtc->cmdq_needs_event = false;
	}

	schedule_work(&mtk_crtc->unreference_work);
	return 0;
}

static int mtk_crtc_ddp_hw_init(struct mtk_drm_crtc *mtk_crtc)
{
	struct drm_crtc *crtc = &mtk_crtc->base;
	struct mtk_drm_private *priv = mtk_crtc->base.dev->dev_private;
	struct device *gce_dev = &priv->gce_pdev->dev;
	struct cmdq_rec *cmdq_handle;
	struct drm_connector *connector;
	struct drm_encoder *encoder;
	unsigned int width, height, vrefresh, bpc = 0;
	int ret;
	int i;

	DRM_DEBUG_DRIVER("%s\n", __func__);
	if (WARN_ON(!crtc->state))
		return -EINVAL;

	width = crtc->state->adjusted_mode.hdisplay;
	height = crtc->state->adjusted_mode.vdisplay;
	vrefresh = crtc->state->adjusted_mode.vrefresh;

	drm_for_each_encoder(encoder, crtc->dev) {
		if (encoder->crtc != crtc)
			continue;

		drm_for_each_connector(connector, crtc->dev) {
			if (connector->encoder != encoder)
				continue;
			if (connector->display_info.bpc >= 3 &&
			    (bpc == 0 || bpc > connector->display_info.bpc))
				bpc = connector->display_info.bpc;
		}
	}

	ret = pm_runtime_get_sync(crtc->dev->dev);
	if (ret < 0) {
		DRM_ERROR("Failed to enable power domain: %d\n", ret);
		return ret;
	}

	ret = mtk_disp_mutex_prepare(mtk_crtc->mutex);
	if (ret < 0) {
		DRM_ERROR("Failed to enable mutex clock: %d\n", ret);
		goto err_pm_runtime_put;
	}

	ret = mtk_crtc_ddp_clk_enable(mtk_crtc);
	if (ret < 0) {
		DRM_ERROR("Failed to enable component clocks: %d\n", ret);
		goto err_mutex_unprepare;
	}

	DRM_DEBUG_DRIVER("mediatek_ddp_ddp_path_setup\n");
	for (i = 0; i < mtk_crtc->ddp_comp_nr - 1; i++) {
		mtk_ddp_add_comp_to_path(mtk_crtc->config_regs,
					 mtk_crtc->ddp_comp[i]->id,
					 mtk_crtc->ddp_comp[i + 1]->id);
		mtk_disp_mutex_add_comp(mtk_crtc->mutex,
					mtk_crtc->ddp_comp[i]->id);
	}
	mtk_disp_mutex_add_comp(mtk_crtc->mutex, mtk_crtc->ddp_comp[i]->id);
	mtk_disp_mutex_enable(mtk_crtc->mutex);

	DRM_DEBUG_DRIVER("ddp_disp_path_power_on %dx%d\n", width, height);
	cmdq_rec_create(gce_dev, mtk_crtc->cmdq_engine_flag, &cmdq_handle);
	/*
	 * During an atomic update, Mediatek DRM disables/enables crtcs and
	 * encoders first, and then applies plane state (enable/FB address)
	 * changes.
	 *
	 * On boot, firmware may have enabled some overlays, with an FB that
	 * is no longer mapped.
	 *
	 * Furthermore, drm/mediatek uses active_only, so state changes are
	 * only applied to hardware when the corresponding crtc is enabled.
	 * In other words, when disabling a CRTC, the CRTC's planes SW state
	 * is disabled, but the hardware state is not actually changed at
	 * disable time.  Thus, like at boot, the overlay hw state will be
	 * 'enabled', but their scanout address is for a FB that has already
	 * been unmapped.
	 *
	 * To avoid an iommu fault between when we enable the encoder and when
	 * the new plane state is later applied to hardware in both of these
	 * cases, we explicitly start all overlays in disabled state.  The
	 * correct plane state for any enabled planes will be applied later in
	 * the atomic update.
	 */
	for (i = 0; i < OVL_LAYER_NR; i++) {
		struct mtk_plane_pending_state pending = { .enable = false };

		mtk_ddp_comp_layer_config(mtk_crtc->ddp_comp[0], i,
					  &pending, cmdq_handle);
	}

	for (i = 0; i < mtk_crtc->ddp_comp_nr; i++) {
		struct mtk_ddp_comp *comp = mtk_crtc->ddp_comp[i];

		mtk_ddp_comp_config(comp, width, height, vrefresh, bpc,
				    cmdq_handle);
		mtk_ddp_comp_start(comp, cmdq_handle);
	}

	cmdq_rec_flush(cmdq_handle);
	cmdq_rec_destroy(cmdq_handle);

	return 0;

err_mutex_unprepare:
	mtk_disp_mutex_unprepare(mtk_crtc->mutex);
err_pm_runtime_put:
	pm_runtime_put(crtc->dev->dev);
	return ret;
}

static void mtk_crtc_ddp_hw_fini(struct mtk_drm_crtc *mtk_crtc)
{
	struct drm_device *drm = mtk_crtc->base.dev;
	struct mtk_drm_private *priv = mtk_crtc->base.dev->dev_private;
	struct device *gce_dev = &priv->gce_pdev->dev;
	struct cmdq_rec *cmdq_handle;
	int i;

	DRM_DEBUG_DRIVER("%s\n", __func__);
	cmdq_rec_create(gce_dev, mtk_crtc->cmdq_engine_flag, &cmdq_handle);
	for (i = 0; i < mtk_crtc->ddp_comp_nr; i++)
		mtk_ddp_comp_stop(mtk_crtc->ddp_comp[i], cmdq_handle);
	cmdq_rec_flush(cmdq_handle);
	cmdq_rec_destroy(cmdq_handle);

	for (i = 0; i < mtk_crtc->ddp_comp_nr; i++)
		mtk_disp_mutex_remove_comp(mtk_crtc->mutex,
					   mtk_crtc->ddp_comp[i]->id);
	mtk_disp_mutex_disable(mtk_crtc->mutex);
	for (i = 0; i < mtk_crtc->ddp_comp_nr - 1; i++) {
		mtk_ddp_remove_comp_from_path(mtk_crtc->config_regs,
					      mtk_crtc->ddp_comp[i]->id,
					      mtk_crtc->ddp_comp[i + 1]->id);
		mtk_disp_mutex_remove_comp(mtk_crtc->mutex,
					   mtk_crtc->ddp_comp[i]->id);
	}
	mtk_disp_mutex_remove_comp(mtk_crtc->mutex, mtk_crtc->ddp_comp[i]->id);
	mtk_crtc_ddp_clk_disable(mtk_crtc);
	mtk_disp_mutex_unprepare(mtk_crtc->mutex);

	pm_runtime_put(drm->dev);
}

static void mtk_drm_crtc_atomic_flush(struct drm_crtc *crtc,
				      struct drm_crtc_state *old_crtc_state)
{
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);
	struct mtk_crtc_state *state;
	unsigned int i;

	mutex_lock(&mtk_crtc->cmdq_pending_lock);
	if (mtk_crtc->event)
		mtk_crtc->pending_needs_vblank = true;

	for (i = 0; i < OVL_LAYER_NR; i++) {
		struct drm_plane *plane = &mtk_crtc->planes[i];
		struct mtk_plane_state *plane_state;

		plane_state = to_mtk_plane_state(plane->state);
		if (plane_state->pending.dirty) {
			mtk_crtc->cmdq_pending[i].dirty = true;
			plane_state->pending.config = true;
			plane_state->pending.dirty = false;
		}
	}

	state = to_mtk_crtc_state(mtk_crtc->base.state);

	if (state->pending_config) {
		state->cmdq_pending_width = state->pending_width;
		state->cmdq_pending_height = state->pending_height;
		state->cmdq_pending_vrefresh = state->pending_vrefresh;
		state->cmdq_pending_config = state->pending_config;
		state->pending_config = false;
	}

	for (i = 0; i < OVL_LAYER_NR; i++) {
		struct drm_plane *plane = &mtk_crtc->planes[i];
		struct mtk_plane_state *plane_state;

		plane_state = to_mtk_plane_state(plane->state);
		if (plane_state->pending.config) {
			mtk_crtc->cmdq_pending[i] = plane_state->pending;

			if (plane_state->base.fb != mtk_crtc->new_fb[i]) {
				/* If replacing a pending FB, unref it now. */
				if (mtk_crtc->new_fb[i])
					drm_framebuffer_unreference(
							mtk_crtc->new_fb[i]);

				if (plane_state->base.fb)
					drm_framebuffer_reference(
							plane_state->base.fb);

				mtk_crtc->new_fb[i] = plane_state->base.fb;
			}

			plane_state->pending.config = false;
		}
	}
	mtk_crtc->cmdq_flush = true;
	mutex_unlock(&mtk_crtc->cmdq_pending_lock);
}

static void mtk_drm_crtc_enable(struct drm_crtc *crtc)
{
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);
	struct mtk_ddp_comp *ovl = mtk_crtc->ddp_comp[0];
	int ret;

	DRM_DEBUG_DRIVER("%s %d\n", __func__, crtc->base.id);

	ret = mtk_smi_larb_get(ovl->larb_dev);
	if (ret) {
		DRM_ERROR("Failed to get larb: %d\n", ret);
		return;
	}

	ret = mtk_crtc_ddp_hw_init(mtk_crtc);
	if (ret) {
		mtk_smi_larb_put(ovl->larb_dev);
		return;
	}

	drm_crtc_vblank_on(crtc);
	mtk_ddp_comp_enable_vblank(mtk_crtc->rdma, &mtk_crtc->base, NULL);
	mtk_crtc->enabled = true;
}

static void mtk_drm_crtc_disable(struct drm_crtc *crtc)
{
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);
	struct mtk_ddp_comp *ovl = mtk_crtc->ddp_comp[0];

	DRM_DEBUG_DRIVER("%s %d\n", __func__, crtc->base.id);
	if (!mtk_crtc->enabled)
		return;

	/* Wait for any pending plane updates to complete */
	flush_work(&mtk_crtc->cmdq_work);
	wait_for_completion(&mtk_crtc->completion);

	mtk_crtc->enabled = false;
	mtk_ddp_comp_disable_vblank(mtk_crtc->rdma, NULL);
	drm_crtc_vblank_off(crtc);
	mtk_crtc_ddp_hw_fini(mtk_crtc);
	mtk_smi_larb_put(ovl->larb_dev);
}

static void mtk_drm_crtc_atomic_begin(struct drm_crtc *crtc,
				      struct drm_crtc_state *old_crtc_state)
{
	struct mtk_crtc_state *state = to_mtk_crtc_state(crtc->state);
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);

	if (mtk_crtc->cmdq_vblank_event && state->base.event)
		DRM_ERROR("new event while there is still a pending event\n");

	if (state->base.event) {
		state->base.event->pipe = drm_crtc_index(crtc);
		WARN_ON(drm_crtc_vblank_get(crtc) != 0);
		mtk_crtc->event = state->base.event;
		state->base.event = NULL;
	}
}

static void mtk_drm_crtc_commit_cmdq(struct drm_crtc *crtc)
{
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);
	struct mtk_drm_private *priv = mtk_crtc->base.dev->dev_private;
	struct device *gce_dev = &priv->gce_pdev->dev;
	struct mtk_ddp_comp *ovl;
	struct mtk_crtc_state *state;
	struct cmdq_rec *cmdq_handle;
	unsigned int i;

	mutex_lock(&mtk_crtc->cmdq_pending_lock);
	mtk_crtc->cmdq_busy = true;
	if (mtk_crtc->pending_needs_vblank) {
		mtk_crtc->cmdq_vblank_event = mtk_crtc->event;
		mtk_crtc->cmdq_needs_event = mtk_crtc->pending_needs_vblank;
		mtk_crtc->event = NULL;
		mtk_crtc->pending_needs_vblank = false;
	}
	reinit_completion(&mtk_crtc->completion);
	cmdq_rec_create(gce_dev, mtk_crtc->cmdq_engine_flag, &cmdq_handle);
	cmdq_rec_clear_event(cmdq_handle, mtk_crtc->cmdq_event);
	cmdq_rec_wait(cmdq_handle, mtk_crtc->cmdq_event);

	for (i = 0; i < OVL_LAYER_NR; i++) {
		if (mtk_crtc->cmdq_pending[i].dirty) {
			mtk_crtc->cmdq_pending[i].config = true;
			mtk_crtc->cmdq_pending[i].dirty = false;
		}
	}

	ovl = mtk_crtc->ddp_comp[0];
	state = to_mtk_crtc_state(mtk_crtc->base.state);

	if (state->cmdq_pending_config) {
		mtk_ddp_comp_config(ovl, state->cmdq_pending_width,
				    state->cmdq_pending_height,
				    state->cmdq_pending_vrefresh,
				    0, cmdq_handle);
		state->cmdq_pending_config = false;
	}

	for (i = 0; i < OVL_LAYER_NR; i++) {
		if (mtk_crtc->cmdq_pending[i].config) {
			/*
			 * There should only be one cmdq_rec active at a time,
			 * so there should not be any old FB that has not yet
			 * been unreferenced.
			 */
			WARN_ON(mtk_crtc->old_fb[i]);

			mtk_crtc->old_fb[i] = mtk_crtc->onscreen_fb[i];
			mtk_crtc->onscreen_fb[i] = mtk_crtc->new_fb[i];
			mtk_crtc->new_fb[i] = NULL;

			mtk_ddp_comp_layer_config(ovl, i,
						  &mtk_crtc->cmdq_pending[i],
						  cmdq_handle);
			mtk_crtc->cmdq_pending[i].config = false;
		}
	}

	cmdq_rec_flush_async_callback(cmdq_handle, ddp_cmdq_cb,
				      crtc, NULL, NULL);
	cmdq_rec_destroy(cmdq_handle);

	mtk_crtc->cmdq_flush = false;
	mutex_unlock(&mtk_crtc->cmdq_pending_lock);
}

static void mtk_drm_crtc_cmdq_work(struct work_struct *work)
{
	struct mtk_drm_crtc *mtk_crtc = container_of(work,
			struct mtk_drm_crtc, cmdq_work);

	mtk_drm_crtc_commit_cmdq(&mtk_crtc->base);
}

static void mtk_drm_crtc_unreference_work(struct work_struct *work)
{
	struct mtk_drm_crtc *mtk_crtc = container_of(work,
			struct mtk_drm_crtc, unreference_work);
	unsigned int i;

	for (i = 0; i < OVL_LAYER_NR; i++) {
		if (mtk_crtc->old_fb[i]) {
			drm_framebuffer_unreference(mtk_crtc->old_fb[i]);
			mtk_crtc->old_fb[i] = NULL;
		}
	}

	mtk_crtc->cmdq_busy = false;
}

static const struct drm_crtc_funcs mtk_crtc_funcs = {
	.set_config		= drm_atomic_helper_set_config,
	.page_flip		= drm_atomic_helper_page_flip,
	.destroy		= mtk_drm_crtc_destroy,
	.reset			= mtk_drm_crtc_reset,
	.atomic_duplicate_state	= mtk_drm_crtc_duplicate_state,
	.atomic_destroy_state	= mtk_drm_crtc_destroy_state,
};

static const struct drm_crtc_helper_funcs mtk_crtc_helper_funcs = {
	.mode_fixup	= mtk_drm_crtc_mode_fixup,
	.enable		= mtk_drm_crtc_enable,
	.disable	= mtk_drm_crtc_disable,
	.atomic_begin	= mtk_drm_crtc_atomic_begin,
	.atomic_flush	= mtk_drm_crtc_atomic_flush,
};

static int mtk_drm_crtc_init(struct drm_device *drm,
			     struct mtk_drm_crtc *mtk_crtc,
			     struct drm_plane *primary,
			     struct drm_plane *cursor, unsigned int pipe)
{
	int ret;

	ret = drm_crtc_init_with_planes(drm, &mtk_crtc->base, primary, cursor,
					&mtk_crtc_funcs, NULL);
	if (ret)
		goto err_cleanup_crtc;

	drm_crtc_helper_add(&mtk_crtc->base, &mtk_crtc_helper_funcs);

	return 0;

err_cleanup_crtc:
	drm_crtc_cleanup(&mtk_crtc->base);
	return ret;
}

void mtk_crtc_vblank_irq(struct drm_crtc *crtc)
{
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);

	drm_crtc_handle_vblank(&mtk_crtc->base);
}

void mtk_crtc_target_line_irq(struct drm_crtc *crtc)
{
	struct mtk_drm_crtc *mtk_crtc = to_mtk_crtc(crtc);

	if (mtk_crtc->enabled && !mtk_crtc->cmdq_busy && mtk_crtc->cmdq_flush)
		schedule_work(&mtk_crtc->cmdq_work);
}

int mtk_drm_crtc_create(struct drm_device *drm_dev,
			const enum mtk_ddp_comp_id *path, unsigned int path_len)
{
	struct mtk_drm_private *priv = drm_dev->dev_private;
	struct device *dev = drm_dev->dev;
	struct mtk_drm_crtc *mtk_crtc;
	enum drm_plane_type type;
	unsigned int zpos;
	int pipe = priv->num_pipes;
	int ret;
	int i;

	for (i = 0; i < path_len; i++) {
		enum mtk_ddp_comp_id comp_id = path[i];
		struct device_node *node;

		node = priv->comp_node[comp_id];
		if (!node) {
			dev_info(dev,
				 "Not creating crtc %d because component %d is disabled or missing\n",
				 pipe, comp_id);
			return 0;
		}
	}

	mtk_crtc = devm_kzalloc(dev, sizeof(*mtk_crtc), GFP_KERNEL);
	if (!mtk_crtc)
		return -ENOMEM;

	mtk_crtc->config_regs = priv->config_regs;
	mtk_crtc->ddp_comp_nr = path_len;
	mtk_crtc->ddp_comp = devm_kmalloc_array(dev, mtk_crtc->ddp_comp_nr,
						sizeof(*mtk_crtc->ddp_comp),
						GFP_KERNEL);

	mtk_crtc->mutex = mtk_disp_mutex_get(priv->mutex_dev, pipe);
	if (IS_ERR(mtk_crtc->mutex)) {
		ret = PTR_ERR(mtk_crtc->mutex);
		dev_err(dev, "Failed to get mutex: %d\n", ret);
		return ret;
	}

	for (i = 0; i < mtk_crtc->ddp_comp_nr; i++) {
		enum mtk_ddp_comp_id comp_id = path[i];
		struct mtk_ddp_comp *comp;
		struct device_node *node;

		node = priv->comp_node[comp_id];
		comp = priv->ddp_comp[comp_id];
		if (!comp) {
			dev_err(dev, "Component %s not initialized\n",
				node->full_name);
			ret = -ENODEV;
			goto unprepare;
		}

		ret = clk_prepare(comp->clk);
		if (ret) {
			dev_err(dev,
				"Failed to prepare clock for component %s: %d\n",
				node->full_name, ret);
			goto unprepare;
		}

		mtk_crtc->ddp_comp[i] = comp;

		if (mtk_crtc->ddp_comp[i]->type == MTK_DISP_RDMA)
			mtk_crtc->rdma = mtk_crtc->ddp_comp[i];
	}

	for (zpos = 0; zpos < OVL_LAYER_NR; zpos++) {
		type = (zpos == 0) ? DRM_PLANE_TYPE_PRIMARY :
				(zpos == 1) ? DRM_PLANE_TYPE_CURSOR :
						DRM_PLANE_TYPE_OVERLAY;
		ret = mtk_plane_init(drm_dev, &mtk_crtc->planes[zpos],
				     BIT(pipe), type);
		if (ret)
			goto unprepare;
	}

	ret = mtk_drm_crtc_init(drm_dev, mtk_crtc, &mtk_crtc->planes[0],
				&mtk_crtc->planes[1], pipe);
	if (ret < 0)
		goto unprepare;

	priv->crtc[pipe] = &mtk_crtc->base;
	priv->num_pipes++;

	mutex_init(&mtk_crtc->cmdq_pending_lock);
	init_completion(&mtk_crtc->completion);
	complete(&mtk_crtc->completion);

	if (drm_crtc_index(&mtk_crtc->base) == 0) {
		mtk_crtc->cmdq_engine_flag = (BIT_ULL(CMDQ_ENG_DISP_OVL0) |
					      BIT_ULL(CMDQ_ENG_DISP_COLOR0) |
					      BIT_ULL(CMDQ_ENG_DISP_AAL) |
					      BIT_ULL(CMDQ_ENG_DISP_RDMA0) |
					      BIT_ULL(CMDQ_ENG_DISP_UFOE) |
					      BIT_ULL(CMDQ_ENG_DISP_DSI0));
		mtk_crtc->cmdq_event = CMDQ_EVENT_MUTEX0_STREAM_EOF;
	} else {
		mtk_crtc->cmdq_engine_flag = (BIT_ULL(CMDQ_ENG_DISP_OVL1) |
					      BIT_ULL(CMDQ_ENG_DISP_COLOR1) |
					      BIT_ULL(CMDQ_ENG_DISP_GAMMA) |
					      BIT_ULL(CMDQ_ENG_DISP_RDMA1) |
					      BIT_ULL(CMDQ_ENG_DISP_DPI0));
		mtk_crtc->cmdq_event = CMDQ_EVENT_MUTEX1_STREAM_EOF;
	}

	INIT_WORK(&mtk_crtc->cmdq_work, mtk_drm_crtc_cmdq_work);
	INIT_WORK(&mtk_crtc->unreference_work, mtk_drm_crtc_unreference_work);

	return 0;

unprepare:
	while (--i >= 0)
		clk_unprepare(mtk_crtc->ddp_comp[i]->clk);

	return ret;
}
