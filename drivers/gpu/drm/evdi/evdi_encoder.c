/*
 * Copyright (C) 2012 Red Hat
 * Copyright (c) 2015 - 2016 DisplayLink (UK) Ltd.
 *
 * Based on parts on udlfb.c:
 * Copyright (C) 2009 its respective authors
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <drm/drmP.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include "evdi_drv.h"

/* dummy encoder */
static void evdi_enc_destroy(struct drm_encoder *encoder)
{
	drm_encoder_cleanup(encoder);
	kfree(encoder);
}

static void evdi_encoder_disable(__always_unused struct drm_encoder *encoder)
{
}

static bool evdi_mode_fixup(
			__always_unused struct drm_encoder *encoder,
			__always_unused const struct drm_display_mode *mode,
			__always_unused struct drm_display_mode *adjusted_mode)
{
	return true;
}

static void evdi_encoder_prepare(__always_unused struct drm_encoder *encoder)
{
}

static void evdi_encoder_commit(__always_unused struct drm_encoder *encoder)
{
}

static void evdi_encoder_mode_set(
			__always_unused struct drm_encoder *encoder,
			__always_unused struct drm_display_mode *mode,
			__always_unused struct drm_display_mode *adjusted_mode)
{
}

static void evdi_encoder_dpms(
			__always_unused struct drm_encoder *encoder,
			__always_unused int mode)
{
}

static const struct drm_encoder_helper_funcs evdi_helper_funcs = {
	.dpms = evdi_encoder_dpms,
	.mode_fixup = evdi_mode_fixup,
	.prepare = evdi_encoder_prepare,
	.mode_set = evdi_encoder_mode_set,
	.commit = evdi_encoder_commit,
	.disable = evdi_encoder_disable,
};

static const struct drm_encoder_funcs evdi_enc_funcs = {
	.destroy = evdi_enc_destroy,
};

struct drm_encoder *evdi_encoder_init(struct drm_device *dev)
{
	struct drm_encoder *encoder;
	int ret = 0;

	encoder = kzalloc(sizeof(struct drm_encoder), GFP_KERNEL);
	if (!encoder)
		goto err;

	ret = drm_encoder_init(dev, encoder, &evdi_enc_funcs,
			       DRM_MODE_ENCODER_TMDS, NULL);
	if (ret) {
		EVDI_ERROR("Failed to initialize encoder: %d\n", ret);
		goto err_encoder;
	}

	drm_encoder_helper_add(encoder, &evdi_helper_funcs);
	encoder->possible_crtcs = 1;
	return encoder;

err_encoder:
	kfree(encoder);
err:
	return NULL;
}
