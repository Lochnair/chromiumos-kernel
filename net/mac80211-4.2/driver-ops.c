/*
 * Copyright 2015 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <net/mac80211.h>
#include "ieee80211_i.h"
#include "trace.h"
#include "driver-ops.h"

int drv_start(struct ieee80211_local *local)
{
	int ret;

	might_sleep();

	if (WARN_ON(local->started))
		return -EALREADY;

	trace_drv_start(local);
	local->started = true;
	/* allow rx frames */
	smp_mb();
	ret = local->ops->start(&local->hw);
	trace_drv_return_int(local, ret);

	if (ret)
		local->started = false;

	return ret;
}

void drv_stop(struct ieee80211_local *local)
{
	might_sleep();

	if (WARN_ON(!local->started))
		return;

	trace_drv_stop(local);
	local->ops->stop(&local->hw);
	trace_drv_return_void(local);

	/* sync away all work on the tasklet before clearing started */
	tasklet_disable(&local->tasklet);
	tasklet_enable(&local->tasklet);

	barrier();

	local->started = false;
}
