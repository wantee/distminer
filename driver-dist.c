/*
 * Copyright 2011-2013 Con Kolivas
 * Copyright 2011-2014 Luke Dashjr
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/wait.h>
#include <sys/resource.h>
#endif
#include <libgen.h>

#include "compat.h"
#include "deviceapi.h"
#include "miner.h"
#include "logging.h"
#include "util.h"
#include "driver-dist.h"

#if defined(unix)
	#include <errno.h>
	#include <fcntl.h>
#endif

BFG_REGISTER_DRIVER(dist_drv)

static int dist_autodetect()
{
	RUNONCE(0);
	
	int i;

    opt_n_threads = 1;

	cpus = calloc(opt_n_threads, sizeof(struct cgpu_info));
	if (unlikely(!cpus))
		quit(1, "Failed to calloc cpus");
	for (i = 0; i < opt_n_threads; ++i) {
		struct cgpu_info *cgpu;

		cgpu = &cpus[i];
		cgpu->drv = &dist_drv;
		cgpu->deven = DEV_ENABLED;
		cgpu->threads = 1;
		add_cgpu(cgpu);
	}
	return opt_n_threads;
}

static void dist_detect()
{
	noserial_detect_manual(&dist_drv, dist_autodetect);
}

static pthread_mutex_t distalgo_lock;

static bool dist_thread_prepare(struct thr_info *thr)
{
	thread_reportin(thr);

	return true;
}

static uint64_t dist_can_limit_work(struct thr_info __maybe_unused *thr)
{
	return 0xffff;
}

static bool dist_thread_init(struct thr_info *thr)
{
	return true;
}

static
float dist_min_nonce_diff(struct cgpu_info * const proc, const struct mining_algorithm * const malgo)
{
	return minimum_pdiff;
}

static int64_t dist_scanhash(struct thr_info *thr, struct work *work, int64_t max_nonce)
{
    return 0;
}

struct device_drv dist_drv = {
	.dname = "dist",
	.name = "DIST",
	.probe_priority = 120,
	.drv_min_nonce_diff = dist_min_nonce_diff,
	.drv_detect = dist_detect,
	.thread_prepare = dist_thread_prepare,
	.can_limit_work = dist_can_limit_work,
	.thread_init = dist_thread_init,
	.scanhash = dist_scanhash,
};
