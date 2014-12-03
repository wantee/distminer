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
#include "task.h"
#include "driver-dist.h"

#if defined(unix)
	#include <errno.h>
	#include <fcntl.h>
#endif


BFG_REGISTER_DRIVER(dist_drv)

pthread_t *g_tids;
task_t *g_tasks;
int g_found_work_id;
pthread_mutex_t g_found_work_id_lock;

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

static bool dist_thread_prepare(struct thr_info *thr)
{
    g_tids = (pthread_t *)malloc(sizeof(pthread_t) * opt_task_num);
    if (g_tids == NULL) {
        applog(LOG_ERR, "Failed to malloc pthread_t.");
        return false;
    }

    g_tasks = (task_t *)malloc(sizeof(task_t) * opt_task_num);
    if (g_tasks == NULL) {
        applog(LOG_ERR, "Failed to malloc tasks.");
        return false;
    }

    pthread_mutex_init(&g_found_work_id_lock, NULL);

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

static size_t recv_nonce_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
    int i;
    uint32_t *nonce = user_data;

    sscanf((char *)ptr, "%*s\toutput\tdrpc\t\t%u\n", nonce);

	return nmemb;
}

static size_t send_task_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
    task_t *task;
    size_t len;

    task = (task_t *)user_data;

	len = size * nmemb;

	if (len > task->enc_str_len - task->enc_str_pos) {
		len = task->enc_str_len - task->enc_str_pos;
    }

	if (len > 0) {
		memcpy(ptr, task->enc_str + task->enc_str_pos, len);
		task->enc_str_pos += len;
	}

	return len;
}

static 
void *task_thread(void *args)
{
    CURL *curl;
    CURLcode res;
    task_t *task;
    uint32_t nonce;

    task = (task_t *)args;

    if (task_enc(task) < 0) {
        applog(LOG_ERR, "curl_easy_init() failed");
        return NULL;
    }

    curl = curl_easy_init();
    if(curl == NULL) {
        applog(LOG_ERR, "curl_easy_init() failed");
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, opt_storm_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_nonce_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &nonce);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, send_task_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, task);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        applog(LOG_ERR, "curl_easy_perform() failed: %s",
                curl_easy_strerror(res));
    } else {
        /* if nonce found, submit work */
        applog(LOG_DEBUG, "%"PRIpreprv" found something?", task->thr->cgpu->proc_repr);
        submit_nonce(task->thr, task->work, le32toh(*(uint32_t*)&nonce));
    }

    curl_easy_cleanup(curl);

    return NULL;
}

static int64_t dist_scanhash(struct thr_info *thr, struct work *work, int64_t max_nonce)
{
    int i;
    uint32_t first_nonce;
    uint32_t step;

    first_nonce = work->blk.nonce;
    step = (max_nonce - first_nonce) / opt_task_num;
    for (i = 0; i < opt_task_num; i++) {
        g_tasks[i].work = work;
        g_tasks[i].thr = thr;
        g_tasks[i].first_nonce = first_nonce + i*step;
        g_tasks[i].last_nonce = first_nonce + (i + 1) * step - 1;
        g_tasks[i].id = i;

        if (unlikely(pthread_create(g_tids + i, NULL, task_thread, (void *)(g_tasks + i)))) {
            applog(LOG_ERR, "Failed to create task thread");
            return -1;
        }
    }

    for (i = 0; i < opt_task_num; i++) {
        pthread_join(g_tids[i], NULL);
    }

	work->blk.nonce = max_nonce + 1;
	return max_nonce - first_nonce + 1;
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
