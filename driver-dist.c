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
CURL **g_curls;
FILE **g_curl_v_fp;

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
    char file[2048];
    int i;

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

    g_curls = (CURL **)malloc(sizeof(CURL *) * (opt_task_num));
    if (g_curls == NULL) {
        applog(LOG_ERR, "Failed to malloc g_curls.");
        return false;
    }

    g_curl_v_fp = (FILE **)malloc(sizeof(FILE *) * (opt_task_num));
    if (g_curl_v_fp == NULL) {
        applog(LOG_ERR, "Failed to malloc curl_v_fp.");
        return false;
    }
    memset(g_curl_v_fp, 0, sizeof(FILE *) * opt_task_num);

    for (i = 0; i < opt_task_num; i++) {
        g_curls[i] = curl_easy_init();
        if(g_curls[i] == NULL) {
            applog(LOG_ERR, "curl_easy_init() failed");
            return false;
        }

        if (opt_curl_verbose != NULL && opt_curl_verbose[0] != 0) {
            snprintf(file, 2048, "%s.%d", opt_curl_verbose, i);
            g_curl_v_fp[i] = fopen(file, "w");
            if (g_curl_v_fp[i] == NULL) {
                applog(LOG_WARNING, "Failed to open curl verbose file[%s]", file);
            }
        }
    }

	thread_reportin(thr);

	return true;
}

static bool dist_thread_init(struct thr_info *thr)
{
	return true;
}

static uint64_t dist_can_limit_work(struct thr_info __maybe_unused *thr)
{
	//return 0xffff;
    if (opt_task_hash == 0) {
        return 0xffffffff;
    } else {
        return opt_task_num * opt_task_hash;
    }
}

static
float dist_min_nonce_diff(struct cgpu_info * const proc, const struct mining_algorithm * const malgo)
{
	return minimum_pdiff;
}

static size_t recv_nonce_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
    char *str;
    size_t len;
    int i;
    task_t *task = (task_t*) user_data;

    if (nmemb >= task->read_buf_len - task->read_buf_pos) {
        applog(LOG_ERR, "task read buffer overflow");
        return nmemb;
    }

    len = nmemb;
    str = (char*)ptr;
    if (task->read_buf_pos == 0) {
        if (*str == 'F') {
            task->found = true;
        }
        str++;
        len--;
    }

    if (task->found == false) {
        return nmemb;
    }

    if (len > 0) {
        memcpy(task->read_buf + task->read_buf_pos, str, len);
        task->read_buf_pos += len;
    }

	return nmemb;
}

#if 0
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
#endif

static 
void *task_thread(void *args)
{
    CURL *curl;
    CURLcode res;
    task_t *task;
    uint32_t nonce;
    struct timeval tts;
    struct timeval tte;
    struct timeval tv_elapsed;
    double secs;

    task = (task_t *)args;

    if (task_enc(task) < 0) {
        applog(LOG_ERR, "task_enc() failed");
        return NULL;
    }
    //applog(LOG_DEBUG, "TASK[%d/%d]: %u-%u", task->work->id, task->id, task->first_nonce, task->last_nonce);

    curl = task->curl;
    curl_easy_reset(curl);

    curl_easy_setopt(curl, CURLOPT_URL, opt_storm_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_nonce_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, task);
    //curl_easy_setopt(curl, CURLOPT_READFUNCTION, send_task_cb);
    //curl_easy_setopt(curl, CURLOPT_READDATA, task);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, task->enc_str);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(task->enc_str));
    //curl_easy_setopt(curl, CURLOPT_TIMEOUT, opt_task_tmo);
    //curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1); // fix bug *** longjmp causes uninitialized stack frame ***

    if (task->curl_v_fp != NULL) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        curl_easy_setopt(curl, CURLOPT_STDERR, task->curl_v_fp);
    }

    applog(LOG_DEBUG, "Task: [%d/%d], CURL start.", task->work->id, task->id);
    gettimeofday(&tts, NULL);
    res = curl_easy_perform(curl);
    gettimeofday(&tte, NULL);
    timersub(&tte, &tts, &tv_elapsed);
    secs = (double)tv_elapsed.tv_sec + ((double)tv_elapsed.tv_usec / 1000000.0);
    applog(LOG_DEBUG, "Task: [%d/%d], CURL time: %.3f", task->work->id, task->id, secs);

    if(res != CURLE_OK) {
        applog(LOG_ERR, "curl_easy_perform() failed: %s",
                curl_easy_strerror(res));
    } else {
        if (task->found == true) {
            sscanf(task->read_buf, "%u\n", &nonce);

            /* if nonce found, submit work */
            applog(LOG_DEBUG, "%"PRIpreprv" found something?", task->thr->cgpu->proc_repr);
            submit_nonce(task->thr, task->work, le32toh(*(uint32_t*)&nonce));
        }
    }

    return NULL;
}

static int64_t dist_scanhash(struct thr_info *thr, struct work *work, int64_t max_nonce)
{
    uint32_t i;
    uint32_t first_nonce;
    uint32_t step;

    first_nonce = work->blk.nonce;
    step = (max_nonce - first_nonce) / opt_task_num;
    //applog(LOG_DEBUG, "Hash: %u-%u, total: %u, step: %u", first_nonce, max_nonce, 
    //        max_nonce - first_nonce, step);
    for (i = 0; i < opt_task_num; i++) {
        task_clear(g_tasks + i);

        g_tasks[i].work = work;
        g_tasks[i].thr = thr;
        g_tasks[i].first_nonce = first_nonce + i*step;
        g_tasks[i].last_nonce = first_nonce + (i + 1) * step - 1;
        g_tasks[i].id = i;
        g_tasks[i].curl = g_curls[i];
        g_tasks[i].curl_v_fp = g_curl_v_fp[i];

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
	.name = "DST",
	.probe_priority = 120,
	.drv_min_nonce_diff = dist_min_nonce_diff,
	.drv_detect = dist_detect,
	.thread_prepare = dist_thread_prepare,
	.thread_init = dist_thread_init,
	.scanhash = dist_scanhash,
	.can_limit_work = dist_can_limit_work,
};
