#ifndef _DISTMINER_TASK_H_
#define _DISTMINER_TASK_H_

#include <stdio.h>
#include <stdint.h>

#include "config.h"

typedef struct _task_t_ {
	unsigned char	data[128];
	unsigned char	hash1[64];
	unsigned char	midstate[32];
	unsigned char	target[32];
	unsigned char	hash[32];

    uint32_t nonce;
    uint32_t max_nonce;
} task_t;

int task_write(task_t *task, FILE *fp);
int task_read(task_t *task, FILE *fp);

#endif 

