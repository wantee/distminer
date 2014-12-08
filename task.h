#ifndef _DISTMINER_TASK_H_
#define _DISTMINER_TASK_H_

#include <stdio.h>
#include <stdint.h>

#include "miner.h"

#define MAX_ENC_LEN 2048

typedef struct _task_t_ {
    int id;
    struct thr_info *thr;
    struct work *work;

    uint32_t first_nonce;
    uint32_t last_nonce;

    char enc_str[MAX_ENC_LEN];
    size_t enc_str_len;
    size_t enc_str_pos;

    bool found;
    uint32_t found_nonce;
    char read_buf[MAX_ENC_LEN];
    size_t read_buf_len;
    size_t read_buf_pos;

    CURL *curl;
    FILE *curl_v_fp;
} task_t;

void task_clear(task_t *task);
int task_enc(task_t *task);
int task_dec(task_t *task);

#endif 

