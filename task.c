#include <stdint.h>
#include <libbase58.h>

#include "task.h"

int task_dec(task_t *task)
{
#define ENC_SIZE (256 + 8)
    char enc_bin[ENC_SIZE];
    size_t enc_sz = ENC_SIZE;
    size_t sz;
    char *ptr;

    ptr = strchr(task->enc_str, '\t');
    if (ptr == NULL) {
        fprintf(stderr, "Error task enc str");
        return -1;
    }
    sz = strlen(ptr);

    if (!b58tobin(enc_bin, &enc_sz, ptr, sz)) {
        fprintf(stderr, "Failed to b58tobin");
        return -1;
    }

    if (b58check(enc_bin, ENC_SIZE, ptr, sz) < 0) {
        fprintf(stderr, "Failed to b58check");
        return -1;
    }

    memcpy(task->work->data, enc_bin, 128);
    memcpy(task->work->midstate, enc_bin + 128, 32);
    memcpy(task->work->target, enc_bin + 128 + 32, 32);
    memcpy(task->work->hash, enc_bin + 128 + 32 + 32, 32);

    memcpy(&task->first_nonce, enc_bin + 256, 4); 
    memcpy(&task->last_nonce, enc_bin + 256 + 4, 4); 

    return 0;
}

int task_enc(task_t *task)
{
    char enc_bin[256 + 8];
    bool rv;
    int res;

    task->enc_str_pos = 0;

    res = snprintf(task->enc_str, MAX_ENC_LEN, "%d-%d\t", task->work->id, task->id);

    task->enc_str_len = MAX_ENC_LEN - res;

    memcpy(enc_bin, task->work->data, 128);
    memcpy(enc_bin + 128, task->work->midstate, 32);
    memcpy(enc_bin + 128 + 32, task->work->target, 32);
    memcpy(enc_bin + 128 + 32 + 32, task->work->hash, 32);

    memcpy(enc_bin + 256, &task->first_nonce, 4); 
    memcpy(enc_bin + 256 + 4, &task->last_nonce, 4); 

    rv = b58enc(task->enc_str + res, &task->enc_str_len, enc_bin, 256 + 8);
    if (!rv) {
        fprintf(stderr, "Failed to encenc");
        task->enc_str_len = 0;
        return -1;
    }

    task->enc_str_len += res;

    return 0;
}

