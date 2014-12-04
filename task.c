#include <stdint.h>
#include <libbase58.h>

#include "peon_utils.h"
#include "task.h"

void task_clear(task_t *task)
{
    memset(task, 0, sizeof(task_t));
    task->enc_str_len = MAX_ENC_LEN;
    task->read_buf_len = MAX_ENC_LEN;
}

int task_dec(task_t *task)
{
#define ENC_SIZE (224 + 8)
    char enc_bin[ENC_SIZE];
    uint8_t cbin[ENC_SIZE];
    size_t enc_sz = ENC_SIZE;

    if (!b58tobin(enc_bin, &enc_sz, task->enc_str, strlen(task->enc_str))) {
        STDERR_LOG("Failed to b58tobin");
        return -1;
    }

    if (enc_sz != ENC_SIZE) {
        STDERR_LOG("Error b58bin. size[%lu] != %u", enc_sz, ENC_SIZE);
        return -1;
    }

    memcpy(task->work->data, enc_bin, 128);
    memcpy(task->work->midstate, enc_bin + 128, 32);
    memcpy(task->work->target, enc_bin + 128 + 32, 32);
    memcpy(task->work->hash, enc_bin + 128 + 32 + 32, 32);

    memcpy(&task->first_nonce, enc_bin + 224, 4); 
    memcpy(&task->last_nonce, enc_bin + 224 + 4, 4); 

    return 0;
}

int task_enc(task_t *task)
{
    char enc_bin[224 + 8];
    bool rv;

    task->enc_str_pos = 0;
    task->enc_str_len = MAX_ENC_LEN;

    memcpy(enc_bin, task->work->data, 128);
    memcpy(enc_bin + 128, task->work->midstate, 32);
    memcpy(enc_bin + 128 + 32, task->work->target, 32);
    memcpy(enc_bin + 128 + 32 + 32, task->work->hash, 32);

    memcpy(enc_bin + 224, &task->first_nonce, 4); 
    memcpy(enc_bin + 224 + 4, &task->last_nonce, 4); 

    rv = b58enc(task->enc_str, &task->enc_str_len, enc_bin, 224 + 8);
    if (!rv) {
        STDERR_LOG("Failed to encenc");
        task->enc_str_len = 0;
        return -1;
    }

    return 0;
}

