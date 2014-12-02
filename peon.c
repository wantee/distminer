#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#include "peon_utils.h"
#include "sha256_sse4_amd64_peon.h"
#include "task.h"

#define PEON_LOG(fmt, ...) \
    fprintf(stderr, "[%s:%d<<%s>>] " fmt "\n", __FILE__, __LINE__, __func__, \
    ##__VA_ARGS__);

void show_usage(char *module_name)
{
    printf("\n");
    printf("Version    :  %s\n", VERSION);
    printf("Description:  Dist-miner Peon\n");
    printf("Usage: %s [-h|v] < task\n", module_name);
    printf("\t-v|-h\tshow help and version, i.e. this page\n");
    printf("\n");
}

static uint64_t peon_scanhash(task_t *task)
{
    uint32_t first_nonce = task->nonce;
    uint32_t last_nonce;
    bool rc;

    last_nonce = first_nonce;
    rc = false;

    /* scan nonces for a proof-of-work hash */
    rc = scanhash_sse4_64_peon(
            task->midstate,
            task->data,
            task->hash1,
            task->hash,
            task->target,
            task->max_nonce,
            &last_nonce,
            task->nonce
            );

    /* if nonce found, submit task */
    if (unlikely(rc)) {
        PEON_LOG("Found something?");
        if (unlikely(task_write(task, stdout) < 0)) {
            PEON_LOG("Failed to task_submit!!");
        }
        task->nonce = last_nonce + 1;
    } else if (unlikely(last_nonce == first_nonce)) {
        return 0;
    }

    task->nonce = last_nonce + 1;
    return last_nonce - first_nonce + 1;
}

int main(int argc, char *argv[])
{
    task_t task;
    uint64_t hashes;
    int c = 0;

    signal(SIGPIPE, SIG_IGN);

    while ((c = getopt(argc, argv, "hv")) != -1) {
        switch (c) {
            case 'h':
            case 'v':
            case '?':
                show_usage(argv[0]);
                exit(-1);
        }
    }

    if (task_read(&task, stdin) < 0) {
        PEON_LOG("Failed to peon_read_task.");
        return -1;
    }

    hashes = peon_scanhash(&task);
    if (hashes == 0) {
        PEON_LOG("Failed to peon_scanhash.");
        return -1;
    }

    PEON_LOG("Hashes Done: %lu", hashes);

    return 0;
}

