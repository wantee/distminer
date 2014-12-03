#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#include "peon_utils.h"
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

const uint32_t hash1_init[] = {
	0,0,0,0,0,0,0,0,
	0x80000000,
	  0,0,0,0,0,0,
	          0x100,
};

extern bool scanhash_sse4_64(struct thr_info *, struct work *, uint32_t max_nonce, uint32_t *last_nonce, uint32_t nonce);

static char g_data_id[2048];

static uint64_t peon_scanhash(task_t *task)
{
    uint32_t first_nonce = task->first_nonce;
    uint32_t last_nonce;
    bool rc;

    last_nonce = first_nonce;
    rc = false;

    /* scan nonces for a proof-of-work hash */
    rc = scanhash_sse4_64(
            task->thr,
            task->work,
            task->last_nonce,
            &last_nonce,
            task->first_nonce
            );

    /* if nonce found, submit task */
    if (unlikely(rc)) {
        PEON_LOG("Found something?");
        printf("%s\toutput\tdrpc\t\t%u\n", g_data_id, *(uint32_t*)&task->work->data[76]);
        fflush(stdout);
    } else if (unlikely(last_nonce == first_nonce)) {
        return 0;
    }

    return last_nonce - first_nonce + 1;
}

int main(int argc, char *argv[])
{
    task_t task;
    uint64_t hashes;
    char *ptr;
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

    while(fgets(task.enc_str, MAX_ENC_LEN, stdin)) {
        ptr = strrchr(task.enc_str, '\n');
        if (ptr != NULL) {
            *ptr = 0;
        }

        if (task_dec(&task) < 0) {
            PEON_LOG("Failed to task_dec.");
            return -1;
        }

        hashes = peon_scanhash(&task);
        if (hashes == 0) {
            PEON_LOG("Failed to peon_scanhash.");
            return -1;
        }

        PEON_LOG("Hashes Done: %lu", hashes);
    }

    return 0;
}

