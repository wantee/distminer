#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#include "peon_utils.h"
#include "task.h"

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
static bool g_found = false;

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
        g_found = true;

        fprintf(stdout, "%s\toutput\tdrpc\t\tF%u\n", g_data_id, *(uint32_t*)&task->work->data[76]);
        fflush(stdout);
        fprintf(stdout, "%s\tack\n", g_data_id);
        fflush(stdout);
        STDERR_LOG("%s\toutput\tdrpc\t\tF%u\n", g_data_id, *(uint32_t*)&task->work->data[76]);
    }

    return last_nonce - first_nonce + 1;
}

int main(int argc, char *argv[])
{
    char line[2048];
    struct work work;
    task_t task;
    struct timeval tts;
    struct timeval tte;
    struct timeval tv_elapsed;
    double secs;
    uint64_t hashes;
    char *ptr;
    int c = 0;

    task.work = &work;
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

    while(fgets(line, 2048, stdin)) {
        ptr = strrchr(line, '\n');
        if (ptr != NULL) {
            *ptr = 0;
        }

        ptr = strchr(line, '\t');
        if (ptr == NULL) {
            fprintf(stdout, "%s\tack\n", line);
            fflush(stdout);
            continue;
        }

        *ptr = 0;
        strncpy(g_data_id, line, 2048);
        g_data_id[2047] = 0;

        ptr++;
        strncpy(task.enc_str, ptr, MAX_ENC_LEN);
        task.enc_str[MAX_ENC_LEN - 1] = 0;

        if (task_dec(&task) < 0) {
            STDERR_LOG("Failed to task_dec. str[%s]", task.enc_str);
            fprintf(stdout, "%s\tack\n", g_data_id);
            fflush(stdout);
            continue;
        }

        g_found = false;
        gettimeofday(&tts, NULL);
        hashes = peon_scanhash(&task);
        if (g_found == false) {
            fprintf(stdout, "%s\toutput\tdrpc\t\tN\n", g_data_id);
            fflush(stdout);
            fprintf(stdout, "%s\tack\n", g_data_id);
            fflush(stdout);
        }
        gettimeofday(&tte, NULL);

        timersub(&tte, &tts, &tv_elapsed);
	    secs = (double)tv_elapsed.tv_sec + ((double)tv_elapsed.tv_usec / 1000000.0);

        STDERR_LOG("Hashes Done: %"PRIu64", %.1f khash/sec. Time: %.3fs, Found: %s(%u)", hashes, 
                hashes / 1000 / secs, secs, 
                g_found ? "YES" : "NO", 
                g_found ? *(uint32_t*)&task.work->data[76] : 0);
    }

    return 0;
}

