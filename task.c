#include "task.h"

int task_write(task_t *task, FILE *fp)
{
    if (fwrite(task, sizeof(task_t), 1, fp) != sizeof(task_t)) {
        fprintf(stderr, "Failed to fwrite task");
        return -1;
    }
    fflush(fp);

    return 0;
}

int task_read(task_t *task, FILE *fp)
{
    if (fread(task, sizeof(task_t), 1, fp) != sizeof(task_t)) {
        fprintf(stderr, "Failed to fread task");
        return -1;
    }

    return 0;
}

