/* Allocate, touch and free large blocks, then malloc_trim() so glibc hands
 * the pages back with madvise(MADV_DONTNEED), as jemalloc/SQLite do.
 * Usage: malloc_churn SECONDS */
#define _GNU_SOURCE /* malloc_trim and CLOCK_MONOTONIC under -std=c11 */
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCKS 64
#define BLOCK_SIZE (512 * 1024)

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    double seconds = argc > 1 ? atof(argv[1]) : 30.0;
    double end = now() + seconds;
    long rounds = 0;
    void *blocks[BLOCKS];

    /* Keep blocks on the heap (not per-block mmap) so trim uses MADV_DONTNEED. */
    mallopt(M_MMAP_THRESHOLD, 64 * 1024 * 1024);
    mallopt(M_TRIM_THRESHOLD, 64 * 1024 * 1024);
    while (now() < end) {
        for (int i = 0; i < BLOCKS; i++) {
            blocks[i] = malloc(BLOCK_SIZE);
            if (!blocks[i]) return 1;
            memset(blocks[i], i, BLOCK_SIZE);
        }
        /* Free every other block so the free chunks are isolated by live
         * neighbours: malloc_trim then releases them with madvise(MADV_DONTNEED)
         * instead of just shrinking the heap with brk. */
        for (int i = 0; i < BLOCKS; i += 2) free(blocks[i]);
        malloc_trim(0);
        for (int i = 1; i < BLOCKS; i += 2) free(blocks[i]);
        malloc_trim(0);
        rounds++;
    }
    printf("[benign-malloc] %ld rounds\n", rounds);
    return 0;
}
