/* V1 baseline: a plain, readable 1 MB buffer holding the marker.
 *
 * This is the control: the scanner should ALWAYS find it. It exists so the
 * other variants have something to be measured against.
 *
 * Build:  make v1   (or: gcc -O2 -o bin/v1 v1_baseline.c)
 * Run:    ./bin/v1   (prints its PID; keep it alive while the scanner runs)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "common/payload.h"

int main(void) {
    uint8_t *buf = malloc(RTS_BUFSZ);
    if (!buf) { perror("malloc"); return 1; }
    rts_fill_marker(buf, RTS_BUFSZ);

    printf("[v1] pid=%d  1MB plaintext marker resident. Ctrl-C to stop.\n", getpid());
    fflush(stdout);

    volatile uint8_t sink = 0;
    for (;;) {
        sink ^= buf[0];      /* keep it referenced so it stays resident */
        sleep(1);
    }
    (void)sink;
    free(buf);
    return 0;
}
