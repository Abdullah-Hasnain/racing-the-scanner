/* V4: memfd_secret.
 *
 * The payload lives in a "secret" memory region created by memfd_secret(2).
 * Secret memory is removed from the kernel's direct map, so another process
 * reading /proc/<pid>/mem cannot see it at all: there is no window to race.
 * This is the "hard bypass" case that scheduling tricks cannot help with, and
 * that Tracee's syscall view (not the RAM scanner) is the way to catch.
 *
 * WORKING SKELETON: creates the secret fd, sizes it, maps it, writes the marker.
 * The access pattern and measurement hooks are this module's first issue.
 *
 * Needs Linux >= 5.14 with secret memory enabled (secretmem.enable=1 on many
 * distro kernels). memfd_secret is syscall 447 on the common arches.
 *
 * Build: make v4
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "common/payload.h"

#ifndef SYS_memfd_secret
#define SYS_memfd_secret 447
#endif

static int memfd_secret_compat(unsigned int flags) {
    return (int)syscall(SYS_memfd_secret, flags);
}

int main(void) {
    int fd = memfd_secret_compat(0);
    if (fd < 0) {
        perror("memfd_secret (needs Linux >=5.14 and secretmem.enable=1)");
        return 1;
    }
    if (ftruncate(fd, RTS_BUFSZ) < 0) { perror("ftruncate"); return 1; }

    uint8_t *buf = mmap(NULL, RTS_BUFSZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) { perror("mmap secret"); return 1; }
    rts_fill_marker(buf, RTS_BUFSZ);

    printf("[v4] pid=%d  marker in secret memory (off the direct map). Ctrl-C to stop.\n", getpid());
    fflush(stdout);

    volatile uint8_t sink = 0;
    for (;;) { sink ^= buf[0]; sleep(1); }
    (void)sink;
    return 0;
}
