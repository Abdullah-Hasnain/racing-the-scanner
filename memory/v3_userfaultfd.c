/* V3: userfaultfd + MADV_DONTNEED page dropping.
 *
 * The buffer's physical pages are dropped back to the OS with MADV_DONTNEED and
 * registered with userfaultfd. When the program touches a missing page, a helper
 * thread catches the fault over the uffd and copies the (de-XORed) page back in
 * on demand, then (TODO) drops it again after use. External /proc/<pid>/mem
 * reads of a dropped page see zero-fill, not the marker.
 *
 * WORKING SKELETON: uffd registration + a fault-handling thread are set up; the
 * drop-after-use cycle and the measurement hooks are the module's first issue.
 *
 * Build: make v3   (Linux only; needs userfaultfd support)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>

#include "common/payload.h"

static int g_uffd;
static uint8_t *g_buf;
static size_t g_len;

static void *fault_thread(void *arg) {
    (void)arg;
    for (;;) {
        struct uffd_msg msg;
        struct pollfd pfd = { .fd = g_uffd, .events = POLLIN };
        if (poll(&pfd, 1, -1) < 0) break;
        if (read(g_uffd, &msg, sizeof(msg)) <= 0) break;
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        uintptr_t addr = (uintptr_t)msg.arg.pagefault.address & ~(uintptr_t)(RTS_PAGE - 1);
        uint8_t page[RTS_PAGE];
        rts_fill_marker(page, RTS_PAGE);   /* reconstruct this page's cleartext */

        struct uffdio_copy copy = {
            .dst = addr, .src = (uintptr_t)page, .len = RTS_PAGE, .mode = 0,
        };
        ioctl(g_uffd, UFFDIO_COPY, &copy);
        /* TODO(issue): after a short dwell, MADV_DONTNEED this page again. */
    }
    return NULL;
}

int main(void) {
    g_len = RTS_BUFSZ;
    g_buf = mmap(NULL, g_len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_buf == MAP_FAILED) { perror("mmap"); return 1; }

    g_uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (g_uffd < 0) { perror("userfaultfd (needs Linux + permission)"); return 1; }

    struct uffdio_api api = { .api = UFFD_API };
    ioctl(g_uffd, UFFDIO_API, &api);
    struct uffdio_register reg = {
        .range = { .start = (uintptr_t)g_buf, .len = g_len },
        .mode = UFFDIO_REGISTER_MODE_MISSING,
    };
    if (ioctl(g_uffd, UFFDIO_REGISTER, &reg) < 0) { perror("uffd register"); return 1; }

    madvise(g_buf, g_len, MADV_DONTNEED);   /* drop all physical pages */

    pthread_t th;
    pthread_create(&th, NULL, fault_thread, NULL);

    printf("[v3] pid=%d  pages dropped; refilled on fault via uffd. Ctrl-C to stop.\n", getpid());
    fflush(stdout);

    volatile uint8_t sink = 0;
    for (;;) { sink ^= g_buf[0]; sleep(1); }
    (void)sink;
    return 0;
}
