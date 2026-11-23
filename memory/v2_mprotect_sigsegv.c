/* V2: mprotect + SIGSEGV single-page unlocking.
 *
 * The whole buffer is kept PROT_NONE (unreadable, and XORed). Touching a page
 * raises SIGSEGV; the handler unlocks and de-XORs just that one 4 KB page, lets
 * the access proceed, and (TODO) re-locks the previous page after a dwell timer.
 * So at any instant at most one page is readable, for a few milliseconds.
 *
 * This file is a WORKING SKELETON: the fault-driven unlock is implemented; the
 * dwell-based re-locking and the access pattern that drives it are the first
 * issue for this module (see .github issues / ROADMAP).
 *
 * Build: make v2
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>

#include "common/payload.h"

static uint8_t *g_buf;
static size_t g_len;

static void unlock_page(uint8_t *page) {
    mprotect(page, RTS_PAGE, PROT_READ | PROT_WRITE);
    rts_xor_page(page, RTS_PAGE);   /* reveal this page */
}

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    uintptr_t addr = (uintptr_t)si->si_addr;
    uintptr_t base = (uintptr_t)g_buf;
    if (addr < base || addr >= base + g_len) _exit(139);  /* not our buffer */
    uint8_t *page = (uint8_t *)(addr & ~(uintptr_t)(RTS_PAGE - 1));
    unlock_page(page);
    /* TODO(issue): record this page and re-lock the PREVIOUS one after a dwell. */
}

int main(void) {
    g_len = RTS_BUFSZ;
    g_buf = mmap(NULL, g_len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_buf == MAP_FAILED) { perror("mmap"); return 1; }
    rts_fill_marker(g_buf, g_len);
    for (size_t off = 0; off < g_len; off += RTS_PAGE)
        rts_xor_page(g_buf + off, RTS_PAGE);     /* hide everything */
    mprotect(g_buf, g_len, PROT_NONE);           /* lock everything */

    struct sigaction sa = {0};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    printf("[v2] pid=%d  buffer PROT_NONE; pages unlock on fault. Ctrl-C to stop.\n", getpid());
    fflush(stdout);

    volatile uint8_t sink = 0;
    for (;;) {
        /* Touch one page per second; the handler reveals it briefly. */
        size_t off = ((size_t)time(NULL) * RTS_PAGE) % g_len;
        sink ^= g_buf[off];
        mprotect(g_buf + (off & ~(size_t)(RTS_PAGE - 1)), RTS_PAGE, PROT_NONE); /* re-hide */
        sleep(1);
    }
    (void)sink;
    return 0;
}
