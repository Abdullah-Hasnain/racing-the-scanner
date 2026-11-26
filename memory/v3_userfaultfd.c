/* V3: userfaultfd + MADV_DONTNEED page dropping with dwell-based reclamation.
 *
 * The 1 MB buffer's physical pages are dropped with MADV_DONTNEED and
 * registered with userfaultfd (MISSING mode). Touching a missing page pauses
 * the worker thread and notifies fault_thread over the uffd:
 *   - Worker faults (matched by kernel TID via UFFD_FEATURE_THREAD_ID) drop
 *     any previously exposed page and copy the de-XORed page back in via
 *     UFFDIO_COPY, arming a dwell deadline in ppoll().
 *   - Once dwell_ms elapses (or before serving a different page), fault_thread
 *     reclaims the page with MADV_DONTNEED, so at most one cleartext page is
 *     resident at any instant.
 *   - External /proc/<pid>/mem reads on missing pages are resolved with
 *     UFFDIO_ZEROPAGE (never leaking cleartext) and swept shortly afterward.
 *
 * Build: make -C memory
 * Run:   ./bin/v3 [--dwell-ms 10] [--interval-ms 100] [--pattern seq|random|stride]
 *                 [--duration 0] [--seed N]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "common/payload.h"

#ifndef UFFD_FEATURE_THREAD_ID
#error "Linux kernel headers with UFFD_FEATURE_THREAD_ID required"
#endif

#define DEFAULT_DWELL_MS    10.0
#define DEFAULT_INTERVAL_MS 100.0
#define DEFAULT_DURATION_S  0.0
#define DEFAULT_SEED        0x9e3779b97f4a7c15ULL
#define MIN_DWELL_US        100LL
#define STRIDE_PAGES        17
#define NUM_PAGES           (RTS_BUFSZ / RTS_PAGE)
#define DECOY_TTL_NS        2000000LL
#define MAX_ZERO_RETRIES    8

enum access_pattern {
    PAT_SEQ = 0,
    PAT_RANDOM,
    PAT_STRIDE,
};

static int g_uffd = -1;
static int g_stop_efd = -1;
static uint8_t *g_buf = NULL;
static uint8_t *g_store = NULL;
static size_t g_len = 0;

static pid_t g_worker_tid = 0;
static int g_user_mode_only = 0;
static long long g_dwell_ns = 10000000LL;
static volatile sig_atomic_t g_stop = 0;
static atomic_int g_shutting_down = 0;
static atomic_int g_fault_thread_failed = 0;

/* A stop is a signal (g_stop, set by the handler) or a dead fault thread, which
 * reports through an atomic rather than writing g_stop from another thread. */
static int stopping(void) {
    return g_stop || atomic_load_explicit(&g_fault_thread_failed, memory_order_acquire);
}

/* Decoy zero-fill pages mapped for external /proc/<pid>/mem readers. */
static atomic_uchar g_decoy_active[NUM_PAGES];
static long long g_decoy_deadline_ns[NUM_PAGES];

/* Active cleartext page state (owned exclusively by fault_thread). */
static uint8_t *g_active_page = NULL;
static long long g_dwell_deadline_ns = 0;

/* Metrics updated by fault_thread and printed by main after pthread_join(). */
static unsigned long g_faults = 0;
static unsigned long g_drops = 0;
static unsigned long g_timer_drops = 0;
static unsigned long g_swap_drops = 0;
static unsigned long g_ext_zerofills = 0;

static void zero_buf_volatile(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++)
        vp[i] = 0;
}

static long long now_monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

static long long elapsed_us(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)(now.tv_sec - start->tv_sec) * 1000000LL +
           (long long)(now.tv_nsec - start->tv_nsec) / 1000LL;
}

static void sleep_us_interruptible(long long us) {
    if (us <= 0 || stopping())
        return;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)(us / 1000000LL);
    deadline.tv_nsec += (long)(us % 1000000LL) * 1000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    while (!stopping()) {
        int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        if (rc == 0 || rc != EINTR)
            break;
    }
}

static void wake_range_helper(uintptr_t addr) {
    struct uffdio_range r = { .start = addr, .len = RTS_PAGE };
    (void)ioctl(g_uffd, UFFDIO_WAKE, &r);
}

static void expire_deadlines(long long now_ns) {
    if (g_active_page != NULL && now_ns >= g_dwell_deadline_ns) {
        (void)madvise(g_active_page, RTS_PAGE, MADV_DONTNEED);
        g_active_page = NULL;
        g_dwell_deadline_ns = 0;
        g_drops++;
        g_timer_drops++;
    }

    for (size_t i = 0; i < NUM_PAGES; i++) {
        if (g_decoy_deadline_ns[i] != 0 && now_ns >= g_decoy_deadline_ns[i]) {
            uint8_t *p = g_buf + i * RTS_PAGE;
            g_decoy_deadline_ns[i] = 0;
            atomic_store_explicit(&g_decoy_active[i], 0, memory_order_release);
            if (p != g_active_page)
                (void)madvise(p, RTS_PAGE, MADV_DONTNEED);
        }
    }
}

static void handle_worker_fault(uintptr_t addr, uint8_t *page, size_t idx) {
    g_decoy_deadline_ns[idx] = 0;
    atomic_store_explicit(&g_decoy_active[idx], 0, memory_order_release);

    if (g_active_page != NULL && g_active_page != page) {
        (void)madvise(g_active_page, RTS_PAGE, MADV_DONTNEED);
        g_active_page = NULL;
        g_dwell_deadline_ns = 0;
        g_drops++;
        g_swap_drops++;
    }

    uint8_t tmp[RTS_PAGE];
    memcpy(tmp, g_store + idx * RTS_PAGE, RTS_PAGE);
    rts_xor_page(tmp, RTS_PAGE);

    struct uffdio_copy copy = {
        .dst = addr,
        .src = (uintptr_t)tmp,
        .len = RTS_PAGE,
        .mode = 0,
        .copy = 0,
    };
    if (ioctl(g_uffd, UFFDIO_COPY, &copy) < 0) {
        if (errno == EEXIST) {
            (void)madvise(page, RTS_PAGE, MADV_DONTNEED);
            copy.copy = 0;
            if (ioctl(g_uffd, UFFDIO_COPY, &copy) < 0) {
                /* Still could not resolve the fault: wake the worker so it
                 * re-faults rather than blocking forever, and do not record a
                 * served page. */
                zero_buf_volatile(tmp, sizeof(tmp));
                wake_range_helper(addr);
                return;
            }
        } else {
            /* Any non-EEXIST failure (e.g. EAGAIN) leaves the page missing.
             * Wake the worker to retry instead of falling through and marking a
             * page resident that was never copied in. */
            zero_buf_volatile(tmp, sizeof(tmp));
            wake_range_helper(addr);
            return;
        }
    }
    zero_buf_volatile(tmp, sizeof(tmp));

    g_active_page = page;
    g_dwell_deadline_ns = now_monotonic_ns() + g_dwell_ns;
    g_faults++;
}

static void handle_external_fault(uintptr_t addr, uint8_t *page, size_t idx) {
    if (page == g_active_page) {
        wake_range_helper(addr);
        return;
    }

    atomic_store_explicit(&g_decoy_active[idx], 1, memory_order_release);
    struct uffdio_zeropage zp = {
        .range = { .start = addr, .len = RTS_PAGE },
        .mode = 0,
        .zeropage = 0,
    };
    if (ioctl(g_uffd, UFFDIO_ZEROPAGE, &zp) == 0) {
        g_decoy_deadline_ns[idx] = now_monotonic_ns() + DECOY_TTL_NS;
        g_ext_zerofills++;
    } else {
        atomic_store_explicit(&g_decoy_active[idx], 0, memory_order_release);
        if (errno == EEXIST)
            wake_range_helper(addr);
    }
}

static void *fault_thread(void *arg) {
    (void)arg;

    for (;;) {
        long long now_ns = now_monotonic_ns();
        expire_deadlines(now_ns);

        if (atomic_load_explicit(&g_shutting_down, memory_order_acquire))
            break;

        int has_deadline = 0;
        long long next_deadline_ns = 0;
        if (g_active_page != NULL) {
            has_deadline = 1;
            next_deadline_ns = g_dwell_deadline_ns;
        }
        for (size_t i = 0; i < NUM_PAGES; i++) {
            long long dl = g_decoy_deadline_ns[i];
            if (dl != 0 && (!has_deadline || dl < next_deadline_ns)) {
                has_deadline = 1;
                next_deadline_ns = dl;
            }
        }

        struct timespec ts = { 0, 0 };
        if (has_deadline) {
            long long rem_ns = next_deadline_ns - now_ns;
            if (rem_ns < 0)
                rem_ns = 0;
            ts.tv_sec = (time_t)(rem_ns / 1000000000LL);
            ts.tv_nsec = (long)(rem_ns % 1000000000LL);
        }

        struct pollfd pfds[2] = {
            { .fd = g_uffd,     .events = POLLIN, .revents = 0 },
            { .fd = g_stop_efd, .events = POLLIN, .revents = 0 },
        };
        int rc = ppoll(pfds, 2, has_deadline ? &ts : NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pfds[1].revents & POLLIN) {
            uint64_t v = 0;
            ssize_t r = read(g_stop_efd, &v, sizeof(v));
            (void)r;
            continue;
        }
        if (!(pfds[0].revents & POLLIN))
            continue;

        struct uffd_msg msg;
        ssize_t n = read(g_uffd, &msg, sizeof(msg));
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            break;
        }
        if (n != (ssize_t)sizeof(msg))
            break;
        if (msg.event != UFFD_EVENT_PAGEFAULT)
            continue;

        uintptr_t addr = (uintptr_t)msg.arg.pagefault.address & ~(uintptr_t)(RTS_PAGE - 1);
        uintptr_t base = (uintptr_t)g_buf;
        if (addr < base || addr >= base + g_len)
            continue;

        uint8_t *page = (uint8_t *)addr;
        size_t idx = (size_t)(page - g_buf) / RTS_PAGE;
        int is_worker = g_user_mode_only ||
                        ((pid_t)msg.arg.pagefault.feat.ptid == g_worker_tid);
        if (is_worker)
            handle_worker_fault(addr, page, idx);
        else
            handle_external_fault(addr, page, idx);
    }

    if (!atomic_load_explicit(&g_shutting_down, memory_order_acquire)) {
        /* An I/O error ended the loop, not a stop. With no handler left, a fault on
         * a registered page would block forever, so unregister (which also wakes
         * any thread already waiting) and stop the worker. The flag goes first, so
         * a worker woken by the unregister already sees the stop. */
        fprintf(stderr, "[v3] fault thread stopped on a userfaultfd error; stopping\n");
        atomic_store_explicit(&g_fault_thread_failed, 1, memory_order_release);
        struct uffdio_range all = { .start = (uintptr_t)g_buf, .len = g_len };
        (void)ioctl(g_uffd, UFFDIO_UNREGISTER, &all);
    }

    if (g_active_page != NULL) {
        (void)madvise(g_active_page, RTS_PAGE, MADV_DONTNEED);
        g_active_page = NULL;
        g_dwell_deadline_ns = 0;
        g_drops++;
    }
    for (size_t i = 0; i < NUM_PAGES; i++) {
        if (g_decoy_deadline_ns[i] != 0) {
            g_decoy_deadline_ns[i] = 0;
            atomic_store_explicit(&g_decoy_active[i], 0, memory_order_release);
            (void)madvise(g_buf + i * RTS_PAGE, RTS_PAGE, MADV_DONTNEED);
        }
    }
    return NULL;
}

static void stop_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static size_t next_page_idx(enum access_pattern pat, size_t cur,
                            size_t num_pages, uint64_t *rng) {
    if (num_pages <= 1)
        return 0;
    switch (pat) {
    case PAT_SEQ:
        return (cur + 1) % num_pages;
    case PAT_STRIDE:
        return (cur + STRIDE_PAGES) % num_pages;
    case PAT_RANDOM: {
        size_t next = (size_t)(xorshift64(rng) % num_pages);
        if (next == cur)
            next = (next + 1) % num_pages;
        return next;
    }
    }
    return (cur + 1) % num_pages;
}

static const char *pattern_name(enum access_pattern pat) {
    switch (pat) {
    case PAT_SEQ:    return "seq";
    case PAT_RANDOM: return "random";
    case PAT_STRIDE: return "stride";
    }
    return "seq";
}

static int parse_nonneg_double(const char *s, double *out) {
    if (!s || !*s)
        return -1;
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (errno != 0 || end == s || *end != '\0')
        return -1;
    if (!(v >= 0.0 && v <= 1e9))
        return -1;
    *out = v;
    return 0;
}

static int parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s || *s == '-')
        return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0')
        return -1;
    *out = (uint64_t)v;
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n"
           "  --dwell-ms <ms>           Page exposure window in ms (default %.1f, min 0.1)\n"
           "  --interval-ms <ms>        Delay between page touches in ms (default %.1f, 0=tight)\n"
           "  --pattern <seq|random|stride>  Page access pattern (default seq)\n"
           "  --duration <sec>          Run duration in seconds (default 0=until Ctrl-C)\n"
           "  --seed <u64>              PRNG seed for random pattern\n"
           "  -h, --help                Show this help\n",
           prog, DEFAULT_DWELL_MS, DEFAULT_INTERVAL_MS);
}

int main(int argc, char **argv) {
    double dwell_ms = DEFAULT_DWELL_MS;
    double interval_ms = DEFAULT_INTERVAL_MS;
    double duration_s = DEFAULT_DURATION_S;
    enum access_pattern pat = PAT_SEQ;
    uint64_t rng = DEFAULT_SEED;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--dwell-ms") == 0 && i + 1 < argc) {
            if (parse_nonneg_double(argv[++i], &dwell_ms) != 0) {
                fprintf(stderr, "[v3] invalid --dwell-ms: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            if (parse_nonneg_double(argv[++i], &interval_ms) != 0) {
                fprintf(stderr, "[v3] invalid --interval-ms: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            if (parse_nonneg_double(argv[++i], &duration_s) != 0) {
                fprintf(stderr, "[v3] invalid --duration: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (parse_u64(argv[++i], &rng) != 0) {
                fprintf(stderr, "[v3] invalid --seed: %s\n", argv[i]);
                return 1;
            }
            if (rng == 0)
                rng = 1;
        } else if (strcmp(argv[i], "--pattern") == 0 && i + 1 < argc) {
            const char *p = argv[++i];
            if (strcmp(p, "seq") == 0) pat = PAT_SEQ;
            else if (strcmp(p, "random") == 0) pat = PAT_RANDOM;
            else if (strcmp(p, "stride") == 0) pat = PAT_STRIDE;
            else {
                fprintf(stderr, "[v3] unknown --pattern: %s\n", p);
                return 1;
            }
        } else {
            fprintf(stderr, "[v3] unknown or incomplete option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    long long dwell_us = (long long)(dwell_ms * 1000.0 + 0.5);
    if (dwell_us < MIN_DWELL_US) {
        fprintf(stderr, "[v3] clamping --dwell-ms to %.1f ms minimum\n",
                (double)MIN_DWELL_US / 1000.0);
        dwell_us = MIN_DWELL_US;
        dwell_ms = (double)MIN_DWELL_US / 1000.0;
    }
    g_dwell_ns = dwell_us * 1000LL;
    long long interval_us = (long long)(interval_ms * 1000.0 + 0.5);
    long long duration_us = (long long)(duration_s * 1000000.0 + 0.5);

    g_worker_tid = (pid_t)syscall(SYS_gettid);
    g_len = RTS_BUFSZ;

    g_store = malloc(g_len);
    if (!g_store) {
        perror("malloc");
        return 1;
    }
    rts_fill_marker(g_store, g_len);
    rts_xor_page(g_store, g_len);

    g_buf = mmap(NULL, g_len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_buf == MAP_FAILED) {
        perror("mmap");
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }

    g_stop_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (g_stop_efd < 0) {
        perror("eventfd");
        munmap(g_buf, g_len);
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }

    g_uffd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
#ifdef UFFD_USER_MODE_ONLY
    if (g_uffd < 0 && errno == EPERM) {
        g_uffd = (int)syscall(SYS_userfaultfd,
                              O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
        if (g_uffd >= 0) {
            g_user_mode_only = 1;
            fprintf(stderr,
                    "[v3] note: fell back to UFFD_USER_MODE_ONLY; kernel-originated "
                    "faults (including /proc/<pid>/mem reads) are not delivered and "
                    "will return EIO instead of zero-fill. Set sysctl "
                    "vm.unprivileged_userfaultfd=1 or grant CAP_SYS_PTRACE for "
                    "scanner runs.\n");
        }
    }
#endif
    if (g_uffd < 0) {
        perror("userfaultfd (needs Linux + permission)");
        close(g_stop_efd);
        munmap(g_buf, g_len);
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }

    struct uffdio_api api = {
        .api = UFFD_API,
        .features = UFFD_FEATURE_THREAD_ID,
        .ioctls = 0,
    };
    if (ioctl(g_uffd, UFFDIO_API, &api) < 0) {
        perror("UFFDIO_API");
        close(g_uffd);
        close(g_stop_efd);
        munmap(g_buf, g_len);
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }
    if ((api.features & UFFD_FEATURE_THREAD_ID) == 0) {
        fprintf(stderr, "[v3] kernel does not support UFFD_FEATURE_THREAD_ID\n");
        close(g_uffd);
        close(g_stop_efd);
        munmap(g_buf, g_len);
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }

    struct uffdio_register reg = {
        .range = { .start = (uintptr_t)g_buf, .len = g_len },
        .mode = UFFDIO_REGISTER_MODE_MISSING,
        .ioctls = 0,
    };
    if (ioctl(g_uffd, UFFDIO_REGISTER, &reg) < 0) {
        perror("uffd register");
        close(g_uffd);
        close(g_stop_efd);
        munmap(g_buf, g_len);
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }

    if (madvise(g_buf, g_len, MADV_DONTNEED) != 0) {
        perror("madvise");
        (void)ioctl(g_uffd, UFFDIO_UNREGISTER, &reg.range);
        close(g_uffd);
        close(g_stop_efd);
        munmap(g_buf, g_len);
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }

    sigset_t stop_mask, old_mask;
    sigemptyset(&stop_mask);
    sigaddset(&stop_mask, SIGINT);
    sigaddset(&stop_mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &stop_mask, &old_mask);

    pthread_t th;
    int th_rc = pthread_create(&th, NULL, fault_thread, NULL);
    if (th_rc != 0) {
        pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        fprintf(stderr, "[v3] pthread_create: %s\n", strerror(th_rc));
        (void)ioctl(g_uffd, UFFDIO_UNREGISTER, &reg.range);
        close(g_uffd);
        close(g_stop_efd);
        munmap(g_buf, g_len);
        zero_buf_volatile(g_store, g_len);
        free(g_store);
        return 1;
    }

    /* Install the stop handlers while SIGINT/SIGTERM are still blocked, then
     * unblock, so there is no window where a signal takes the default action.
     * The fault thread was created under the block and keeps it, so only the
     * main worker services the stop. */
    struct sigaction sa_stop;
    memset(&sa_stop, 0, sizeof(sa_stop));
    sa_stop.sa_handler = stop_handler;
    sigemptyset(&sa_stop.sa_mask);
    if (sigaction(SIGINT, &sa_stop, NULL) != 0 || sigaction(SIGTERM, &sa_stop, NULL) != 0) {
        perror("sigaction SIGINT/SIGTERM");
        return 1;
    }
    pthread_sigmask(SIG_SETMASK, &old_mask, NULL);

    printf("[v3] pid=%d  dwell_ms=%.2f interval_ms=%.2f pattern=%s (buf=%p len=%zu). Ctrl-C to stop.\n",
           getpid(), dwell_ms, interval_ms, pattern_name(pat), (void *)g_buf, g_len);
    fflush(stdout);

    size_t num_pages = g_len / RTS_PAGE;
    size_t mlen = strlen(RTS_MARKER);
    size_t page_idx = 0;
    volatile uint8_t *vbuf = g_buf;
    volatile uint8_t sink = 0;
    unsigned long accesses = 0;
    int status = 0;

    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    while (!stopping()) {
        if (duration_us > 0 && elapsed_us(&t_start) >= duration_us)
            break;

        size_t off = page_idx * RTS_PAGE;
        if (atomic_load_explicit(&g_decoy_active[page_idx], memory_order_acquire) != 0)
            (void)madvise(g_buf + off, RTS_PAGE, MADV_DONTNEED);

        /* A zero first byte means the page is still a decoy zero-fill (or not yet
         * faulted in), so drop it and re-read to force a real fault. This relies
         * on RTS_MARKER (common/payload.h) having no 0x00 bytes, so real
         * cleartext never starts a page with zero. */
        /* Check two offsets, not just the first byte, so a partial de-XOR or a
         * wrong-offset copy is caught rather than passing on a single byte. Both
         * reads retry, because the page can be dropped between them. */
        size_t off2 = off + RTS_PAGE / 2;
        uint8_t val = vbuf[off];
        uint8_t val2 = vbuf[off2];
        for (int attempt = 0; (val == 0 || val2 == 0) && attempt < MAX_ZERO_RETRIES && !stopping(); attempt++) {
            (void)madvise(g_buf + off, RTS_PAGE, MADV_DONTNEED);
            val = vbuf[off];
            val2 = vbuf[off2];
        }
        if ((val == 0 || val2 == 0) && stopping())
            break;

        uint8_t expected = (uint8_t)RTS_MARKER[off % mlen];
        uint8_t expected2 = (uint8_t)RTS_MARKER[off2 % mlen];
        if (val != expected || val2 != expected2) {
            fprintf(stderr,
                    "[v3] integrity mismatch: off=%zu got=0x%02x exp=0x%02x, "
                    "off=%zu got=0x%02x exp=0x%02x\n",
                    off, val, expected, off2, val2, expected2);
            status = 2;
            break;
        }
        sink ^= val;
        accesses++;

        page_idx = next_page_idx(pat, page_idx, num_pages, &rng);
        sleep_us_interruptible(interval_us);
    }

    atomic_store_explicit(&g_shutting_down, 1, memory_order_release);
    uint64_t stop_val = 1;
    ssize_t wr = write(g_stop_efd, &stop_val, sizeof(stop_val));
    (void)wr;
    pthread_join(th, NULL);
    if (atomic_load_explicit(&g_fault_thread_failed, memory_order_acquire) && status == 0)
        status = 3;

    (void)ioctl(g_uffd, UFFDIO_UNREGISTER, &reg.range);

    double secs = (double)elapsed_us(&t_start) / 1000000.0;
    double fps = secs > 0.0 ? (double)g_faults / secs : 0.0;
    printf("[v3] done: accesses=%lu faults=%lu drops=%lu (timer=%lu, swap=%lu) ext_zerofills=%lu elapsed_s=%.3f faults_per_s=%.1f\n",
           accesses, g_faults, g_drops, g_timer_drops, g_swap_drops, g_ext_zerofills, secs, fps);
    fflush(stdout);

    (void)sink;
    close(g_uffd);
    close(g_stop_efd);
    munmap(g_buf, g_len);
    zero_buf_volatile(g_store, g_len);
    free(g_store);
    return status;
}
