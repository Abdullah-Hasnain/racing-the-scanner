/* V2: mprotect + SIGSEGV single-page unlocking with dwell-based re-locking.
 *
 * The whole 1 MB buffer is kept PROT_NONE and XORed. Touching a page raises
 * SIGSEGV; the handler unlocks and de-XORs just that one 4 KB page and arms a
 * one-shot ITIMER_REAL dwell timer. Either the timer (SIGALRM) re-XORs and
 * re-locks the page after dwell_ms, or the next page fault swaps it out first,
 * so at most one page is readable at any instant.
 *
 * Build: make -C memory
 * Run:   ./bin/v2 [--dwell-ms 10] [--interval-ms 100] [--pattern seq|random|stride]
 *                 [--duration 0] [--seed N]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "common/payload.h"

#define DEFAULT_DWELL_MS    10.0
#define DEFAULT_INTERVAL_MS 100.0
#define DEFAULT_DURATION_S  0.0
#define DEFAULT_SEED        0x9e3779b97f4a7c15ULL
#define MIN_DWELL_US        100LL
#define STRIDE_PAGES        17

enum access_pattern {
    PAT_SEQ = 0,
    PAT_RANDOM,
    PAT_STRIDE,
};

static uint8_t *g_buf = NULL;
static size_t g_len = 0;
static uint8_t * volatile g_active_page = NULL;
static long long g_dwell_us = 10000;
static volatile sig_atomic_t g_stop = 0;

static volatile unsigned long g_faults = 0;
static volatile unsigned long g_relocks = 0;
static volatile unsigned long g_timer_relocks = 0;
static volatile unsigned long g_swap_relocks = 0;

static void unlock_page(uint8_t *page) {
    if (mprotect(page, RTS_PAGE, PROT_READ | PROT_WRITE) != 0)
        _exit(1);
    rts_xor_page(page, RTS_PAGE);
}

static void lock_page(uint8_t *page) {
    rts_xor_page(page, RTS_PAGE);
    if (mprotect(page, RTS_PAGE, PROT_NONE) != 0)
        _exit(1);
}

static void disarm_dwell_timer(void) {
    struct itimerval zero = {{0, 0}, {0, 0}};
    (void)setitimer(ITIMER_REAL, &zero, NULL);
}

static void arm_dwell_timer(long long dwell_us) {
    struct itimerval it;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;
    it.it_value.tv_sec = (time_t)(dwell_us / 1000000LL);
    it.it_value.tv_usec = (suseconds_t)(dwell_us % 1000000LL);
    (void)setitimer(ITIMER_REAL, &it, NULL);
}

static void segv_handler(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    uintptr_t addr = (uintptr_t)si->si_addr;
    uintptr_t base = (uintptr_t)g_buf;
    if (addr < base || addr >= base + g_len)
        _exit(139);

    uint8_t *page = (uint8_t *)(addr & ~(uintptr_t)(RTS_PAGE - 1));

    if (g_active_page != NULL && g_active_page != page) {
        disarm_dwell_timer();
        lock_page(g_active_page);
        g_active_page = NULL;
        g_relocks++;
        g_swap_relocks++;
    }

    if (g_active_page != page) {
        unlock_page(page);
        g_active_page = page;
        g_faults++;
    }

    arm_dwell_timer(g_dwell_us);
}

static void dwell_handler(int sig) {
    (void)sig;
    if (g_active_page != NULL) {
        lock_page(g_active_page);
        g_active_page = NULL;
        g_relocks++;
        g_timer_relocks++;
    }
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

static long long elapsed_us(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)(now.tv_sec - start->tv_sec) * 1000000LL +
           (long long)(now.tv_nsec - start->tv_nsec) / 1000LL;
}

static void sleep_us_interruptible(long long us) {
    if (us <= 0 || g_stop)
        return;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)(us / 1000000LL);
    deadline.tv_nsec += (long)(us % 1000000LL) * 1000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    while (!g_stop) {
        int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        if (rc == 0 || rc != EINTR)
            break;
    }
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
                fprintf(stderr, "[v2] invalid --dwell-ms: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            if (parse_nonneg_double(argv[++i], &interval_ms) != 0) {
                fprintf(stderr, "[v2] invalid --interval-ms: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            if (parse_nonneg_double(argv[++i], &duration_s) != 0) {
                fprintf(stderr, "[v2] invalid --duration: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (parse_u64(argv[++i], &rng) != 0) {
                fprintf(stderr, "[v2] invalid --seed: %s\n", argv[i]);
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
                fprintf(stderr, "[v2] unknown --pattern: %s\n", p);
                return 1;
            }
        } else {
            fprintf(stderr, "[v2] unknown or incomplete option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    long long dwell_us = (long long)(dwell_ms * 1000.0 + 0.5);
    if (dwell_us < MIN_DWELL_US) {
        fprintf(stderr, "[v2] clamping --dwell-ms to %.1f ms minimum\n",
                (double)MIN_DWELL_US / 1000.0);
        dwell_us = MIN_DWELL_US;
        dwell_ms = (double)MIN_DWELL_US / 1000.0;
    }
    g_dwell_us = dwell_us;
    long long interval_us = (long long)(interval_ms * 1000.0 + 0.5);
    long long duration_us = (long long)(duration_s * 1000000.0 + 0.5);

    g_len = RTS_BUFSZ;
    g_buf = mmap(NULL, g_len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    rts_fill_marker(g_buf, g_len);
    for (size_t off = 0; off < g_len; off += RTS_PAGE)
        rts_xor_page(g_buf + off, RTS_PAGE);
    if (mprotect(g_buf, g_len, PROT_NONE) != 0) {
        perror("mprotect");
        munmap(g_buf, g_len);
        return 1;
    }

    struct sigaction sa_segv;
    memset(&sa_segv, 0, sizeof(sa_segv));
    sa_segv.sa_sigaction = segv_handler;
    sa_segv.sa_flags = SA_SIGINFO;
    sigemptyset(&sa_segv.sa_mask);
    sigaddset(&sa_segv.sa_mask, SIGALRM);
    if (sigaction(SIGSEGV, &sa_segv, NULL) != 0) {
        perror("sigaction SIGSEGV");
        munmap(g_buf, g_len);
        return 1;
    }

    struct sigaction sa_alrm;
    memset(&sa_alrm, 0, sizeof(sa_alrm));
    sa_alrm.sa_handler = dwell_handler;
    sa_alrm.sa_flags = SA_RESTART;
    sigemptyset(&sa_alrm.sa_mask);
    sigaddset(&sa_alrm.sa_mask, SIGSEGV);
    if (sigaction(SIGALRM, &sa_alrm, NULL) != 0) {
        perror("sigaction SIGALRM");
        munmap(g_buf, g_len);
        return 1;
    }

    struct sigaction sa_stop;
    memset(&sa_stop, 0, sizeof(sa_stop));
    sa_stop.sa_handler = stop_handler;
    sigemptyset(&sa_stop.sa_mask);
    sigaction(SIGINT, &sa_stop, NULL);
    sigaction(SIGTERM, &sa_stop, NULL);

    printf("[v2] pid=%d  dwell_ms=%.2f interval_ms=%.2f pattern=%s (buf=%p len=%zu). Ctrl-C to stop.\n",
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

    while (!g_stop) {
        if (duration_us > 0 && elapsed_us(&t_start) >= duration_us)
            break;

        size_t off = page_idx * RTS_PAGE;
        uint8_t val = vbuf[off];
        uint8_t expected = (uint8_t)RTS_MARKER[off % mlen];
        if (val != expected) {
            fprintf(stderr,
                    "[v2] integrity mismatch at off=%zu: got=0x%02x expected=0x%02x\n",
                    off, val, expected);
            status = 2;
            break;
        }
        sink ^= val;
        accesses++;

        page_idx = next_page_idx(pat, page_idx, num_pages, &rng);
        sleep_us_interruptible(interval_us);
    }

    sigset_t alrm_set;
    sigemptyset(&alrm_set);
    sigaddset(&alrm_set, SIGALRM);
    sigprocmask(SIG_BLOCK, &alrm_set, NULL);
    disarm_dwell_timer();
    if (g_active_page != NULL) {
        lock_page(g_active_page);
        g_active_page = NULL;
        g_relocks++;
    }

    double secs = (double)elapsed_us(&t_start) / 1000000.0;
    double fps = secs > 0.0 ? (double)g_faults / secs : 0.0;
    printf("[v2] done: accesses=%lu faults=%lu relocks=%lu (timer=%lu, swap=%lu) elapsed_s=%.3f faults_per_s=%.1f\n",
           accesses, g_faults, g_relocks, g_timer_relocks, g_swap_relocks, secs, fps);
    fflush(stdout);

    (void)sink;
    munmap(g_buf, g_len);
    return status;
}
