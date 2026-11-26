/* V4: memfd_secret.
 *
 * The payload lives in a "secret" memory region created by memfd_secret(2).
 * Secret memory is removed from the kernel's direct map, so another process
 * reading /proc/<pid>/mem cannot see it at all: there is no window to race.
 * This is the "hard bypass" case that scheduling tricks cannot help with, and
 * that Tracee's syscall view (not the RAM scanner) is the way to catch.
 *
 * Needs Linux >= 5.14 with secret memory enabled (secretmem.enable=1 on many
 * distro kernels). memfd_secret is syscall 447 on the common arches.
 *
 * Build: make -C memory
 * Run:   ./bin/v4 [--interval-ms 100] [--pattern seq|random|stride]
 *                 [--duration 0] [--seed N]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "common/payload.h"

#ifndef SYS_memfd_secret
#define SYS_memfd_secret 447
#endif

#define DEFAULT_INTERVAL_MS 100.0
#define DEFAULT_DURATION_S  0.0
#define DEFAULT_SEED        0x9e3779b97f4a7c15ULL
#define STRIDE_PAGES        17

enum access_pattern {
    PAT_SEQ = 0,
    PAT_RANDOM,
    PAT_STRIDE,
};

static volatile sig_atomic_t g_stop = 0;

static int memfd_secret_compat(unsigned int flags) {
    return (int)syscall(SYS_memfd_secret, flags);
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
           "  --interval-ms <ms>        Delay between page touches in ms (default %.1f, 0=tight)\n"
           "  --pattern <seq|random|stride>  Page access pattern (default seq)\n"
           "  --duration <sec>          Run duration in seconds (default 0=until Ctrl-C)\n"
           "  --seed <u64>              PRNG seed for random pattern\n"
           "  -h, --help                Show this help\n",
           prog, DEFAULT_INTERVAL_MS);
}

int main(int argc, char **argv) {
    double interval_ms = DEFAULT_INTERVAL_MS;
    double duration_s = DEFAULT_DURATION_S;
    enum access_pattern pat = PAT_SEQ;
    uint64_t rng = DEFAULT_SEED;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            if (parse_nonneg_double(argv[++i], &interval_ms) != 0) {
                fprintf(stderr, "[v4] invalid --interval-ms: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            if (parse_nonneg_double(argv[++i], &duration_s) != 0) {
                fprintf(stderr, "[v4] invalid --duration: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (parse_u64(argv[++i], &rng) != 0) {
                fprintf(stderr, "[v4] invalid --seed: %s\n", argv[i]);
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
                fprintf(stderr, "[v4] unknown --pattern: %s\n", p);
                return 1;
            }
        } else {
            fprintf(stderr, "[v4] unknown or incomplete option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    long long interval_us = (long long)(interval_ms * 1000.0 + 0.5);
    long long duration_us = (long long)(duration_s * 1000000.0 + 0.5);

    int fd = memfd_secret_compat(0);
    if (fd < 0) {
        perror("memfd_secret (needs Linux >=5.14 and secretmem.enable=1)");
        return 1;
    }
    if (ftruncate(fd, RTS_BUFSZ) < 0) {
        perror("ftruncate");
        close(fd);
        return 1;
    }

    uint8_t *buf = mmap(NULL, RTS_BUFSZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        perror("mmap secret");
        close(fd);
        return 1;
    }
    rts_fill_marker(buf, RTS_BUFSZ);

    struct sigaction sa_stop;
    memset(&sa_stop, 0, sizeof(sa_stop));
    sa_stop.sa_handler = stop_handler;
    sigemptyset(&sa_stop.sa_mask);
    if (sigaction(SIGINT, &sa_stop, NULL) != 0 || sigaction(SIGTERM, &sa_stop, NULL) != 0) {
        perror("sigaction SIGINT/SIGTERM");
        munmap(buf, RTS_BUFSZ);
        close(fd);
        return 1;
    }

    printf("[v4] pid=%d  interval_ms=%.2f pattern=%s (secretmem len=%zu). Ctrl-C to stop.\n",
           getpid(), interval_ms, pattern_name(pat), (size_t)RTS_BUFSZ);
    fflush(stdout);

    size_t num_pages = RTS_BUFSZ / RTS_PAGE;
    size_t mlen = strlen(RTS_MARKER);
    size_t page_idx = 0;
    volatile uint8_t *vbuf = buf;
    volatile uint8_t sink = 0;
    uint64_t accesses = 0;
    int status = 0;

    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    while (!g_stop) {
        if (duration_us > 0 && (interval_us > 0 || (accesses & 1023ULL) == 0) &&
            elapsed_us(&t_start) >= duration_us)
            break;

        size_t off = page_idx * RTS_PAGE;
        uint8_t val = vbuf[off];
        uint8_t expected = (uint8_t)RTS_MARKER[off % mlen];
        if (val != expected) {
            fprintf(stderr,
                    "[v4] integrity mismatch at off=%zu: got=0x%02x expected=0x%02x\n",
                    off, val, expected);
            status = 2;
            break;
        }
        sink ^= val;
        accesses++;

        page_idx = next_page_idx(pat, page_idx, num_pages, &rng);
        sleep_us_interruptible(interval_us);
    }

    double secs = (double)elapsed_us(&t_start) / 1000000.0;
    printf("[v4] done: accesses=%" PRIu64 " faults=0 elapsed_s=%.3f faults_per_s=0.0\n",
           accesses, secs);
    fflush(stdout);

    (void)sink;
    munmap(buf, RTS_BUFSZ);
    close(fd);
    return status;
}
