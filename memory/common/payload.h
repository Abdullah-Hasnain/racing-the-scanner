/* Shared helpers for the memory-hiding payloads (V1-V4).
 *
 * The "payload" is a harmless 1 MB buffer containing a known YARA marker
 * string. Each variant hides this buffer from a live /proc/<pid>/mem scanner
 * in a different way. A trivial XOR keeps the bytes out of plaintext while a
 * page is locked; this is NOT real cryptography and is only here so the scanner
 * has something to miss. Nothing here touches disk, network, or privilege.
 */
#ifndef RTS_PAYLOAD_H
#define RTS_PAYLOAD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define RTS_PAGE 4096
#define RTS_BUFSZ (1024 * 1024)            /* 1 MB */
#define RTS_MARKER "RTS_SECRET_MARKER_v1"  /* what the YARA rule looks for */
#define RTS_XOR_KEY 0x5A

static inline void rts_fill_marker(uint8_t *buf, size_t n) {
    size_t mlen = strlen(RTS_MARKER);
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)RTS_MARKER[i % mlen];
}

static inline void rts_xor_page(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        p[i] ^= RTS_XOR_KEY;
}

#endif /* RTS_PAYLOAD_H */
