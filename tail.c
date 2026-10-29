// C hash-tail solver, drop-in replacement for tail.mjs (same semantics):
//   ./tail_c "<prefix ending in :>" <bits> [threads]
// Finds a decimal nonce such that keccak256("<prefix><nonce>") starts with
// <bits> zero bits. Original Keccak padding (0x01 ... 0x80), NOT NIST SHA3.
// Nonces are partitioned exactly like tail.mjs: thread i tries i, i+step, ...
// Progress to stderr every ~2s, result JSON {"nonce","hash","seconds"} to stdout.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
static const int ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};
static const int PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4
};
#define ROL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5];
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ ROL(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        // Rho+Pi, as in tail.mjs: B[PI[i]] = rotate(S[i], ROT[i]).
        uint64_t tmp[25];
        for (int i = 0; i < 25; i++) {
            int r = ROT[i];
            tmp[PI[i]] = r ? ROL(st[i], r) : st[i];
        }
        for (int i = 0; i < 25; i++) st[i] = tmp[i];
        for (int j = 0; j < 25; j += 5) {
            uint64_t row[5];
            for (int i = 0; i < 5; i++) row[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] = row[i] ^ (~row[(i + 1) % 5] & row[(i + 2) % 5]);
        }
        st[0] ^= RC[round];
    }
}

// Keccak-256 digest of msg[0..len). Caller supplies a 136-byte block buffer
// when len < 135 (our prefixes + decimal nonce are always < 135 bytes);
// fall back to a generic multi-block path for longer inputs.
static void keccak256(const unsigned char *msg, size_t len, unsigned char out[32]) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    if (len < 135) {
        unsigned char block[136];
        memset(block, 0, sizeof(block));
        memcpy(block, msg, len);
        block[len] ^= 0x01;
        block[135] ^= 0x80;
        for (int i = 0; i < 17; i++) {
            uint64_t w = 0;
            for (int b = 0; b < 8; b++) w |= (uint64_t)block[i * 8 + b] << (8 * b);
            st[i] ^= w;
        }
        keccakf(st);
    } else {
        // Generic path (not used by Boltbook prefixes, kept for safety).
        size_t off = 0;
        while (off + 136 <= len) {
            for (int i = 0; i < 17; i++) {
                uint64_t w = 0;
                for (int b = 0; b < 8; b++) w |= (uint64_t)msg[off + i * 8 + b] << (8 * b);
                st[i] ^= w;
            }
            keccakf(st);
            off += 136;
        }
        unsigned char block[136];
        memset(block, 0, sizeof(block));
        size_t rem = len - off;
        memcpy(block, msg + off, rem);
        block[rem] ^= 0x01;
        block[135] ^= 0x80;
        for (int i = 0; i < 17; i++) {
            uint64_t w = 0;
            for (int b = 0; b < 8; b++) w |= (uint64_t)block[i * 8 + b] << (8 * b);
            st[i] ^= w;
        }
        keccakf(st);
    }
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 8; b++) out[i * 8 + b] = (unsigned char)(st[i] >> (8 * b));
}

static int leading_zero_bits(const unsigned char d[32]) {
    int n = 0;
    for (int i = 0; i < 32; i++) {
        unsigned char b = d[i];
        if (!b) { n += 8; continue; }
        for (int k = 7; k >= 0; k--) {
            if (b & (1u << k)) return n;
            n++;
        }
    }
    return n;
}

static const char *g_prefix;
static size_t g_prelen;
static int g_bits;
static int g_threads;
static _Atomic long long g_tried;
static _Atomic int g_found;
static char g_found_nonce[32];
static unsigned char g_found_hash[32];
static struct timespec g_t0;

static double elapsed_s(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - g_t0.tv_sec) + (now.tv_nsec - g_t0.tv_nsec) / 1e9;
}

static void *worker(void *arg) {
    long tid = (long)arg;
    unsigned char buf[256];
    memcpy(buf, g_prefix, g_prelen);
    unsigned char digest[32];
    for (unsigned long long n = (unsigned long long)tid; ; n += (unsigned long long)g_threads) {
        if (atomic_load(&g_found)) break;
        int ndig = snprintf((char *)buf + g_prelen, sizeof(buf) - g_prelen, "%llu", n);
        keccak256(buf, g_prelen + (size_t)ndig, digest);
        if (leading_zero_bits(digest) >= g_bits) {
            int expected = 0;
            if (atomic_compare_exchange_strong(&g_found, &expected, 1)) {
                snprintf(g_found_nonce, sizeof(g_found_nonce), "%llu", n);
                memcpy(g_found_hash, digest, 32);
            }
            break;
        }
        long long t = atomic_fetch_add(&g_tried, 1) + 1;
        (void)t;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s \"<prefix ending in :>\" <bits> [threads]\n", argv[0]);
        return 2;
    }
    g_prefix = argv[1];
    g_prelen = strlen(g_prefix);
    if (g_prelen == 0 || g_prefix[g_prelen - 1] != ':') {
        fprintf(stderr, "prefix must end in ':'\n");
        return 2;
    }
    g_bits = atoi(argv[2]);
    if (g_bits < 1 || g_bits > 64) { fprintf(stderr, "bits must be 1..64\n"); return 2; }
    g_threads = argc >= 4 ? atoi(argv[3]) : 2;
    if (g_threads < 1) g_threads = 1;
    clock_gettime(CLOCK_MONOTONIC, &g_t0);
    pthread_t *th = malloc(sizeof(pthread_t) * (size_t)g_threads);
    for (long i = 0; i < g_threads; i++) pthread_create(&th[i], NULL, worker, (void *)i);
    double last_report = 0;
    for (;;) {
        struct timespec ts = {0, 200 * 1000 * 1000};
        nanosleep(&ts, NULL);
        double el = elapsed_s();
        long long tried = atomic_load(&g_tried);
        if (atomic_load(&g_found)) break;
        if (el - last_report >= 2.0) {
            fprintf(stderr, "\r%.1fM tried, %.0f s, %d threads; expected ~%.1fM",
                    tried / 1e6, el, g_threads, (double)(1ULL << (g_bits >= 64 ? 63 : g_bits)) / 1e6 * (g_bits >= 64 ? 2.0 : 1.0));
            fflush(stderr);
            last_report = el;
        }
    }
    for (long i = 0; i < g_threads; i++) pthread_join(th[i], NULL);
    double el = elapsed_s();
    fprintf(stderr, "\n");
    printf("{\"nonce\": \"%s\", \"hash\": \"0x", g_found_nonce);
    for (int i = 0; i < 32; i++) printf("%02x", g_found_hash[i]);
    printf("\", \"seconds\": %.1f}\n", el);
    fflush(stdout);
    return 0;
}
