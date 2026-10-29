// Range version of tail_opt.c: same semantics, plus a start offset and
// an optional count limit, so parallel jobs can split the nonce space
// without duplicating work. Usage: tail_range "<prefix:>" <bits> [threads] [start] [count]
// Optimizations: precomputed prefix words (lanes 0..8), nonce digits written
// directly into lanes 9..10, padding via word XORs, per-thread counters
// batched to atomics only every 131072 hashes, fast integer-to-string.
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

static const char *g_prefix;
static size_t g_prelen;
static uint64_t g_pref[9];
static int g_bits, g_threads;
static _Atomic long long g_tried[16];
static _Atomic int g_found;
static _Atomic int g_done;
static unsigned long long g_start, g_limit;
static char g_found_nonce[32];
static unsigned char g_found_hash[32];
static struct timespec g_t0;

static double elapsed_s(void) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - g_t0.tv_sec) + (now.tv_nsec - g_t0.tv_nsec) / 1e9;
}
static int leading_zero_bits(const unsigned char d[32]) {
    int n = 0;
    for (int i = 0; i < 32; i++) {
        unsigned char b = d[i];
        if (!b) { n += 8; continue; }
        for (int k = 7; k >= 0; k--) { if (b & (1u << k)) return n; n++; }
    }
    return n;
}
// fast decimal conversion, returns digit count, digits in buf (not NUL-terminated)
static int u64toa(unsigned long long n, char *buf) {
    char tmp[20]; int t = 0;
    do { tmp[t++] = (char)('0' + (n % 10)); n /= 10; } while (n);
    for (int i = 0; i < t; i++) buf[i] = tmp[t - 1 - i];
    return t;
}

static void *worker(void *arg) {
    long tid = (long)arg;
    uint64_t st[25];
    unsigned char digest[32];
    char dig[20];
    unsigned long long local = 0;
    for (unsigned long long n = g_start + (unsigned long long)tid; ; n += (unsigned long long)g_threads) {
        if (atomic_load(&g_found)) break;
        if (g_limit && n >= g_start + g_limit) break;
        int ndig = u64toa(n, dig);
        // state: prefix lanes 0..8 precomputed, rest zero except nonce lanes + padding
        memcpy(st, g_pref, sizeof(g_pref));
        for (int i = 9; i < 25; i++) st[i] = 0;
        // nonce bytes start at byte 72 = lane 9 byte 0
        uint64_t w9 = 0, w10 = 0;
        for (int i = 0; i < ndig && i < 8; i++) w9 |= (uint64_t)(unsigned char)dig[i] << (8 * i);
        for (int i = 8; i < ndig; i++) w10 |= (uint64_t)(unsigned char)dig[i] << (8 * (i - 8));
        st[9] = w9; st[10] = w10;
        // padding: byte at total_len ^= 0x01, byte 135 ^= 0x80
        size_t total = g_prelen + (size_t)ndig;
        st[total / 8] ^= 0x01ULL << (8 * (total % 8));
        st[16] ^= 0x80ULL << 56;
        keccakf(st);
        for (int i = 0; i < 4; i++)
            for (int b = 0; b < 8; b++) digest[i * 8 + b] = (unsigned char)(st[i] >> (8 * b));
        if (leading_zero_bits(digest) >= g_bits) {
            int expected = 0;
            if (atomic_compare_exchange_strong(&g_found, &expected, 1)) {
                for (int i = 0; i < ndig; i++) g_found_nonce[i] = dig[i];
                g_found_nonce[ndig] = 0;
                memcpy(g_found_hash, digest, 32);
            }
            break;
        }
        if ((++local & 131071ULL) == 0) atomic_fetch_add(&g_tried[tid], 131072);
    }
    atomic_fetch_add(&g_tried[tid], (long long)(local & 131071ULL));
    atomic_fetch_add(&g_done, 1);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s \"<prefix:>\" <bits> [threads] [start] [count]\n", argv[0]); return 2; }
    g_prefix = argv[1]; g_prelen = strlen(g_prefix);
    if (g_prelen == 0 || g_prefix[g_prelen - 1] != ':' || g_prelen > 72) {
        fprintf(stderr, "prefix must end in ':' and be <=72 bytes (got %zu)\n", g_prelen); return 2;
    }
    // prefix words: bytes 0..71 into lanes 0..8
    memset(g_pref, 0, sizeof(g_pref));
    for (size_t i = 0; i < g_prelen; i++) g_pref[i / 8] |= (uint64_t)(unsigned char)g_prefix[i] << (8 * (i % 8));
    g_bits = atoi(argv[2]);
    if (g_bits < 1 || g_bits > 64) { fprintf(stderr, "bits 1..64\n"); return 2; }
    g_threads = argc >= 4 ? atoi(argv[3]) : 2;
    g_start = argc >= 5 ? strtoull(argv[4], NULL, 10) : 0;
    g_limit = argc >= 6 ? strtoull(argv[5], NULL, 10) : 0;
    if (g_threads < 1 || g_threads > 16) g_threads = 2;
    clock_gettime(CLOCK_MONOTONIC, &g_t0);
    pthread_t *th = malloc(sizeof(pthread_t) * (size_t)g_threads);
    for (long i = 0; i < g_threads; i++) pthread_create(&th[i], NULL, worker, (void *)i);
    double last = 0;
    for (;;) {
        struct timespec ts = {0, 200 * 1000 * 1000}; nanosleep(&ts, NULL);
        if (atomic_load(&g_found)) break;
        if (atomic_load(&g_done) >= g_threads) break;
        double el = elapsed_s();
        long long tried = 0; for (int i = 0; i < g_threads; i++) tried += atomic_load(&g_tried[i]);
        if (el - last >= 2.0) {
            fprintf(stderr, "\r%.1fM tried, %.0f s, %d threads; expected ~%.1fM", tried / 1e6, el, g_threads, (double)(1ULL << g_bits) / 1e6);
            fflush(stderr); last = el;
        }
    }
    for (long i = 0; i < g_threads; i++) pthread_join(th[i], NULL);
    fprintf(stderr, "\n");
    if (!atomic_load(&g_found)) { printf("{\"nonce\": null, \"hash\": null, \"seconds\": %.1f}\n", elapsed_s()); return 0; }
    printf("{\"nonce\": \"%s\", \"hash\": \"0x", g_found_nonce);
    for (int i = 0; i < 32; i++) printf("%02x", g_found_hash[i]);
    printf("\", \"seconds\": %.1f}\n", elapsed_s());
    return 0;
}
