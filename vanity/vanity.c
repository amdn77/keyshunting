/* vanity.c — fast BSC/EVM vanity address generator.
 *
 * Usage:
 *   vanity --prefix <hex> --suffix <hex> --max-tries <N> [--seed <hex>]
 *   vanity --selftest
 *
 * Output (stdout, one JSON line):
 *   {"found":true,"private_key":"0x..","address":"0x..","tries":N,"prefix_len":P,"suffix_len":S}
 *   {"found":false,"tries":N,"prefix_len":P,"suffix_len":S}
 *
 * Build: cc -O2 -o vanity vanity.c -lsecp256k1
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/random.h>
#include <secp256k1.h>

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static const int keccakf_rotc[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
static const int keccakf_piln[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

static void keccakf(uint64_t st[25]) {
    int i, j, r;
    uint64_t t, bc[5];
    for (r = 0; r < 24; r++) {
        for (i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) bc[i] = st[j + i];
            for (i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= keccakf_rndc[r];
    }
}

static void keccak256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    const size_t rate = 136;
    size_t i = 0;
    while (inlen - i >= rate) {
        for (size_t j = 0; j < rate / 8; j++) {
            uint64_t v = 0;
            for (int k = 0; k < 8; k++) v |= ((uint64_t)in[i + j * 8 + k]) << (8 * k);
            st[j] ^= v;
        }
        keccakf(st);
        i += rate;
    }
    uint8_t temp[136];
    memset(temp, 0, rate);
    memcpy(temp, in + i, inlen - i);
    temp[inlen - i] = 0x01;
    temp[rate - 1] |= 0x80;
    for (size_t j = 0; j < rate / 8; j++) {
        uint64_t v = 0;
        for (int k = 0; k < 8; k++) v |= ((uint64_t)temp[j * 8 + k]) << (8 * k);
        st[j] ^= v;
    }
    keccakf(st);
    for (i = 0; i < 32; i++) out[i] = (uint8_t)((st[i / 8] >> (8 * (i % 8))) & 0xff);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void to_hex(const uint8_t *in, size_t len, char *out) {
    static const char *hexd = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hexd[in[i] >> 4];
        out[i * 2 + 1] = hexd[in[i] & 0xf];
    }
    out[len * 2] = 0;
}

/* xorshift256 PRNG */
typedef struct { uint64_t s[4]; } rng_t;

static void rng_seed(rng_t *r) {
    if (getrandom(r->s, sizeof(r->s), 0) != (ssize_t)sizeof(r->s)) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) { fread(r->s, sizeof(r->s), 1, f); fclose(f); }
    }
    if (!(r->s[0] | r->s[1] | r->s[2] | r->s[3])) r->s[0] = 0x9e3779b97f4a7c15ULL;
}

static uint64_t rng_next(rng_t *r) {
    uint64_t x = r->s[0], y = r->s[1], z = r->s[2], w = r->s[3];
    uint64_t t = x ^ (x << 11);
    r->s[0] = y; r->s[1] = z; r->s[2] = w;
    r->s[3] = w ^ (w >> 19) ^ (t ^ (t >> 8));
    return r->s[3];
}

static void rng_bytes(rng_t *r, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 8 == 0) rng_next(r);
        out[i] = (uint8_t)((r->s[3] >> (8 * (i % 8))) & 0xff);
    }
}

static int selftest(void) {
    /* keccak256("") */
    uint8_t h[32];
    keccak256((const uint8_t *)"", 0, h);
    char hex[65];
    to_hex(h, 32, hex);
    if (strcmp(hex, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") != 0) {
        fprintf(stderr, "keccak selftest FAILED: %s\n", hex);
        return 1;
    }
    /* privkey = 1 -> known address */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    uint8_t sk[32];
    memset(sk, 0, 32);
    sk[31] = 1;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, sk)) { fprintf(stderr, "pubkey create failed\n"); return 1; }
    uint8_t pub[65];
    size_t publen = 65;
    secp256k1_ec_pubkey_serialize(ctx, pub, &publen, &pk, SECP256K1_EC_UNCOMPRESSED);
    uint8_t addr_hash[32];
    keccak256(pub + 1, 64, addr_hash);
    char addrhex[41];
    to_hex(addr_hash + 12, 20, addrhex);
    if (strcmp(addrhex, "7e5f4552091a69125d5dfcb7b8c2659029395bdf") != 0) {
        fprintf(stderr, "address selftest FAILED: %s\n", addrhex);
        return 1;
    }
    printf("selftest OK\n");
    secp256k1_context_destroy(ctx);
    return 0;
}

int main(int argc, char **argv) {
    const char *prefix = "";
    const char *suffix = "";
    long long max_tries = 1000000;
    if (argc >= 2 && strcmp(argv[1], "--selftest") == 0) return selftest();
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) prefix = argv[++i];
        else if (strcmp(argv[i], "--suffix") == 0 && i + 1 < argc) suffix = argv[++i];
        else if (strcmp(argv[i], "--max-tries") == 0 && i + 1 < argc) max_tries = atoll(argv[++i]);
    }
    size_t plen = strlen(prefix), slen = strlen(suffix);
    for (size_t i = 0; i < plen; i++) if (hexval(prefix[i]) < 0) { fprintf(stderr, "bad prefix\n"); return 2; }
    for (size_t i = 0; i < slen; i++) if (hexval(suffix[i]) < 0) { fprintf(stderr, "bad suffix\n"); return 2; }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    uint8_t randseed[32];
    if (getrandom(randseed, 32, 0) == 32) (void)secp256k1_context_randomize(ctx, randseed);

    rng_t rng;
    rng_seed(&rng);
    uint8_t pub[65], hash[32], addr[20];
    char addrhex[41];
    secp256k1_pubkey pk;
    long long tries = 0;

    /* Step mode: walk the curve with P := P + G (one base EC mult, then cheap adds).
       private key for step i is base + i. */
    uint8_t sk[32];
    for (;;) {
        rng_bytes(&rng, sk, 32);
        sk[0] &= 0x7f; /* keep well below the curve order */
        if (secp256k1_ec_seckey_verify(ctx, sk)) break;
    }
    if (!secp256k1_ec_pubkey_create(ctx, &pk, sk)) { fprintf(stderr, "base pubkey failed\n"); return 3; }
    uint8_t one[32];
    memset(one, 0, 32);
    one[31] = 1;
    secp256k1_pubkey gpk, tmp;
    if (!secp256k1_ec_pubkey_create(ctx, &gpk, one)) { fprintf(stderr, "generator pubkey failed\n"); return 3; }
    uint64_t kacc[4];
    for (int j = 0; j < 4; j++) {
        kacc[j] = 0;
        for (int b = 0; b < 8; b++) kacc[j] = (kacc[j] << 8) | sk[j * 8 + b];
    }

    while (tries < max_tries) {
        size_t publen = 65;
        secp256k1_ec_pubkey_serialize(ctx, pub, &publen, &pk, SECP256K1_EC_UNCOMPRESSED);
        keccak256(pub + 1, 64, hash);
        memcpy(addr, hash + 12, 20);
        to_hex(addr, 20, addrhex);
        tries++;
        if ((plen == 0 || strncmp(addrhex, prefix, plen) == 0) &&
            (slen == 0 || strncmp(addrhex + 40 - slen, suffix, slen) == 0)) {
            char skhex[67];
            skhex[0] = '0';
            skhex[1] = 'x';
            for (int j = 0; j < 4; j++) {
                for (int b = 0; b < 8; b++) {
                    uint8_t byte = (uint8_t)((kacc[j] >> (8 * (7 - b))) & 0xff);
                    static const char *hexd = "0123456789abcdef";
                    skhex[2 + j * 16 + b * 2] = hexd[byte >> 4];
                    skhex[2 + j * 16 + b * 2 + 1] = hexd[byte & 0xf];
                }
            }
            skhex[66] = 0;
            printf("{\"found\":true,\"private_key\":\"%s\",\"address\":\"0x%s\",\"tries\":%lld,\"prefix_len\":%zu,\"suffix_len\":%zu}\n",
                   skhex, addrhex, tries, plen, slen);
            secp256k1_context_destroy(ctx);
            return 0;
        }
        /* P := P + G */
        const secp256k1_pubkey *arr[2] = {&pk, &gpk};
        if (!secp256k1_ec_pubkey_combine(ctx, &tmp, arr, 2)) { fprintf(stderr, "combine failed\n"); return 3; }
        pk = tmp;
        /* k += 1 (256-bit big-endian) */
        for (int j = 3; j >= 0; j--) {
            if (++kacc[j]) break;
        }
    }
    printf("{\"found\":false,\"tries\":%lld,\"prefix_len\":%zu,\"suffix_len\":%zu}\n", tries, plen, slen);
    secp256k1_context_destroy(ctx);
    return 1;
}
