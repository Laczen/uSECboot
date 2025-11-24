#include "soft_sha256.h"

static void wipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t *)secret;
	for (size_t i = 0; i < size; i++) {
                v_secret[i] = 0U;
        }
}

// Cyclic right rotation.
#define ROTR32(x, y)  (((x) >> (y)) ^ ((x) << (32 - (y))))
#define SHR(x, y) ((x) >> (y))

static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(struct soft_sha256_ctx *ctx)
{
        uint32_t W[64];
        uint32_t A, B, C, D, E, F, G, H;
        uint8_t* p = ctx->buf;
        int t;

        for(t = 0; t < 16; ++t) {
                uint32_t tmp =  *p++ << 24;
                tmp |= *p++ << 16;
                tmp |= *p++ << 8;
                tmp |= *p++;
                W[t] = tmp;
        }

        for(; t < 64; t++) {
                uint32_t s0 = ROTR32(W[t-15], 7) ^ ROTR32(W[t-15], 18) ^ SHR(W[t-15], 3);
                uint32_t s1 = ROTR32(W[t-2], 17) ^ ROTR32(W[t-2], 19) ^ SHR(W[t-2], 10);
                W[t] = W[t-16] + s0 + W[t-7] + s1;
        }

        A = ctx->state[0];
        B = ctx->state[1];
        C = ctx->state[2];
        D = ctx->state[3];
        E = ctx->state[4];
        F = ctx->state[5];
        G = ctx->state[6];
        H = ctx->state[7];

        for(t = 0; t < 64; t++) {
                uint32_t s0 = ROTR32(A, 2) ^ ROTR32(A, 13) ^ ROTR32(A, 22);
                uint32_t maj = (A & B) ^ (A & C) ^ (B & C);
                uint32_t t2 = s0 + maj;
                uint32_t s1 = ROTR32(E, 6) ^ ROTR32(E, 11) ^ ROTR32(E, 25);
                uint32_t ch = (E & F) ^ ((~E) & G);
                uint32_t t1 = H + s1 + ch + K[t] + W[t];

                H = G;
                G = F;
                F = E;
                E = D + t1;
                D = C;
                C = B;
                B = A;
                A = t1 + t2;
        }

        ctx->state[0] += A;
        ctx->state[1] += B;
        ctx->state[2] += C;
        ctx->state[3] += D;
        ctx->state[4] += E;
        ctx->state[5] += F;
        ctx->state[6] += G;
        ctx->state[7] += H;
}

void soft_sha256_init(struct soft_sha256_ctx *ctx)
{
        if (ctx == NULL) {
                return;
        }

        ctx->state[0] = 0x6a09e667;
        ctx->state[1] = 0xbb67ae85;
        ctx->state[2] = 0x3c6ef372;
        ctx->state[3] = 0xa54ff53a;
        ctx->state[4] = 0x510e527f;
        ctx->state[5] = 0x9b05688c;
        ctx->state[6] = 0x1f83d9ab;
        ctx->state[7] = 0x5be0cd19;
        ctx->count = 0U;
}

void soft_sha256_update(struct soft_sha256_ctx *ctx, const void *in,
			size_t inlen)
{
        if (ctx == NULL) {
                return;
        }

        const uint8_t* p = (const uint8_t*)in;
        int i = (int) (ctx->count & 63);

        ctx->count += inlen;

        while (inlen--) {
                ctx->buf[i++] = *p++;
                if (i == 64) {
                        sha256_transform(ctx);
                        i = 0;
                }
        }
}

void soft_sha256_final(struct soft_sha256_ctx *ctx, void *out)
{

        if (ctx == NULL) {
                return;
        }

        uint8_t *p = (uint8_t *)out;
        uint64_t cnt = ctx->count * 8;
        int i;

        soft_sha256_update(ctx, (uint8_t*)"\x80", 1);
        while ((ctx->count & 63) != 56) {
                soft_sha256_update(ctx, (uint8_t*)"\0", 1);
        }

        for (i = 0; i < 8; ++i) {
                uint8_t tmp = (uint8_t) (cnt >> ((7 - i) * 8));
                soft_sha256_update(ctx, &tmp, 1);
        }

        for (i = 0; i < 8; i++) {
                uint32_t tmp = ctx->state[i];
                *p++ = tmp >> 24;
                *p++ = tmp >> 16;
                *p++ = tmp >> 8;
                *p++ = tmp >> 0;
        }

        wipe(ctx, sizeof(struct soft_sha256_ctx));
}
