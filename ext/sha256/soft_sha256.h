/*
 * software sha256 implementation
 *
 * Modified from mincrypt (see https://github.com/topjohnwu/mincrypt/)
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef SOFT_SHA256_H_
#define SOFT_SHA256_H_

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

///////////
// SHA26 //
///////////
#define SOFT_SHA256_DIGESTSIZE 32

struct soft_sha256_ctx {
	uint64_t count;
	uint8_t buf[64];
	uint32_t state[8];
};

static inline size_t soft_sha256_digest_size(void)
{
	return SOFT_SHA256_DIGESTSIZE;
}

void soft_sha256_init(struct soft_sha256_ctx *ctx);
void soft_sha256_update(struct soft_sha256_ctx *ctx, const void *in,
			size_t inlen);
void soft_sha256_final(struct soft_sha256_ctx *ctx, void *out);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SOFT_SHA256_H_ */