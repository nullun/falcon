/*
 * Glue between the Falcon repo and the ntrugen keygen library.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017-2019  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 */

#include "ntrugen_glue.h"
#include "inner.h"

/*
 * ntrugen is an independent library for NTRU key pair generation. It
 * uses its own naming prefix (default: "ntrugen_") to avoid collisions
 * with the Falcon implementation. We include its internal header to
 * get the Falcon_keygen() declaration.
 */
#include "ntrugen/ng_inner.h"

/*
 * RNG adapter: ntrugen expects a callback of type ntrugen_rng:
 *   void (*)(void *ctx, void *dst, size_t len)
 * We wrap the Falcon inner_shake256_context to satisfy this interface.
 */
typedef struct {
	inner_shake256_context *shake;
} ntrugen_rng_ctx;

static void
ntrugen_rng_from_shake(void *ctx, void *dst, size_t len)
{
	inner_shake256_extract(
		((ntrugen_rng_ctx *)ctx)->shake, dst, len);
}

/* see ntrugen_glue.h */
int
falcon_keygen_make_ntrugen(
	shake256_context *rng,
	unsigned logn,
	void *privkey, size_t privkey_len,
	void *pubkey, size_t pubkey_len,
	void *tmp, size_t tmp_len)
{
	int8_t *f, *g, *F;
	uint16_t *h;
	uint8_t *atmp;
	size_t n, u, v, sk_len, pk_len;
	uint8_t *sk, *pk;
	ntrugen_rng_ctx rng_ctx;
	int r;

	/*
	 * Check parameters.
	 */
	if (logn < 1 || logn > 10) {
		return FALCON_ERR_BADARG;
	}
	if (privkey_len < FALCON_PRIVKEY_SIZE(logn)
		|| (pubkey != NULL && pubkey_len < FALCON_PUBKEY_SIZE(logn))
		|| tmp_len < FALCON_TMPSIZE_KEYGEN(logn))
	{
		return FALCON_ERR_SIZE;
	}

	n = (size_t)1 << logn;

	/*
	 * Prepare buffers. Layout in tmp[]:
	 *   f    n bytes
	 *   g    n bytes
	 *   F    n bytes
	 *   (alignment padding to 8 bytes)
	 *   ntrugen_tmp   at least 20*n + 7 bytes
	 *
	 * Total needed: <= 23*n + 14 bytes.
	 * FALCON_TMPSIZE_KEYGEN(logn) provides >= 31*n + 7 (for logn > 3),
	 * so there is plenty of room.
	 */
	f = tmp;
	g = f + n;
	F = g + n;

	/*
	 * Align the ntrugen temporary buffer to 64-bit boundary.
	 * ntrugen requires 20*n + 7 bytes (the extra 7 is for alignment).
	 * We provide exactly 20*n + 7 bytes; ntrugen will handle its own
	 * internal alignment.
	 */
	{
		uint8_t *atmp_u8;
		unsigned off;

		atmp_u8 = (uint8_t *)(F + n);
		off = (uintptr_t)atmp_u8 & 7u;
		if (off != 0) {
			atmp_u8 += 8u - off;
		}
		atmp = atmp_u8;
	}

	/*
	 * Set up the RNG adapter and invoke the ntrugen keygen.
	 */
	rng_ctx.shake = (inner_shake256_context *)rng;
	r = Falcon_keygen(logn, f, g, F, NULL,
		ntrugen_rng_from_shake, &rng_ctx,
		atmp, ((size_t)20 << logn) + 7);
	if (r != 0) {
		return FALCON_ERR_INTERNAL;
	}

	/*
	 * Encode private key (same format as the default implementation).
	 */
	sk = privkey;
	sk_len = FALCON_PRIVKEY_SIZE(logn);
	sk[0] = 0x50 + logn;
	u = 1;
	v = Zf(trim_i8_encode)(sk + u, sk_len - u,
		f, logn, Zf(max_fg_bits)[logn]);
	if (v == 0) {
		return FALCON_ERR_INTERNAL;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, sk_len - u,
		g, logn, Zf(max_fg_bits)[logn]);
	if (v == 0) {
		return FALCON_ERR_INTERNAL;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, sk_len - u,
		F, logn, Zf(max_FG_bits)[logn]);
	if (v == 0) {
		return FALCON_ERR_INTERNAL;
	}
	u += v;
	if (u != sk_len) {
		return FALCON_ERR_INTERNAL;
	}

	/*
	 * Compute and encode public key.
	 */
	if (pubkey != NULL) {
		h = (uint16_t *)(g + n);
		atmp = (uint8_t *)(h + n);
		if (!Zf(compute_public)(h, f, g, logn, atmp)) {
			return FALCON_ERR_INTERNAL;
		}
		pk = pubkey;
		pk_len = FALCON_PUBKEY_SIZE(logn);
		pk[0] = 0x00 + logn;
		v = Zf(modq_encode)(pk + 1, pk_len - 1, h, logn);
		if (v != pk_len - 1) {
			return FALCON_ERR_INTERNAL;
		}
	}

	return 0;
}
