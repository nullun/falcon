/*
 * Glue between the Falcon repo and the ntrugen keygen library.
 *
 * Provides an alternative keygen implementation using ntrugen's
 * fixed-point arithmetic (no floating-point required), selected
 * at compile time via FALCON_KG_NTRUGEN.
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

#ifndef NTRUGEN_GLUE_H__
#define NTRUGEN_GLUE_H__

#include "falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generate a new Falcon key pair using the ntrugen library.
 * The interface is the same as falcon_keygen_make().
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_keygen_make_ntrugen(
	shake256_context *rng,
	unsigned logn,
	void *privkey, size_t privkey_len,
	void *pubkey, size_t pubkey_len,
	void *tmp, size_t tmp_len);

#ifdef __cplusplus
}
#endif

#endif
