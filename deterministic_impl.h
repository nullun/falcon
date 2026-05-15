/*
 * Template body for the Deterministic Falcon public API.
 *
 * This file is intentionally not guarded against multiple inclusion: it is
 * included twice from deterministic.c, once for n=1024 (DET_LOGN=10) and
 * once for n=512 (DET_LOGN=9), to instantiate the falcon_det1024_* and
 * falcon_det512_* function families from a single source.
 *
 * Required macros (defined by the includer before each inclusion):
 *
 *   DET_LOGN                    -- 10 for det1024, 9 for det512
 *   DET_FN(name)                -- token-paste helper for the function name
 *                                  prefix (e.g. falcon_det1024_##name)
 *   DET_PUBKEY_SIZE             -- FALCON_DETnnn_PUBKEY_SIZE
 *   DET_PRIVKEY_SIZE            -- FALCON_DETnnn_PRIVKEY_SIZE
 *   DET_CURRENT_SALT_VERSION    -- FALCON_DETnnn_CURRENT_SALT_VERSION
 *   DET_SIG_COMPRESSED_HEADER   -- FALCON_DETnnn_SIG_COMPRESSED_HEADER
 *   DET_SIG_CT_HEADER           -- FALCON_DETnnn_SIG_CT_HEADER
 *   DET_SIG_CT_SIZE             -- FALCON_DETnnn_SIG_CT_SIZE (unsalted form)
 *
 * All of these macros, plus the locally-defined helper macros below, are
 * #undef'd at the end of the file so that the includer can redefine them
 * for the next instantiation.
 *
 * Shared static helpers det_write_salt(), det_resalt(), det_salt_domain
 * and the constant Q live in deterministic.c (outside this template).
 */

#define DET_TMPSIZE_KEYGEN              FALCON_TMPSIZE_KEYGEN(DET_LOGN)
#define DET_TMPSIZE_SIGNDYN             FALCON_TMPSIZE_SIGNDYN(DET_LOGN)
#define DET_TMPSIZE_VERIFY              FALCON_TMPSIZE_VERIFY(DET_LOGN)
#define DET_SALTED_SIG_COMPRESSED_MAX   FALCON_SIG_COMPRESSED_MAXSIZE(DET_LOGN)
#define DET_SALTED_SIG_CT               FALCON_SIG_CT_SIZE(DET_LOGN)


int DET_FN(keygen)(shake256_context *rng, void *privkey, void *pubkey) {
	uint8_t tmpkg[DET_TMPSIZE_KEYGEN];

	return falcon_keygen_make(rng, DET_LOGN,
		privkey, DET_PRIVKEY_SIZE,
		pubkey, DET_PUBKEY_SIZE,
		tmpkg, DET_TMPSIZE_KEYGEN);
}

int DET_FN(sign_compressed)(void *sig, size_t *sig_len,
        const void *privkey, const void *data, size_t data_len) {

	shake256_context detrng;
	shake256_context hd;
	uint8_t tmpsd[DET_TMPSIZE_SIGNDYN];
	uint8_t logn[1] = {DET_LOGN};
	uint8_t salt[40];

	size_t saltedsig_len = DET_SALTED_SIG_COMPRESSED_MAX;
	uint8_t saltedsig[DET_SALTED_SIG_COMPRESSED_MAX];

	if (falcon_get_logn(privkey, DET_PRIVKEY_SIZE) != DET_LOGN) {
		return FALCON_ERR_FORMAT;
	}

	// SHAKE(logn || privkey || data), set to output mode.
	shake256_init(&detrng);
	shake256_inject(&detrng, logn, 1);
	shake256_inject(&detrng, privkey, DET_PRIVKEY_SIZE);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	det_write_salt(salt, DET_LOGN, DET_CURRENT_SALT_VERSION);

	// SHAKE(salt || data), still in input mode.
	shake256_init(&hd);
	shake256_inject(&hd, salt, 40);
	shake256_inject(&hd, data, data_len);

	int r = falcon_sign_dyn_finish(&detrng, saltedsig, &saltedsig_len,
		FALCON_SIG_COMPRESSED, privkey, DET_PRIVKEY_SIZE,
		&hd, salt, tmpsd, DET_TMPSIZE_SIGNDYN);
	if (r != 0) {
		return r;
	}

	// Transform the salted signature to unsalted format.
	uint8_t *sigbytes = sig;
	sigbytes[0] = saltedsig[0] | 0x80;
	sigbytes[1] = DET_CURRENT_SALT_VERSION;
	memcpy(sigbytes+2, saltedsig+41, saltedsig_len-41);

	*sig_len = saltedsig_len-40+1;

	return 0;
}

int DET_FN(convert_compressed_to_ct)(void *sig_ct,
        const void *sig_compressed, size_t sig_compressed_len) {

	int16_t coeffs[1 << DET_LOGN];
	size_t v;

	if (((uint8_t*)sig_compressed)[0] != DET_SIG_COMPRESSED_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	// Decode signature's s_bytes into (1 << DET_LOGN) signed-integer coefficients.
	v = Zf(comp_decode)(coeffs, DET_LOGN, ((uint8_t*)sig_compressed)+2, sig_compressed_len-2);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	uint8_t *sig = sig_ct;
	sig[0] = DET_SIG_CT_HEADER;
	sig[1] = ((uint8_t*)sig_compressed)[1]; // Copy the salt_version byte.

	// Encode the signed-integer coefficients into CT format.
	v = Zf(trim_i16_encode)(sig+2, DET_SIG_CT_SIZE-2, coeffs, DET_LOGN,
		Zf(max_sig_bits)[DET_LOGN]);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	return 0;
}

int DET_FN(verify_compressed)(const void *sig, size_t sig_len,
        const void *pubkey, const void *data, size_t data_len) {

	uint8_t tmpvv[DET_TMPSIZE_VERIFY];
	uint8_t salted_sig[DET_SALTED_SIG_COMPRESSED_MAX];

	if (sig_len < 2) {
		return FALCON_ERR_BADSIG;
	}

	if (((uint8_t*)sig)[0] != DET_SIG_COMPRESSED_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	// Add back the salt; drop the version byte.
	size_t salted_sig_len = sig_len + 40 - 1;

	if (salted_sig_len > DET_SALTED_SIG_COMPRESSED_MAX){
		return FALCON_ERR_BADSIG;
	}


	det_resalt(salted_sig, DET_LOGN, sig, sig_len);

	return falcon_verify(salted_sig, salted_sig_len, FALCON_SIG_COMPRESSED,
		pubkey, DET_PUBKEY_SIZE, data, data_len,
		tmpvv, DET_TMPSIZE_VERIFY);
}

int DET_FN(verify_ct)(const void *sig,
        const void *pubkey, const void *data, size_t data_len) {

	uint8_t tmpvv[DET_TMPSIZE_VERIFY];
	uint8_t salted_sig[DET_SALTED_SIG_CT];

	if (((uint8_t*)sig)[0] != DET_SIG_CT_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	det_resalt(salted_sig, DET_LOGN, sig, DET_SIG_CT_SIZE);

	return falcon_verify(salted_sig, DET_SALTED_SIG_CT, FALCON_SIG_CT,
		pubkey, DET_PUBKEY_SIZE, data, data_len,
		tmpvv, DET_TMPSIZE_VERIFY);
}

int DET_FN(get_salt_version)(const void* sig) {
	return ((uint8_t*)sig)[1];
}

int DET_FN(pubkey_coeffs)(uint16_t *h, const void *pubkey) {
	/*
	 * Decode public key.
	 */
	if (Zf(modq_decode)(h, DET_LOGN, (uint8_t*)pubkey + 1, DET_PUBKEY_SIZE - 1)
		!= DET_PUBKEY_SIZE - 1)
	{
		return FALCON_ERR_FORMAT;
	}
	return 0;
}

void DET_FN(hash_to_point_coeffs)(uint16_t *c, const void *data, size_t data_len, uint8_t salt_version) {
	uint8_t salt[40];
	det_write_salt(salt, DET_LOGN, salt_version);

	shake256_context ctx;
	shake256_init(&ctx);
	shake256_inject(&ctx, salt, 40);
	shake256_inject(&ctx, data, data_len);
	shake256_flip(&ctx);

	uint8_t tmp[(1<<DET_LOGN)*2];
	Zf(hash_to_point_ct)((inner_shake256_context *)&ctx, c, DET_LOGN, tmp);
}

int DET_FN(s2_coeffs)(int16_t *s2, const void* sig) {
	unsigned logn = DET_LOGN;

	// This function is limited to CT signatures for now,
	// but support for compressed signatures can be added later.
	if (((uint8_t*)sig)[0] != DET_SIG_CT_HEADER) {
		return FALCON_ERR_FORMAT;
	}

	size_t v = Zf(trim_i16_decode)(s2, logn, Zf(max_sig_bits)[logn], (uint8_t*)sig+2, DET_SIG_CT_SIZE-2);
	if (v != DET_SIG_CT_SIZE-2) {
		return FALCON_ERR_FORMAT;
	}
	return 0;
}

int DET_FN(s1_coeffs)(int16_t *s1, const uint16_t *h, const uint16_t *c, const int16_t *s2) {
	unsigned logn = DET_LOGN;
	size_t u, n;
	n = (size_t)1<<logn;

	uint16_t h_ntt[1<<DET_LOGN];
	for (u = 0; u < n; u++) {
		h_ntt[u] = h[u];
	}
	Zf(to_ntt_monty)(h_ntt, logn);

	// Copied from verify_raw.
	uint16_t tt[1<<DET_LOGN];
	/*
	 * Reduce s2 elements modulo q ([0..q-1] range).
	 */
	for (u = 0; u < n; u ++) {
		uint32_t w;

		w = (uint32_t)s2[u];
		w += Q & -(w >> 31);
		tt[u] = (uint16_t)w;
	}

	/*
	 * Compute s1 = c - s2*h mod phi mod q (in tt[]).
	 */
	Zf(mq_NTT)(tt, logn); // tt = s2
	Zf(mq_poly_montymul_ntt)(tt, h_ntt, logn); // tt = s2*h
	Zf(mq_iNTT)(tt, logn);
	// don't use mq_poly_sub because it overwrites the first
	// argument (c); use an explicit loop instead
	for (u = 0; u < n; u ++) {
		tt[u] = (uint16_t)Zf(mq_sub)(c[u], tt[u]);
	}

	/*
	 * Normalize s1 elements into the [-q/2..q/2] range.
	 */
	for (u = 0; u < n; u ++) {
		int32_t w;

		w = (int32_t)tt[u];
		w -= (int32_t)(Q & -(((Q >> 1) - (uint32_t)w) >> 31));
		s1[u] = (int16_t)w;
	}

	/*
	 * Test if the aggregate (s1,s2) vector is short enough.
	 */
	int vv = Zf(is_short)(s1, s2, logn);
	if (vv != 1) {
		return FALCON_ERR_BADSIG;
	}

	return 0;
}


#undef DET_LOGN
#undef DET_FN
#undef DET_PUBKEY_SIZE
#undef DET_PRIVKEY_SIZE
#undef DET_CURRENT_SALT_VERSION
#undef DET_SIG_COMPRESSED_HEADER
#undef DET_SIG_CT_HEADER
#undef DET_SIG_CT_SIZE
#undef DET_TMPSIZE_KEYGEN
#undef DET_TMPSIZE_SIGNDYN
#undef DET_TMPSIZE_VERIFY
#undef DET_SALTED_SIG_COMPRESSED_MAX
#undef DET_SALTED_SIG_CT
