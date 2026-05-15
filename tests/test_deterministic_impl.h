/*
 * Parameterized body of the deterministic-mode KAT runner.
 *
 * Included twice from test_deterministic.c -- once for det1024 and once for
 * det512 -- so a single binary exercises both parameter sets. Never compile
 * this file directly.
 *
 * Required macros (defined by the includer before each inclusion):
 *
 *   DET_FN(name)                -- token-paster for the public function name
 *                                  prefix (e.g. falcon_det1024_##name)
 *   TEST_FN(name)               -- token-paster for the per-variant test
 *                                  helpers/state (e.g. name##_det1024)
 *   DET_DISPLAY_NAME            -- printable variant label, e.g. "FALCON-DET1024"
 *   DET_KAT_NAME                -- KAT array prefix for GENERATE_KATS output,
 *                                  e.g. "FALCON_DET1024"
 *   DET_PUBKEY_SIZE             -- FALCON_DETnnn_PUBKEY_SIZE
 *   DET_PRIVKEY_SIZE            -- FALCON_DETnnn_PRIVKEY_SIZE
 *   DET_SIG_COMPRESSED_MAXSIZE  -- FALCON_DETnnn_SIG_COMPRESSED_MAXSIZE
 *   DET_SIG_CT_SIZE             -- FALCON_DETnnn_SIG_CT_SIZE
 *   DET_CURRENT_SALT_VERSION    -- FALCON_DETnnn_CURRENT_SALT_VERSION
 *   DET_KAT                     -- compressed-signature KAT vector array
 *   DET_KAT_CT                  -- CT-signature KAT vector array
 *
 * The driver (test_deterministic.c) provides NUM_KATS, NUM_KATS_CT and the
 * shared hextobin() helper.
 *
 * All required macros plus TEST_FN(sigs_ct) are #undef'd at the bottom so
 * the includer can redefine them for the next instantiation.
 */

static uint8_t TEST_FN(sigs_ct)[NUM_KATS][DET_SIG_CT_SIZE] = {{0}};

static void TEST_FN(test_inner)(size_t data_len) {
	uint8_t pubkey[DET_PUBKEY_SIZE];
	uint8_t privkey[DET_PRIVKEY_SIZE];
	uint8_t sig[DET_SIG_COMPRESSED_MAXSIZE];
	size_t sig_len;
	uint8_t expected_sig[DET_SIG_COMPRESSED_MAXSIZE];
	uint8_t data[data_len];

	memset(privkey, 0, DET_PRIVKEY_SIZE);
	memset(pubkey, 0, DET_PUBKEY_SIZE);

	shake256_context msg_rng;
	char msg_seed[8+1];
	sprintf(msg_seed, "msg-%04zu", data_len);
	shake256_init_prng_from_seed(&msg_rng, msg_seed, 8);
	shake256_extract(&msg_rng, data, data_len);

	shake256_context key_rng;
	char key_seed[8+1];
	sprintf(key_seed, "key-%04zu", data_len);
	shake256_init_prng_from_seed(&key_rng, key_seed, 8);
	int r = DET_FN(keygen)(&key_rng, privkey, pubkey);
	if (r != 0) {
		fprintf(stderr, "[%s] keygen (data_len=%zu) failed: %d\n", DET_DISPLAY_NAME, data_len, r);
		exit(EXIT_FAILURE);
	}

	memset(sig, 0, DET_SIG_COMPRESSED_MAXSIZE);
	r = DET_FN(sign_compressed)(sig, &sig_len, privkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "[%s] sign_compressed (data_len=%zu) failed: %d\n", DET_DISPLAY_NAME, data_len, r);
		exit(EXIT_FAILURE);
	}

	int v = DET_FN(get_salt_version)(sig);
	if (v != DET_CURRENT_SALT_VERSION) {
		fprintf(stderr, "[%s] unexpected salt version: %d", DET_DISPLAY_NAME, v);
		exit(EXIT_FAILURE);
	}

	r = DET_FN(verify_compressed)(sig, sig_len, pubkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "[%s] verify_compressed (data_len=%zu) failed: %d\n", DET_DISPLAY_NAME, data_len, r);
		exit(EXIT_FAILURE);
	}

	r = DET_FN(convert_compressed_to_ct)(TEST_FN(sigs_ct)[data_len], sig, sig_len);
	if (r != 0) {
		fprintf(stderr, "[%s] conversion to CT format (data_len=%zu) failed: %d\n", DET_DISPLAY_NAME, data_len, r);
		exit(EXIT_FAILURE);
	}

	int vct = DET_FN(get_salt_version)(TEST_FN(sigs_ct)[data_len]);
	if (vct != DET_CURRENT_SALT_VERSION) {
		fprintf(stderr, "[%s] unexpected salt version: %d", DET_DISPLAY_NAME, vct);
		exit(EXIT_FAILURE);
	}

	r = DET_FN(verify_ct)(TEST_FN(sigs_ct)[data_len], pubkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "[%s] verify_ct (data_len=%zu) failed: %d\n", DET_DISPLAY_NAME, data_len, r);
		exit(EXIT_FAILURE);
	}

#ifdef GENERATE_KATS            /* print the KAT */
	printf("\t\"");
	for (size_t i = 0; i < sig_len; i++) {
		printf("%02x", sig[i]);
	}
	printf("\",\n");
#else  /* compare to the KAT */
	size_t elen = hextobin(expected_sig, DET_SIG_COMPRESSED_MAXSIZE, DET_KAT[data_len]);
	if (elen != sig_len) {
		fprintf(stderr, "[%s] sign_compressed (data_len=%zu) length %zu does not match KAT length %zu\n", DET_DISPLAY_NAME, data_len, sig_len, elen);
		exit(EXIT_FAILURE);
	}
	if (memcmp(sig, expected_sig, sig_len) != 0) {
		fprintf(stderr, "[%s] sign_compressed (data_len=%zu) does not match KAT\n", DET_DISPLAY_NAME, data_len);
		exit(EXIT_FAILURE);
	}
#endif
}

static void TEST_FN(run_kats)(void) {
	printf("\n%s:\n", DET_DISPLAY_NAME);

#ifdef GENERATE_KATS
	printf("\nstatic const char *const %s_KAT[] = {\n", DET_KAT_NAME);
#endif

	for (int kat = 0; kat < NUM_KATS; kat++) {
		TEST_FN(test_inner)((size_t)kat);
#ifndef GENERATE_KATS
		printf(".");
		fflush(stdout);
#endif
	}

#ifdef GENERATE_KATS
	printf("};\n\n");
	printf("\nstatic const char *const %s_KAT_CT[] = {\n", DET_KAT_NAME);
	for (int kat = 0; kat < NUM_KATS_CT; kat++) {
		printf("\t\"");
		for (int i = 0; i < DET_SIG_CT_SIZE; i++) {
			printf("%02x", TEST_FN(sigs_ct)[kat][i]);
		}
		printf("\",\n");
	}
	printf("};\n\n");
#else
	uint8_t expected_sig_ct[DET_SIG_CT_SIZE];
	for (int kat = 0; kat < NUM_KATS_CT; kat++) {
		hextobin(expected_sig_ct, DET_SIG_CT_SIZE, DET_KAT_CT[kat]);
		if (memcmp(TEST_FN(sigs_ct)[kat], expected_sig_ct, DET_SIG_CT_SIZE) != 0) {
			fprintf(stderr, "[%s] convert_compressed_to_ct (data_len=%d) does not match KAT\n", DET_DISPLAY_NAME, kat);
			exit(EXIT_FAILURE);
		}
	}
#endif
}

#undef DET_FN
#undef TEST_FN
#undef DET_DISPLAY_NAME
#undef DET_KAT_NAME
#undef DET_PUBKEY_SIZE
#undef DET_PRIVKEY_SIZE
#undef DET_SIG_COMPRESSED_MAXSIZE
#undef DET_SIG_CT_SIZE
#undef DET_CURRENT_SALT_VERSION
#undef DET_KAT
#undef DET_KAT_CT
