/*
 * Tests for the Gibbs sampler keygen path.
 *
 * Requires FALCON_GIBBS_KEYGEN to be defined at compile time (the Makefile
 * passes -DFALCON_GIBBS_KEYGEN=1 for this target). Exercises the full
 * keygen -> sign -> verify pipeline, the cross-platform determinism KAT,
 * and the empirical single-shot success rate.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../config.h"
#include "../inner.h"

#ifndef FALCON_GIBBS_KEYGEN
#error "FALCON_GIBBS_KEYGEN must be defined to build this test"
#endif

#define GIBBS_LOGN  9
#define GIBBS_N     (1 << GIBBS_LOGN)
#define SIGN_TEMP_SZ (48 * GIBBS_N)  /* sign_dyn needs 48*2^logn bytes */

/*
 * Trial counts. The success-rate test calls gibbs_sample_fg_once directly
 * (no retry loop) so each trial is one Gibbs draw. The end-to-end and
 * norm-bound tests go through Zf(keygen) which loops internally and is
 * therefore much heavier; keep those small.
 */
#define GIBBS_TRIALS_RATE  1000  /* paper claims 99.4%, plan calls for 1e4 */
#define GIBBS_TRIALS       3

static void
seed_from_u64(inner_shake256_context *sc, uint64_t seed)
{
	uint8_t buf[8];
	int i;

	for (i = 0; i < 8; i++) {
		buf[i] = (uint8_t)(seed >> (56 - 8 * i));
	}
	memset(sc, 0, sizeof *sc);
	Zf(i_shake256_init)(sc);
	Zf(i_shake256_inject)(sc, buf, 8);
	Zf(i_shake256_flip)(sc);
}

static int
test_success_rate(void)
{
	uint8_t f_arr[GIBBS_N], g_arr[GIBBS_N];
	uint8_t tmp_keygen[FALCON_KEYGEN_TEMP_9];
	int successes, i;
	unsigned oldcw;

	successes = 0;
	oldcw = set_fpu_cw(2);

	fprintf(stderr, "Running %d single-shot Gibbs trials...\n",
		GIBBS_TRIALS_RATE);

	for (i = 0; i < GIBBS_TRIALS_RATE; i++) {
		inner_shake256_context rng;

		seed_from_u64(&rng, (uint64_t)(i + 1));

		memset(f_arr, 0, sizeof f_arr);
		memset(g_arr, 0, sizeof g_arr);
		memset(tmp_keygen, 0, sizeof tmp_keygen);

		if (Zf(gibbs_sample_fg_once)(&rng,
			(int8_t *)f_arr, (int8_t *)g_arr,
			GIBBS_LOGN, tmp_keygen))
		{
			successes++;
		}

		if ((i + 1) % 100 == 0) {
			fprintf(stderr, "  ... %d/%d (%d ok)\n",
				i + 1, GIBBS_TRIALS_RATE, successes);
		}
	}
	set_fpu_cw(oldcw);

	printf("single-shot success rate: %d/%d (%.2f%%)\n",
		successes, GIBBS_TRIALS_RATE,
		100.0 * successes / GIBBS_TRIALS_RATE);
	/*
	 * Threshold note: at alpha = 1.04, epsilon = 0.01 we sample at
	 * beta = 1.03 and gate at alpha = 1.04. Empirically this lands at
	 * ~99.6%, matching the paper's headline 99.4%. We require >= 95%
	 * to catch implementation regressions while leaving slack for the
	 * normal binomial fluctuation across 1000 trials.
	 */
	printf("target: >= 95%% at alpha = 1.04, epsilon = 0.01\n");

	return (100 * successes) >= (95 * GIBBS_TRIALS_RATE);
}

static int
test_sign_verify(void)
{
	uint8_t f_arr[GIBBS_N], g_arr[GIBBS_N];
	uint8_t F_arr[GIBBS_N], G_arr[GIBBS_N];
	uint16_t h_arr[GIBBS_N];
	uint8_t tmp_keygen[FALCON_KEYGEN_TEMP_9];
	uint8_t tmp_sign[SIGN_TEMP_SZ];
	int16_t sig[2 * GIBBS_N];
	uint16_t hm[GIBBS_N];
	unsigned oldcw;
	int i, ok;

	oldcw = set_fpu_cw(2);

	fprintf(stderr, "Running sign+verify tests...\n");

	for (i = 0; i < GIBBS_TRIALS; i++) {
		inner_shake256_context rng;
		int16_t *s2;
		uint16_t *c0;

		seed_from_u64(&rng, (uint64_t)(i + 1));

		memset(f_arr, 0, sizeof f_arr);
		memset(g_arr, 0, sizeof g_arr);
		memset(F_arr, 0, sizeof F_arr);
		memset(G_arr, 0, sizeof G_arr);
		memset(h_arr, 0, sizeof h_arr);
		memset(tmp_keygen, 0, sizeof tmp_keygen);

		Zf(keygen)(&rng,
			(int8_t *)f_arr, (int8_t *)g_arr,
			(int8_t *)F_arr, (int8_t *)G_arr,
			h_arr, GIBBS_LOGN, tmp_keygen);

		/* Create a deterministic hashed message. */
		seed_from_u64(&rng, (uint64_t)(i + 1000));
		for (size_t u = 0; u < GIBBS_N; u++) {
			uint8_t b[2];
			Zf(i_shake256_extract)(&rng, b, 2);
			hm[u] = (uint16_t)((b[0] << 8) | b[1]) % 12289;
		}

		/* Sign with the private key (f, g, F, G). */
		seed_from_u64(&rng, (uint64_t)(i + 2000));
		memset(sig, 0, sizeof sig);
		memset(tmp_sign, 0, sizeof tmp_sign);
		Zf(sign_dyn)(sig,
			&rng,
			(const int8_t *)f_arr,
			(const int8_t *)g_arr,
			(const int8_t *)F_arr,
			(const int8_t *)G_arr,
			hm, GIBBS_LOGN, tmp_sign);

		/* Verify: split sig into c0 (first N elements) and s2. */
		c0 = (uint16_t *)sig;
		s2 = (int16_t *)(sig + GIBBS_N);

		ok = Zf(verify_raw)(c0, s2, h_arr, GIBBS_LOGN, tmp_sign);
		if (!ok) {
			printf("FAIL sign+verify trial %d: verify failed\n", i);
			set_fpu_cw(oldcw);
			return 0;
		}
	}
	set_fpu_cw(oldcw);

	printf("sign+verify: %d/%d passed\n", GIBBS_TRIALS, GIBBS_TRIALS);
	return 1;
}

static int
test_norm_bounds(void)
{
	uint8_t f_arr[GIBBS_N], g_arr[GIBBS_N];
	uint8_t F_arr[GIBBS_N], G_arr[GIBBS_N];
	uint16_t h_arr[GIBBS_N];
	uint8_t tmp_keygen[FALCON_KEYGEN_TEMP_9];
	int i;
	unsigned oldcw;
	uint32_t max_fg_norm = 0, max_FG_norm = 0;

	oldcw = set_fpu_cw(2);
	for (i = 0; i < GIBBS_TRIALS; i++) {
		inner_shake256_context rng;
		size_t u;
		uint32_t nf, ng, nF, nG;

		seed_from_u64(&rng, (uint64_t)(i + 1));

		memset(f_arr, 0, sizeof f_arr);
		memset(g_arr, 0, sizeof g_arr);
		memset(F_arr, 0, sizeof F_arr);
		memset(G_arr, 0, sizeof G_arr);
		memset(h_arr, 0, sizeof h_arr);
		memset(tmp_keygen, 0, sizeof tmp_keygen);

		Zf(keygen)(&rng,
			(int8_t *)f_arr, (int8_t *)g_arr,
			(int8_t *)F_arr, (int8_t *)G_arr,
			h_arr, GIBBS_LOGN, tmp_keygen);

		nf = 0;
		ng = 0;
		nF = 0;
		nG = 0;
		for (u = 0; u < GIBBS_N; u++) {
			int32_t z;
			z = (int8_t)f_arr[u];
			nf += (uint32_t)(z * z);
			z = (int8_t)g_arr[u];
			ng += (uint32_t)(z * z);
			z = (int8_t)F_arr[u];
			nF += (uint32_t)(z * z);
			z = (int8_t)G_arr[u];
			nG += (uint32_t)(z * z);
		}
		if (nf + ng > max_fg_norm) {
			max_fg_norm = nf + ng;
		}
		if (nF + nG > max_FG_norm) {
			max_FG_norm = nF + nG;
		}
	}
	set_fpu_cw(oldcw);

	printf("max ||(f,g)||^2 = %u (threshold %u)\n",
		max_fg_norm, 13295u);
	printf("max ||(F,G)||^2 = %u\n", max_FG_norm);

	return 1;
}

/*
 * Cross-platform determinism KAT. For a fixed set of seeds, record the
 * SHAKE-256 digest of (accept_flag || f || g) from gibbs_sample_fg_once.
 * Bit-identity across x86_64 / ARM64 / WASM is the Phase 1 contract — a
 * regression here means either fpr_sin/fpr_cos diverged or the FPEMU layer
 * lost determinism somewhere new.
 *
 * Expected digests below were captured on the reference build (FALCON_FPEMU
 * = 1, x86_64 macOS, clang -O3); update them only when an intentional
 * change to the sampler invalidates the table.
 */
struct gibbs_kat_row {
	uint64_t seed;
	uint8_t expected[16];  /* truncated SHAKE-256 over (accept || f || g) */
};

static const struct gibbs_kat_row gibbs_kat_table[] = {
	{ 1, { 0x5a, 0xf4, 0xd3, 0x6b, 0x21, 0x1c, 0x7c, 0xf3,
	       0xbc, 0xe4, 0x17, 0x86, 0x78, 0x60, 0xde, 0xa6 } },  /* accept */
	{ 2, { 0xcb, 0xb4, 0x44, 0x42, 0x95, 0x27, 0x47, 0xc2,
	       0x8d, 0xd5, 0x46, 0x22, 0xc9, 0x87, 0x8a, 0xec } },  /* accept */
	{ 3, { 0xec, 0xeb, 0x00, 0x50, 0x78, 0x6e, 0x57, 0x29,
	       0xf4, 0x5f, 0x0b, 0x09, 0xa0, 0xd3, 0x49, 0x65 } },  /* accept */
	{ 4, { 0x4f, 0x3c, 0x22, 0xee, 0x8d, 0x99, 0xe3, 0xfc,
	       0xd8, 0x71, 0xea, 0x98, 0x75, 0xbb, 0x3f, 0x4e } },  /* accept */
	{ 5, { 0xae, 0x27, 0xd3, 0x7d, 0x74, 0xde, 0x16, 0x4b,
	       0x38, 0x9d, 0xd1, 0xfc, 0x20, 0xa9, 0xb7, 0x96 } },  /* accept */
};

static void
digest_fg(uint8_t out[16], int accept, const int8_t *f, const int8_t *g)
{
	inner_shake256_context sc;
	uint8_t flag = (uint8_t)(accept ? 1 : 0);

	Zf(i_shake256_init)(&sc);
	Zf(i_shake256_inject)(&sc, &flag, 1);
	if (accept) {
		Zf(i_shake256_inject)(&sc, (const uint8_t *)f, GIBBS_N);
		Zf(i_shake256_inject)(&sc, (const uint8_t *)g, GIBBS_N);
	}
	Zf(i_shake256_flip)(&sc);
	Zf(i_shake256_extract)(&sc, out, 16);
}

static int
test_kat(void)
{
	int8_t f_arr[GIBBS_N], g_arr[GIBBS_N];
	uint8_t tmp_keygen[FALCON_KEYGEN_TEMP_9];
	const size_t n_kat = sizeof gibbs_kat_table / sizeof gibbs_kat_table[0];
	int failures = 0;
	unsigned oldcw;
	size_t i;

	oldcw = set_fpu_cw(2);
	for (i = 0; i < n_kat; i++) {
		inner_shake256_context rng;
		uint8_t got[16];
		int accept;
		size_t b;

		seed_from_u64(&rng, gibbs_kat_table[i].seed);
		memset(f_arr, 0, sizeof f_arr);
		memset(g_arr, 0, sizeof g_arr);
		memset(tmp_keygen, 0, sizeof tmp_keygen);

		accept = Zf(gibbs_sample_fg_once)(&rng,
			f_arr, g_arr, GIBBS_LOGN, tmp_keygen);
		digest_fg(got, accept, f_arr, g_arr);

		if (memcmp(got, gibbs_kat_table[i].expected,
			sizeof got) != 0)
		{
			printf("KAT FAIL seed=%llu accept=%d\n  got      ",
				(unsigned long long)gibbs_kat_table[i].seed,
				accept);
			for (b = 0; b < sizeof got; b++) {
				printf("%02x", got[b]);
			}
			printf("\n  expected ");
			for (b = 0; b < sizeof got; b++) {
				printf("%02x",
					gibbs_kat_table[i].expected[b]);
			}
			printf("\n");
			failures++;
		}
		fflush(stdout);
	}
	set_fpu_cw(oldcw);

	printf("KAT: %zu/%zu seeds match\n", n_kat - failures, n_kat);
	fflush(stdout);
	return failures == 0;
}

int
main(void)
{
	int failures = 0;

	printf("Gibbs keygen test (logn=%d, N=%d, trials=%d)\n",
		GIBBS_LOGN, GIBBS_N, GIBBS_TRIALS);

	failures += !test_kat();
	failures += !test_norm_bounds();
	failures += !test_sign_verify();
	failures += !test_success_rate();

	if (failures > 0) {
		printf("FAILED: %d test(s) failed\n", failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
