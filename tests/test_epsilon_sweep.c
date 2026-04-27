/*
 * Sweep epsilon values to measure single-shot acceptance rate.
 * Compile once per epsilon value via -DSWEEP_EPSILON=<val>.
 *
 * Usage (from repo root):
 *   for e in 0.005 0.010 0.015 0.020 0.030 0.040 0.050; do
 *     clang -O3 -DFALCON_GIBBS_KEYGEN=1 -DSWEEP_EPSILON=$e \
 *       -c -o keygen_sweep.o keygen.c
 *     clang -O3 -DFALCON_GIBBS_KEYGEN=1 -DSWEEP_EPSILON=$e \
 *       -c -o tests/test_epsilon_sweep.o tests/test_epsilon_sweep.c
 *     clang -o tests/test_epsilon_sweep tests/test_epsilon_sweep.o \
 *       keygen_sweep.o codec.o common.o deterministic.o falcon.o \
 *       fft.o fpr.o rng.o shake.o sign.o vrfy.o -lm
 *     ./tests/test_epsilon_sweep
 *   done
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../config.h"
#include "../inner.h"

#ifndef FALCON_GIBBS_KEYGEN
#error "FALCON_GIBBS_KEYGEN must be defined"
#endif

#ifndef SWEEP_EPSILON
#define SWEEP_EPSILON 0.005
#endif

#ifndef SWEEP_LOGN
#define SWEEP_LOGN 9
#endif

#define LOGN   SWEEP_LOGN
#define N      (1 << LOGN)
#if LOGN == 10
#define TMP_SZ FALCON_KEYGEN_TEMP_10
#else
#define TMP_SZ FALCON_KEYGEN_TEMP_9
#endif
#define TRIALS 1000

static void
seed_from_u64(inner_shake256_context *sc, uint64_t seed)
{
	uint8_t buf[8];
	int i;
	for (i = 0; i < 8; i++)
		buf[i] = (uint8_t)(seed >> (56 - 8 * i));
	memset(sc, 0, sizeof *sc);
	Zf(i_shake256_init)(sc);
	Zf(i_shake256_inject)(sc, buf, 8);
	Zf(i_shake256_flip)(sc);
}

int
main(void)
{
	int8_t f[N], g[N];
	uint8_t tmp[TMP_SZ];
	int successes = 0, i;
	unsigned oldcw;
	double alpha = 1.04;
	double epsilon = SWEEP_EPSILON;

	oldcw = set_fpu_cw(2);

	for (i = 0; i < TRIALS; i++) {
		inner_shake256_context rng;
		seed_from_u64(&rng, (uint64_t)(i + 1));
		memset(f, 0, sizeof f);
		memset(g, 0, sizeof g);
		memset(tmp, 0, sizeof tmp);
		if (Zf(gibbs_sample_fg_once)(&rng, f, g, LOGN, tmp))
			successes++;
	}

	set_fpu_cw(oldcw);

	printf("logn=%d  epsilon=%.3f  alpha=%.2f  beta=%.3f  "
	       "accept=%d/%d (%.1f%%)\n",
	       LOGN, epsilon, alpha, alpha - epsilon,
	       successes, TRIALS,
	       100.0 * successes / TRIALS);

	return 0;
}
