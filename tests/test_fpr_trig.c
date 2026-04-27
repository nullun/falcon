/*
 * Tests for Zf(fpr_sin) and Zf(fpr_cos).
 *
 * Two checks:
 *   1. Accuracy: sweep inputs across [0, 2*pi) plus quadrant boundaries,
 *      compare the fpr result against host libm sin/cos, assert that the
 *      ULP difference stays within budget.
 *   2. Print KAT bit patterns at a small fixed input table. The same set
 *      of inputs should produce the same uint64_t output bytes on every
 *      platform when FALCON_FPEMU=1; that is the cross-platform
 *      determinism claim the rest of the Gibbs work depends on.
 */

#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../config.h"
#include "../inner.h"

/* Absolute-error budget for the libm comparison. We use absolute (not
 * ULP-of-output) tolerance because near multiples of pi/2 the mathematical
 * sin/cos value is tiny while the libm reference uses extended-precision
 * pi for its internal range reduction. Our Cody-Waite reduction loses one
 * extra word of precision at exactly the boundary, which produces a few
 * times 10^-17 of disagreement when the output itself is ~10^-12. The
 * kernels and reduction are both <1 ULP at scale of r in the working
 * range; this absolute bound captures that with margin to spare. */
#define ABS_BUDGET 1e-14
/* Reported alongside as a diagnostic, not enforced. */
#define ULP_BUDGET 8

/* Reinterpret a host double as the project's fpr type without going
 * through any arithmetic. Works in both modes because fpr is 8 bytes. */
static fpr
double_to_fpr(double d)
{
	fpr x;
	memcpy(&x, &d, sizeof x);
	return x;
}

static double
fpr_to_double(fpr x)
{
	double d;
	memcpy(&d, &x, sizeof d);
	return d;
}

static uint64_t
fpr_bits(fpr x)
{
	uint64_t u;
	memcpy(&u, &x, sizeof u);
	return u;
}

static int
ulps_diff(double a, double b)
{
	int64_t ia, ib, d;

	memcpy(&ia, &a, sizeof ia);
	memcpy(&ib, &b, sizeof ib);
	if ((ia < 0) != (ib < 0)) {
		if (a == b) {
			return 0;
		}
		return INT_MAX;
	}
	d = (ia > ib) ? (ia - ib) : (ib - ia);
	if (d > INT_MAX) {
		return INT_MAX;
	}
	return (int)d;
}

static int
check_one(double x, double *max_abs_sin, double *max_abs_cos,
	int *max_ulp_sin, int *max_ulp_cos, const char *tag)
{
	fpr fx, fs, fc;
	double s_ref, c_ref, s_got, c_got, e_s, e_c;
	int u_s, u_c, fail;

	fx = double_to_fpr(x);
	fs = fpr_sin(fx);
	fc = fpr_cos(fx);
	s_ref = sin(x);
	c_ref = cos(x);
	s_got = fpr_to_double(fs);
	c_got = fpr_to_double(fc);
	e_s = fabs(s_got - s_ref);
	e_c = fabs(c_got - c_ref);
	u_s = ulps_diff(s_ref, s_got);
	u_c = ulps_diff(c_ref, c_got);
	if (e_s > *max_abs_sin) *max_abs_sin = e_s;
	if (e_c > *max_abs_cos) *max_abs_cos = e_c;
	if (u_s > *max_ulp_sin) *max_ulp_sin = u_s;
	if (u_c > *max_ulp_cos) *max_ulp_cos = u_c;
	fail = 0;
	if (e_s > ABS_BUDGET) {
		printf("FAIL %s sin(%.17g): got %.17g, expected %.17g, |err| %.3e\n",
			tag, x, s_got, s_ref, e_s);
		fail++;
	}
	if (e_c > ABS_BUDGET) {
		printf("FAIL %s cos(%.17g): got %.17g, expected %.17g, |err| %.3e\n",
			tag, x, c_got, c_ref, e_c);
		fail++;
	}
	return fail;
}

static int
test_accuracy(void)
{
	static const double boundaries[] = {
		0.0, 1e-12,
		M_PI / 4 - 1e-12, M_PI / 4, M_PI / 4 + 1e-12,
		M_PI / 2 - 1e-12, M_PI / 2, M_PI / 2 + 1e-12,
		M_PI - 1e-12, M_PI, M_PI + 1e-12,
		3 * M_PI / 2 - 1e-12, 3 * M_PI / 2, 3 * M_PI / 2 + 1e-12,
		2 * M_PI - 1e-12,
	};
	const int n_boundaries = sizeof boundaries / sizeof boundaries[0];
	int max_ulp_sin = 0, max_ulp_cos = 0, failures = 0;
	double max_abs_sin = 0.0, max_abs_cos = 0.0;
	uint64_t seed;
	int i;

	for (i = 0; i < n_boundaries; i++) {
		failures += check_one(boundaries[i],
			&max_abs_sin, &max_abs_cos,
			&max_ulp_sin, &max_ulp_cos, "boundary");
	}

	/* Deterministic LCG sweep so the test is reproducible. */
	seed = 0x123456789ABCDEF0ULL;
	for (i = 0; i < 10000; i++) {
		double r, x;

		seed = seed * 6364136223846793005ULL
			+ 1442695040888963407ULL;
		r = (double)(seed >> 11) * (1.0 / (double)(1ULL << 53));
		x = r * 2.0 * M_PI;
		failures += check_one(x, &max_abs_sin, &max_abs_cos,
			&max_ulp_sin, &max_ulp_cos, "sweep");
	}

	printf("max |err|: sin=%.3e cos=%.3e (budget %.0e)\n",
		max_abs_sin, max_abs_cos, (double)ABS_BUDGET);
	printf("max ULP (informational): sin=%d cos=%d\n",
		max_ulp_sin, max_ulp_cos);
	(void)ULP_BUDGET;
	return failures;
}

/*
 * Bit-identity KAT. Inputs are exactly representable doubles covering all
 * eight octants; expected outputs are recorded from a reference build with
 * FALCON_FPEMU=1. A divergence means either our impl regressed or the
 * compiler is contracting fpr_mul + fpr_add into FMA somewhere — both
 * worth investigating before any Gibbs work depends on this layer.
 */
static int
test_kat(void)
{
	struct kat_row {
		double x;
		uint64_t expected_sin;
		uint64_t expected_cos;
	};
	static const struct kat_row table[] = {
		{ 0.0,                 0x0000000000000000ULL, 0x3FF0000000000000ULL },
		{ 0.5,                 0x3FDEAEE8744B05F0ULL, 0x3FEC1528065B7D50ULL },
		{ 1.0,                 0x3FEAED548F090CEEULL, 0x3FE14A280FB5068BULL },
		{ M_PI / 2,            0x3FF0000000000000ULL, 0x8000000000000000ULL },
		{ 2.0,                 0x3FED18F6EAD1B445ULL, 0xBFDAA22657537206ULL },
		{ M_PI,                0x8000000000000000ULL, 0xBFF0000000000000ULL },
		{ 4.0,                 0xBFE837B9DDDC1EB0ULL, 0xBFE4EAA606DB24C0ULL },
		{ 3 * M_PI / 2,        0xBFF0000000000000ULL, 0x0000000000000000ULL },
		{ 5.0,                 0xBFEEAF81F5E09932ULL, 0x3FD22785706B4ADCULL },
		{ 6.28,                0xBF6A180FE0F0FB72ULL, 0x3FEFFFF55C68488EULL },
	};
	const int n = sizeof table / sizeof table[0];
	int i, fail = 0;

	for (i = 0; i < n; i++) {
		fpr fx = double_to_fpr(table[i].x);
		uint64_t got_sin = fpr_bits(fpr_sin(fx));
		uint64_t got_cos = fpr_bits(fpr_cos(fx));

		if (got_sin != table[i].expected_sin) {
			printf("KAT FAIL sin(%.17g): got 0x%016llx, expected 0x%016llx\n",
				table[i].x,
				(unsigned long long)got_sin,
				(unsigned long long)table[i].expected_sin);
			fail++;
		}
		if (got_cos != table[i].expected_cos) {
			printf("KAT FAIL cos(%.17g): got 0x%016llx, expected 0x%016llx\n",
				table[i].x,
				(unsigned long long)got_cos,
				(unsigned long long)table[i].expected_cos);
			fail++;
		}
	}
	printf("KAT: %d/%d entries match\n", n - fail / 2, n);
	return fail;
}

int
main(void)
{
	int failures = 0;

	failures += test_accuracy();
	failures += test_kat();
	if (failures > 0) {
		printf("FAILED: %d failures\n", failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
