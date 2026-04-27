#!/bin/bash
#
# Epsilon sweep on the unmodified Gibbs_Falcon reference repo.
#
# What this does:
#   For each epsilon value, it patches two lines:
#     1. param.h: ANTRAG_ALPHA = 1.04 - epsilon  (the sampling beta)
#     2. keygen.c line 124: ANTRAG_ALPHA + epsilon  (the gate alpha)
#   Then builds and runs a small test harness that calls keygen_fg() 1000
#   times and counts single-shot successes (keygen_fg returns 1 = first
#   embedding attempt passed).
#
# Prerequisites:
#   - The reference repo cloned and patched for your platform (ARM64 patches
#     described in gibbs-paper-vs-reference.md §8, or unpatched on x86-64).
#   - Working C compiler (clang or gcc).
#
# Usage:
#   cd /path/to/Gibbs_Falcon/Code
#   bash /path/to/this/script.sh
#
# The script restores all modified files when done.

set -e

REPO="${1:-.}"
cd "$REPO"

# Save originals
cp param.h param.h.bak
cp keygen.c keygen.c.bak

# Write the test harness OUTSIDE the Code dir to avoid wildcard Makefile
SWEEP_DIR=$(mktemp -d)
trap "rm -rf $SWEEP_DIR" EXIT
cat > "$SWEEP_DIR/test_sweep.c" << 'HARNESS'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "api.h"
#include "randombytes.h"
#include "param.h"

/* Provided by keygen.c */
int keygen_fg(secret_key *sk);

#define TRIALS 1000

int main(void)
{
    srand(42);
    seed_rng();

    secret_key sk;
    int single_shot = 0;
    int total_retries = 0;

    for (int i = 0; i < TRIALS; i++) {
        int t = keygen_fg(&sk);
        total_retries += t;
        if (t == 1)
            single_shot++;
    }

    double avg = (double)total_retries / TRIALS;
    /*
     * Print: epsilon, beta (=ANTRAG_ALPHA), gate alpha, single-shot
     * count, single-shot rate, average retries.
     *
     * Note: ANTRAG_ALPHA in the reference is the sampling parameter
     * (paper's beta). The gate alpha = ANTRAG_ALPHA + epsilon, which
     * is baked into keygen.c at compile time.
     */
    printf("beta=%.4f  single_shot=%d/%d (%.1f%%)  avg_retries=%.2f\n",
           (double)ANTRAG_ALPHA, single_shot, TRIALS,
           100.0 * single_shot / TRIALS, avg);

    return 0;
}
HARNESS

echo "Epsilon sweep: alpha = 1.04 held fixed, varying epsilon"
echo ""
echo "epsilon  beta    single-shot          avg_retries"
echo "-------  ------  -------------------  -----------"

for eps in 0.005 0.006 0.007 0.008 0.009 0.010 0.012 0.015 0.020 0.030; do
    # Compute beta = 1.04 - eps  (using awk for float arithmetic)
    beta=$(awk "BEGIN { printf \"%.4f\", 1.04 - $eps }")

    # Patch param.h: replace the ANTRAG_ALPHA value for d=512.
    # The original line is:  #define ANTRAG_ALPHA 1.045  // 1.15
    # We replace the number after ANTRAG_ALPHA on the d==512 branch.
    awk -v b="$beta" '
        /ANTRAG_D == 512/,/ANTRAG_D == 1024/ {
            if ($0 ~ /#define ANTRAG_ALPHA/) {
                sub(/ANTRAG_ALPHA [0-9.]+/, "ANTRAG_ALPHA " b)
            }
        }
        { print }
    ' param.h.bak > param.h

    # Patch keygen.c: replace the hardcoded 0.005 offset with this eps.
    awk -v e="$eps" '
        /ANTRAG_ALPHA_PRIME = ANTRAG_ALPHA \+/ {
            sub(/\+ 0\.005/, "+ " e)
        }
        { print }
    ' keygen.c.bak > keygen.c

    # Build (suppress warnings)
    make clean  > /dev/null 2>&1 || true
    make        > /dev/null 2>&1

    # Compile and link the test harness (from temp dir)
    cc -O3 -I. -c -o "$SWEEP_DIR/test_sweep.o" "$SWEEP_DIR/test_sweep.c"
    cc -o "$SWEEP_DIR/test_sweep" "$SWEEP_DIR/test_sweep.o" \
       keygen.o codec.o common.o cpucycles.o \
       falcon_keygen.o fft.o fips202.o fpr.o normaldist.o poly.o \
       randombytes.o rng.o shake.o -lm

    # Run and prefix with epsilon
    result=$("$SWEEP_DIR/test_sweep")
    printf "%.3f    %s\n" "$eps" "$result"
done

# Restore originals
mv param.h.bak param.h
mv keygen.c.bak keygen.c

echo ""
echo "Done. Original files restored."
