#!/usr/bin/env bash
# Compare the falcon_det1024_* function bodies in the current
# deterministic.c against the PR base on main, to confirm that moving
# them into the parameterized template did not change what the
# compiler sees.
#
# Each function is preprocessed with `cc -E` and diffed. The expected
# output is that every body is identical, with the only differences
# being:
#  1. the four call sites that previously called
#     falcon_det1024_write_salt / falcon_det1024_resalt and now call
#     the shared static helpers det_write_salt / det_resalt with
#     logn=10 passed as a literal argument; and
#  2. the signature header byte comparisons, which previously inlined
#     literal magic numbers (0x3A | 0x80) / (0x5A | 0x80) and are now
#     derived from logn as ((0x30 + 10) | 0x80) / ((0x50 + 10) | 0x80).
# Both rewrites are textual-only: every preprocessed numeric value is
# unchanged.
#
# The det512 variant did not exist in the baseline, so this script
# does not compare it.
#
# Usage: ./scripts/verify_preprocessed.sh [baseline=ce15e75]
#
# The default baseline is pinned to commit ce15e75 ("Merge pull request
# #13 from cce/Wno-strict-prototypes"), which is the tip of main this
# branch is PR'd against.

set -eu

BASE_REF="${1:-ce15e75}"
REPO="$(git rev-parse --show-toplevel)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"

# Stage the headers needed for preprocessing the baseline
for f in falcon.h inner.h fpr.h config.h; do
  git --git-dir="$REPO/.git" show "$BASE_REF:$f" > "$f"
done
git --git-dir="$REPO/.git" show "$BASE_REF:deterministic.c" > base.c
git --git-dir="$REPO/.git" show "$BASE_REF:deterministic.h" > deterministic.h

# Preprocess baseline and current
clang -E -P base.c                          | grep -v '^$' > base.i
clang -E -P -I"$REPO" "$REPO/deterministic.c" | grep -v '^$' > new.i

failures=0
for fn in keygen sign_compressed convert_compressed_to_ct verify_compressed \
          verify_ct get_salt_version pubkey_coeffs hash_to_point_coeffs \
          s2_coeffs s1_coeffs; do
  sym="falcon_det1024_${fn}"
  # 2nd match of "^(int|void) <sym>(" is the function definition (1st is the
  # forward declaration expanded from the header).
  a_line=$(awk -v s="$sym" '$0 ~ "^(int|void) "s"\\(" {n++; if(n==2){print NR; exit}}' base.i)
  b_line=$(awk -v s="$sym" '$0 ~ "^(int|void) "s"\\(" {n++; if(n==2){print NR; exit}}' new.i)
  sed -n "${a_line},/^}/p" base.i > a.txt
  sed -n "${b_line},/^}/p" new.i  > b.txt

  if diff -q a.txt b.txt > /dev/null; then
    printf "  IDENTICAL  %-45s (%d lines)\n" "$sym" "$(wc -l < a.txt | tr -d ' ')"
  else
    # Allow only the expected refactor differences:
    #   - calls to the shared helpers det_write_salt / det_resalt
    #     replacing the per-variant falcon_det1024_* ones;
    #   - signature header byte comparisons that were literal
    #     (0x3A | 0x80) / (0x5A | 0x80) and are now derived from logn
    #     as ((0x30 + 10) | 0x80) / ((0x50 + 10) | 0x80).
    unexpected=$(diff a.txt b.txt \
      | grep -E '^[<>]' \
      | grep -vE "falcon_det1024_(write_salt|resalt)\(" \
      | grep -vE "det_(write_salt|resalt)\(" \
      | grep -vE "\(0x[35]A \| 0x80\)" \
      | grep -vE "\(\(0x[35]0 \+ 10\) \| 0x80\)" \
      || true)
    if [ -z "$unexpected" ]; then
      printf "  HELPER-RENAME-ONLY %-37s — diff:\n" "$sym"
      diff a.txt b.txt | sed 's/^/    /'
    else
      printf "  UNEXPECTED-DIFF    %-37s — diff:\n" "$sym"
      diff a.txt b.txt | sed 's/^/    /'
      failures=$((failures+1))
    fi
  fi
done

if [ "$failures" -ne 0 ]; then
  echo
  echo "FAIL: $failures function(s) showed unexpected differences vs $BASE_REF."
  exit 1
fi

echo
echo "PASS: every falcon_det1024_* body is identical to $BASE_REF, except"
echo "for the four call sites where det_write_salt / det_resalt now take logn"
echo "as a literal argument instead of having it baked into the helper name,"
echo "and for the header-byte comparisons that are now derived from logn"
echo "instead of inlined as literals."
