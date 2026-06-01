#!/bin/sh
# Generate the Deterministic Falcon implementation source(s) from the single
# template deterministic.c.tmpl. One file is produced per Falcon parameter n
# (e.g. deterministic1024.c for n = 1024, deterministic512.c for n = 512);
# generating them all from one template keeps their shared algorithm body
# from diverging.
#
# The lines of the template up to the __FALCON_DET_VERBATIM__ marker are the
# template's own documentation and are dropped. The lines between the
# __FALCON_DET_VERBATIM__ and __FALCON_DET_EXPAND__ markers (the #includes)
# are copied verbatim. Everything after __FALCON_DET_EXPAND__ is run through
# the C preprocessor with DET_N set to the parameter n -- e.g. 1024
# (falcon_det1024_*) or 512 (falcon_det512_*) -- which selects the function
# family and the matching parameter set.
#
# The template is tab-indented like the rest of the tree. The body is passed
# through "expand" before the C preprocessor (which would otherwise collapse
# each tab to a single space, destroying the indentation) and back through
# "unexpand" afterwards, so the generated files keep the tab indentation used
# throughout the rest of the tree.
#
# Usage: gen_deterministic.sh [CC] [OUTDIR] N...
#   CC      C compiler to use as the preprocessor (default: cc)
#   OUTDIR  directory to write the generated files into (default: the
#           repository root; a relative path is interpreted relative to it)
#   N...    Falcon parameters n to generate, e.g. "1024 512"; the Makefile
#           passes a single n to regenerate one file at a time, which keeps
#           the per-file rules race-free under "make -j"
set -eu

# The template lives in the repository root, one level above this script.
# Work from there so the script behaves the same wherever it is invoked from.
cd "$(dirname "$0")/.."

CC="${1:-cc}"
OUT="${2:-.}"
IN="deterministic.c.tmpl"
BANNER='/* GENERATED from deterministic.c.tmpl -- DO NOT EDIT. Run "make gen" to regenerate. */'

emit() { # $1 = DET_N value, $2 = output file
	{
		printf '%s\n' "$BANNER"
		# Verbatim section: lines between the two markers (exclusive).
		awk '/__FALCON_DET_EXPAND__/{exit} v; /__FALCON_DET_VERBATIM__/{v=1}' "$IN"
		# Expanded section: everything after the EXPAND marker. Tabs are
		# expanded to 8 spaces first so indentation survives the C
		# preprocessor (which collapses each tab to a single space), the
		# body is macro-expanded, the line markers cpp emits are stripped
		# with grep, and unexpand restores the tab indentation. -C keeps
		# comments, no -P so blank lines survive. -ffreestanding stops
		# gcc on glibc systems from pre-including <stdc-predef.h>, whose
		# comments -C would otherwise copy into the output.
		awk 'e; /__FALCON_DET_EXPAND__/{e=1}' "$IN" \
			| expand -t 8 \
			| "$CC" -E -C -ffreestanding -DDET_N="$1" -x c - \
			| grep -vE '^# [0-9]' \
			| unexpand
	} > "$2"
}

# The parameters n to generate follow CC and OUTDIR (e.g. 1024 512); each
# produces deterministic<n>.c. The list is supplied by the caller so this
# script has no built-in knowledge of which parameter sets exist.
if [ $# -ge 2 ]; then
	shift 2
else
	set --
fi
for n in "$@"; do
	emit "$n" "$OUT/deterministic$n.c"
done
