DETERMINISTIC FALCON IMPLEMENTATION
===================================

GIBBS SAMPLER KEY GENERATION (gibbs branch)
-------------------------------------------

This branch integrates the Gibbs sampler trapdoor generation algorithm
from:

  Chao Sun, Thomas Espitau, Junjie Song, Jinguang Han, Mehdi Tibouchi.
  "Generating FALCON Trapdoors via Gibbs Sampler" (PQCrypto 2026).

The paper is included as falcon-gibbs.pdf.

Overview

  Instead of the standard trial-and-repeat approach (sampling f, g from
  discrete Gaussians and rejecting when the quality bound is not met),
  this branch uses a Gibbs sampler in the Fourier domain to directly
  generate (f, g) pairs that achieve a quality parameter alpha = 1.04,
  down from the standard alpha = 1.17.  This raises the classical
  security of FALCON-512 from ~120 bits to ~128 bits (NIST level 1).

  The implementation targets logn = 9 (n = 512) only.

Differences from the paper

  - epsilon = 0.01 instead of the paper's 0.005.  The paper predicts
    ~99.4% single-shot acceptance at epsilon = 0.005, but in practice
    rounding noise consumes most of the margin and acceptance drops to
    ~74%.  Doubling epsilon to 0.01 restores acceptance to ~99.6%.
    This trades a slightly tighter Gibbs sampling region for reliable
    acceptance.  The output is still gated on alpha = 1.04 quality.

  - gibbs_decode_odd() adds a parity fix not described in the paper:
    after rounding each coefficient to the nearest integer, the sum of
    coefficients is forced odd (required by the NTRU equation solver).
    The standard keygen gets this from poly_small_mkgauss's biased-coin
    trick; the Gibbs path must do it explicitly.

  - A coefficient bounds gate rejects keys where any coefficient exceeds
    the FALCON_COMP_TRIM encoding limit (max_fg_bits), matching the
    standard keygen path.

  - An integer-norm gate (||f||^2 + ||g||^2 < alpha^2 * q) serves as a
    cheap pre-filter before the full FFT-domain GS-norm gate.

Build

  The Gibbs keygen is gated behind -DFALCON_GIBBS_KEYGEN=1.  The Go
  build-tag file falcon_gibbs.go sets this automatically when the
  'gibbs' build tag is used:

    go build -tags gibbs ./...

  For the C test harness:

    make test_gibbs       # KAT, acceptance rate, sign+verify tests
    make test_fpr_trig    # sin/cos accuracy tests

  The standard 'make' target builds without Gibbs support; existing
  tests and benchmarks are unaffected.

WARNING

  Keys generated with this path are NOT compatible with standard FALCON.
  The alpha = 1.04 quality produces shorter signatures and higher
  security, but the encoding and verification differ from the NIST
  standard.  Do not use in production.

Integration with deterministic-512 (det512)

  The Gibbs keygen is a drop-in replacement for the Falcon-512 key
  generation step.  All other components — deterministic signing,
  verification, CT conversion, and auxiliary functions in
  deterministic512.h — work unchanged with Gibbs-generated keys.  The
  MCU workbuf APIs (see EMBEDDED USAGE below) are also compatible.

  Build and run the integration test:

    make tests/test_gibbs_det512 && ./tests/test_gibbs_det512

  This exercises the full pipeline: Gibbs keygen → det512 compressed
  sign → det512 verify → CT conversion → CT verify, using both the
  convenience wrappers and the workbuf API variants.


BASE IMPLEMENTATION
-------------------

Version: 2021-12-03

Falcon is a post-quantum signature algorithm, submitted to NIST's
Post-Quantum Cryptography project:

   https://csrc.nist.gov/Projects/Post-Quantum-Cryptography

Falcon is based on NTRU lattices, used with a hash-and-sign structure
and a Fourier-based sampling method that allows efficient signature
generation and verification, while producing and using relatively
compact signatures and public keys. The official Falcon Web site is:

   https://falcon-sign.info/

This implementation slightly extends the official Falcon code to
support a fully deterministic (or "derandomized") signing mode; the
interface is given in deterministic.h. (This is an alternative to the
randomized-hashing mode enabled by the original implementation.) For
the motivation for, and specification of, the deterministic mode, see
falcon-det.pdf .

This implementation is written in C and is configurable at compile
time through macros which are documented in config.h; each macro is a
boolean option and can be enabled or disabled in config.h and/or as a
command-line parameter to the compiler. Several implementation
strategies are available; however, in all cases, the same API is
implemented.

*** CRITICAL SECURITY WARNING ***

For robust determinism across supported devices, which is needed to
prevent a potential catastrophic security failure in the deterministic
mode, it is STRONGLY RECOMMENDED that the following macro settings be
used, as is done in config.h (see that file for further details):

  - floating-point emulation (FALCON_FPEMU) should be enabled, in lieu
    of native FP operations.

  - "fused multiply-add" (FALCON_FMA) should be disabled, *especially*
    if native FP operations are enabled.

  - other optimizations like FALCON_AVX2 and FALCON_ASM_CORTEXM4
    should be disabled as a cautionary measure, unless they are needed
    for performance and can be thoroughly checked to not affect
    determinism on the relevant signing devices.

(According to the documentation below, FALCOM_FMA and FALCON_AVX2 have
no effect when FALCON_FPEMU is enabled, but in config.h they are
explicitly disabled as a defensive measure.)

*** END CRITICAL SECURITY WARNING ***

Main options are the following:

  - FALCON_FPNATIVE and FALCON_FPEMU

    If using FALCON_FPNATIVE, then the C 'double' type is used for all
    floating-point operations. This is the default. This requires the
    'double' type to implement IEEE-754 semantics, in particular
    rounding to the exact precision of the 'binary64' type (i.e. "53
    bits"). The Falcon implementation takes special steps to ensure
    these properties on most common architectures. When using this
    engine, the code _may_ need to call the standard library function
    sqrt() (depending on the local architecture), which may in turn
    require linking with a specific library (e.g. adding '-lm' to the
    link command on Unix-like systems).

    FALCON_FPEMU does not use the C 'double' type, but instead works
    over only 64-bit integers and embeds its own emulation of IEEE-754
    operations. This is slower but portable, since it will work on any
    machine with a C99-compliant compiler.

  - FALCON_AVX2 and FALCON_FMA

    FALCON_AVX2, when enabled, activates the use of AVX2 compiler
    intrinsics. This works only on x86 CPU that offer AVX2 opcodes.
    Use of AVX2 improves performance. FALCON_AVX2 has no effect if
    FALCON_FPEMU is used.

    FALCON_FMA further enables the use for FMA ("fused multiply-add")
    compiler intrinsics for an extra boost to performance. This
    setting is ignored unless FALCON_FPNATIVE and FALCON_AVX2 are
    both used. Occasionally (but rarely), use of FALCON_FMA will
    change the keys and/or signatures generated from a given random
    seed, impacting reproducibility of test vectors; however, this
    has no bearing on the security of normal usage.

  - FALCON_ASM_CORTEXM4

    When enabled, inline assembly routines for FP emulation and SHAKE256
    will be used. This will work only on the ARM Cortex M3, M4 and
    compatible CPU. This assembly code is constant-time on the M4, and
    about twice faster than the generic C code used by FALCON_FPEMU.


USAGE
-----

See the Makefile for compilation flags, and config.h for configurable
options. Type 'make' to compile: this will generate two binaries called
'test_falcon' and 'speed'. 'test_falcon' runs unit tests to verify that
everything computes the expected values. 'speed' runs performance
benchmarks on Falcon-256, Falcon-512 and Falcon-1024 (Falcon-256 is a
reduced version that is faster and smaller than Falcon-512, but provides
only reduced security, and not part of the "official" Falcon).

Applications that want to use Falcon normally work on the external API,
which is documented in the "falcon.h" file. This is the only file that
an external application needs to use.

EMBEDDED USAGE
--------------

The C implementation can be used on embedded targets, but Falcon-1024
needs substantial temporary storage. The generic Falcon API in
"falcon.h" already lets the caller provide temporary buffers. This
repository now exposes matching MCU-oriented entry points for the
deterministic det1024 wrapper in "deterministic.h":

  - falcon_det1024_keygen_with_workbuf()
  - falcon_det1024_sign_compressed_with_workbuf()
  - falcon_det1024_verify_compressed_with_workbuf()
  - falcon_det1024_verify_ct_with_workbuf()
  - falcon_det1024_convert_compressed_to_ct_with_workbuf()
  - falcon_det1024_hash_to_point_coeffs_with_workbuf()
  - falcon_det1024_s1_coeffs_with_workbuf()

A parallel interface exists for deterministic Falcon-512 (det512) in
"deterministic512.h", including workbuf entry points for keygen,
signing, verification, CT conversion, hashing, and s1 computation.
The det512 layer is compatible with the Gibbs-sampler keygen path
(see GIBBS SAMPLER section above).

Each such function has a corresponding FALCON_DET1024_WORKBUF_*_SIZE
macro so that applications can place the work area in static RAM,
thread-local storage, or another caller-controlled memory region,
instead of using large stack allocations in the convenience wrappers.

In real-world terms, these changes mostly save *stack*, not total RAM.
The algorithm still needs the same temporary space, but the caller now
decides where that space lives.

For Falcon-1024 det1024, the rough stack impact of the convenience
wrappers versus the workbuf APIs is:

  - keygen: about 31.8 kB moved off the stack
  - sign_compressed: about 81.3 kB moved off the stack
  - verify_compressed: about 9.7 kB moved off the stack
  - verify_ct: about 9.8 kB moved off the stack

A typical embedded scenario is an RTOS task with an 8 kB or 16 kB
stack. In the old wrapper API, calling falcon_det1024_sign_compressed()
would often require making that task stack much larger, or risk stack
overflow. With falcon_det1024_sign_compressed_with_workbuf(), the task
stack stays small while the ~81 kB work area can be placed in static
RAM, a dedicated arena, or another memory region chosen by the
application.

Likewise, verification often becomes easier to deploy on small stacks:
the old API needs roughly 10 kB of stack, while the workbuf API allows
that temporary memory to be preallocated elsewhere.

On bare-metal systems, do not rely on shake256_init_prng_from_system():
it is implemented only for supported hosted environments. Instead, seed
the RNG explicitly with shake256_init_prng_from_seed(), using bytes
obtained from the platform TRNG or other approved entropy source.

For research purposes, the inner API is documented in "inner.h". This
API gives access to many internal functions that perform some elementary
operations used in Falcon. That API also has some non-obvious
requirements, such as alignment on temporary buffers, or the need to
adjust FPU precision on 32-bit x86 systems.


LICENSE
-------

This code is provided under the MIT license:

==========================(LICENSE BEGIN)============================
Copyright (c) 2017-2020  Falcon Project

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
===========================(LICENSE END)=============================

The main code was written by Thomas Pornin <thomas.pornin@nccgroup.com>, to
whom questions may be addressed. I'll endeavour to respond more or less
promptly.

The deterministic mode was written by David Lazar
<lazard@csail.mit.edu>, with input from Chris Peikert
<chris.peikert@algorand.com> and others from Algorand, Inc.
