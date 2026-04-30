#ifndef FALCON_DET512_H__
#define FALCON_DET512_H__

#include <stddef.h>
#include <stdint.h>
#include "falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FALCON_DET512_LOGN 9
#define FALCON_DET512_PUBKEY_SIZE FALCON_PUBKEY_SIZE(FALCON_DET512_LOGN)
#define FALCON_DET512_PRIVKEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_DET512_LOGN)

// Replace the 40 byte salt (nonce) with a single byte representing
// the salt version:
#define FALCON_DET512_SIG_COMPRESSED_MAXSIZE FALCON_SIG_COMPRESSED_MAXSIZE(FALCON_DET512_LOGN)-40+1
#define FALCON_DET512_SIG_CT_SIZE FALCON_SIG_CT_SIZE(FALCON_DET512_LOGN)-40+1

// The header bytes for deterministic mode correspond to the headers
// for ordinary compressed/CT format, but with n=512 and MSB=1:
#define FALCON_DET512_SIG_COMPRESSED_HEADER (0x39 | 0x80)
#define FALCON_DET512_SIG_CT_HEADER (0x59 | 0x80)

// This version should be incremented upon any functional
// (input-output) changes to the signing algorithm.
#define FALCON_DET512_CURRENT_SALT_VERSION 0

/*
 * Generate a keypair (for Falcon parameter n=512).
 *
 * The source of randomness is the provided SHAKE256 context *rng,
 * which must have been already initialized, seeded, and set to output
 * mode (see shake256_init_prng_from_seed() and
 * shake256_init_prng_from_system()).
 *
 * The private key is written in the buffer pointed to by privkey.
 * The size of that buffer must be FALCON_DET512_PRIVKEY_SIZE bytes.
 *
 * The public key is written in the buffer pointed to by pubkey.
 * The size of that buffer must be FALCON_DET512_PUBKEY_SIZE bytes.
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det512_keygen(shake256_context *rng, void *privkey, void *pubkey);

/*
 * Deterministically sign the data provided in buffer data[] (of
 * length data_len bytes), using the private key held in privkey[] (of
 * length FALCON_DET512_PRIVKEY_SIZE bytes). The resulting
 * compressed-format, variable-length signature is written in sig[]
 * (which should be at least FALCON_DET512_SIG_COMPRESSED_MAXSIZE
 * bytes); the signature length is written to sig_len.
 *
 * The resulting signature is incompatible with randomized ("salted")
 * Falcon signatures: it excludes the salt (nonce), adds a salt
 * version byte, and changes the header byte. See the "Deterministic
 * Falcon" specification for further details.
 *
 * This function implements only the following subset of the
 * specification:
 *
 *   -- the parameter n is fixed to n=512
 *   -- the signature format is 'compressed'
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det512_sign_compressed(void *sig, size_t *sig_len,
	const void *privkey, const void *data, size_t data_len);

/*
 * Verify the compressed-format, deterministic-mode (det512)
 * signature provided in sig[] (of length sig_len bytes) with respect
 * to the public key provided in pubkey[] (of length
 * FALCON_DET512_PUBKEY_SIZE bytes) and the data provided in data[]
 * (of length data_len bytes).
 *
 * This function accepts a strict subset of valid deterministic-mode
 * Falcon signatures, namely, only those having n=512 and
 * "compressed" signature format (thus matching the choices
 * implemented by falcon_det512_sign_compressed).
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det512_verify_compressed(const void *sig, size_t sig_len,
	const void *pubkey, const void *data, size_t data_len);

/*
 * Verify the CT-format, deterministic-mode (det512) signature
 * provided in sig[] (of length FALCON_DET512_SIG_CT_SIZE bytes) with
 * respect to the public key provided in pubkey[] (of length
 * FALCON_DET512_PUBKEY_SIZE bytes) and the data provided in data[]
 * (of length data_len bytes).
 *
 * This function accepts a strict subset of valid deterministic-mode
 * Falcon signatures, namely, only those having n=512 and "CT"
 * signature format.
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det512_verify_ct(const void *sig,
	const void *pubkey, const void *data, size_t data_len);

/*
 * Convert the compressed-format, deterministic-mode (det512)
 * signature in sig_compressed (of length sig_compressed_len bytes) to
 * CT format. The resulting CT signature is written to sig_ct (of
 * length FALCON_DET512_SIG_CT_SIZE bytes).
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det512_convert_compressed_to_ct(void *sig_ct,
	const void *sig_compressed, size_t sig_compressed_len);

/*
 * Returns the salt version of a signature, in either compressed or CT
 * form.
 */
int falcon_det512_get_salt_version(const void* sig);

/*
 * Unpack a det512 public key representing a ring element h to its
 * vector of polynomial coefficients, i.e.,
 *
 * h(x) = h[0] + h[1] * x + h[2] * x^2 + ... + h[511] * x^511.
 *
 * Returns a non-zero error code if pubkey is invalid.
 */
int falcon_det512_pubkey_coeffs(uint16_t *h, const void *pubkey);

/*
 * Hash data of length data_len, using the fixed 40-byte salt
 * specified by salt_version, to a ring element c, represented by
 * its vector of polynomial coefficients.
 *
 * (See Section 3.7 of the Falcon specification for the details of the
 *  hashing, and Section 2.3.2-3 of the Deterministic Falcon
 *  specification for the definition of the fixed salt.)
 */
void falcon_det512_hash_to_point_coeffs(uint16_t *c, const void *data, size_t data_len, uint8_t salt_version);

/*
 * Unpack a det512 signature in CT format to the vector of polynomial
 * coefficients of the associated ring element s_2.
 *
 * (See Section 3.10 of the Falcon specification for details.)
 *
 * Returns a non-zero error code if sig cannot be properly unpacked.
 */
int falcon_det512_s2_coeffs(int16_t *s2, const void* sig);

/*
 * Compute the vector of polynomial coefficients of s_1 = c - s_2 * h,
 * given the unpacked values h, c, and s_2.
 *
 * (See Section 3.10 of the Falcon specification for details.)
 *
 * Returns a non-zero error code if the aggregate (s_1,s_2) vector is
 * not short enough to constitute a valid signature (for the public
 * key corresponding to h, the hash digest corresponding to c, and the
 * signature corresponding to s_2).
 */
int falcon_det512_s1_coeffs(int16_t *s1, const uint16_t *h, const uint16_t *c, const int16_t *s2);

#ifdef __cplusplus
}
#endif

#endif
