// Copyright (C) 2026 Algorand, Inc.
//
// Slice-based, variant-parameterised wrappers covering all four Falcon
// parameterisations exposed by the underlying C library:
//
//   * FALCON-DET1024 (deterministic, n=1024)
//   * FALCON-DET512  (deterministic, n=512)
//   * FALCON-1024    (randomised,    n=1024)
//   * FALCON-512     (randomised,    n=512)
//
// The legacy fixed-array API in falcon.go (PublicKey/PrivateKey types) is
// untouched and remains det1024-only. Callers that need other variants use
// the slice-based functions in this file.

package falcon

// #include "falcon.h"
// #include "deterministic.h"
// #include "deterministic512.h"
//
// // Wrap parameterised FALCON_* macros so cgo can read them as constants.
// // (cgo cannot evaluate function-like macros directly.)
// enum {
// 	fg_pub_size_512        = FALCON_PUBKEY_SIZE(9),
// 	fg_priv_size_512       = FALCON_PRIVKEY_SIZE(9),
// 	fg_pub_size_1024       = FALCON_PUBKEY_SIZE(10),
// 	fg_priv_size_1024      = FALCON_PRIVKEY_SIZE(10),
// 	fg_sig_comp_max_512    = FALCON_SIG_COMPRESSED_MAXSIZE(9),
// 	fg_sig_comp_max_1024   = FALCON_SIG_COMPRESSED_MAXSIZE(10),
// 	fg_sig_ct_size_512     = FALCON_SIG_CT_SIZE(9),
// 	fg_sig_ct_size_1024    = FALCON_SIG_CT_SIZE(10),
// 	fg_tmp_keygen_512      = FALCON_TMPSIZE_KEYGEN(9),
// 	fg_tmp_keygen_1024     = FALCON_TMPSIZE_KEYGEN(10),
// 	fg_tmp_signdyn_512     = FALCON_TMPSIZE_SIGNDYN(9),
// 	fg_tmp_signdyn_1024    = FALCON_TMPSIZE_SIGNDYN(10),
// 	fg_tmp_verify_512      = FALCON_TMPSIZE_VERIFY(9),
// 	fg_tmp_verify_1024     = FALCON_TMPSIZE_VERIFY(10)
// };
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Variant identifies which Falcon parameterisation is in use.
type Variant int

const (
	// Det1024 selects FALCON-DET1024 (deterministic, n=1024).
	Det1024 Variant = iota
	// Det512 selects FALCON-DET512 (deterministic, n=512).
	Det512
	// Rand1024 selects randomised Falcon at n=1024.
	Rand1024
	// Rand512 selects randomised Falcon at n=512.
	Rand512
)

// Variant errors.
var (
	ErrUnknownVariant  = errors.New("falcon: unknown variant")
	ErrCTConvertNotDet = errors.New("falcon: CT conversion is only supported for deterministic variants")
)

func (v Variant) String() string {
	switch v {
	case Det1024:
		return "FALCON-DET1024"
	case Det512:
		return "FALCON-DET512"
	case Rand1024:
		return "FALCON-1024 (randomised)"
	case Rand512:
		return "FALCON-512 (randomised)"
	default:
		return fmt.Sprintf("unknown(%d)", int(v))
	}
}

// LogN returns the binary logarithm of the Falcon degree (9 for n=512, 10 for n=1024).
func (v Variant) LogN() uint {
	switch v {
	case Det1024, Rand1024:
		return 10
	case Det512, Rand512:
		return 9
	}
	return 0
}

// IsDeterministic reports whether v selects a deterministic-mode variant.
func (v Variant) IsDeterministic() bool {
	return v == Det1024 || v == Det512
}

// PublicKeySize returns the encoded public-key length, in bytes.
func (v Variant) PublicKeySize() int {
	if v.LogN() == 10 {
		return int(C.fg_pub_size_1024)
	}
	return int(C.fg_pub_size_512)
}

// PrivateKeySize returns the encoded private-key length, in bytes.
func (v Variant) PrivateKeySize() int {
	if v.LogN() == 10 {
		return int(C.fg_priv_size_1024)
	}
	return int(C.fg_priv_size_512)
}

// SigCompressedMaxSize returns the maximum size of a compressed-format signature.
// Deterministic variants drop the 40-byte nonce and add a 1-byte salt version, so
// they are 39 bytes shorter than randomised signatures at the same degree.
func (v Variant) SigCompressedMaxSize() int {
	switch v {
	case Det1024:
		return int(C.FALCON_DET1024_SIG_COMPRESSED_MAXSIZE)
	case Det512:
		return int(C.FALCON_DET512_SIG_COMPRESSED_MAXSIZE)
	case Rand1024:
		return int(C.fg_sig_comp_max_1024)
	case Rand512:
		return int(C.fg_sig_comp_max_512)
	}
	return 0
}

// SigCTSize returns the constant-time-format signature size.
func (v Variant) SigCTSize() int {
	switch v {
	case Det1024:
		return int(C.FALCON_DET1024_SIG_CT_SIZE)
	case Det512:
		return int(C.FALCON_DET512_SIG_CT_SIZE)
	case Rand1024:
		return int(C.fg_sig_ct_size_1024)
	case Rand512:
		return int(C.fg_sig_ct_size_512)
	}
	return 0
}

func (v Variant) tmpKeygen() int {
	if v.LogN() == 10 {
		return int(C.fg_tmp_keygen_1024)
	}
	return int(C.fg_tmp_keygen_512)
}

func (v Variant) tmpSign() int {
	if v.LogN() == 10 {
		return int(C.fg_tmp_signdyn_1024)
	}
	return int(C.fg_tmp_signdyn_512)
}

func (v Variant) tmpVerify() int {
	if v.LogN() == 10 {
		return int(C.fg_tmp_verify_1024)
	}
	return int(C.fg_tmp_verify_512)
}

// GenerateKeyVariant generates a public/private keypair for the given variant.
// If seed is empty, a system-RNG seed is used.
func GenerateKeyVariant(v Variant, seed []byte) (pub, priv []byte, err error) {
	var rng C.shake256_context
	if len(seed) == 0 {
		C.shake256_init_prng_from_seed(&rng, C.NULL, 0)
	} else {
		C.shake256_init_prng_from_seed(&rng, unsafe.Pointer(&seed[0]), C.size_t(len(seed)))
	}

	pub = make([]byte, v.PublicKeySize())
	priv = make([]byte, v.PrivateKeySize())

	var r C.int
	switch v {
	case Det1024:
		r = C.falcon_det1024_keygen(&rng, unsafe.Pointer(&priv[0]), unsafe.Pointer(&pub[0]))
	case Det512:
		r = C.falcon_det512_keygen(&rng, unsafe.Pointer(&priv[0]), unsafe.Pointer(&pub[0]))
	case Rand1024, Rand512:
		tmp := make([]byte, v.tmpKeygen())
		r = C.falcon_keygen_make(&rng, C.unsigned(v.LogN()),
			unsafe.Pointer(&priv[0]), C.size_t(len(priv)),
			unsafe.Pointer(&pub[0]), C.size_t(len(pub)),
			unsafe.Pointer(&tmp[0]), C.size_t(len(tmp)))
		runtime.KeepAlive(tmp)
	default:
		return nil, nil, ErrUnknownVariant
	}
	if r != 0 {
		return nil, nil, fmt.Errorf("error code %d: %w", int(r), ErrKeygenFail)
	}
	runtime.KeepAlive(seed)
	return pub, priv, nil
}

// SignCompressedVariant signs msg under priv and returns a compressed-format
// signature. Deterministic variants are reproducible from (priv, msg);
// randomised variants draw fresh entropy from crypto/rand on every call.
func SignCompressedVariant(v Variant, priv, msg []byte) ([]byte, error) {
	if len(priv) != v.PrivateKeySize() {
		return nil, fmt.Errorf("falcon: bad private-key length %d for %s: %w",
			len(priv), v, ErrSignFail)
	}

	sigBuf := make([]byte, v.SigCompressedMaxSize())
	sigLen := C.size_t(len(sigBuf))

	var msgPtr unsafe.Pointer
	if len(msg) > 0 {
		msgPtr = unsafe.Pointer(&msg[0])
	} else {
		msgPtr = C.NULL
	}

	var r C.int
	switch v {
	case Det1024:
		r = C.falcon_det1024_sign_compressed(unsafe.Pointer(&sigBuf[0]), &sigLen,
			unsafe.Pointer(&priv[0]), msgPtr, C.size_t(len(msg)))
	case Det512:
		r = C.falcon_det512_sign_compressed(unsafe.Pointer(&sigBuf[0]), &sigLen,
			unsafe.Pointer(&priv[0]), msgPtr, C.size_t(len(msg)))
	case Rand1024, Rand512:
		var seed [48]byte
		if _, e := rand.Read(seed[:]); e != nil {
			return nil, fmt.Errorf("falcon: rand: %w", e)
		}
		var rng C.shake256_context
		C.shake256_init_prng_from_seed(&rng, unsafe.Pointer(&seed[0]), C.size_t(len(seed)))

		tmp := make([]byte, v.tmpSign())
		r = C.falcon_sign_dyn(&rng,
			unsafe.Pointer(&sigBuf[0]), &sigLen, C.int(C.FALCON_SIG_COMPRESSED),
			unsafe.Pointer(&priv[0]), C.size_t(len(priv)),
			msgPtr, C.size_t(len(msg)),
			unsafe.Pointer(&tmp[0]), C.size_t(len(tmp)))
		runtime.KeepAlive(tmp)
	default:
		return nil, ErrUnknownVariant
	}
	if r != 0 {
		return nil, fmt.Errorf("error code %d: %w", int(r), ErrSignFail)
	}
	runtime.KeepAlive(msg)
	runtime.KeepAlive(priv)
	return sigBuf[:sigLen], nil
}

// VerifyCompressedVariant verifies a compressed-format signature against msg under pub.
func VerifyCompressedVariant(v Variant, pub, sig, msg []byte) error {
	if len(sig) == 0 {
		return fmt.Errorf("empty signature: %w", ErrVerifyFail)
	}
	if len(pub) != v.PublicKeySize() {
		return fmt.Errorf("falcon: bad public-key length %d for %s: %w",
			len(pub), v, ErrVerifyFail)
	}

	var msgPtr unsafe.Pointer
	if len(msg) > 0 {
		msgPtr = unsafe.Pointer(&msg[0])
	} else {
		msgPtr = C.NULL
	}

	var r C.int
	switch v {
	case Det1024:
		r = C.falcon_det1024_verify_compressed(unsafe.Pointer(&sig[0]), C.size_t(len(sig)),
			unsafe.Pointer(&pub[0]), msgPtr, C.size_t(len(msg)))
	case Det512:
		r = C.falcon_det512_verify_compressed(unsafe.Pointer(&sig[0]), C.size_t(len(sig)),
			unsafe.Pointer(&pub[0]), msgPtr, C.size_t(len(msg)))
	case Rand1024, Rand512:
		tmp := make([]byte, v.tmpVerify())
		r = C.falcon_verify(unsafe.Pointer(&sig[0]), C.size_t(len(sig)),
			C.int(C.FALCON_SIG_COMPRESSED),
			unsafe.Pointer(&pub[0]), C.size_t(len(pub)),
			msgPtr, C.size_t(len(msg)),
			unsafe.Pointer(&tmp[0]), C.size_t(len(tmp)))
		runtime.KeepAlive(tmp)
	default:
		return ErrUnknownVariant
	}
	if r != 0 {
		return fmt.Errorf("error code %d: %w", int(r), ErrVerifyFail)
	}
	runtime.KeepAlive(msg)
	runtime.KeepAlive(sig)
	runtime.KeepAlive(pub)
	return nil
}

// ConvertCompressedToCTVariant converts a compressed-format deterministic
// signature to CT format. Randomised variants are not supported (their
// signatures embed a 40-byte nonce, and the upstream library exposes no
// public conversion routine for them).
func ConvertCompressedToCTVariant(v Variant, sig []byte) ([]byte, error) {
	if len(sig) == 0 {
		return nil, fmt.Errorf("empty signature: %w", ErrConvertFail)
	}
	out := make([]byte, v.SigCTSize())
	var r C.int
	switch v {
	case Det1024:
		r = C.falcon_det1024_convert_compressed_to_ct(unsafe.Pointer(&out[0]),
			unsafe.Pointer(&sig[0]), C.size_t(len(sig)))
	case Det512:
		r = C.falcon_det512_convert_compressed_to_ct(unsafe.Pointer(&out[0]),
			unsafe.Pointer(&sig[0]), C.size_t(len(sig)))
	case Rand1024, Rand512:
		return nil, ErrCTConvertNotDet
	default:
		return nil, ErrUnknownVariant
	}
	if r != 0 {
		return nil, fmt.Errorf("error code %d: %w", int(r), ErrConvertFail)
	}
	runtime.KeepAlive(sig)
	return out, nil
}
