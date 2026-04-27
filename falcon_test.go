package falcon

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)


func testKAT(t *testing.T, msgLen int) {
	msgrng := sha3.NewShake256()
	fmt.Fprintf(msgrng, "msg-%04d", msgLen)
	msg := make([]byte, msgLen)
	msgrng.Read(msg)

	keySeed := fmt.Sprintf("key-%04d", msgLen)
	_, priv, err := GenerateKey([]byte(keySeed))
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	sig, err := priv.SignCompressed(msg)
	if err != nil {
		t.Fatalf("failed to sign keys. err message: %s", err)
	}

	if s := hex.EncodeToString(sig); s != kats[msgLen] {
		t.Fatalf("kat %d: got %s, want %s", msgLen, s, kats[msgLen])
	}
}

func TestKATs(t *testing.T) {
	for i := range kats {
		testKAT(t, i)
	}
}

func TestFalcon(t *testing.T) {
	mathrand.Seed(time.Now().Unix())
	for count := 0; count < 64; count++ {
		seed := make([]byte, 64)
		rand.Read(seed)

		pub, priv, err := GenerateKey(seed)
		if err != nil {
			t.Fatalf("failed to generate keys. err message: %s", err)
		}

		msg := make([]byte, 500)
		rand.Read(msg)

		sig, err := priv.SignCompressed(msg)
		if err != nil {
			t.Fatalf("failed to sign message. err message: %s on pk: %v , sk: %v, msg: %v", err, pub, priv, msg)
		}

		err = pub.Verify(sig, msg)
		if err != nil {
			t.Fatalf("failed to verify message. err message: %s on pk: %v , sk: %v, msg: %v", err, pub, priv, msg)
		}

		v := sig.SaltVersion()
		if v != CurrentSaltVersion {
			t.Fatalf("unexpected salt version: %d", v)
		}

		badmsg := make([]byte, len(msg))
		copy(badmsg, msg)
		// Flip a random bit in the message.
		badmsg[mathrand.Intn(len(msg))] ^= 1 << mathrand.Intn(8)

		err = pub.Verify(sig, badmsg)
		if err == nil {
			t.Fatalf("expected verify to fail on modified message. on pk: %v , sk: %v, msg: %v", pub, priv, msg)
		}

		badpub := PublicKey{}
		copy(badpub[:], pub[:])
		badpub[mathrand.Intn(len(pub))] ^= 1 << mathrand.Intn(8)

		err = badpub.Verify(sig, msg)
		if err == nil {
			t.Fatalf("expected verify to fail with modified public key. on pk: %v , sk: %v, msg: %v", pub, priv, msg)
		}

		sigCT, err := sig.ConvertToCT()
		if err != nil {
			t.Fatalf("failed to conver sign to CT. err: %s on pk: %v , sk: %v, msg: %v", err, pub, priv, msg)
		}

		err = pub.VerifyCTSignature(sigCT, msg)
		if err != nil {
			t.Fatalf("verify_ct failed err msg %s on pk: %v , sk: %v, msg: %v", err, pub, priv, msg)
		}

		h, err := pub.Coefficients()
		if err != nil {
			t.Fatalf("pubkey coefficients failed: %s", err)
		}
		c := HashToPointCoefficients(msg, sigCT.SaltVersion())
		s2, err := sigCT.S2Coefficients()
		if err != nil {
			t.Fatalf("s2 coefficients failed: %s", err)
		}
		s1, err := S1Coefficients(h, c, s2)
		if err != nil {
			t.Fatalf("s1 coefficients failed: %s", err)
		}
		_ = s1
	}
}

func TestFalconCompressedSignatureSizes(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	msg := make([]byte, 500)
	rand.Read(msg)

	sig, err := priv.SignCompressed(msg)
	if err != nil {
		t.Fatalf("failed to sign message. err message: %s", err)
	}

	var sig2 [SignatureMaxSize + 1]byte
	copy(sig2[:], sig)
	err = pub.Verify(sig2[:], msg)
	if err == nil || !strings.Contains(err.Error(), "-4") {
		t.Fatalf("verification succeeded. should have failed.")
	}

}

func TestFalconSignNilMessage(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	sig, err := priv.SignCompressed(nil)
	if err != nil {
		t.Fatalf("failed to sign message. err message: %s", err)
	}

	err = pub.Verify(sig, nil)
	if err != nil {
		t.Fatalf("failed to verify message. err message: %s", err)
	}

	err = pub.Verify(sig, []byte{})
	if err != nil {
		t.Fatalf("failed to verify message. err message: %s", err)
	}

	ctSignature, err := sig.ConvertToCT()
	if err != nil {
		t.Fatalf("failed to verify message. err message: %s", err)
	}

	err = pub.VerifyCTSignature(ctSignature, nil)
	if err != nil {
		t.Fatalf("failed to verify message. err message: %s", err)
	}

	err = pub.VerifyCTSignature(ctSignature, []byte{})
	if err != nil {
		t.Fatalf("failed to verify message. err message: %s", err)
	}
}

func TestFalconGenerateKeysDifferentSeed(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, sk, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	seed2 := make([]byte, 64)
	rand.Read(seed2)

	if bytes.Compare(seed, seed2) == 0 {
		t.Fatalf("Seeds are the same")
	}

	pub2, sk2, err := GenerateKey(seed2)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	if pub == pub2 {
		t.Fatalf("public keys are the same")
	}

	if sk == sk2 {
		t.Fatalf("private keys are the same")
	}
}

func TestFalconNilSignature(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, _, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	msg := make([]byte, 500)
	rand.Read(msg)

	err = pub.Verify(nil, msg)
	if err == nil {
		t.Fatalf("verification succeeded. should have failed.")
	}

	err = pub.Verify([]byte{}, msg)
	if err == nil {
		t.Fatalf("verification succeeded. should have failed.")
	}
}

func TestFalconNilSeed(t *testing.T) {
	_, _, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate keys with nil. err message: %v", err)
	}

	_, _, err = GenerateKey([]byte{})
	if err != nil {
		t.Fatalf("failed to generate keys with empty byte slice. err message: %v", err)
	}
}

func TestSaltedVersions(t *testing.T) {
	emptyCTSig := CTSignature{}
	if emptyCTSig.SaltVersion() != 0 {
		t.Fatalf("expected salt value to be error")
	}

	emptyCompressSig := CompressedSignature{}
	if emptyCompressSig.SaltVersion() != 0 {
		t.Fatalf("expected salt value to be error")
	}

	emptyCompressSig = []byte{0x0}
	if emptyCompressSig.SaltVersion() != 0 {
		t.Fatalf("expected salt value to be error")
	}
}

type PointerToPointerPanicGenerator struct {
	seed  [32]byte
	msg   [128]byte
	sig   CompressedSignature
	ctsig CTSignature
	pub   PublicKey
	priv  PrivateKey
	p     *int
}

func TestPointerToPointer(t *testing.T) {
	r := 42
	v := &PointerToPointerPanicGenerator{
		p: &r,
	}
	rand.Read(v.seed[:])
	rand.Read(v.msg[:])

	var err error
	v.pub, v.priv, err = GenerateKey(v.seed[:])
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}
	_, _, err = GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate keys from empty seed: %s", err)
	}

	v.sig, err = v.priv.SignCompressed(v.msg[:])
	if err != nil {
		t.Fatalf("failed to sign message: %s", err)
	}
	if err := v.pub.Verify(v.sig, v.msg[:]); err != nil {
		t.Fatalf("failed to verify sig: %s", err)
	}

	sig2, err := v.priv.SignCompressed(nil)
	if err != nil {
		t.Fatalf("failed to sign empty message. err message: %s", err)
	}
	if err := v.pub.Verify(sig2, nil); err != nil {
		t.Fatalf("failed to verify sig on empty message: %s", err)
	}

	v.ctsig, err = v.sig.ConvertToCT()
	if err != nil {
		t.Fatalf("failed to convert signature: %s", err)
	}
	if err := v.pub.VerifyCTSignature(v.ctsig, v.msg[:]); err != nil {
		t.Fatalf("failed to verify ct signature: %s", err)
	}

	ctSig2, err := sig2.ConvertToCT()
	if err != nil {
		t.Fatalf("failed to convert signature of empty message: %s", err)
	}
	if err := v.pub.VerifyCTSignature(ctSig2, nil); err != nil {
		t.Fatalf("failed to verify ct signature of empty message: %s", err)
	}

	_, err = v.pub.Coefficients()
	if err != nil {
		t.Fatalf("failed to compute pubkey coefficients: %s", err)
	}
	_, err = v.ctsig.S2Coefficients()
	if err != nil {
		t.Fatalf("failed to compute s2 coefficients: %s", err)
	}
	_ = HashToPointCoefficients(nil, 0)
	_ = HashToPointCoefficients(v.msg[:], 0)
}

func BenchmarkFalconKeyGen(b *testing.B) {
	var seed [48]byte
	rand.Read(seed[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateKey(seed[:])
	}
}

func BenchmarkFalconSignCompressed(b *testing.B) {
	_, sk, err := GenerateKey([]byte("seed"))
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.SignCompressed(strs[i][:])
	}
}

func BenchmarkFalconVerify(b *testing.B) {
	pk, sk, err := GenerateKey([]byte("seed"))
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	sigs := make([]CompressedSignature, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
		sigs[i], err = sk.SignCompressed(msg[:])
		if err != nil {
			b.Fatalf("SignCompressed failed with error %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sigs[i], strs[i][:])
	}
}
