package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestValidateUID(t *testing.T) {
	cases := []struct {
		uid string
		ok  bool
	}{
		{"abcdef0123456789abcd", true},
		{"ABCDEF0123456789ABCD", false},                 // uppercase not allowed
		{"abcdef0123456789abc", false},                  // too short
		{"abcdef0123456789abcde", false},                // too long
		{"abcdef0123456789abcg", false},                 // non-hex
		{"abcdef0123456789abcdef0123456789", false},     // legacy 128-bit UID, no longer accepted
		{"", false},
	}
	for _, c := range cases {
		if got := ValidateUID(c.uid); got != c.ok {
			t.Errorf("ValidateUID(%q) = %v, want %v", c.uid, got, c.ok)
		}
	}
}

func TestUIDDerivation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	uid := UIDFromPublicKeyBytes(der)
	if len(uid) != 20 {
		t.Errorf("UID length = %d, want 20", len(uid))
	}
	if !ValidateUID(uid) {
		t.Errorf("Derived UID %q failed ValidateUID", uid)
	}
	// Sanity: same input → same UID
	if uid2 := UIDFromPublicKeyBytes(der); uid2 != uid {
		t.Errorf("UID not deterministic: %q vs %q", uid, uid2)
	}
	// Sanity: matches manual computation — first 80 bits of SHA-256(DER)
	// as lowercase hex.
	h := sha256.Sum256(der)
	want := ""
	for _, b := range h[:10] {
		want += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}
	if uid != want {
		t.Errorf("UID mismatch: got %q want %q", uid, want)
	}
}

func TestValidatePublicKey(t *testing.T) {
	// RSA 2048: ok
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := ValidatePublicKey(&rsa2048.PublicKey); err != "" {
		t.Errorf("RSA-2048 rejected: %s", err)
	}

	// RSA 1024: rejected
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	if err := ValidatePublicKey(&rsa1024.PublicKey); err == "" {
		t.Error("RSA-1024 accepted, want rejection")
	}

	// ECDSA P-256: ok
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := ValidatePublicKey(&ecKey.PublicKey); err != "" {
		t.Errorf("ECDSA P-256 rejected: %s", err)
	}

	// ECDSA P-384: rejected
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := ValidatePublicKey(&ec384.PublicKey); err == "" {
		t.Error("ECDSA P-384 accepted, want rejection")
	}

	// Ed25519: ok
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := ValidatePublicKey(edPub); err != "" {
		t.Errorf("Ed25519 rejected: %s", err)
	}
}

func TestVerifySignatureRSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	nonce := []byte("test-nonce-32-bytes-long-padding")
	payload := append([]byte{}, AuthDomain...)
	payload = append(payload, nonce...)
	hash := sha256.Sum256(payload)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, 5, hash[:]) // crypto.SHA256 = 5

	if err := VerifySignature(&priv.PublicKey, nonce, sig); err != nil {
		t.Errorf("VerifySignature(RSA) failed: %v", err)
	}

	// Wrong nonce → fail
	if err := VerifySignature(&priv.PublicKey, []byte("wrong-nonce"), sig); err == nil {
		t.Error("VerifySignature(RSA) accepted wrong nonce")
	}
}

func TestVerifySignatureECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce := []byte("test-nonce-32-bytes-long-padding")
	payload := append([]byte{}, AuthDomain...)
	payload = append(payload, nonce...)
	hash := sha256.Sum256(payload)
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, hash[:])

	if err := VerifySignature(&priv.PublicKey, nonce, sig); err != nil {
		t.Errorf("VerifySignature(ECDSA) failed: %v", err)
	}
}

func TestVerifySignatureEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nonce := []byte("test-nonce-32-bytes-long-padding")
	payload := append([]byte{}, AuthDomain...)
	payload = append(payload, nonce...)
	sig := ed25519.Sign(priv, payload)

	if err := VerifySignature(pub, nonce, sig); err != nil {
		t.Errorf("VerifySignature(Ed25519) failed: %v", err)
	}
}

func TestParsePublicKeyB64(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	b64 := base64.StdEncoding.EncodeToString(der)

	key, gotDER, err := ParsePublicKeyB64(b64)
	if err != nil {
		t.Fatalf("ParsePublicKeyB64 failed: %v", err)
	}
	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Errorf("Parsed key is not *rsa.PublicKey: %T", key)
	}
	if len(gotDER) != len(der) {
		t.Errorf("DER length mismatch: got %d want %d", len(gotDER), len(der))
	}

	// Malformed base64
	if _, _, err := ParsePublicKeyB64("not-base64!"); err == nil {
		t.Error("ParsePublicKeyB64 accepted malformed base64")
	}
	// Valid base64, invalid DER
	if _, _, err := ParsePublicKeyB64(base64.StdEncoding.EncodeToString([]byte("garbage"))); err == nil {
		t.Error("ParsePublicKeyB64 accepted invalid DER")
	}
}
