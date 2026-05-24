// Package identity implements UID derivation and signature verification
// for the signaling server. Mirrors the Python implementation in
// signaling.py — wire-compatible behavior is the contract.
//
// Supported key algorithms:
//   - RSA  (>= 2048 bits): RSASSA-PKCS1v15 + SHA-256
//   - ECDSA P-256:         ECDSA + SHA-256
//   - Ed25519:             Ed25519 (no separate hash)
//
// All signatures are over AuthDomain || nonce. The domain tag prevents the
// auth signature from being interchangeable with signatures produced for any
// other purpose. Bumped only if the signing scheme itself changes
// (padding/hash/structure), not when the surrounding protocol version changes.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

// AuthDomain is the domain separation tag prepended to challenge nonces
// before signing. Must match signaling.py: AUTH_DOMAIN.
var AuthDomain = []byte("bitbang-auth-v1:")

// MinRSAKeySize is the smallest RSA modulus we accept (NIST SP 800-57 floor).
const MinRSAKeySize = 2048

// uidPattern matches the wire UID format: 22 base64url chars (128 bits,
// no padding). The companion 64-bit access code rides in the URL fragment
// and is never sent to the server.
var uidPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// ValidateUID reports whether uid is well-formed.
func ValidateUID(uid string) bool {
	return uidPattern.MatchString(uid)
}

// UIDFromPublicKeyBytes derives the wire UID from a DER-encoded public key:
// first 128 bits of SHA256(publicKeyDER), base64url-encoded (no padding).
func UIDFromPublicKeyBytes(publicBytes []byte) string {
	h := sha256.Sum256(publicBytes)
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

// ParsePublicKeyB64 decodes a base64 DER SubjectPublicKeyInfo and parses
// the underlying public key. Returns the parsed key and the raw DER bytes
// (which the caller needs for UID re-derivation).
func ParsePublicKeyB64(publicKeyB64 string) (key crypto.PublicKey, der []byte, err error) {
	der, err = base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public_key format")
	}
	key, err = x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public_key format")
	}
	return key, der, nil
}

// ValidatePublicKey checks a parsed public key against the protocol's
// supported types and size constraints. Returns "" if acceptable,
// otherwise a short error string suitable for sending back to the device.
//
// Error strings are wire-visible to clients — they must match the Python
// implementation's strings byte-for-byte to preserve client error handling.
func ValidatePublicKey(key crypto.PublicKey) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < MinRSAKeySize {
			return fmt.Sprintf("RSA key too small (%d < %d)", bits, MinRSAKeySize)
		}
		return ""
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Sprintf("Unsupported EC curve: %s", curveName(k.Curve))
		}
		return ""
	case ed25519.PublicKey:
		return ""
	default:
		return fmt.Sprintf("Unsupported public key type: %T", key)
	}
}

// VerifySignature verifies a challenge signature against AuthDomain || nonce.
// Returns nil on success, error on failure or unsupported key type.
//
// Signature schemes are fixed per key type (see package comment).
func VerifySignature(key crypto.PublicKey, nonce, signature []byte) error {
	payload := make([]byte, 0, len(AuthDomain)+len(nonce))
	payload = append(payload, AuthDomain...)
	payload = append(payload, nonce...)

	switch k := key.(type) {
	case *rsa.PublicKey:
		hash := sha256.Sum256(payload)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], signature)
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(payload)
		// crypto/ecdsa.VerifyASN1 expects ASN.1 DER-encoded signature, which
		// is the standard cryptography.io ECDSA signature format. Python's
		// cryptography library emits this same format by default.
		if !ecdsa.VerifyASN1(k, hash[:], signature) {
			return errors.New("ecdsa: verification failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, payload, signature) {
			return errors.New("ed25519: verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

// curveName returns the Python-compatible curve name string.
// Python's cryptography uses "secp256r1" for P-256; Go's elliptic.Curve.Params().Name is "P-256".
func curveName(c elliptic.Curve) string {
	if c == elliptic.P256() {
		return "secp256r1"
	}
	return c.Params().Name
}
