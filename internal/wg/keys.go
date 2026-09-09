package wg

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

// GenerateKeyPair returns a fresh Curve25519 keypair as hex strings.
// The private key is clamped per RFC 7748 so wireguard-go accepts it.
func GenerateKeyPair() (privHex, pubHex string, err error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", err
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	pub, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(privKey[:]), hex.EncodeToString(pub), nil
}

// PublicKeyFromPrivate derives the public key hex for a private key hex.
func PublicKeyFromPrivate(privHex string) (string, error) {
	raw, err := hex.DecodeString(privHex)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid private key (want 64 hex chars): %w", err)
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

// IsValidPublicKey reports whether s is a 64-hex-char WireGuard public key.
// Used to validate peer keys before handing them to the device.
func IsValidPublicKey(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == device.NoisePublicKeySize
}
