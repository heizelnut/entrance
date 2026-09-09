// Package auth implements password hashing (argon2id) and opaque-token
// handling (D3).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (D3): m=65536, t=3, p=4, salt 16 bytes, key 32 bytes.
const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 4
	argonSaltLen = 16
	argonKeyLen  = 32
)

// DummyPasswordHash is a valid argon2id hash of a random string. It is
// verified (burning the same ~64MB/100ms as a real check) for unknown
// usernames so login response timing cannot enumerate accounts.
const DummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$xlPMF1hNiw++oyzXIHv3mw$I+p0LOwwDim90Avwj1xoYmJ4E411hCUQjgO7n4uywvk"

// HashPassword returns an encoded argon2id hash string of the form
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded argon2id hash.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false
	}
	// parse params (defensively; only the encoded m/t/p are trusted here)
	m, t, p := argonMemory, argonTime, argonThreads
	for _, kv := range strings.Split(parts[3], ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch key {
		case "m":
			fmt.Sscanf(val, "%d", &m)
		case "t":
			fmt.Sscanf(val, "%d", &t)
		case "p":
			fmt.Sscanf(val, "%d", &p)
		}
	}
	got := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
