package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"
)

// Key represents a single RSA key pair along with the metadata (kid, expiry)
// needed to serve it correctly from JWKS and to sign JWTs with it.
type Key struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
	Expiry     time.Time
}

// KeyStore holds all generated keys in memory and is safe for concurrent use.
//
// NOTE: this is an in-memory, non-persistent store built for a classroom
// assignment. A production system would persist keys securely (e.g. an HSM
// or encrypted database) and rotate them automatically.
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]*Key
}

// NewKeyStore builds a store pre-populated with:
//   - one currently-valid key ("active-key-1"), used for normal /auth requests
//   - one already-expired key ("expired-key-1"), used only when a caller
//     explicitly asks for an expired token via /auth?expired
func NewKeyStore() (*KeyStore, error) {
	ks := &KeyStore{keys: make(map[string]*Key)}

	if err := ks.generateKey("active-key-1", time.Now().Add(1*time.Hour)); err != nil {
		return nil, fmt.Errorf("generating active key: %w", err)
	}

	if err := ks.generateKey("expired-key-1", time.Now().Add(-1*time.Hour)); err != nil {
		return nil, fmt.Errorf("generating expired key: %w", err)
	}

	return ks, nil
}

// generateKey creates a fresh 2048-bit RSA key pair and stores it under kid.
func (ks *KeyStore) generateKey(kid string, expiry time.Time) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[kid] = &Key{Kid: kid, PrivateKey: priv, Expiry: expiry}
	return nil
}

// Valid returns every key whose expiry has not yet passed. This is exactly
// the set of keys the JWKS endpoint is allowed to publish.
func (ks *KeyStore) Valid() []*Key {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	now := time.Now()
	var out []*Key
	for _, k := range ks.keys {
		if k.Expiry.After(now) {
			out = append(out, k)
		}
	}
	return out
}

// ActiveKey returns a non-expired key suitable for signing a normal,
// verifiable JWT.
func (ks *KeyStore) ActiveKey() (*Key, error) {
	valid := ks.Valid()
	if len(valid) == 0 {
		return nil, fmt.Errorf("no active keys available")
	}
	return valid[0], nil
}

// ExpiredKey returns an already-expired key, used to deliberately issue an
// expired JWT when the "expired" query parameter is supplied to /auth.
func (ks *KeyStore) ExpiredKey() (*Key, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	now := time.Now()
	for _, k := range ks.keys {
		if !k.Expiry.After(now) {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no expired keys available")
}
