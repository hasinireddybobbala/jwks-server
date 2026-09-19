package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// jwtHeader is the JOSE header of a compact JWT. Including kid is what lets a
// verifier pick the right public key out of the JWKS document.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// jwtClaims is a minimal claim set; sufficient for this mock-auth assignment
// (no real user database, just a fixed subject).
type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// base64URLEncode encodes bytes using unpadded base64url, as required by the
// JWS compact serialization (RFC 7515 §2).
func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// signJWT builds a compact RS256-signed JWT for the given key, with the
// supplied expiry timestamp baked into the "exp" claim.
func signJWT(key *Key, expiry time.Time) (string, error) {
	header := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: key.Kid}
	now := time.Now()
	claims := jwtClaims{Sub: "fake-user", Iat: now.Unix(), Exp: expiry.Unix()}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %w", err)
	}

	signingInput := base64URLEncode(headerJSON) + "." + base64URLEncode(claimsJSON)

	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return signingInput + "." + base64URLEncode(sig), nil
}
