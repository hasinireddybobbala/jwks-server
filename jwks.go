package main

import "encoding/base64"

// jwk represents a single public key in JSON Web Key format (RFC 7517).
// Only the fields needed for RSA signature verification are included.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksResponse is the top-level document served at the JWKS endpoint.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// toJWK extracts the public components of an RSA key pair and encodes them
// as a JWK. Private key material is never included.
func toJWK(k *Key) jwk {
	pub := k.PrivateKey.PublicKey
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: k.Kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(intToBigEndianBytes(pub.E)),
	}
}

// intToBigEndianBytes encodes the RSA public exponent (almost always 65537)
// as minimal big-endian bytes, matching the JWK "e" encoding convention.
func intToBigEndianBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}
