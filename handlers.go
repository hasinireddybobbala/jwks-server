package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// server bundles the dependencies (currently just the key store) that the
// HTTP handlers need.
type server struct {
	keys *KeyStore
}

// jwksHandler serves GET /.well-known/jwks.json.
// Only currently-unexpired keys are published, per RFC 7517 best practice:
// a verifier should never be handed a key that's no longer valid to use.
func (s *server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var resp jwksResponse
	for _, k := range s.keys.Valid() {
		resp.Keys = append(resp.Keys, toJWK(k))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("jwksHandler: encode error: %v", err)
	}
}

// authHandler serves POST /auth and mocks user authentication: it doesn't
// check any credentials, it simply issues a signed JWT for a fake user.
//
// If the "expired" query parameter is present (with or without a value),
// the response is instead signed with the store's expired key and carries
// an already-past "exp" claim, per the assignment's expired-key flow.
func (s *server) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, wantExpired := r.URL.Query()["expired"]

	var (
		key    *Key
		err    error
		expiry time.Time
	)

	if wantExpired {
		key, err = s.keys.ExpiredKey()
		expiry = time.Now().Add(-1 * time.Hour)
	} else {
		key, err = s.keys.ActiveKey()
		expiry = time.Now().Add(5 * time.Minute)
	}

	if err != nil {
		log.Printf("authHandler: %v", err)
		http.Error(w, "no signing key available", http.StatusInternalServerError)
		return
	}

	token, err := signJWT(key, expiry)
	if err != nil {
		log.Printf("authHandler: signing error: %v", err)
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"token": token}); err != nil {
		log.Printf("authHandler: encode error: %v", err)
	}
}
