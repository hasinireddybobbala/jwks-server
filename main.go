// Command jwks-server implements a minimal JWKS + mock-auth server for
// educational purposes (CSCE 3550 style assignment). It is NOT suitable for
// production use as-is: authentication is entirely mocked, and keys live
// only in memory.
package main

import (
	"log"
	"net/http"
)

// newMux wires up the server's routes. Split out from main so it can be
// exercised directly in tests without binding a real network port.
func newMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.jwksHandler)
	mux.HandleFunc("/auth", s.authHandler)
	return mux
}

func main() {
	ks, err := NewKeyStore()
	if err != nil {
		log.Fatalf("failed to initialize key store: %v", err)
	}

	s := &server{keys: ks}
	mux := newMux(s)

	const addr = ":8080"
	log.Printf("JWKS server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
