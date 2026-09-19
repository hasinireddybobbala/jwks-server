package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer spins up a server backed by a fresh, real key store.
func newTestServer(t *testing.T) *server {
	t.Helper()
	ks, err := NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}
	return &server{keys: ks}
}

// decodeToken parses a compact JWT's header and claims (without verifying
// the signature) so tests can assert on kid/exp values.
func decodeToken(t *testing.T, token string) (jwtHeader, jwtClaims) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding claims: %v", err)
	}

	var header jwtHeader
	var claims jwtClaims
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshaling header: %v", err)
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("unmarshaling claims: %v", err)
	}
	return header, claims
}

func TestNewKeyStore(t *testing.T) {
	ks, err := NewKeyStore()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := ks.ActiveKey(); err != nil {
		t.Errorf("expected an active key, got error: %v", err)
	}
	if _, err := ks.ExpiredKey(); err != nil {
		t.Errorf("expected an expired key, got error: %v", err)
	}
	if got := len(ks.Valid()); got != 1 {
		t.Errorf("expected exactly 1 valid key, got %d", got)
	}
}

func TestKeyStore_NoKeysAvailable(t *testing.T) {
	// An empty store should cleanly report errors rather than panic.
	ks := &KeyStore{keys: make(map[string]*Key)}
	if _, err := ks.ActiveKey(); err == nil {
		t.Error("expected error for empty store, got nil")
	}
	if _, err := ks.ExpiredKey(); err == nil {
		t.Error("expected error for empty store, got nil")
	}
}

func TestJWKSHandler_OnlyValidKeys(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	s.jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}

	var resp jwksResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(resp.Keys))
	}
	if resp.Keys[0].Kid != "active-key-1" {
		t.Errorf("expected kid active-key-1, got %s", resp.Keys[0].Kid)
	}
	if resp.Keys[0].Kty != "RSA" || resp.Keys[0].Alg != "RS256" {
		t.Errorf("unexpected key type/alg: %+v", resp.Keys[0])
	}
}

func TestJWKSHandler_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	s.jwksHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestAuthHandler_ValidToken(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	s.authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	token := body["token"]
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	header, claims := decodeToken(t, token)
	if header.Kid != "active-key-1" {
		t.Errorf("expected kid active-key-1, got %s", header.Kid)
	}
	if header.Alg != "RS256" {
		t.Errorf("expected alg RS256, got %s", header.Alg)
	}
	if time.Unix(claims.Exp, 0).Before(time.Now()) {
		t.Error("expected token to not be expired")
	}
}

func TestAuthHandler_ExpiredToken(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rec := httptest.NewRecorder()

	s.authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	token := body["token"]

	header, claims := decodeToken(t, token)
	if header.Kid != "expired-key-1" {
		t.Errorf("expected kid expired-key-1, got %s", header.Kid)
	}
	if time.Unix(claims.Exp, 0).After(time.Now()) {
		t.Error("expected token to be expired")
	}
}

func TestAuthHandler_ExpiredParamPresentButEmpty(t *testing.T) {
	// The spec only requires the "expired" parameter to be present, with no
	// particular value, to trigger the expired-key flow.
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	rec := httptest.NewRecorder()

	s.authHandler(rec, req)

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	header, _ := decodeToken(t, body["token"])
	if header.Kid != "expired-key-1" {
		t.Errorf("expected expired key to be used, got kid %s", header.Kid)
	}
}

func TestAuthHandler_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rec := httptest.NewRecorder()

	s.authHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestSignJWT_StructureIsValid(t *testing.T) {
	ks, _ := NewKeyStore()
	key, _ := ks.ActiveKey()

	token, err := signJWT(key, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signJWT error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}

	header, claims := decodeToken(t, token)
	if header.Kid != key.Kid {
		t.Errorf("expected kid %s, got %s", key.Kid, header.Kid)
	}
	if claims.Sub != "fake-user" {
		t.Errorf("expected sub fake-user, got %s", claims.Sub)
	}
}

func TestToJWK(t *testing.T) {
	ks, _ := NewKeyStore()
	key, _ := ks.ActiveKey()
	j := toJWK(key)

	if j.Kty != "RSA" || j.Alg != "RS256" || j.Use != "sig" {
		t.Errorf("unexpected JWK fields: %+v", j)
	}
	if j.Kid != key.Kid {
		t.Errorf("expected kid %s, got %s", key.Kid, j.Kid)
	}
	if j.N == "" || j.E == "" {
		t.Error("expected non-empty n and e")
	}
}

func TestNewMux_Routes(t *testing.T) {
	s := newTestServer(t)
	mux := newMux(s)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	resp2, err := http.Post(srv.URL+"/auth", "application/json", nil)
	if err != nil {
		t.Fatalf("POST auth: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestAuthHandler_NoActiveKey(t *testing.T) {
	// An empty store has no valid key, so a normal /auth request must fail
	// loudly (500) rather than silently issuing a bad token.
	s := &server{keys: &KeyStore{keys: make(map[string]*Key)}}
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	s.authHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestAuthHandler_NoExpiredKey(t *testing.T) {
	ks, _ := NewKeyStore()
	ks.mu.Lock()
	delete(ks.keys, "expired-key-1")
	ks.mu.Unlock()

	s := &server{keys: ks}
	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	rec := httptest.NewRecorder()

	s.authHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestGenerateKey_RandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = strings.NewReader("") // empty reader forces a read error
	defer func() { rand.Reader = orig }()

	ks := &KeyStore{keys: make(map[string]*Key)}
	if err := ks.generateKey("bad", time.Now()); err == nil {
		t.Error("expected error when the randomness source fails")
	}
}

func TestNewKeyStore_RandFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = strings.NewReader("")
	defer func() { rand.Reader = orig }()

	if _, err := NewKeyStore(); err == nil {
		t.Error("expected NewKeyStore to surface the key generation error")
	}
}

func TestSignJWT_UndersizedKeyFails(t *testing.T) {
	// A 64-bit RSA key is far too small to hold a SHA-256 PKCS#1 v1.5
	// signature, so signing must fail — exercising signJWT's error path.
	tinyKey, err := rsa.GenerateKey(rand.Reader, 64)
	if err != nil {
		t.Fatalf("generating undersized key: %v", err)
	}
	key := &Key{Kid: "tiny", PrivateKey: tinyKey, Expiry: time.Now().Add(time.Hour)}

	if _, err := signJWT(key, time.Now().Add(time.Hour)); err == nil {
		t.Error("expected signing to fail with an undersized key")
	}
}

// TestEndToEnd_TokenVerifiesAgainstJWKS is the crucial integration check:
// it fetches the JWKS document, reconstructs the RSA public key purely from
// the published n/e values (as a real verifier would), and confirms it can
// cryptographically verify a token issued by /auth. This proves the kid
// linkage between the two endpoints actually works, not just that each
// endpoint returns well-formed JSON in isolation.
func TestEndToEnd_TokenVerifiesAgainstJWKS(t *testing.T) {
	s := newTestServer(t)
	mux := newMux(s)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1. Get a token from /auth.
	authResp, err := http.Post(srv.URL+"/auth", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /auth: %v", err)
	}
	defer authResp.Body.Close()
	var authBody map[string]string
	if err := json.NewDecoder(authResp.Body).Decode(&authBody); err != nil {
		t.Fatalf("decoding /auth response: %v", err)
	}
	token := authBody["token"]

	header, claims := decodeToken(t, token)

	// 2. Fetch JWKS and find the matching kid.
	jwksResp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer jwksResp.Body.Close()
	var doc jwksResponse
	if err := json.NewDecoder(jwksResp.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding jwks: %v", err)
	}

	var matched *jwk
	for i := range doc.Keys {
		if doc.Keys[i].Kid == header.Kid {
			matched = &doc.Keys[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("no JWKS entry found for kid %q", header.Kid)
	}

	// 3. Reconstruct the RSA public key from n/e exactly as a verifier would.
	nBytes, err := base64.RawURLEncoding.DecodeString(matched.N)
	if err != nil {
		t.Fatalf("decoding n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(matched.E)
	if err != nil {
		t.Fatalf("decoding e: %v", err)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	// 4. Verify the signature over the actual signing input.
	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	hashed := sha256.Sum256([]byte(signingInput))

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig); err != nil {
		t.Fatalf("signature did NOT verify against JWKS-published key: %v", err)
	}
	if claims.Sub != "fake-user" {
		t.Errorf("expected sub fake-user, got %s", claims.Sub)
	}
}

func TestIntToBigEndianBytes(t *testing.T) {
	cases := map[int][]byte{
		0:     {0},
		65537: {0x01, 0x00, 0x01},
		256:   {0x01, 0x00},
	}
	for in, want := range cases {
		got := intToBigEndianBytes(in)
		if len(got) != len(want) {
			t.Errorf("intToBigEndianBytes(%d) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("intToBigEndianBytes(%d) = %v, want %v", in, got, want)
				break
			}
		}
	}
}
