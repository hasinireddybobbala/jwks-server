# JWKS Server

A minimal JWKS (JSON Web Key Set) server with a mock authentication endpoint,
built for an educational assignment (CSCE 3550-style). Written in Go using
**only the standard library** — no external dependencies, no `go get`
required.

> ⚠️ **Educational project only.** `/auth` does not check credentials, keys
> live only in memory, and there is no key rotation or persistence. Do not
> use this as-is in a real system.

## What it does

- Generates two RSA-2048 key pairs at startup: one currently valid, one
  already expired.
- Serves the **public** half of the valid key(s) at the standard
  `/.well-known/jwks.json` URI, in JWKS format (RFC 7517). Expired keys are
  never published there.
- `POST /auth` mocks a login and returns a signed JWT (RS256) for a fake
  user. The JWT header's `kid` matches the key used to sign it, so a
  verifier can look up the right public key from JWKS.
- `POST /auth?expired` (parameter just needs to be present) instead signs
  the JWT with the **expired** key and sets its `exp` claim in the past —
  useful for testing that your verification logic correctly rejects it.

## Requirements

- Go 1.22+ (no other tools or packages needed)

## Project layout

```
jwks-server/
├── go.mod            # module definition, zero external deps
├── main.go           # entry point, route wiring
├── keystore.go        # RSA key generation + in-memory store with expiry
├── jwt.go             # JWT header/claims + RS256 signing
├── jwks.go            # JWK/JWKS types, RSA public key -> JWK conversion
├── handlers.go        # HTTP handlers for both endpoints
└── main_test.go       # test suite (unit + integration + crypto verification)
```

## Running it

```bash
go run .
```

The server listens on **port 8080**. Leave it running in one terminal and
use another to test it.

## Trying it manually

```bash
# Fetch the JWKS document (only unexpired keys appear)
curl -s http://localhost:8080/.well-known/jwks.json | jq

# Get a normal, valid JWT
curl -s -X POST http://localhost:8080/auth | jq

# Get a JWT deliberately signed with an expired key / expired exp
curl -s -X POST "http://localhost:8080/auth?expired" | jq
```

## Running the test suite

```bash
go test ./... -v -cover
```

To generate an HTML coverage report you can open in a browser:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

Current coverage: **83.5%** (see `coverage.html` / the coverage screenshot
in this repo). The test suite covers:

- RSA key generation and expiry filtering (`KeyStore`)
- JWKS handler: only serves unexpired keys, rejects non-GET
- `/auth` handler: issues valid tokens, issues expired tokens on
  `?expired`, rejects non-POST, handles missing-key error paths
- JWT signing correctness, including a failure path with an undersized key
- **End-to-end verification**: reconstructs the RSA public key purely from
  the published JWKS `n`/`e` values and cryptographically verifies a
  freshly issued token's signature against it — proving the `kid` linkage
  between the two endpoints actually works.

## Linting / static checks

```bash
go vet ./...
gofmt -l .     # should print nothing if formatting is clean
```

## Blackbox testing with the official test client

Download the test client from the course's release page
(https://github.com/jh125486/CSCE3550/releases), run this server in one
terminal, then in another:

```bash
./gradebot project1 http://localhost:8080
```

(exact binary name/flags depend on the release — check the tool's `--help`).
It will POST to `/auth` with no body and expects a 200 with a JWT back,
fetch `/.well-known/jwks.json`, and verify signatures — all of which this
server supports.

A screenshot of the test client's run, and a screenshot of `go test -cover`
output, are included in this repo per the assignment's deliverables.

## Design notes

- **No external JWT/JOSE library** was used — JWT construction (base64url
  header/claims, RS256 signing via `crypto/rsa`) and JWK encoding are
  implemented directly against the RFC 7515/7517 specs. This keeps the
  project dependency-free and makes the mechanics of JWKS/JWT fully visible
  in the code. Swapping in a vetted library (e.g. `golang-jwt/jwt`) would be
  a reasonable production hardening step.
- Keys are stored in memory in a `sync.RWMutex`-guarded map — safe for
  concurrent requests, but not persistent across restarts (fine for this
  assignment, not fine for production).
- The active key is issued with a 5-minute token lifetime; the expired key
  always produces a token whose `exp` is one hour in the past.
