# Sigil v1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build device-bound identity for AI agents — a builder that compiles obfuscated identity binaries, server SDKs (TypeScript + Python) for authentication, and a CLI for enrollment/signing.

**Architecture:** Go builder compiles per-agent identity binaries with embedded Ed25519 keys. Server SDKs orchestrate enrollment, challenge-response auth, and JWT session management. CLI handles agent-side enrollment and signing.

**Tech Stack:** Go (builder + identity binary + CLI), TypeScript (Node SDK — jose, @noble/ed25519, better-sqlite3, pg, tsup), Python (SDK — PyJWT, cryptography, aiosqlite, asyncpg, hatchling)

---

## Phase 1: Builder + Identity Binary (Go)

### Task 1: Go Project Scaffolding

**Files:**
- Create: `builder/go.mod`
- Create: `builder/cmd/sigil-builder/main.go`
- Create: `builder/template/cmd/identity/main.go` (placeholder)

**Step 1: Initialize Go module**

```bash
cd builder
go mod init github.com/sigil-auth/sigil/builder
```

**Step 2: Create directory structure**

```bash
mkdir -p cmd/sigil-builder
mkdir -p internal/compiler
mkdir -p internal/crypto
mkdir -p internal/server
mkdir -p template/cmd/identity
mkdir -p template/internal/keys
mkdir -p template/internal/signer
```

**Step 3: Create placeholder main.go for builder**

```go
// builder/cmd/sigil-builder/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sigil-builder <build|serve>")
		os.Exit(1)
	}
	fmt.Println("sigil-builder", os.Args[1])
}
```

**Step 4: Verify it compiles**

Run: `go build -o sigil-builder ./cmd/sigil-builder/`
Expected: binary created, no errors

**Step 5: Commit**

```bash
git add .
git commit -m "feat: scaffold builder Go project"
```

---

### Task 2: Crypto Primitives

**Files:**
- Create: `builder/internal/crypto/crypto.go`
- Create: `builder/internal/crypto/crypto_test.go`

**Step 1: Write failing tests**

```go
// builder/internal/crypto/crypto_test.go
package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("test-private-key-32-bytes-long!!")
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if string(ciphertext) == string(plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted: got %q, want %q", decrypted, plaintext)
	}
}

func TestFingerprint(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(pub)
	if fp[:7] != "sha256:" {
		t.Fatalf("fingerprint should start with sha256:, got %s", fp)
	}
	if len(fp) != 7+64 { // "sha256:" + 64 hex chars
		t.Fatalf("fingerprint length: got %d, want %d", len(fp), 71)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("challenge-nonce-here")
	sig := Sign(priv, message)
	if !Verify(pub, message, sig) {
		t.Fatal("signature should verify")
	}
	// tampered message should fail
	if Verify(pub, []byte("tampered"), sig) {
		t.Fatal("tampered message should not verify")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd builder && go test ./internal/crypto/ -v`
Expected: FAIL — functions not defined

**Step 3: Implement crypto primitives**

```go
// builder/internal/crypto/crypto.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateKeyPair creates a new Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// GenerateAESKey creates a random 32-byte AES-256 key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM. Returns nonce prepended to ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts AES-256-GCM ciphertext (nonce prepended).
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// Fingerprint returns "sha256:<hex>" of a public key.
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Sign signs a message with an Ed25519 private key.
func Sign(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// Verify checks an Ed25519 signature.
func Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}
```

**Step 4: Run tests to verify they pass**

Run: `cd builder && go test ./internal/crypto/ -v`
Expected: PASS — all 4 tests

**Step 5: Commit**

```bash
git add builder/internal/crypto/
git commit -m "feat: add Ed25519 + AES-256-GCM crypto primitives"
```

---

### Task 3: Identity Binary Template

The template is Go source code that the compiler copies and modifies per agent. It contains placeholder variables that get replaced with the actual encrypted key at build time.

**Files:**
- Create: `builder/template/cmd/identity/main.go`
- Create: `builder/template/internal/keys/keys.go`
- Create: `builder/template/internal/signer/signer.go`
- Create: `builder/template/go.mod`

**Step 1: Create the template go.mod**

```
module github.com/sigil-auth/sigil/identity
go 1.23
```

**Step 2: Create the keys placeholder**

```go
// builder/template/internal/keys/keys.go
package keys

// These variables are replaced at build time by the compiler.
// SIGIL_ENCRYPTED_KEY and SIGIL_KEY_NONCE hold the AES-256-GCM encrypted Ed25519 private key.
// SIGIL_AES_KEY holds the obfuscated decryption key.
var (
	SIGIL_ENCRYPTED_KEY = []byte("PLACEHOLDER_ENCRYPTED_KEY")
	SIGIL_KEY_NONCE     = []byte("PLACEHOLDER_KEY_NONCE")
	SIGIL_AES_KEY       = []byte("PLACEHOLDER_AES_KEY")
	SIGIL_FINGERPRINT   = "PLACEHOLDER_FINGERPRINT"
	SIGIL_VERSION       = "0.1.0"
	SIGIL_PLATFORM      = "unknown"
)
```

**Step 3: Create the signer**

```go
// builder/template/internal/signer/signer.go
package signer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"fmt"

	"github.com/sigil-auth/sigil/identity/internal/keys"
)

// Sign decrypts the embedded private key, signs the message, zeros the key, and returns the signature.
func Sign(message []byte) ([]byte, error) {
	block, err := aes.NewCipher(keys.SIGIL_AES_KEY)
	if err != nil {
		return nil, fmt.Errorf("cipher init failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init failed")
	}

	privKey, err := gcm.Open(nil, keys.SIGIL_KEY_NONCE, keys.SIGIL_ENCRYPTED_KEY, nil)
	if err != nil {
		return nil, fmt.Errorf("key decryption failed")
	}

	// Ed25519 private key is 64 bytes (seed + public key), but we store only the 32-byte seed.
	// Reconstruct the full private key from the seed.
	fullPrivKey := ed25519.NewKeyFromSeed(privKey)

	sig := ed25519.Sign(fullPrivKey, message)

	// Zero the decrypted key from memory
	for i := range privKey {
		privKey[i] = 0
	}
	for i := range fullPrivKey {
		fullPrivKey[i] = 0
	}

	return sig, nil
}
```

**Step 4: Create the main CLI**

```go
// builder/template/cmd/identity/main.go
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/sigil-auth/sigil/identity/internal/keys"
	"github.com/sigil-auth/sigil/identity/internal/signer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: identity <sign|fingerprint|health|version>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sign":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: identity sign <base64_challenge>")
			os.Exit(1)
		}
		challenge, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid base64 challenge")
			os.Exit(1)
		}
		sig, err := signer.Sign(challenge)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(base64.StdEncoding.EncodeToString(sig))

	case "fingerprint":
		fmt.Print(keys.SIGIL_FINGERPRINT)

	case "health":
		fmt.Print("OK")

	case "version":
		fmt.Printf("sigil v%s (%s)", keys.SIGIL_VERSION, keys.SIGIL_PLATFORM)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
```

**Step 5: Verify template compiles with placeholders**

Run: `cd builder/template && go build -o /dev/null ./cmd/identity/`
Expected: compiles (will fail at runtime since keys are placeholders, but that's fine)

**Step 6: Commit**

```bash
git add builder/template/
git commit -m "feat: add identity binary template (sign, fingerprint, health, version)"
```

---

### Task 4: Compiler — Source Generation + Build

The compiler takes a private key + platform, generates a customized copy of the template, and builds it with garble.

**Files:**
- Create: `builder/internal/compiler/compiler.go`
- Create: `builder/internal/compiler/compiler_test.go`

**Step 1: Write the failing integration test**

```go
// builder/internal/compiler/compiler_test.go
package compiler

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func TestCompileAndSignVerify(t *testing.T) {
	// Skip if garble not installed
	if _, err := exec.LookPath("garble"); err != nil {
		t.Skip("garble not installed, skipping integration test")
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Use current platform
	platform := runtime.GOOS + "-" + runtime.GOARCH

	outDir := t.TempDir()
	outPath := outDir + "/identity"

	err = Compile(CompileOptions{
		PrivateKeySeed: priv.Seed(), // 32 bytes
		PublicKey:      pub,
		Platform:       platform,
		OutputPath:     outPath,
		UseGarble:      false, // skip garble in tests for speed
		UseUPX:         false, // skip UPX in tests
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify binary exists and is executable
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("binary is empty")
	}

	// Test health command
	out, err := exec.Command(outPath, "health").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "OK" {
		t.Fatalf("health: got %q, want %q", out, "OK")
	}

	// Test fingerprint command
	out, err = exec.Command(outPath, "fingerprint").Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || string(out)[:7] != "sha256:" {
		t.Fatalf("fingerprint: got %q, want sha256:...", out)
	}

	// Test sign + verify round trip
	challenge := []byte("test-challenge-nonce")
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)

	out, err = exec.Command(outPath, "sign", challengeB64).Output()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	if !ed25519.Verify(pub, challenge, sig) {
		t.Fatal("signature verification failed")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd builder && go test ./internal/compiler/ -v -run TestCompileAndSignVerify`
Expected: FAIL — Compile not defined

**Step 3: Implement the compiler**

```go
// builder/internal/compiler/compiler.go
package compiler

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sigil-auth/sigil/builder/internal/crypto"
)

type CompileOptions struct {
	PrivateKeySeed []byte           // 32-byte Ed25519 seed
	PublicKey      ed25519.PublicKey // 32-byte public key
	Platform       string           // e.g., "linux-amd64"
	OutputPath     string           // where to write the compiled binary
	UseGarble      bool             // use garble for obfuscation
	UseUPX         bool             // use UPX for compression
}

func Compile(opts CompileOptions) error {
	parts := strings.SplitN(opts.Platform, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid platform: %s", opts.Platform)
	}
	goos, goarch := parts[0], parts[1]

	// 1. Generate AES key and encrypt private key seed
	aesKey, err := crypto.GenerateAESKey()
	if err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}

	encrypted, err := crypto.Encrypt(aesKey, opts.PrivateKeySeed)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	// Split nonce and ciphertext (nonce is prepended by Encrypt)
	nonceSize := 12 // AES-GCM standard nonce size
	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	fingerprint := crypto.Fingerprint(opts.PublicKey)

	// 2. Copy template to temp directory
	tmpDir, err := os.MkdirTemp("", "sigil-build-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	templateDir := findTemplateDir()
	if err := copyDir(templateDir, tmpDir); err != nil {
		return fmt.Errorf("copy template: %w", err)
	}

	// 3. Generate keys.go with embedded values
	keysFile := filepath.Join(tmpDir, "internal", "keys", "keys.go")
	keysContent := generateKeysSource(aesKey, nonce, ciphertext, fingerprint, opts.Platform)
	if err := os.WriteFile(keysFile, []byte(keysContent), 0644); err != nil {
		return fmt.Errorf("write keys.go: %w", err)
	}

	// 4. Build
	var buildCmd *exec.Cmd
	if opts.UseGarble {
		buildCmd = exec.Command("garble", "-literals", "-tiny",
			"build", "-ldflags=-s -w", "-o", opts.OutputPath, "./cmd/identity/")
	} else {
		buildCmd = exec.Command("go", "build",
			"-ldflags=-s -w", "-o", opts.OutputPath, "./cmd/identity/")
	}
	buildCmd.Dir = tmpDir
	buildCmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	// 5. UPX (skip for darwin — crashes on macOS 13+)
	if opts.UseUPX && goos != "darwin" {
		upxCmd := exec.Command("upx", "--best", opts.OutputPath)
		upxCmd.Stderr = os.Stderr
		if err := upxCmd.Run(); err != nil {
			return fmt.Errorf("upx failed: %w", err)
		}
	}

	return nil
}

func generateKeysSource(aesKey, nonce, ciphertext []byte, fingerprint, platform string) string {
	return fmt.Sprintf(`package keys

var (
	SIGIL_ENCRYPTED_KEY = %s
	SIGIL_KEY_NONCE     = %s
	SIGIL_AES_KEY       = %s
	SIGIL_FINGERPRINT   = %q
	SIGIL_VERSION       = "0.1.0"
	SIGIL_PLATFORM      = %q
)
`, byteSliceLiteral(ciphertext), byteSliceLiteral(nonce), byteSliceLiteral(aesKey), fingerprint, platform)
}

func byteSliceLiteral(b []byte) string {
	hex := hex.EncodeToString(b)
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, "0x"+hex[i:i+2])
	}
	return "[]byte{" + strings.Join(parts, ", ") + "}"
}

func findTemplateDir() string {
	// Look for template relative to the builder binary or working directory
	candidates := []string{
		"template",
		filepath.Join("..", "template"),
		filepath.Join(filepath.Dir(os.Args[0]), "..", "template"),
	}
	// Also check relative to this source file (for tests)
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(thisFile), "..", "..", "template"),
		)
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return "template" // fallback
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
```

**Step 4: Run the integration test**

Run: `cd builder && go test ./internal/compiler/ -v -run TestCompileAndSignVerify -timeout 60s`
Expected: PASS — binary compiles, health/fingerprint/sign all work, signature verifies

**Step 5: Commit**

```bash
git add builder/internal/compiler/
git commit -m "feat: add compiler that generates identity binaries from template"
```

---

### Task 5: Builder CLI Mode

**Files:**
- Modify: `builder/cmd/sigil-builder/main.go`

**Step 1: Implement the build subcommand**

```go
// builder/cmd/sigil-builder/main.go
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/sigil-auth/sigil/builder/internal/compiler"
	"github.com/sigil-auth/sigil/builder/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sigil-builder <build|serve>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "build":
		cmdBuild()
	case "serve":
		cmdServe()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func cmdBuild() {
	var privKeyB64, platform, output string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--private-key":
			i++
			privKeyB64 = args[i]
		case "--platform":
			i++
			platform = args[i]
		case "--output":
			i++
			output = args[i]
		}
	}

	if privKeyB64 == "" || platform == "" || output == "" {
		fmt.Fprintln(os.Stderr, "usage: sigil-builder build --private-key <base64> --platform <platform> --output <path>")
		os.Exit(1)
	}

	seed, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid base64 private key: %v\n", err)
		os.Exit(1)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	err = compiler.Compile(compiler.CompileOptions{
		PrivateKeySeed: seed,
		PublicKey:      pub,
		Platform:       platform,
		OutputPath:     output,
		UseGarble:      true,
		UseUPX:         true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "built: %s (%s)\n", output, platform)
	fmt.Print(crypto.Fingerprint(pub))
}

func cmdServe() {
	fmt.Fprintln(os.Stderr, "serve mode not yet implemented")
	os.Exit(1)
}
```

**Step 2: Test manually**

```bash
cd builder
go build -o sigil-builder ./cmd/sigil-builder/

# Generate a test key
KEY=$(openssl rand -base64 32)

# Build identity binary for current platform
./sigil-builder build --private-key "$KEY" --platform "$(go env GOOS)-$(go env GOARCH)" --output /tmp/test-identity
```

Expected: binary built at `/tmp/test-identity`, fingerprint printed to stdout

**Step 3: Commit**

```bash
git add builder/cmd/sigil-builder/
git commit -m "feat: add sigil-builder build CLI command"
```

---

### Task 6: Builder HTTP Server Mode

**Files:**
- Create: `builder/internal/server/server.go`
- Create: `builder/internal/server/server_test.go`
- Modify: `builder/cmd/sigil-builder/main.go` (wire up cmdServe)

**Step 1: Write failing test**

```go
// builder/internal/server/server_test.go
package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func TestBuildEndpoint(t *testing.T) {
	srv := New()

	_, priv, _ := ed25519.GenerateKey(nil)

	body, _ := json.Marshal(BuildRequest{
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
		Platform:   runtime.GOOS + "-" + runtime.GOARCH,
	})

	req := httptest.NewRequest("POST", "/build", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d. body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if rec.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content-type: got %q", rec.Header().Get("Content-Type"))
	}

	if rec.Header().Get("X-Binary-SHA256") == "" {
		t.Fatal("missing X-Binary-SHA256 header")
	}

	if rec.Body.Len() == 0 {
		t.Fatal("empty response body")
	}
}

func TestBuildEndpointInvalidPlatform(t *testing.T) {
	srv := New()

	body, _ := json.Marshal(BuildRequest{
		PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Platform:   "commodore-64",
	})

	req := httptest.NewRequest("POST", "/build", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd builder && go test ./internal/server/ -v`
Expected: FAIL

**Step 3: Implement the server**

```go
// builder/internal/server/server.go
package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/sigil-auth/sigil/builder/internal/compiler"
)

var supportedPlatforms = map[string]bool{
	"linux-amd64":  true,
	"linux-arm64":  true,
	"darwin-amd64": true,
	"darwin-arm64": true,
	"windows-amd64": true,
}

type BuildRequest struct {
	PrivateKey string `json:"private_key"` // base64-encoded 32-byte Ed25519 seed
	Platform   string `json:"platform"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func New() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /build", handleBuild)
	return mux
}

func handleBuild(w http.ResponseWriter, r *http.Request) {
	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if !supportedPlatforms[req.Platform] {
		writeError(w, http.StatusBadRequest, "unsupported_platform")
		return
	}

	seed, err := base64.StdEncoding.DecodeString(req.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		writeError(w, http.StatusBadRequest, "invalid_key")
		return
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	tmpFile, err := os.CreateTemp("", "sigil-binary-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build_failed")
		return
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	err = compiler.Compile(compiler.CompileOptions{
		PrivateKeySeed: seed,
		PublicKey:      pub,
		Platform:       req.Platform,
		OutputPath:     tmpPath,
		UseGarble:      true,
		UseUPX:         true,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build_failed")
		return
	}

	binary, err := os.ReadFile(tmpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build_failed")
		return
	}

	hash := sha256.Sum256(binary)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Binary-SHA256", hex.EncodeToString(hash[:]))
	w.Write(binary)
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: code})
}
```

**Step 4: Wire up cmdServe in main.go**

Update `cmdServe` in `builder/cmd/sigil-builder/main.go`:

```go
func cmdServe() {
	port := "8080"
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" {
			i++
			port = args[i]
		}
	}

	srv := server.New()
	fmt.Fprintf(os.Stderr, "sigil-builder serving on :%s\n", port)
	if err := http.ListenAndServe(":"+port, srv); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
```

Add import: `"github.com/sigil-auth/sigil/builder/internal/server"` and `"net/http"`

**Step 5: Run tests**

Run: `cd builder && go test ./internal/server/ -v -timeout 120s`
Expected: PASS

**Step 6: Commit**

```bash
git add builder/internal/server/ builder/cmd/sigil-builder/
git commit -m "feat: add builder HTTP server mode (POST /build)"
```

---

### Task 7: Builder Dockerfile

**Files:**
- Create: `builder/Dockerfile`

**Step 1: Write the Dockerfile**

```dockerfile
# builder/Dockerfile
FROM golang:1.23-alpine AS base

RUN apk add --no-cache git upx

# Install garble
RUN go install mvdan.cc/garble@latest

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /sigil-builder ./cmd/sigil-builder/

FROM golang:1.23-alpine AS runtime

RUN apk add --no-cache git upx
COPY --from=base /root/go/bin/garble /usr/local/bin/garble
COPY --from=base /sigil-builder /usr/local/bin/sigil-builder
COPY --from=base /app/template /template

ENV SIGIL_TEMPLATE_DIR=/template

EXPOSE 8080
ENTRYPOINT ["sigil-builder", "serve"]
CMD ["--port", "8080"]
```

**Step 2: Verify it builds**

Run: `cd builder && docker build -t sigil/builder .`
Expected: image builds successfully

**Step 3: Commit**

```bash
git add builder/Dockerfile
git commit -m "feat: add builder Dockerfile"
```

---

## Phase 2a: Node.js Server SDK (TypeScript)

### Task 8: Node SDK Project Setup

**Files:**
- Create: `sdk/node/package.json`
- Create: `sdk/node/tsconfig.json`
- Create: `sdk/node/src/index.ts`

**Step 1: Initialize project**

```bash
cd sdk/node
npm init -y
npm install jose @noble/ed25519 @noble/hashes better-sqlite3 pg uuid
npm install -D typescript tsup @types/better-sqlite3 @types/pg @types/uuid vitest
```

**Step 2: Configure tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "declaration": true,
    "outDir": "dist",
    "rootDir": "src",
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src"]
}
```

**Step 3: Update package.json** (add scripts, exports)

Set name to `@sigil/server`. Add:
```json
{
  "name": "@sigil/server",
  "main": "./dist/index.js",
  "module": "./dist/index.mjs",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": { "types": "./dist/index.d.mts", "default": "./dist/index.mjs" },
      "require": { "types": "./dist/index.d.ts", "default": "./dist/index.js" }
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsup src/index.ts --format cjs,esm --dts --clean",
    "test": "vitest run"
  }
}
```

**Step 4: Create barrel export**

```typescript
// sdk/node/src/index.ts
export { Sigil } from './sigil.js';
export type { SigilConfig, Agent, StorageAdapter } from './types.js';
```

**Step 5: Create types**

```typescript
// sdk/node/src/types.ts
export interface SigilConfig {
  builder: string;                   // 'local' or 'http://...'
  platforms: string[];
  jwtSecret: string;
  challengeTTL?: number;             // seconds, default 30
  sessionTTL?: number;               // seconds, default 300
  enrollmentTTL?: number;            // seconds, default 1800
  storage: StorageAdapter;
  maxKeyAge?: string | null;         // e.g., '90d', null = no enforced rotation
}

export interface Agent {
  id: string;
  name: string;
  externalUserId: string;
  publicKey: Buffer | null;
  keyFingerprint: string | null;
  platform: string | null;
  status: 'pending_enrollment' | 'active' | 'rotating' | 'revoked';
  enrolledAt: Date | null;
  lastAuthAt: Date | null;
  keyExpiresAt: Date | null;
  createdAt: Date;
}

export interface EnrollmentToken {
  tokenHash: string;
  agentId: string;
  expiresAt: Date;
  used: boolean;
}

export interface Challenge {
  challenge: string;
  agentId: string;
  expiresAt: Date;
  used: boolean;
}

export interface StorageAdapter {
  agents: {
    create(agent: Omit<Agent, 'createdAt'>): Promise<Agent>;
    get(id: string): Promise<Agent | null>;
    updateStatus(id: string, status: Agent['status'], fields?: Partial<Agent>): Promise<void>;
    listByUser(userId: string): Promise<Agent[]>;
  };
  enrollmentTokens: {
    create(token: EnrollmentToken): Promise<void>;
    validate(tokenHash: string): Promise<EnrollmentToken | null>;
    burn(tokenHash: string): Promise<void>;
  };
  challenges: {
    create(challenge: Challenge): Promise<void>;
    validate(challenge: string): Promise<Challenge | null>;
    burn(challenge: string): Promise<void>;
  };
  cleanup(): Promise<void>;
}
```

**Step 6: Verify it compiles**

Run: `cd sdk/node && npx tsc --noEmit`
Expected: type errors for missing sigil.ts (that's fine for now — we just need types to compile)

**Step 7: Commit**

```bash
git add sdk/node/
git commit -m "feat: scaffold Node SDK with types and project config"
```

---

### Task 9: Node SDK — SQLite Storage Adapter

**Files:**
- Create: `sdk/node/src/storage/sqlite.ts`
- Create: `sdk/node/src/storage/sqlite.test.ts`

**Step 1: Write failing tests**

```typescript
// sdk/node/src/storage/sqlite.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createSQLiteStorage } from './sqlite.js';
import crypto from 'node:crypto';

describe('SQLiteStorage', () => {
  let storage: ReturnType<typeof createSQLiteStorage>;

  beforeEach(() => {
    storage = createSQLiteStorage(':memory:');
  });

  describe('agents', () => {
    it('creates and retrieves an agent', async () => {
      const agent = await storage.agents.create({
        id: crypto.randomUUID(),
        name: 'test-agent',
        externalUserId: 'user-1',
        publicKey: null,
        keyFingerprint: null,
        platform: null,
        status: 'pending_enrollment',
        enrolledAt: null,
        lastAuthAt: null,
        keyExpiresAt: null,
      });

      const found = await storage.agents.get(agent.id);
      expect(found).not.toBeNull();
      expect(found!.name).toBe('test-agent');
      expect(found!.status).toBe('pending_enrollment');
    });

    it('returns null for unknown agent', async () => {
      const found = await storage.agents.get(crypto.randomUUID());
      expect(found).toBeNull();
    });

    it('updates agent status', async () => {
      const agent = await storage.agents.create({
        id: crypto.randomUUID(),
        name: 'test-agent',
        externalUserId: 'user-1',
        publicKey: null,
        keyFingerprint: null,
        platform: null,
        status: 'pending_enrollment',
        enrolledAt: null,
        lastAuthAt: null,
        keyExpiresAt: null,
      });

      await storage.agents.updateStatus(agent.id, 'active', {
        publicKey: Buffer.from('test-key'),
        keyFingerprint: 'sha256:abc',
        platform: 'linux-amd64',
        enrolledAt: new Date(),
      });

      const found = await storage.agents.get(agent.id);
      expect(found!.status).toBe('active');
      expect(found!.keyFingerprint).toBe('sha256:abc');
    });
  });

  describe('enrollment tokens', () => {
    it('creates, validates, and burns a token', async () => {
      const tokenHash = crypto.randomBytes(32).toString('hex');
      const agentId = crypto.randomUUID();

      await storage.enrollmentTokens.create({
        tokenHash,
        agentId,
        expiresAt: new Date(Date.now() + 60000),
        used: false,
      });

      const valid = await storage.enrollmentTokens.validate(tokenHash);
      expect(valid).not.toBeNull();
      expect(valid!.agentId).toBe(agentId);

      await storage.enrollmentTokens.burn(tokenHash);

      const burned = await storage.enrollmentTokens.validate(tokenHash);
      expect(burned).toBeNull();
    });

    it('rejects expired token', async () => {
      const tokenHash = crypto.randomBytes(32).toString('hex');
      await storage.enrollmentTokens.create({
        tokenHash,
        agentId: crypto.randomUUID(),
        expiresAt: new Date(Date.now() - 1000), // already expired
        used: false,
      });

      const valid = await storage.enrollmentTokens.validate(tokenHash);
      expect(valid).toBeNull();
    });
  });

  describe('challenges', () => {
    it('creates, validates, and burns a challenge', async () => {
      const challenge = crypto.randomBytes(32).toString('base64');
      const agentId = crypto.randomUUID();

      await storage.challenges.create({
        challenge,
        agentId,
        expiresAt: new Date(Date.now() + 30000),
        used: false,
      });

      const valid = await storage.challenges.validate(challenge);
      expect(valid).not.toBeNull();

      await storage.challenges.burn(challenge);

      const burned = await storage.challenges.validate(challenge);
      expect(burned).toBeNull();
    });
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd sdk/node && npx vitest run src/storage/sqlite.test.ts`
Expected: FAIL

**Step 3: Implement SQLite adapter**

```typescript
// sdk/node/src/storage/sqlite.ts
import Database from 'better-sqlite3';
import type { StorageAdapter, Agent, EnrollmentToken, Challenge } from '../types.js';

export function createSQLiteStorage(path: string): StorageAdapter {
  const db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS sigil_agents (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      external_user_id TEXT NOT NULL,
      public_key BLOB,
      key_fingerprint TEXT,
      platform TEXT,
      status TEXT DEFAULT 'pending_enrollment',
      enrolled_at TEXT,
      last_auth_at TEXT,
      key_expires_at TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sigil_enrollment_tokens (
      token_hash TEXT PRIMARY KEY,
      agent_id TEXT REFERENCES sigil_agents(id),
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sigil_challenges (
      challenge TEXT PRIMARY KEY,
      agent_id TEXT REFERENCES sigil_agents(id),
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  return {
    agents: {
      async create(agent) {
        db.prepare(`
          INSERT INTO sigil_agents (id, name, external_user_id, public_key, key_fingerprint, platform, status, enrolled_at, last_auth_at, key_expires_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(agent.id, agent.name, agent.externalUserId, agent.publicKey, agent.keyFingerprint, agent.platform, agent.status, agent.enrolledAt?.toISOString() ?? null, agent.lastAuthAt?.toISOString() ?? null, agent.keyExpiresAt?.toISOString() ?? null);
        return { ...agent, createdAt: new Date() };
      },
      async get(id) {
        const row = db.prepare('SELECT * FROM sigil_agents WHERE id = ?').get(id) as any;
        return row ? rowToAgent(row) : null;
      },
      async updateStatus(id, status, fields = {}) {
        const sets = ['status = ?'];
        const values: any[] = [status];
        if (fields.publicKey !== undefined) { sets.push('public_key = ?'); values.push(fields.publicKey); }
        if (fields.keyFingerprint !== undefined) { sets.push('key_fingerprint = ?'); values.push(fields.keyFingerprint); }
        if (fields.platform !== undefined) { sets.push('platform = ?'); values.push(fields.platform); }
        if (fields.enrolledAt !== undefined) { sets.push('enrolled_at = ?'); values.push(fields.enrolledAt?.toISOString() ?? null); }
        if (fields.lastAuthAt !== undefined) { sets.push('last_auth_at = ?'); values.push(fields.lastAuthAt?.toISOString() ?? null); }
        if (fields.keyExpiresAt !== undefined) { sets.push('key_expires_at = ?'); values.push(fields.keyExpiresAt?.toISOString() ?? null); }
        values.push(id);
        db.prepare(`UPDATE sigil_agents SET ${sets.join(', ')} WHERE id = ?`).run(...values);
      },
      async listByUser(userId) {
        const rows = db.prepare('SELECT * FROM sigil_agents WHERE external_user_id = ?').all(userId) as any[];
        return rows.map(rowToAgent);
      },
    },
    enrollmentTokens: {
      async create(token) {
        db.prepare(`
          INSERT INTO sigil_enrollment_tokens (token_hash, agent_id, expires_at, used)
          VALUES (?, ?, ?, ?)
        `).run(token.tokenHash, token.agentId, token.expiresAt.toISOString(), token.used ? 1 : 0);
      },
      async validate(tokenHash) {
        const row = db.prepare(`
          SELECT * FROM sigil_enrollment_tokens
          WHERE token_hash = ? AND used = 0 AND expires_at > datetime('now')
        `).get(tokenHash) as any;
        return row ? { tokenHash: row.token_hash, agentId: row.agent_id, expiresAt: new Date(row.expires_at), used: !!row.used } : null;
      },
      async burn(tokenHash) {
        db.prepare('UPDATE sigil_enrollment_tokens SET used = 1 WHERE token_hash = ?').run(tokenHash);
      },
    },
    challenges: {
      async create(challenge) {
        db.prepare(`
          INSERT INTO sigil_challenges (challenge, agent_id, expires_at, used)
          VALUES (?, ?, ?, ?)
        `).run(challenge.challenge, challenge.agentId, challenge.expiresAt.toISOString(), challenge.used ? 1 : 0);
      },
      async validate(challenge) {
        const row = db.prepare(`
          SELECT * FROM sigil_challenges
          WHERE challenge = ? AND used = 0 AND expires_at > datetime('now')
        `).get(challenge) as any;
        return row ? { challenge: row.challenge, agentId: row.agent_id, expiresAt: new Date(row.expires_at), used: !!row.used } : null;
      },
      async burn(challenge) {
        db.prepare('UPDATE sigil_challenges SET used = 1 WHERE challenge = ?').run(challenge);
      },
    },
    async cleanup() {
      db.prepare("DELETE FROM sigil_challenges WHERE expires_at < datetime('now')").run();
      db.prepare("DELETE FROM sigil_enrollment_tokens WHERE used = 1 OR expires_at < datetime('now')").run();
    },
  };
}

function rowToAgent(row: any): Agent {
  return {
    id: row.id,
    name: row.name,
    externalUserId: row.external_user_id,
    publicKey: row.public_key ? Buffer.from(row.public_key) : null,
    keyFingerprint: row.key_fingerprint,
    platform: row.platform,
    status: row.status,
    enrolledAt: row.enrolled_at ? new Date(row.enrolled_at) : null,
    lastAuthAt: row.last_auth_at ? new Date(row.last_auth_at) : null,
    keyExpiresAt: row.key_expires_at ? new Date(row.key_expires_at) : null,
    createdAt: new Date(row.created_at),
  };
}
```

**Step 4: Run tests**

Run: `cd sdk/node && npx vitest run src/storage/sqlite.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add sdk/node/src/storage/
git commit -m "feat: add SQLite storage adapter for Node SDK"
```

---

### Task 10: Node SDK — Builder Client

**Files:**
- Create: `sdk/node/src/builder.ts`
- Create: `sdk/node/src/builder.test.ts`

**Step 1: Write failing test for local builder**

```typescript
// sdk/node/src/builder.test.ts
import { describe, it, expect } from 'vitest';
import { createBuilder } from './builder.js';

describe('createBuilder', () => {
  it('returns a local builder when mode is "local"', () => {
    const builder = createBuilder('local');
    expect(builder.type).toBe('local');
  });

  it('returns a remote builder when mode is a URL', () => {
    const builder = createBuilder('http://localhost:8080');
    expect(builder.type).toBe('remote');
  });
});
```

**Step 2: Implement builder client**

```typescript
// sdk/node/src/builder.ts
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const execFileAsync = promisify(execFile);

export interface BuildResult {
  binary: Buffer;
  sha256: string;
}

export interface Builder {
  type: 'local' | 'remote';
  build(privateKeySeedB64: string, platform: string): Promise<BuildResult>;
}

export function createBuilder(mode: string): Builder {
  if (mode === 'local') {
    return {
      type: 'local',
      async build(privateKeySeedB64, platform) {
        const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sigil-'));
        const outPath = path.join(tmpDir, 'identity');

        try {
          const { stdout } = await execFileAsync('sigil-builder', [
            'build',
            '--private-key', privateKeySeedB64,
            '--platform', platform,
            '--output', outPath,
          ], { timeout: 120000 });

          const binary = await fs.readFile(outPath);
          const crypto = await import('node:crypto');
          const sha256 = crypto.createHash('sha256').update(binary).digest('hex');

          return { binary, sha256 };
        } finally {
          await fs.rm(tmpDir, { recursive: true, force: true });
        }
      },
    };
  }

  // Remote builder
  const baseUrl = mode.replace(/\/$/, '');
  return {
    type: 'remote',
    async build(privateKeySeedB64, platform) {
      const res = await fetch(`${baseUrl}/build`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ private_key: privateKeySeedB64, platform }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'unknown' }));
        throw new Error(`Builder error: ${(err as any).error} (${res.status})`);
      }

      const binary = Buffer.from(await res.arrayBuffer());
      const sha256 = res.headers.get('X-Binary-SHA256') || '';

      return { binary, sha256 };
    },
  };
}
```

**Step 3: Run tests**

Run: `cd sdk/node && npx vitest run src/builder.test.ts`
Expected: PASS

**Step 4: Commit**

```bash
git add sdk/node/src/builder.ts sdk/node/src/builder.test.ts
git commit -m "feat: add builder client (local + remote) for Node SDK"
```

---

### Task 11: Node SDK — Core Sigil Class + Route Handlers

This is the main orchestration class. It wires builder, storage, and crypto together into route handlers.

**Files:**
- Create: `sdk/node/src/sigil.ts`
- Create: `sdk/node/src/auth.ts`
- Create: `sdk/node/src/sigil.test.ts`

**Step 1: Write failing tests**

```typescript
// sdk/node/src/sigil.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { Sigil } from './sigil.js';
import { createSQLiteStorage } from './storage/sqlite.js';

describe('Sigil', () => {
  let sigil: Sigil;

  beforeEach(() => {
    sigil = new Sigil({
      builder: 'local',
      platforms: ['linux-amd64', 'darwin-arm64'],
      jwtSecret: 'test-secret-at-least-32-chars-long!!',
      storage: createSQLiteStorage(':memory:'),
    });
  });

  describe('createAgent', () => {
    it('creates an agent and returns enrollment token', async () => {
      const result = await sigil.createAgent({
        name: 'test-agent',
        userId: 'user-1',
      });

      expect(result.agentId).toBeDefined();
      expect(result.enrollmentToken).toBeDefined();
      expect(result.enrollmentExpiresAt).toBeInstanceOf(Date);
    });
  });

  describe('challenge', () => {
    it('issues a challenge for an active agent', async () => {
      // Create and manually activate an agent
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await sigil.config.storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test',
      });

      const result = await sigil.challenge(agentId);
      expect(result.challenge).toBeDefined();
      expect(result.expiresIn).toBe(30);
    });

    it('rejects challenge for unknown agent', async () => {
      await expect(sigil.challenge('nonexistent')).rejects.toThrow();
    });
  });
});
```

**Step 2: Implement auth utilities**

```typescript
// sdk/node/src/auth.ts
import { SignJWT, jwtVerify } from 'jose';
import crypto from 'node:crypto';

export async function issueToken(
  secret: string,
  payload: { agentId: string; userId: string; fingerprint: string },
  ttlSeconds: number,
): Promise<string> {
  const key = new TextEncoder().encode(secret);
  return new SignJWT({
    agent_id: payload.agentId,
    user_id: payload.userId,
    fingerprint: payload.fingerprint,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(key);
}

export async function verifyToken(
  secret: string,
  token: string,
): Promise<{ agentId: string; userId: string; fingerprint: string }> {
  const key = new TextEncoder().encode(secret);
  const { payload } = await jwtVerify(token, key);
  return {
    agentId: payload.agent_id as string,
    userId: payload.user_id as string,
    fingerprint: payload.fingerprint as string,
  };
}

export function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function generateChallenge(): string {
  return crypto.randomBytes(32).toString('base64');
}
```

**Step 3: Implement Sigil class**

```typescript
// sdk/node/src/sigil.ts
import crypto from 'node:crypto';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { createBuilder, type Builder } from './builder.js';
import { issueToken, verifyToken, generateToken, hashToken, generateChallenge } from './auth.js';
import type { SigilConfig, StorageAdapter, Agent } from './types.js';

// Required for Node.js
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

export class Sigil {
  config: SigilConfig & { challengeTTL: number; sessionTTL: number; enrollmentTTL: number };
  private builder: Builder;

  constructor(config: SigilConfig) {
    this.config = {
      challengeTTL: 30,
      sessionTTL: 300,
      enrollmentTTL: 1800,
      ...config,
    };
    this.builder = createBuilder(config.builder);
  }

  async createAgent(params: { name: string; userId: string }): Promise<{
    agentId: string;
    enrollmentToken: string;
    enrollmentExpiresAt: Date;
  }> {
    const agentId = crypto.randomUUID();
    const token = generateToken();
    const expiresAt = new Date(Date.now() + this.config.enrollmentTTL * 1000);

    await this.config.storage.agents.create({
      id: agentId,
      name: params.name,
      externalUserId: params.userId,
      publicKey: null,
      keyFingerprint: null,
      platform: null,
      status: 'pending_enrollment',
      enrolledAt: null,
      lastAuthAt: null,
      keyExpiresAt: null,
    });

    await this.config.storage.enrollmentTokens.create({
      tokenHash: hashToken(token),
      agentId,
      expiresAt,
      used: false,
    });

    return { agentId, enrollmentToken: token, enrollmentExpiresAt: expiresAt };
  }

  async enroll(token: string, platform: string): Promise<{
    agentId: string;
    binary: Buffer;
    fingerprint: string;
  }> {
    if (!this.config.platforms.includes(platform)) {
      throw new SigilError('unsupported_platform', 400);
    }

    const tokenRecord = await this.config.storage.enrollmentTokens.validate(hashToken(token));
    if (!tokenRecord) {
      throw new SigilError('token_expired', 401);
    }

    const agent = await this.config.storage.agents.get(tokenRecord.agentId);
    if (!agent) {
      throw new SigilError('agent_not_found', 404);
    }
    if (agent.status !== 'pending_enrollment' && agent.status !== 'rotating') {
      throw new SigilError('already_enrolled', 403);
    }

    // Generate Ed25519 key pair
    const privKey = ed.utils.randomPrivateKey(); // 32-byte seed
    const pubKey = await ed.getPublicKeyAsync(privKey);
    const fingerprint = 'sha256:' + crypto.createHash('sha256').update(pubKey).digest('hex');

    // Build identity binary
    const { binary } = await this.builder.build(
      Buffer.from(privKey).toString('base64'),
      platform,
    );

    // Store public key, burn token
    await this.config.storage.agents.updateStatus(tokenRecord.agentId, 'active', {
      publicKey: Buffer.from(pubKey),
      keyFingerprint: fingerprint,
      platform,
      enrolledAt: new Date(),
    });
    await this.config.storage.enrollmentTokens.burn(tokenRecord.tokenHash);

    return { agentId: tokenRecord.agentId, binary, fingerprint };
  }

  async challenge(agentId: string): Promise<{ challenge: string; expiresIn: number }> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) {
      throw new SigilError('agent_not_found', 404);
    }
    if (agent.status === 'revoked') {
      throw new SigilError('agent_revoked', 403);
    }
    if (agent.status !== 'active') {
      throw new SigilError('agent_not_active', 403);
    }

    const challenge = generateChallenge();
    await this.config.storage.challenges.create({
      challenge,
      agentId,
      expiresAt: new Date(Date.now() + this.config.challengeTTL * 1000),
      used: false,
    });

    return { challenge, expiresIn: this.config.challengeTTL };
  }

  async verify(agentId: string, challenge: string, signatureB64: string): Promise<{
    token: string;
    expiresIn: number;
  }> {
    const challengeRecord = await this.config.storage.challenges.validate(challenge);
    if (!challengeRecord) {
      throw new SigilError('challenge_expired', 401);
    }
    if (challengeRecord.agentId !== agentId) {
      throw new SigilError('challenge_expired', 401);
    }

    const agent = await this.config.storage.agents.get(agentId);
    if (!agent || !agent.publicKey) {
      throw new SigilError('agent_not_found', 404);
    }
    if (agent.status === 'revoked') {
      throw new SigilError('agent_revoked', 403);
    }

    const signature = Buffer.from(signatureB64, 'base64');
    const message = Buffer.from(challenge, 'base64');
    const isValid = ed.verify(signature, message, new Uint8Array(agent.publicKey));

    if (!isValid) {
      throw new SigilError('signature_invalid', 401);
    }

    await this.config.storage.challenges.burn(challenge);

    await this.config.storage.agents.updateStatus(agentId, 'active', {
      lastAuthAt: new Date(),
    });

    const token = await issueToken(
      this.config.jwtSecret,
      { agentId, userId: agent.externalUserId, fingerprint: agent.keyFingerprint! },
      this.config.sessionTTL,
    );

    return { token, expiresIn: this.config.sessionTTL };
  }

  async rotate(agentId: string): Promise<{ enrollmentToken: string; expiresAt: Date }> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) throw new SigilError('agent_not_found', 404);

    const token = generateToken();
    const expiresAt = new Date(Date.now() + this.config.enrollmentTTL * 1000);

    await this.config.storage.agents.updateStatus(agentId, 'rotating');
    await this.config.storage.enrollmentTokens.create({
      tokenHash: hashToken(token),
      agentId,
      expiresAt,
      used: false,
    });

    return { enrollmentToken: token, expiresAt };
  }

  async revoke(agentId: string): Promise<void> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) throw new SigilError('agent_not_found', 404);

    await this.config.storage.agents.updateStatus(agentId, 'revoked', {
      publicKey: null,
      keyFingerprint: null,
    });
  }

  async reEnroll(agentId: string): Promise<{ enrollmentToken: string; expiresAt: Date }> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) throw new SigilError('agent_not_found', 404);
    if (agent.status !== 'revoked') throw new SigilError('agent_not_revoked', 400);

    const token = generateToken();
    const expiresAt = new Date(Date.now() + this.config.enrollmentTTL * 1000);

    await this.config.storage.agents.updateStatus(agentId, 'pending_enrollment');
    await this.config.storage.enrollmentTokens.create({
      tokenHash: hashToken(token),
      agentId,
      expiresAt,
      used: false,
    });

    return { enrollmentToken: token, expiresAt };
  }

  async verifyJWT(token: string): Promise<{ agentId: string; userId: string; fingerprint: string }> {
    return verifyToken(this.config.jwtSecret, token);
  }
}

export class SigilError extends Error {
  constructor(public code: string, public statusCode: number) {
    super(code);
    this.name = 'SigilError';
  }
}
```

**Step 4: Run tests**

Run: `cd sdk/node && npx vitest run src/sigil.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add sdk/node/src/
git commit -m "feat: add Sigil class with all route handlers (Node SDK)"
```

---

### Task 12: Node SDK — Express/Fastify Middleware

**Files:**
- Create: `sdk/node/src/middleware.ts`

**Step 1: Implement middleware**

```typescript
// sdk/node/src/middleware.ts
import type { Sigil, SigilError } from './sigil.js';

// Framework-agnostic — works with Express, Fastify, or any (req, res, next) handler
export function createMiddleware(sigil: Sigil) {
  return async (req: any, res: any, next: any) => {
    const authHeader = req.headers?.authorization || req.headers?.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'missing_token' });
      return;
    }

    const token = authHeader.slice(7);
    try {
      const agent = await sigil.verifyJWT(token);
      req.agent = {
        id: agent.agentId,
        userId: agent.userId,
        fingerprint: agent.fingerprint,
      };
      next();
    } catch {
      res.status(401).json({ error: 'invalid_token' });
    }
  };
}

// Route handler wrappers that map Sigil methods to HTTP request/response
export function createRouteHandlers(sigil: Sigil) {
  return {
    createAgent: async (req: any, res: any) => {
      try {
        const result = await sigil.createAgent({ name: req.body.name, userId: req.body.user_id });
        res.status(201).json({
          agent_id: result.agentId,
          enrollment_token: result.enrollmentToken,
          enrollment_expires_at: result.enrollmentExpiresAt.toISOString(),
        });
      } catch (e: any) {
        handleError(res, e);
      }
    },

    enroll: async (req: any, res: any) => {
      try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        const result = await sigil.enroll(token, req.body.platform);
        res.set('X-Agent-ID', result.agentId);
        res.set('X-Key-Fingerprint', result.fingerprint);
        res.set('Content-Type', 'application/octet-stream');
        res.send(result.binary);
      } catch (e: any) {
        handleError(res, e);
      }
    },

    challenge: async (req: any, res: any) => {
      try {
        const result = await sigil.challenge(req.body.agent_id);
        res.json({ challenge: result.challenge, expires_in: result.expiresIn });
      } catch (e: any) {
        handleError(res, e);
      }
    },

    verify: async (req: any, res: any) => {
      try {
        const result = await sigil.verify(req.body.agent_id, req.body.challenge, req.body.signature);
        res.json({ token: result.token, expires_in: result.expiresIn });
      } catch (e: any) {
        handleError(res, e);
      }
    },

    rotate: async (req: any, res: any) => {
      try {
        const result = await sigil.rotate(req.params.id);
        res.json({ enrollment_token: result.enrollmentToken, expires_at: result.expiresAt.toISOString() });
      } catch (e: any) {
        handleError(res, e);
      }
    },

    revoke: async (req: any, res: any) => {
      try {
        await sigil.revoke(req.params.id);
        res.json({ ok: true });
      } catch (e: any) {
        handleError(res, e);
      }
    },

    reEnroll: async (req: any, res: any) => {
      try {
        const result = await sigil.reEnroll(req.params.id);
        res.json({ enrollment_token: result.enrollmentToken, expires_at: result.expiresAt.toISOString() });
      } catch (e: any) {
        handleError(res, e);
      }
    },
  };
}

function handleError(res: any, e: any) {
  if (e.name === 'SigilError') {
    res.status(e.statusCode).json({ error: e.code });
  } else {
    res.status(500).json({ error: 'internal_error' });
  }
}
```

**Step 2: Update index.ts exports**

```typescript
// sdk/node/src/index.ts
export { Sigil, SigilError } from './sigil.js';
export { createMiddleware, createRouteHandlers } from './middleware.js';
export { createSQLiteStorage } from './storage/sqlite.js';
export type { SigilConfig, Agent, StorageAdapter } from './types.js';
```

**Step 3: Verify it compiles**

Run: `cd sdk/node && npx tsc --noEmit`
Expected: no errors

**Step 4: Commit**

```bash
git add sdk/node/src/
git commit -m "feat: add Express middleware and route handlers (Node SDK)"
```

---

## Phase 2b: Python Server SDK

### Task 13: Python SDK Project Setup + Types

**Files:**
- Create: `sdk/python/pyproject.toml`
- Create: `sdk/python/sigil/__init__.py`
- Create: `sdk/python/sigil/types.py`

**Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "sigil-server"
version = "0.1.0"
description = "Device-bound identity for AI agents — server SDK"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "Apache-2.0" }
dependencies = [
    "PyJWT>=2.8",
    "cryptography>=41.0",
]

[project.optional-dependencies]
sqlite = ["aiosqlite>=0.19"]
postgres = ["asyncpg>=0.28"]
dev = ["pytest>=7.0", "pytest-asyncio>=0.21", "aiosqlite>=0.19"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

**Step 2: Create types**

```python
# sdk/python/sigil/types.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from abc import abstractmethod


@dataclass
class Agent:
    id: str
    name: str
    external_user_id: str
    public_key: bytes | None = None
    key_fingerprint: str | None = None
    platform: str | None = None
    status: str = "pending_enrollment"
    enrolled_at: datetime | None = None
    last_auth_at: datetime | None = None
    key_expires_at: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EnrollmentToken:
    token_hash: str
    agent_id: str
    expires_at: datetime
    used: bool = False


@dataclass
class Challenge:
    challenge: str
    agent_id: str
    expires_at: datetime
    used: bool = False


class StorageAdapter(Protocol):
    @abstractmethod
    async def create_agent(self, agent: Agent) -> Agent: ...
    @abstractmethod
    async def get_agent(self, agent_id: str) -> Agent | None: ...
    @abstractmethod
    async def update_agent_status(self, agent_id: str, status: str, **fields) -> None: ...
    @abstractmethod
    async def list_agents_by_user(self, user_id: str) -> list[Agent]: ...

    @abstractmethod
    async def create_enrollment_token(self, token: EnrollmentToken) -> None: ...
    @abstractmethod
    async def validate_enrollment_token(self, token_hash: str) -> EnrollmentToken | None: ...
    @abstractmethod
    async def burn_enrollment_token(self, token_hash: str) -> None: ...

    @abstractmethod
    async def create_challenge(self, challenge: Challenge) -> None: ...
    @abstractmethod
    async def validate_challenge(self, challenge: str) -> Challenge | None: ...
    @abstractmethod
    async def burn_challenge(self, challenge: str) -> None: ...

    @abstractmethod
    async def cleanup(self) -> None: ...
```

**Step 3: Create __init__.py**

```python
# sdk/python/sigil/__init__.py
from sigil.server import Sigil, SigilError
from sigil.types import Agent, StorageAdapter

__all__ = ["Sigil", "SigilError", "Agent", "StorageAdapter"]
```

**Step 4: Commit**

```bash
git add sdk/python/
git commit -m "feat: scaffold Python SDK with types and project config"
```

---

### Task 14: Python SDK — SQLite Storage + Server Class + Tests

**Files:**
- Create: `sdk/python/sigil/storage/sqlite.py`
- Create: `sdk/python/sigil/storage/__init__.py`
- Create: `sdk/python/sigil/server.py`
- Create: `sdk/python/sigil/builder.py`
- Create: `sdk/python/sigil/auth.py`
- Create: `sdk/python/tests/test_server.py`

This task mirrors the Node SDK implementation. The Python SDK follows the same patterns: storage adapter, builder client, auth utilities, and the main Sigil class.

**Implementation notes:**
- `sigil/storage/sqlite.py` — mirrors `sdk/node/src/storage/sqlite.ts` using `aiosqlite`
- `sigil/auth.py` — mirrors `sdk/node/src/auth.ts` using `PyJWT`
- `sigil/builder.py` — mirrors `sdk/node/src/builder.ts` using `subprocess` (local) and `httpx`/`urllib` (remote)
- `sigil/server.py` — mirrors `sdk/node/src/sigil.ts`, same Sigil class with identical methods:
  - `create_agent()`, `enroll()`, `challenge()`, `verify()`, `rotate()`, `revoke()`, `re_enroll()`, `verify_jwt()`
- Ed25519 verification via `cryptography` library

**Tests** should cover the same cases as the Node SDK tests:
- `test_create_agent` — creates agent, returns enrollment token
- `test_challenge` — issues challenge for active agent, rejects unknown agent
- `test_sqlite_storage` — CRUD operations, token validation, expiry

**Step 1:** Write tests first, then implement each file. Follow the same TDD pattern as Node SDK tasks.

**Step 2: Run tests**

Run: `cd sdk/python && pip install -e ".[dev]" && pytest tests/ -v`
Expected: PASS

**Step 3: Commit**

```bash
git add sdk/python/
git commit -m "feat: add Python SDK with SQLite storage, auth, and Sigil class"
```

---

### Task 15: Python SDK — Middleware (Flask + FastAPI)

**Files:**
- Create: `sdk/python/sigil/middleware.py`

**Step 1: Implement middleware for both frameworks**

```python
# sdk/python/sigil/middleware.py
from functools import wraps
from sigil.server import Sigil


def require_auth_flask(sigil: Sigil):
    """Flask decorator for protected routes."""
    def decorator(f):
        @wraps(f)
        async def wrapper(*args, **kwargs):
            from flask import request, jsonify
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "missing_token"}), 401
            try:
                agent = await sigil.verify_jwt(auth[7:])
                request.agent = agent
            except Exception:
                return jsonify({"error": "invalid_token"}), 401
            return await f(*args, **kwargs)
        return wrapper
    return decorator


def require_auth_fastapi(sigil: Sigil):
    """FastAPI dependency for protected routes."""
    async def dependency():
        from fastapi import Request, HTTPException
        from starlette.requests import Request as StarletteRequest
        import inspect
        # This is used as a FastAPI Depends() dependency
        # The actual implementation will receive the request via FastAPI's DI
        pass
    # Return a factory that creates the dependency
    from fastapi import Depends, HTTPException, Request

    async def get_agent(request: Request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing_token")
        try:
            return await sigil.verify_jwt(auth[7:])
        except Exception:
            raise HTTPException(status_code=401, detail="invalid_token")

    return get_agent
```

**Step 2: Commit**

```bash
git add sdk/python/sigil/middleware.py
git commit -m "feat: add Flask and FastAPI middleware (Python SDK)"
```

---

## Phase 3: CLI

### Task 16: CLI Project Scaffolding

**Files:**
- Create: `cli/go.mod`
- Create: `cli/cmd/sigil/main.go`

**Step 1: Initialize Go module**

```bash
cd cli
go mod init github.com/sigil-auth/sigil/cli
mkdir -p cmd/sigil internal/enroll internal/auth internal/init
```

**Step 2: Create main.go with command routing**

```go
// cli/cmd/sigil/main.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enroll":
		cmdEnroll()
	case "sign":
		delegateToIdentity("sign", os.Args[2:])
	case "fingerprint":
		delegateToIdentity("fingerprint", nil)
	case "health":
		delegateToIdentity("health", nil)
	case "version":
		fmt.Printf("sigil v%s\n", version)
	case "auth":
		cmdAuth()
	case "init":
		cmdInit()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: sigil <command>

Commands:
  enroll       Enroll this agent with a server
  sign         Sign a challenge
  fingerprint  Show public key fingerprint
  health       Health check
  version      Show version
  auth         Authenticate and get a session token
  init         Initialize Sigil for a server project`)
}

func sigilDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sigil")
}

func identityPath() string {
	return filepath.Join(sigilDir(), "identity")
}

func delegateToIdentity(command string, args []string) {
	path := identityPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "not enrolled — run: sigil enroll --token <token> --server <url>")
		os.Exit(1)
	}

	cmdArgs := append([]string{command}, args...)
	cmd := exec.Command(path, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func cmdEnroll() {
	fmt.Fprintln(os.Stderr, "enroll not yet implemented")
	os.Exit(1)
}

func cmdAuth() {
	fmt.Fprintln(os.Stderr, "auth not yet implemented")
	os.Exit(1)
}

func cmdInit() {
	fmt.Fprintln(os.Stderr, "init not yet implemented")
	os.Exit(1)
}
```

**Step 3: Verify it compiles**

Run: `cd cli && go build -o sigil ./cmd/sigil/ && ./sigil version`
Expected: `sigil v0.1.0`

**Step 4: Commit**

```bash
git add cli/
git commit -m "feat: scaffold CLI with command routing and identity delegation"
```

---

### Task 17: CLI — Enroll Command

**Files:**
- Create: `cli/internal/enroll/enroll.go`
- Modify: `cli/cmd/sigil/main.go` (wire up)

**Step 1: Implement enroll**

```go
// cli/internal/enroll/enroll.go
package enroll

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func Run(token, serverURL string) error {
	sigilDir, err := getSigilDir()
	if err != nil {
		return err
	}

	platform := runtime.GOOS + "-" + runtime.GOARCH

	// POST /sigil/enroll
	body := fmt.Sprintf(`{"platform": %q}`, platform)
	req, err := http.NewRequest("POST", serverURL+"/sigil/enroll", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment failed (%d): %s", resp.StatusCode, string(errBody))
	}

	agentID := resp.Header.Get("X-Agent-ID")
	fingerprint := resp.Header.Get("X-Key-Fingerprint")

	// Save binary
	if err := os.MkdirAll(sigilDir, 0700); err != nil {
		return err
	}

	binaryPath := filepath.Join(sigilDir, "identity")
	binary, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := os.WriteFile(binaryPath, binary, 0700); err != nil {
		return err
	}

	// Verify fingerprint
	out, err := exec.Command(binaryPath, "fingerprint").Output()
	if err != nil {
		os.Remove(binaryPath)
		return fmt.Errorf("fingerprint verification failed: %w", err)
	}
	if string(out) != fingerprint {
		os.Remove(binaryPath)
		return fmt.Errorf("fingerprint mismatch: got %s, expected %s", string(out), fingerprint)
	}

	// Save agent ID
	agentIDPath := filepath.Join(sigilDir, "agent_id")
	if err := os.WriteFile(agentIDPath, []byte(agentID), 0600); err != nil {
		return err
	}

	// Save server URL
	config := map[string]string{"server": serverURL}
	configBytes, _ := json.Marshal(config)
	configPath := filepath.Join(sigilDir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "enrolled successfully\n")
	fmt.Fprintf(os.Stderr, "  agent_id:    %s\n", agentID)
	fmt.Fprintf(os.Stderr, "  fingerprint: %s\n", fingerprint)
	fmt.Print(agentID)

	return nil
}

func getSigilDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".sigil"), nil
}
```

**Step 2: Wire up in main.go**

Replace `cmdEnroll()` to parse `--token` and `--server` flags and call `enroll.Run(token, server)`.

**Step 3: Commit**

```bash
git add cli/
git commit -m "feat: add enroll command to CLI"
```

---

### Task 18: CLI — Auth Command

**Files:**
- Create: `cli/internal/auth/auth.go`
- Modify: `cli/cmd/sigil/main.go` (wire up)

**Step 1: Implement auth convenience wrapper**

```go
// cli/internal/auth/auth.go
package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func Run(serverURL string) error {
	sigilDir, _ := os.UserHomeDir()
	sigilDir = filepath.Join(sigilDir, ".sigil")

	agentIDBytes, err := os.ReadFile(filepath.Join(sigilDir, "agent_id"))
	if err != nil {
		return fmt.Errorf("not enrolled — run: sigil enroll")
	}
	agentID := string(agentIDBytes)

	// If no server URL provided, try config
	if serverURL == "" {
		configBytes, err := os.ReadFile(filepath.Join(sigilDir, "config.json"))
		if err == nil {
			var config map[string]string
			json.Unmarshal(configBytes, &config)
			serverURL = config["server"]
		}
	}
	if serverURL == "" {
		return fmt.Errorf("no server URL — use --server <url> or enroll first")
	}

	// 1. Request challenge
	challengeBody := fmt.Sprintf(`{"agent_id": %q}`, agentID)
	resp, err := http.Post(serverURL+"/sigil/auth/challenge", "application/json", strings.NewReader(challengeBody))
	if err != nil {
		return fmt.Errorf("challenge request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("challenge failed (%d): %s", resp.StatusCode, body)
	}

	var challengeResp struct {
		Challenge string `json:"challenge"`
	}
	json.NewDecoder(resp.Body).Decode(&challengeResp)

	// 2. Sign challenge
	identityPath := filepath.Join(sigilDir, "identity")
	sigBytes, err := exec.Command(identityPath, "sign", challengeResp.Challenge).Output()
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	signature := string(sigBytes)

	// 3. Verify
	verifyBody := fmt.Sprintf(`{"agent_id": %q, "challenge": %q, "signature": %q}`,
		agentID, challengeResp.Challenge, signature)
	resp2, err := http.Post(serverURL+"/sigil/auth/verify", "application/json", strings.NewReader(verifyBody))
	if err != nil {
		return fmt.Errorf("verify request failed: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		body, _ := io.ReadAll(resp2.Body)
		return fmt.Errorf("verify failed (%d): %s", resp2.StatusCode, body)
	}

	var verifyResp struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp2.Body).Decode(&verifyResp)

	// Print JWT to stdout
	fmt.Print(verifyResp.Token)
	return nil
}
```

**Step 2: Wire up and commit**

```bash
git add cli/
git commit -m "feat: add auth convenience command to CLI"
```

---

### Task 19: CLI — Init Command

**Files:**
- Create: `cli/internal/init/init.go`
- Modify: `cli/cmd/sigil/main.go` (wire up)

**Step 1: Implement init with auto-detection**

```go
// cli/internal/init/init.go
package initcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Config struct {
	Builder   string   `json:"builder"`
	Platforms []string `json:"platforms"`
}

func Run() error {
	// Check for local toolchain
	hasGo := commandExists("go")
	hasGarble := commandExists("garble")
	hasUPX := commandExists("upx")

	if hasGo && hasGarble && hasUPX {
		fmt.Fprintln(os.Stderr, "detected local toolchain: go + garble + upx")
		fmt.Fprintln(os.Stderr, "using local builder mode")

		config := Config{
			Builder:   "local",
			Platforms: []string{"linux-amd64", "linux-arm64", "darwin-arm64"},
		}
		return writeConfig(config)
	}

	fmt.Fprintln(os.Stderr, "local toolchain not found")
	if hasGo && !hasGarble {
		fmt.Fprintln(os.Stderr, "  missing: garble (install: go install mvdan.cc/garble@latest)")
	}
	if !hasUPX {
		fmt.Fprintln(os.Stderr, "  missing: upx (install: brew install upx)")
	}

	// Check for Docker
	if commandExists("docker") {
		fmt.Fprintln(os.Stderr, "docker detected — using Docker builder mode")
		fmt.Fprintln(os.Stderr, "pull the builder image: docker pull sigil/builder")

		config := Config{
			Builder:   "http://localhost:8080",
			Platforms: []string{"linux-amd64", "linux-arm64", "darwin-arm64"},
		}
		return writeConfig(config)
	}

	return fmt.Errorf("no builder available — install Go + garble + upx, or install Docker")
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func writeConfig(config Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("sigil.config.json", data, 0644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote sigil.config.json\n")
	return nil
}
```

**Step 2: Wire up and commit**

```bash
git add cli/
git commit -m "feat: add init command with builder auto-detection"
```

---

## Phase 4: Integration Testing

### Task 20: End-to-End Integration Test

**Files:**
- Create: `test/e2e/e2e_test.go`

This test starts the builder HTTP server, starts a Node SDK server, and runs the full flow: create agent → enroll → challenge → sign → verify → get JWT.

**Step 1: Write the test**

This test uses `exec.Command` to start the builder service, a small Node.js script that runs the SDK, and the CLI to enroll and authenticate. It validates:

1. Agent creation returns enrollment token
2. `sigil enroll` downloads binary, verifies fingerprint
3. `sigil auth` completes challenge-response, returns valid JWT
4. The JWT can be verified

**Step 2: Run the test**

Run: `go test ./test/e2e/ -v -timeout 300s`

**Step 3: Commit**

```bash
git add test/
git commit -m "test: add end-to-end integration test"
```

---

## Summary

| Phase | Tasks | Component |
|-------|-------|-----------|
| 1 | 1-7 | Builder + Identity Binary (Go) |
| 2a | 8-12 | Node.js Server SDK (TypeScript) |
| 2b | 13-15 | Python Server SDK |
| 3 | 16-19 | CLI (Go) |
| 4 | 20 | End-to-end integration test |

**Phases 2a and 2b can run in parallel** — they have no dependencies on each other.

**Total: 20 tasks.** Build order enforces that the builder exists before SDKs, and SDKs exist before end-to-end tests.
