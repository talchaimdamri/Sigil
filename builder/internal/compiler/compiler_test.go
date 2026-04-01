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
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	platform := runtime.GOOS + "-" + runtime.GOARCH

	outDir := t.TempDir()
	outPath := outDir + "/identity"

	err = Compile(CompileOptions{
		PrivateKeySeed: priv.Seed(),
		PublicKey:      pub,
		Platform:       platform,
		OutputPath:     outPath,
		UseGarble:      false,
		UseUPX:         false,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify binary exists
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
