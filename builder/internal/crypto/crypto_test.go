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
	if len(fp) != 7+64 {
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
	if Verify(pub, []byte("tampered"), sig) {
		t.Fatal("tampered message should not verify")
	}
}
