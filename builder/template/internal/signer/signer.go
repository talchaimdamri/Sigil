// builder/template/internal/signer/signer.go
package signer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"fmt"

	"github.com/sigil-auth/sigil/identity/internal/keys"
)

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
