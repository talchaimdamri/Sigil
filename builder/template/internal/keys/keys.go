// builder/template/internal/keys/keys.go
package keys

// These variables are replaced at build time by the compiler.
var (
	SIGIL_ENCRYPTED_KEY = []byte("PLACEHOLDER_ENCRYPTED_KEY")
	SIGIL_KEY_NONCE     = []byte("PLACEHOLDER_KEY_NONCE")
	SIGIL_AES_KEY       = []byte("PLACEHOLDER_AES_KEY")
	SIGIL_FINGERPRINT   = "PLACEHOLDER_FINGERPRINT"
	SIGIL_VERSION       = "0.1.0"
	SIGIL_PLATFORM      = "unknown"
)
