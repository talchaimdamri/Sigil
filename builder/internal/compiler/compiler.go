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

// CompileOptions configures the identity binary compilation.
type CompileOptions struct {
	PrivateKeySeed []byte           // 32-byte Ed25519 seed
	PublicKey      ed25519.PublicKey // 32-byte public key
	Platform       string           // e.g., "linux-amd64"
	OutputPath     string
	UseGarble      bool
	UseUPX         bool
}

// Compile generates a customized identity binary from the template source.
// It encrypts the private key seed with a fresh AES-256-GCM key, writes the
// key material into the template's keys.go, and builds the binary.
func Compile(opts CompileOptions) error {
	parts := strings.SplitN(opts.Platform, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid platform format %q: expected \"os-arch\"", opts.Platform)
	}
	goos, goarch := parts[0], parts[1]

	// 1. Generate AES key and encrypt the private key seed.
	aesKey, err := crypto.GenerateAESKey()
	if err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}

	encrypted, err := crypto.Encrypt(aesKey, opts.PrivateKeySeed)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	// crypto.Encrypt prepends the 12-byte GCM nonce to the ciphertext.
	const nonceSize = 12
	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	fingerprint := crypto.Fingerprint(opts.PublicKey)

	// 2. Copy the template source into a temp directory.
	tmpDir, err := os.MkdirTemp("", "sigil-build-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	templateDir, err := findTemplateDir()
	if err != nil {
		return fmt.Errorf("find template: %w", err)
	}

	if err := copyDir(templateDir, tmpDir); err != nil {
		return fmt.Errorf("copy template: %w", err)
	}

	// 3. Generate keys.go with the real embedded values.
	keysFile := filepath.Join(tmpDir, "internal", "keys", "keys.go")
	keysContent := generateKeysSource(aesKey, nonce, ciphertext, fingerprint, opts.Platform)
	if err := os.WriteFile(keysFile, []byte(keysContent), 0644); err != nil {
		return fmt.Errorf("write keys.go: %w", err)
	}

	// 4. Build the binary.
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

	// 5. Optionally compress with UPX (skip for darwin — crashes on macOS 13+).
	if opts.UseUPX && goos != "darwin" {
		upxCmd := exec.Command("upx", "--best", opts.OutputPath)
		upxCmd.Stderr = os.Stderr
		if err := upxCmd.Run(); err != nil {
			return fmt.Errorf("upx failed: %w", err)
		}
	}

	return nil
}

// generateKeysSource produces the Go source for keys.go with real key material
// embedded as byte slice literals.
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

// byteSliceLiteral converts a byte slice into a Go source literal like
// []byte{0xab, 0xcd, ...}.
func byteSliceLiteral(b []byte) string {
	h := hex.EncodeToString(b)
	parts := make([]string, 0, len(b))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, "0x"+h[i:i+2])
	}
	return "[]byte{" + strings.Join(parts, ", ") + "}"
}

// findTemplateDir locates the template directory relative to this source file.
// The template lives at builder/template/, and this file lives at
// builder/internal/compiler/compiler.go, so the relative path is ../../template.
func findTemplateDir() (string, error) {
	// Primary strategy: locate relative to this source file using runtime.Caller.
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		candidate := filepath.Join(filepath.Dir(thisFile), "..", "..", "template")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return "", fmt.Errorf("abs path: %w", err)
			}
			return abs, nil
		}
	}

	// Fallback: check common relative paths from the working directory.
	fallbacks := []string{
		"template",
		filepath.Join("..", "template"),
		filepath.Join("..", "..", "template"),
		filepath.Join("builder", "template"),
	}
	for _, f := range fallbacks {
		if info, err := os.Stat(f); err == nil && info.IsDir() {
			abs, err := filepath.Abs(f)
			if err != nil {
				return "", fmt.Errorf("abs path: %w", err)
			}
			return abs, nil
		}
	}

	return "", fmt.Errorf("template directory not found; checked runtime.Caller path and working directory fallbacks")
}

// copyDir recursively copies a directory tree from src to dst.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
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
