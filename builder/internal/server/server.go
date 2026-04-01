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
	"linux-amd64":   true,
	"linux-arm64":   true,
	"darwin-amd64":  true,
	"darwin-arm64":  true,
	"windows-amd64": true,
}

// BuildRequest is the JSON body for POST /build.
type BuildRequest struct {
	PrivateKey string `json:"private_key"` // base64-encoded 32-byte Ed25519 seed
	Platform   string `json:"platform"`
}

// ErrorResponse is the JSON body returned on errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Config controls optional build behavior.
type Config struct {
	UseGarble bool
	UseUPX    bool
}

// Server holds the HTTP handler and build configuration.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

// New creates a Server with the given configuration and returns its http.Handler.
func New(cfg Config) http.Handler {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /build", s.handleBuild)
	return s.mux
}

func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
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
		UseGarble:      s.cfg.UseGarble,
		UseUPX:         s.cfg.UseUPX,
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
	fmt.Fprintf(w, `{"error":%q}`, code)
}
