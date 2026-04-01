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
	srv := New(Config{UseGarble: false, UseUPX: false})

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
	srv := New(Config{})

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

func TestBuildEndpointInvalidKey(t *testing.T) {
	srv := New(Config{})

	body, _ := json.Marshal(BuildRequest{
		PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 16)), // too short
		Platform:   "linux-amd64",
	})

	req := httptest.NewRequest("POST", "/build", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestBuildEndpointInvalidJSON(t *testing.T) {
	srv := New(Config{})

	req := httptest.NewRequest("POST", "/build", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
