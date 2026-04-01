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
	if err := os.WriteFile(filepath.Join(sigilDir, "agent_id"), []byte(agentID), 0600); err != nil {
		return err
	}

	// Save server URL in config
	config := map[string]string{"server": serverURL}
	configBytes, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(sigilDir, "config.json"), configBytes, 0600); err != nil {
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
