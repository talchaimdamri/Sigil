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

	// 3. Verify
	verifyBody := fmt.Sprintf(`{"agent_id": %q, "challenge": %q, "signature": %q}`,
		agentID, challengeResp.Challenge, string(sigBytes))
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

	fmt.Print(verifyResp.Token)
	return nil
}
