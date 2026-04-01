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
	hasGo := commandExists("go")
	hasGarble := commandExists("garble")
	hasUPX := commandExists("upx")

	if hasGo && hasGarble && hasUPX {
		fmt.Fprintln(os.Stderr, "detected local toolchain: go + garble + upx")
		fmt.Fprintln(os.Stderr, "using local builder mode")
		return writeConfig(Config{
			Builder:   "local",
			Platforms: []string{"linux-amd64", "linux-arm64", "darwin-arm64"},
		})
	}

	fmt.Fprintln(os.Stderr, "local toolchain not found")
	if hasGo && !hasGarble {
		fmt.Fprintln(os.Stderr, "  missing: garble (install: go install mvdan.cc/garble@latest)")
	}
	if !hasUPX {
		fmt.Fprintln(os.Stderr, "  missing: upx (install: brew install upx)")
	}

	if commandExists("docker") {
		fmt.Fprintln(os.Stderr, "docker detected — using Docker builder mode")
		fmt.Fprintln(os.Stderr, "pull the builder image: docker pull sigil/builder")
		return writeConfig(Config{
			Builder:   "http://localhost:8080",
			Platforms: []string{"linux-amd64", "linux-arm64", "darwin-arm64"},
		})
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
	fmt.Fprintln(os.Stderr, "wrote sigil.config.json")
	return nil
}
