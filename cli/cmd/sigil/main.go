package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enroll":
		cmdEnroll()
	case "sign":
		delegateToIdentity("sign", os.Args[2:])
	case "fingerprint":
		delegateToIdentity("fingerprint", nil)
	case "health":
		delegateToIdentity("health", nil)
	case "version":
		fmt.Printf("sigil v%s\n", version)
	case "auth":
		cmdAuth()
	case "init":
		cmdInit()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: sigil <command>

Commands:
  enroll       Enroll this agent with a server
  sign         Sign a challenge
  fingerprint  Show public key fingerprint
  health       Health check
  version      Show version
  auth         Authenticate and get a session token
  init         Initialize Sigil for a server project`)
}

func sigilDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sigil")
}

func identityPath() string {
	return filepath.Join(sigilDir(), "identity")
}

func delegateToIdentity(command string, args []string) {
	path := identityPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "not enrolled — run: sigil enroll --token <token> --server <url>")
		os.Exit(1)
	}

	cmdArgs := append([]string{command}, args...)
	cmd := exec.Command(path, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func cmdEnroll() {
	fmt.Fprintln(os.Stderr, "enroll not yet implemented")
	os.Exit(1)
}

func cmdAuth() {
	fmt.Fprintln(os.Stderr, "auth not yet implemented")
	os.Exit(1)
}

func cmdInit() {
	fmt.Fprintln(os.Stderr, "init not yet implemented")
	os.Exit(1)
}
