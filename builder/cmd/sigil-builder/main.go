package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/sigil-auth/sigil/builder/internal/compiler"
	"github.com/sigil-auth/sigil/builder/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sigil-builder <build|serve>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "build":
		cmdBuild()
	case "serve":
		cmdServe()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func cmdBuild() {
	var privKeyB64, platform, output string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--private-key":
			i++
			if i < len(args) {
				privKeyB64 = args[i]
			}
		case "--platform":
			i++
			if i < len(args) {
				platform = args[i]
			}
		case "--output":
			i++
			if i < len(args) {
				output = args[i]
			}
		}
	}

	if privKeyB64 == "" || platform == "" || output == "" {
		fmt.Fprintln(os.Stderr, "usage: sigil-builder build --private-key <base64> --platform <platform> --output <path>")
		os.Exit(1)
	}

	seed, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid base64 private key: %v\n", err)
		os.Exit(1)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	err = compiler.Compile(compiler.CompileOptions{
		PrivateKeySeed: seed,
		PublicKey:      pub,
		Platform:       platform,
		OutputPath:     output,
		UseGarble:      true,
		UseUPX:         true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "built: %s (%s)\n", output, platform)
	fmt.Print(crypto.Fingerprint(pub))
}

func cmdServe() {
	fmt.Fprintln(os.Stderr, "serve mode not yet implemented")
	os.Exit(1)
}
