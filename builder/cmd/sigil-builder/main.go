package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/sigil-auth/sigil/builder/internal/compiler"
	"github.com/sigil-auth/sigil/builder/internal/crypto"
	"github.com/sigil-auth/sigil/builder/internal/server"
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
	useGarble := true
	useUPX := true
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
		case "--no-garble":
			useGarble = false
		case "--no-upx":
			useUPX = false
		}
	}

	if privKeyB64 == "" || platform == "" || output == "" {
		fmt.Fprintln(os.Stderr, "usage: sigil-builder build --private-key <base64> --platform <platform> --output <path> [--no-garble] [--no-upx]")
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
		UseGarble:      useGarble,
		UseUPX:         useUPX,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "built: %s (%s)\n", output, platform)
	fmt.Print(crypto.Fingerprint(pub))
}

func cmdServe() {
	port := "8080"
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" {
			i++
			if i < len(args) {
				port = args[i]
			}
		}
	}

	srv := server.New(server.Config{
		UseGarble: true,
		UseUPX:    true,
	})
	fmt.Fprintf(os.Stderr, "sigil-builder serving on :%s\n", port)
	if err := http.ListenAndServe(":"+port, srv); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
