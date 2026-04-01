// builder/template/cmd/identity/main.go
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/sigil-auth/sigil/identity/internal/keys"
	"github.com/sigil-auth/sigil/identity/internal/signer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: identity <sign|fingerprint|health|version>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sign":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: identity sign <base64_challenge>")
			os.Exit(1)
		}
		challenge, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid base64 challenge")
			os.Exit(1)
		}
		sig, err := signer.Sign(challenge)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(base64.StdEncoding.EncodeToString(sig))

	case "fingerprint":
		fmt.Print(keys.SIGIL_FINGERPRINT)

	case "health":
		fmt.Print("OK")

	case "version":
		fmt.Printf("sigil v%s (%s)", keys.SIGIL_VERSION, keys.SIGIL_PLATFORM)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
