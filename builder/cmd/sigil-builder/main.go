package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sigil-builder <build|serve>")
		os.Exit(1)
	}
	fmt.Println("sigil-builder", os.Args[1])
}
