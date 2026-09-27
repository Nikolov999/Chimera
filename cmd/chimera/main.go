package main

import (
	"fmt"
	"os"

	"github.com/Nikolov999/chimera/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "chimera:", err)
		os.Exit(1)
	}
}
