package main

import (
	"os"

	"github.com/tamcore/go-autobump/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
