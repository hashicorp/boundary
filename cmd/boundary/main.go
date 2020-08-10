package main

import (
	"os"

	"github.com/hashicorp/boundary/internal/cmd"
)

func main() {
	os.Exit(cmd.Run(os.Args[1:]))
}
