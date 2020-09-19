package main

import (
	"math/rand"
	"os"
	"time"

	"github.com/hashicorp/boundary/internal/cmd"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	os.Exit(cmd.Run(os.Args[1:]))
}
