package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/sdk/helper/base62"
)

const idLength = 10

func main() {
	rand, err := base62.Random(idLength)
	if err != nil {
		fmt.Printf("failed to generate error ID: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(rand)
}
