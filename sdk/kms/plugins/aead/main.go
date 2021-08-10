package main

import aead "github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"

func main() {
	aead.ServePlugin()
}
