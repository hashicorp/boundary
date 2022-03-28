// Adds an "attributes" field to the OpenAPIv2 message definition of any protobuf message
// that defines a "oneof" field named "attrs".
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-openapi/loads"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: addattributes <openapiv2 spec path>")
	}
	path := os.Args[1]
	if err := mutateSpec(path); err != nil {
		log.Fatal("failed to add attributes: ", err)
	}
}

func mutateSpec(path string) error {
	doc, err := loads.JSONSpec(path)
	if err != nil {
		return fmt.Errorf("failed to load spec at path %q: %w", path, err)
	}
	openapiSpec := doc.Spec()
	if err := AddAttributes(doc.Spec()); err != nil {
		return err
	}
	json, err := json.MarshalIndent(openapiSpec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}
	return ioutil.WriteFile(path, json, os.ModePerm)
}
