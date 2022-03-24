package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: addattributes <openapiv2 spec path>")
	}

	path := os.Args[1]
	if err := addAttributes(path); err != nil {
		log.Fatal("failed to add attributes: ", err)
	}
}

func addAttributes(path string) error {
	log.Printf("Loading spec at %q", path)
	doc, err := loads.JSONSpec(path)
	if err != nil {
		return fmt.Errorf("failed to load spec at path %q: %w", path, err)
	}

	openapiSpec := doc.Spec()

	for name, definition := range openapiSpec.Definitions {
		switch name {
		case "controller.api.resources.accounts.v1.Account":
			attributesSchema := spec.Schema{}
			attributesSchema.Type = spec.StringOrArray{"object"}
			attributesSchema.Description = "The attributes that are applicable for the specific Account type."
			definition.Properties["attributes"] = attributesSchema
		}
	}

	json, err := json.MarshalIndent(openapiSpec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}

	// Overwrite existing json with the updated json spec
	log.Printf("Overwriting spec at %q", path)
	return ioutil.WriteFile(path, json, os.ModePerm)
}
