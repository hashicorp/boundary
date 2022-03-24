package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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
	specBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to load spec at path %q: %w", path, err)
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(specBytes, &spec); err != nil {
		return fmt.Errorf("failed to unmarshal spec as JSON: %w", err)
	}

	if spec["definitions"] == nil {
		return fmt.Errorf("no definitions found in spec")
	}
	definitions, ok := spec["definitions"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("definitions were unexpected format, expected object, found %T", spec["definitions"])
	}

	for name, definition := range definitions {
		definition, ok := definition.(map[string]interface{})
		if !ok {
			return fmt.Errorf("definition was unexpected format, expected object, found %T", definition)
		}
		switch name {
		case "controller.api.resources.accounts.v1.Account":
			properties, ok := definition["properties"].(map[string]interface{})
			if !ok {
				return fmt.Errorf("properties was unexpected format, expected object, found %T", definition["properties"])
			}
			properties["attributes"] = map[string]interface{}{
				"type":        "object",
				"description": "The attributes that are applicable for the specific Account type.",
			}
		}
	}

	json, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}

	// Overwrite existing json with the updated json spec
	log.Printf("Overwriting spec at %q", path)
	return ioutil.WriteFile(path, json, os.ModePerm)
}
