// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1
//
// Post-processes the generated OpenAPI v2 spec to remove the default 200
// response from delete operations and ensure only 204 is advertised.
//
// Background: protoc-gen-openapiv2 always emits a default 200 response
// based on the RPC return type. There is no annotation-level way to suppress
// it for specific operations. This script runs after buf generate and
// performs the targeted fix.
//
// The file is edited at the byte level (rather than parsed and re-serialised)
// to avoid any key-ordering or escaping differences introduced by
// encoding/json, which would produce large spurious diffs.
//
// Usage:
//
//	go run ./scripts/fix-delete-responses/ -path ./internal/gen/controller.swagger.json

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
)

var swaggerPath = flag.String("path", "", "The path to the swagger file to parse. Will also be written to")

// deleteResponseBlock matches the auto-generated 200 block that
// protoc-gen-openapiv2 emits for delete RPCs, e.g.:
//
//	"200": {
//	  "description": "A successful response.",
//	  "schema": {
//	    "$ref": "#/definitions/controller.api.services.v1.Delete<X>Response"
//	  }
//	},
//
// The trailing comma+newline are included so the preceding entry ("204": {...})
// is left with clean JSON.
var deleteResponseBlock = regexp.MustCompile(
	`\s+"200": \{\s+"description": "A successful response\.",\s+"schema": \{\s+"\$ref": "#/definitions/[^"]+Delete[^"]+Response"\s+\}\s+\},`,
)

func main() {
	flag.Parse()

	if err := run(*swaggerPath); err != nil {
		log.Fatal(err)
	}
}

func run(swaggerPath string) error {
	if swaggerPath == "" {
		return errors.New("swagger file path is required")
	}

	data, err := os.ReadFile(swaggerPath)
	if err != nil {
		return fmt.Errorf("failed to read swagger file: %w", err)
	}

	// Parse just enough to find which paths have delete operations with a 200,
	// so we can report them. The actual removal is done on raw bytes.
	var spec map[string]any
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("failed to parse swagger file: %w", err)
	}

	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		return errors.New("swagger spec missing 'paths' object")
	}

	fixed := 0
	for path, methods := range paths {
		methodMap, ok := methods.(map[string]any)
		if !ok {
			continue
		}
		deleteOp, ok := methodMap["delete"].(map[string]any)
		if !ok {
			continue
		}
		responses, ok := deleteOp["responses"].(map[string]any)
		if !ok {
			continue
		}
		_, has200 := responses["200"]
		_, has204 := responses["204"]
		switch {
		case has200 && has204:
			fixed++
			fmt.Printf("  Fixed: DELETE %s  (removed 200, kept 204)\n", path)
		case has200 && !has204:
			fmt.Printf("  WARNING: DELETE %s has 200 but no 204 — skipping (check proto annotation)\n", path)
		case !has200 && has204:
			fmt.Printf("  OK:    DELETE %s  (204 already correct)\n", path)
		}
	}

	// Remove the 200 blocks from the raw bytes so key order and escaping are
	// preserved exactly as buf generate wrote them.
	out := deleteResponseBlock.ReplaceAll(data, nil)

	if err := os.WriteFile(swaggerPath, out, 0o644); err != nil {
		return fmt.Errorf("failed to write swagger file: %w", err)
	}

	fmt.Printf("\nDone. Fixed %d delete operation(s) in %s\n", fixed, swaggerPath)
	return nil
}
