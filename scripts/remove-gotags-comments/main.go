// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/boundary/internal/observability/event"
)

var swaggerPath = flag.String("path", "", "The path to the swagger file to parse. Will also be written to")

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
	swaggerBytes, err := os.ReadFile(swaggerPath)
	if err != nil {
		return fmt.Errorf("failed to read swagger file: %w", err)
	}
	for _, classification := range []event.DataClassification{event.PublicClassification, event.SensitiveClassification, event.SecretClassification} {
		// Gotag comments appear both with and without the wrapping "`"
		for _, wrapper := range []string{"", "`"} {
			// The two cases we're covering are:
			//   - When gotags appears on its own.
			//   - When gotags appears at the end of another comment (preceded by \n\n).
			for _, prefix := range []string{"\\n\\n", ""} {
				swaggerBytes = bytes.ReplaceAll(swaggerBytes, []byte(fmt.Sprintf("%s@gotags: %sclass:\\\"%s\\\"%s", prefix, wrapper, classification, wrapper)), nil)
			}
		}
	}
	// Some fields have a comment explaining that their classification is manually managed
	swaggerBytes = bytes.ReplaceAll(swaggerBytes, []byte("\\n\\nclassified as public via taggable implementation"), nil)
	if err := os.WriteFile(swaggerPath, swaggerBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write new swagger file: %w", err)
	}
	return nil
}
