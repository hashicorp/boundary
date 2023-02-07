// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
)

// TestWrapper initializes an AEAD wrapping.Wrapper for testing
func TestWrapper(t testing.TB) wrapping.Wrapper {
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper()
	_, err = root.SetConfig(
		context.Background(),
		wrapping.WithKeyId(base64.StdEncoding.EncodeToString(rootKey)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.SetAesGcmKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root
}
