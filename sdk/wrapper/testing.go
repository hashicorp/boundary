package wrapper

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
)

// TestWrapper initializes an AEAD wrapping.Wrapper for testing
func TestWrapper(t *testing.T) wrapping.Wrapper {
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper()
	_, err = root.SetConfig(context.Background(), wrapping.WithKeyId(base64.StdEncoding.EncodeToString(rootKey)), aead.WithKey(rootKey))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
