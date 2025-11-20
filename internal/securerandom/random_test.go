// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: Apache-2.0

package securerandom

import (
	"testing"
)

func TestGetSecureReader(t *testing.T) {
	sr := getSecureReader()
	if sr == nil || sr.Reader == nil {
		t.Fatal("NewSecureRandom returned nil")
	}

	buf := make([]byte, 32)
	n, err := sr.Reader.Read(buf)

	if err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}

	if n != len(buf) {
		t.Fatalf("expected to read %d bytes, got %d", len(buf), n)
	}

}
