// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package subtypes_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/stretchr/testify/assert"
)

func TestSubtypeFromId(t *testing.T) {
	testSubtype := globals.Subtype("test")
	r := subtypes.NewRegistry()
	r.Register(context.Background(), testSubtype, "tttst")
	tests := []struct {
		name  string
		given string
		want  globals.Subtype
	}{
		{"empty-string", "", globals.UnknownSubtype},
		{"no-prefix-delimiter", "tttst1234", globals.UnknownSubtype},
		{"prefix-first", "_tttst_1234", globals.UnknownSubtype},
		{"unknown-prefix", "kaz_1234", globals.UnknownSubtype},
		{"prefix-no-id", "tttst_", testSubtype},
		{"vault-prefix", "tttst_1234", testSubtype},
		{"prefix-no-delimiter-no-id", "tttst", globals.UnknownSubtype},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := r.SubtypeFromId(tt.given)
			assert.Equalf(t, tt.want, got, "given: %s", tt.given)
			if got != tt.want {
				t.Errorf("(%s): expected %s, actual %s", tt.given, tt.want, got)
			}
		})
	}
}

func TestSubtypeFromType(t *testing.T) {
	testSubtype := globals.Subtype("test")
	r := subtypes.NewRegistry()
	r.Register(context.Background(), testSubtype, "tttst")
	tests := []struct {
		name  string
		given string
		want  globals.Subtype
	}{
		{"empty-string", "", globals.UnknownSubtype},
		{"correct-string", "test", testSubtype},
		{"captialized", "TEST", globals.UnknownSubtype},
		{"typo", "testt", globals.UnknownSubtype},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := r.SubtypeFromType(tt.given)
			assert.Equalf(t, tt.want, got, "given: %s", tt.given)
			if got != tt.want {
				t.Errorf("(%s): expected %s, actual %s", tt.given, tt.want, got)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	r := subtypes.NewRegistry()
	ctx := context.Background()
	assert.NoError(t, r.Register(ctx, "test", "testprefix"))
	// registering multiple subtypes should be fine.
	assert.NoError(t, r.Register(ctx, "second", "secondprefix"))
	// registering another prefix with a different subtype errors.
	assert.Error(t, r.Register(ctx, "third", "testprefix"))
	// Registering the same subtype twice errors.
	assert.Error(t, r.Register(ctx, "test", "repeatedprefix"))
}
