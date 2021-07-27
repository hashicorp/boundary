package subtypes_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/stretchr/testify/assert"
)

func TestSubtypeFromId(t *testing.T) {
	testSubtype := subtypes.Subtype("test")
	r := subtypes.NewRegistry()
	r.Register(testSubtype, "tttst")
	tests := []struct {
		name  string
		given string
		want  subtypes.Subtype
	}{
		{"empty-string", "", subtypes.UnknownSubtype},
		{"no-prefix-delimiter", "tttst1234", subtypes.UnknownSubtype},
		{"prefix-first", "_tttst_1234", subtypes.UnknownSubtype},
		{"unknown-prefix", "kaz_1234", subtypes.UnknownSubtype},
		{"prefix-no-id", "tttst_", testSubtype},
		{"vault-prefix", "tttst_1234", testSubtype},
		{"prefix-no-delimiter-no-id", "tttst", subtypes.UnknownSubtype},
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
	testSubtype := subtypes.Subtype("test")
	r := subtypes.NewRegistry()
	r.Register(testSubtype, "tttst")
	tests := []struct {
		name  string
		given string
		want  subtypes.Subtype
	}{
		{"empty-string", "", subtypes.UnknownSubtype},
		{"correct-string", "test", testSubtype},
		{"captialized", "TEST", subtypes.UnknownSubtype},
		{"typo", "testt", subtypes.UnknownSubtype},
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
	assert.NoError(t, r.Register("test", "testprefix"))
	// registering multiple subtypes should be fine.
	assert.NoError(t, r.Register("second", "secondprefix"))
	// registering another prefix with a different subtype errors.
	assert.Error(t, r.Register("third", "testprefix"))
	// Registering the same subtype twice errors.
	assert.Error(t, r.Register("test", "repeatedprefix"))
}
