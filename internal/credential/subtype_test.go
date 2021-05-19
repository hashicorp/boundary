package credential_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/stretchr/testify/assert"
)

func TestSubtypeFromId(t *testing.T) {
	credential.Register(credential.VaultSubtype, "csvlt")
	tests := []struct {
		name  string
		given string
		want  credential.Subtype
	}{
		{"empty-string", "", credential.UnknownSubtype},
		{"no-prefix-delimiter", "csvlt1234", credential.UnknownSubtype},
		{"prefix-first", "_csvlt_1234", credential.UnknownSubtype},
		{"unknown-prefix", "kaz_1234", credential.UnknownSubtype},
		{"prefix-no-id", "csvlt_", credential.VaultSubtype},
		{"vault-prefix", "csvlt_1234", credential.VaultSubtype},
		{"prefix-no-delimiter-no-id", "csvlt", credential.UnknownSubtype},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := credential.SubtypeFromId(tt.given)
			assert.Equalf(t, tt.want, got, "given: %s", tt.given)
			if got != tt.want {
				t.Errorf("(%s): expected %s, actual %s", tt.given, tt.want, got)
			}
		})
	}
}
