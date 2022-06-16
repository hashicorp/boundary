package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/stretchr/testify/assert"
)

type unknownMapper int

func (u unknownMapper) clone() MappingOverride { return u }
func (u unknownMapper) setLibraryId(_ string)  {}
func (u unknownMapper) sanitize()              {}

var _ MappingOverride = unknownMapper(0)

func TestValidMappingOverrides(t *testing.T) {
	tests := []struct {
		m    MappingOverride
		ct   credential.Type
		want bool
	}{
		{
			m:    nil,
			ct:   "invalid",
			want: true,
		},
		{
			m:    nil,
			ct:   credential.UnspecifiedType,
			want: true,
		},
		{
			m:    nil,
			ct:   credential.UsernamePasswordType,
			want: true,
		},
		{
			m:    unknownMapper(1),
			ct:   credential.UnspecifiedType,
			want: false,
		},
		{
			m:    unknownMapper(1),
			ct:   credential.UsernamePasswordType,
			want: false,
		},
		{
			m:    allocUserPasswordOverride(),
			ct:   credential.UnspecifiedType,
			want: false,
		},
		{
			m:    allocUserPasswordOverride(),
			ct:   credential.UsernamePasswordType,
			want: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("%T-%s", tt.m, tt.ct), func(t *testing.T) {
			got := validMappingOverride(tt.m, tt.ct)
			assert.Equal(t, tt.want, got)
		})
	}
}
