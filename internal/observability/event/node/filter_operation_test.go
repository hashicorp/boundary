package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_convertToOperation(t *testing.T) {

	tests := []struct {
		name string
		seg  string
		want FilterOperation
	}{
		{
			name: "NoOperation",
			seg:  "",
			want: NoOperation,
		},
		{
			name: "UnknownOperation",
			seg:  "unknown",
			want: UnknownOperation,
		},
		{
			name: "RedactOperation",
			seg:  "redact",
			want: RedactOperation,
		},
		{
			name: "EncryptOperation",
			seg:  "encrypt",
			want: EncryptOperation,
		},
		{
			name: "HmacSha256Operation",
			seg:  "hmac-sha256",
			want: HmacSha256Operation,
		},
		{
			name: "default-UnknownOperation",
			seg:  "doesn't matter what you put here",
			want: UnknownOperation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := convertToOperation(tt.seg)
			assert.Equal(tt.want, got)
		})
	}
}
