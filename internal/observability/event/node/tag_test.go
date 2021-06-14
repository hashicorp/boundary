package node

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getClassificationFromTagString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tag  string
		opt  []Option
		want *tagInfo
	}{
		{
			name: "no-tag",
			want: &tagInfo{
				Classification: UnknownClassification,
				Operation:      UnknownOperation,
			},
		},
		{
			name: "public-with-no-operation",
			tag:  string(PublicClassification),
			want: &tagInfo{
				Classification: PublicClassification,
				Operation:      NoOperation,
			},
		},
		{
			name: "public-with-operation",
			tag:  fmt.Sprintf("%s,%s", string(PublicClassification), RedactOperation),
			want: &tagInfo{
				Classification: PublicClassification,
				Operation:      NoOperation,
			},
		},
		{
			name: "public-with-operation-override",
			tag:  fmt.Sprintf("%s,%s", string(PublicClassification), EncryptOperation),
			opt: []Option{withFilterOperations(map[DataClassification]FilterOperation{
				PublicClassification: RedactOperation,
			})},
			want: &tagInfo{
				Classification: PublicClassification,
				Operation:      RedactOperation,
			},
		},
		{
			name: "sensitive-with-no-operation",
			tag:  string(SensitiveClassification),
			want: &tagInfo{
				Classification: SensitiveClassification,
				Operation:      EncryptOperation,
			},
		},
		{
			name: "sensitive-with-operation",
			tag:  fmt.Sprintf("%s,%s", string(SensitiveClassification), RedactOperation),
			want: &tagInfo{
				Classification: SensitiveClassification,
				Operation:      RedactOperation,
			},
		},
		{
			name: "sensitive-with-operation-override",
			tag:  fmt.Sprintf("%s,%s", string(SensitiveClassification), EncryptOperation),
			opt: []Option{withFilterOperations(map[DataClassification]FilterOperation{
				SensitiveClassification: RedactOperation,
			})},
			want: &tagInfo{
				Classification: SensitiveClassification,
				Operation:      RedactOperation,
			},
		},
		{
			name: "sensitive-with-unknown-operation",
			tag:  fmt.Sprintf("%s,%s", string(SensitiveClassification), UnknownOperation),
			want: &tagInfo{
				Classification: SensitiveClassification,
				Operation:      EncryptOperation,
			},
		},
		// -------------
		{
			name: "secret-with-no-operation",
			tag:  string(SecretClassification),
			want: &tagInfo{
				Classification: SecretClassification,
				Operation:      RedactOperation,
			},
		},
		{
			name: "secret-with-operation",
			tag:  fmt.Sprintf("%s,%s", string(SecretClassification), RedactOperation),
			want: &tagInfo{
				Classification: SecretClassification,
				Operation:      RedactOperation,
			},
		},
		{
			name: "secret-with-operation-override",
			tag:  fmt.Sprintf("%s,%s", string(SecretClassification), EncryptOperation),
			opt: []Option{withFilterOperations(map[DataClassification]FilterOperation{
				SecretClassification: RedactOperation,
			})},
			want: &tagInfo{
				Classification: SecretClassification,
				Operation:      RedactOperation,
			},
		},
		{
			name: "secret-with-unknown-operation",
			tag:  fmt.Sprintf("%s,%s", string(SecretClassification), UnknownOperation),
			want: &tagInfo{
				Classification: SecretClassification,
				Operation:      RedactOperation,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := getClassificationFromTagString(tt.tag, tt.opt...)
			assert.Equal(tt.want, got)
		})
	}
}
