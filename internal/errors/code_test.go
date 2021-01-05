package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCode_Both_String_Info(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    Code
		want Code
	}{
		{
			name: "undefined-code",
			c:    Code(4294967295),
			want: Unknown,
		},
		{
			name: "default-value",
			want: Unknown,
		},
		{
			name: "Unknown",
			c:    Unknown,
			want: Unknown,
		},
		{
			name: "InvalidParameter",
			c:    InvalidParameter,
			want: InvalidParameter,
		},
		{
			name: "InvalidAddress",
			c:    InvalidAddress,
			want: InvalidAddress,
		},
		{
			name: "InvalidPublicId",
			c:    InvalidPublicId,
			want: InvalidPublicId,
		},
		{
			name: "InvalidFieldMask",
			c:    InvalidFieldMask,
			want: InvalidFieldMask,
		},
		{
			name: "EmptyFieldMask",
			c:    EmptyFieldMask,
			want: EmptyFieldMask,
		},
		{
			name: "PasswordTooShort",
			c:    PasswordTooShort,
			want: PasswordTooShort,
		},
		{
			name: "PasswordUnsupportedConfiguration",
			c:    PasswordUnsupportedConfiguration,
			want: PasswordUnsupportedConfiguration,
		},
		{
			name: "PasswordInvalidConfiguration",
			c:    PasswordInvalidConfiguration,
			want: PasswordInvalidConfiguration,
		},
		{
			name: "PasswordsEqual",
			c:    PasswordsEqual,
			want: PasswordsEqual,
		},
		{
			name: "Encrypt",
			c:    Encrypt,
			want: Encrypt,
		},
		{
			name: "Decrypt",
			c:    Decrypt,
			want: Decrypt,
		},
		{
			name: "CheckConstraint",
			c:    CheckConstraint,
			want: CheckConstraint,
		},
		{
			name: "NotNull",
			c:    NotNull,
			want: NotNull,
		},
		{
			name: "NotUnique",
			c:    NotUnique,
			want: NotUnique,
		},
		{
			name: "RecordNotFound",
			c:    RecordNotFound,
			want: RecordNotFound,
		},
		{
			name: "ColumnNotFound",
			c:    ColumnNotFound,
			want: ColumnNotFound,
		},
		{
			name: "MaxRetries",
			c:    MaxRetries,
			want: MaxRetries,
		},
		{
			name: "Exception",
			c:    Exception,
			want: Exception,
		},
		{
			name: "MultipleRecords",
			c:    MultipleRecords,
			want: MultipleRecords,
		},
		{
			name: "NotSpecificIntegrity",
			c:    NotSpecificIntegrity,
			want: NotSpecificIntegrity,
		},
		{
			name: "MissingTable",
			c:    MissingTable,
			want: MissingTable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(errorCodeInfo[tt.want], tt.c.Info())
			assert.Equal(errorCodeInfo[tt.want].Message, tt.c.String())

		})
	}
}
