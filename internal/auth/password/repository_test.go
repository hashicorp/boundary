package password

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_Builder(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	tests := []struct {
		name       string
		builder	       *Builder
		want       *Repository
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "valid global key id",
			builder: (&Builder{}).ReadWriter(rw).Kms(kmsCache).KeyId(scope.Global.String()),
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				keyId: scope.Global.String(),
				defaultLimit: db.DefaultLimit,
			},
		},
		{
			name: "valid with limit",
			builder: (&Builder{}).ReadWriter(rw).Kms(kmsCache).KeyId(scope.Global.String()).DefaultLimit(5),
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				keyId: scope.Global.String(),
				defaultLimit: 5,
			},
		},
		{
			name: "nil-reader",
			builder: (&Builder{}).Writer(rw).Kms(kmsCache).KeyId(scope.Global.String()),
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Builder).Build: missing db.Reader: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			builder: (&Builder{}).Reader(rw).Kms(kmsCache).KeyId(scope.Global.String()),
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Builder).Build: missing db.Writer: parameter violation: error #100",
		},
		{
			name: "nil-wrapper",
			builder: (&Builder{}).ReadWriter(rw).KeyId(scope.Global.String()),
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Builder).Build: missing kms: parameter violation: error #100",
		},
		{
			name: "empty key id",
			builder: (&Builder{}).ReadWriter(rw).Kms(kmsCache),
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Builder).Build: unrecognized kms key id: parameter violation: error #100",
		},
		{
			name: "all-nils",
			builder: &Builder{},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Builder).Build: missing db.Reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tt.builder.Build()
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

// TODO(toddknight): Test LookupScopeIdForResource
