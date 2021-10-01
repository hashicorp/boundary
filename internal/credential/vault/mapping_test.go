package vault

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertPrivateId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PrivateId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PrivateId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestNewMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		libraryId   string
		mapping     credential.Mapping
		want        Mapping
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-library-id",
			libraryId:   "",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-mapping-id",
			libraryId:   "lId",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "user-pass-missing-username",
			libraryId: "lId",
			mapping: credential.UserPasswordMapping{
				Username: "",
				Password: "pass",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:      "user-pass-missing-password",
			libraryId: "lId",
			mapping: credential.UserPasswordMapping{
				Username: "user",
				Password: "",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "invalid-mapping-type",
			libraryId:   "lId",
			mapping:     "invalid",
			wantErr:     true,
			wantErrCode: errors.InvalidMapping,
		},
		{
			name:      "valid-user-pass",
			libraryId: "lId",
			mapping: credential.UserPasswordMapping{
				Username: "user",
				Password: "pass",
			},
			want: &UserPasswordMap{
				UserPasswordMap: &store.UserPasswordMap{
					UsernameAttribute: "user",
					PasswordAttribute: "pass",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			got, err := newMapping(ctx, tt.mapping, tt.libraryId)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			switch m := got.(type) {
			case *UserPasswordMap:
				m1, ok := tt.want.(*UserPasswordMap)
				require.True(ok)
				assert.Equal(m1.UsernameAttribute, m.UsernameAttribute)
				assert.Equal(m1.PasswordAttribute, m.PasswordAttribute)
				assertPrivateId(t, usernamePasswordMapPrefix, m.GetPrivateId())
			default:
				t.Fatal("unsupported mapping type")
			}
		})
	}
}
