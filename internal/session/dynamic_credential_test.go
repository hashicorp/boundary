package session

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicCredential_New(t *testing.T) {
	t.Parallel()

	type args struct {
		sessionId    string
		credentialId string
		library      *target.CredentialLibrary
	}
	tests := []struct {
		name    string
		args    args
		want    *DynamicCredential
		wantErr errors.Code
	}{
		{
			name: "empty-sessionId",
			args: args{
				sessionId: "",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "empty-credentialId",
			args: args{
				sessionId: "abcd_OOOOOOOOOO",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-library",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "empty-library",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library:      &target.CredentialLibrary{},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "library-empty-library-id",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library: &target.CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						CredentialPurpose: "application",
					},
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "library-empty-purpose",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library: &target.CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						CredentialLibraryId: "library_1",
					},
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library: &target.CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						TargetId:            "target_1",
						CredentialLibraryId: "library_1",
						CredentialPurpose:   "application",
					},
				},
			},
			want: &DynamicCredential{
				SessionId:         "abcd_OOOOOOOOOO",
				CredentialId:      "cred_OOOOOOOOOO",
				LibraryId:         "library_1",
				CredentialPurpose: "application",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewDynamicCredential(tt.args.sessionId, tt.args.credentialId, tt.args.library)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}
