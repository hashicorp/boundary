package target_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialStatic_New(t *testing.T) {
	type args struct {
		targetId string
		credId   string
	}
	tests := []struct {
		name    string
		args    args
		want    *target.CredentialStatic
		wantErr errors.Code
	}{
		{
			name: "no-targetId",
			args: args{
				credId: "cred_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-credId",
			args: args{
				targetId: "targ_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				targetId: "targ_0000000",
				credId:   "cred_0000000",
			},
			want: &target.CredentialStatic{
				CredentialStatic: &store.CredentialStatic{
					TargetId:           "targ_0000000",
					CredentialStaticId: "cred_0000000",
					CredentialPurpose:  string(credential.ApplicationPurpose),
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := target.NewCredentialStatic(tt.args.targetId, tt.args.credId, credential.ApplicationPurpose)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.EqualValues(tt.want, got)
		})
	}
}
