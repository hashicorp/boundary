// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialLibrary_New(t *testing.T) {
	type args struct {
		targetId  string
		libraryId string
	}
	tests := []struct {
		name    string
		args    args
		want    *target.CredentialLibrary
		wantErr errors.Code
	}{
		{
			name: "no-targetId",
			args: args{
				libraryId: "lib_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-libraryId",
			args: args{
				targetId: "targ_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				targetId:  "targ_0000000",
				libraryId: "lib_0000000",
			},
			want: &target.CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					TargetId:            "targ_0000000",
					CredentialLibraryId: "lib_0000000",
					CredentialPurpose:   string(credential.BrokeredPurpose),
				},
				CredentialType: "test",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := target.NewCredentialLibrary(context.Background(), tt.args.targetId, tt.args.libraryId, credential.BrokeredPurpose, "test")
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
