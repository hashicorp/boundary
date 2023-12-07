// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package target_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddress_New(t *testing.T) {
	type args struct {
		targetId string
		address  string
	}
	tests := []struct {
		name    string
		args    args
		want    *target.Address
		wantErr errors.Code
	}{
		{
			name: "no-target_id",
			args: args{
				address: "0.0.0.0",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-address",
			args: args{
				targetId: "targ_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				targetId: "targ_0000000",
				address:  "0.0.0.0",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "0.0.0.0",
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := target.NewAddress(context.Background(), tt.args.targetId, tt.args.address)
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
