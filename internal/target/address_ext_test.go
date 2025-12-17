// Copyright IBM Corp. 2020, 2025
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
			name: "invalid-address-1",
			args: args{
				address:  "-invalid.address",
				targetId: "targ_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-address-2",
			args: args{
				address:  "invalid.1234",
				targetId: "targ_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-address-3",
			args: args{
				address:  "invalid_address",
				targetId: "targ_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-address-4",
			args: args{
				address:  "toolonglabeltoolonglabeltoolonglabeltoolonglabeltoolonglabeltoolonglabeltoolong.co",
				targetId: "targ_0000000",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid-dns-1",
			args: args{
				targetId: "targ_0000000",
				address:  "valid.",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "valid.",
				},
			},
		},
		{
			name: "valid-dns-2",
			args: args{
				targetId: "targ_0000000",
				address:  "valid.address",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "valid.address",
				},
			},
		},
		{
			name: "valid-dns-3",
			args: args{
				targetId: "targ_0000000",
				address:  "valid-address",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "valid-address",
				},
			},
		},
		{
			name: "valid-dns-4",
			args: args{
				targetId: "targ_0000000",
				address:  "123-valid",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "123-valid",
				},
			},
		},
		{
			name: "valid-dns-5",
			args: args{
				targetId: "targ_0000000",
				address:  "xn--d1acufc.xn--p1ai",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "xn--d1acufc.xn--p1ai",
				},
			},
		},
		{
			name: "valid-ipv4",
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
		{
			name: "valid-ipv4-port",
			args: args{
				targetId: "targ_0000000",
				address:  "0.0.0.0:35",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "0.0.0.0:35",
				},
			},
		},
		{
			name: "valid-ipv6",
			args: args{
				targetId: "targ_0000000",
				address:  "0::0",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "0::0",
				},
			},
		},
		{
			name: "valid-ipv6-port",
			args: args{
				targetId: "targ_0000000",
				address:  "0::0:45",
			},
			want: &target.Address{
				TargetAddress: &store.TargetAddress{
					TargetId: "targ_0000000",
					Address:  "0::0:45",
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
