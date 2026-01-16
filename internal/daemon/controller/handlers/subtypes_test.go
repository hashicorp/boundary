// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"testing"

	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
	accountspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	authmethodspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	hostspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	targetspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestStructToProtoToStruct(t *testing.T) {
	testCases := []struct {
		name     string
		pb       proto.Message
		wantJson string
	}{
		{
			name:     "password accounts",
			pb:       &accountspb.PasswordAccountAttributes{LoginName: "testun", Password: &wrapperspb.StringValue{Value: "testpw"}},
			wantJson: `{"login_name": "testun", "password": "testpw"}`,
		},
		{
			name:     "password auth-methods",
			pb:       &authmethodspb.PasswordAuthMethodAttributes{MinLoginNameLength: 4, MinPasswordLength: 2},
			wantJson: `{"min_login_name_length": 4, "min_password_length": 2}`,
		},
		{
			name:     "tcp target",
			pb:       &targetspb.TcpTargetAttributes{DefaultPort: &wrapperspb.UInt32Value{Value: 22}, DefaultClientPort: &wrapperspb.UInt32Value{Value: 23}},
			wantJson: `{"default_port": 22, "default_client_port": 23}`,
		},
		{
			name:     "static host",
			pb:       &hostspb.StaticHostAttributes{Address: &wrapperspb.StringValue{Value: "::1"}},
			wantJson: `{"address": "::1"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := ProtoToStruct(context.Background(), tc.pb)
			require.NoError(t, err)

			wantStruct := &structpb.Struct{}
			require.NoError(t, protojson.Unmarshal([]byte(tc.wantJson), wantStruct))
			assert.Empty(t, cmp.Diff(wantStruct, st, protocmp.Transform()))

			newAttr := tc.pb.ProtoReflect().New().Interface()
			require.NoError(t, StructToProto(st, newAttr))
			assert.Equal(t, tc.pb, newAttr)
		})
	}
}
