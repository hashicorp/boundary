package handlers

import (
	"testing"

	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
	accountspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/accounts"
	hostspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	targetspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
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
			name:     "password",
			pb:       &accountspb.PasswordAccountAttributes{LoginName: "testun", Password: &wrapperspb.StringValue{Value: "testpw"}},
			wantJson: `{"login_name": "testun", "password": "testpw"}`,
		},
		{
			name:     "tcp",
			pb:       &targetspb.TcpTargetAttributes{DefaultPort: &wrapperspb.UInt32Value{Value: 22}},
			wantJson: `{"default_port": 22}`,
		},
		{
			name:     "host",
			pb:       &hostspb.StaticHostAttributes{Address: &wrapperspb.StringValue{Value: "::1"}},
			wantJson: `{"address": "::1"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := ProtoToStruct(tc.pb)
			require.NoError(t, err)

			wantStruct := &structpb.Struct{}
			require.NoError(t, protojson.Unmarshal([]byte(tc.wantJson), wantStruct))
			assert.Empty(t, cmp.Diff(wantStruct, st, protocmp.Transform()))

			newAttr := tc.pb.ProtoReflect().New().Interface()
			StructToProto(st, newAttr)
			assert.Equal(t, tc.pb, newAttr)
		})
	}
}
