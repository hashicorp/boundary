package handlers

import (
	"testing"

	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	hostpb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
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
			pb:       &authpb.PasswordAccountAttributes{Username: "testun", Password: &wrapperspb.StringValue{Value: "testpw"}},
			wantJson: `{"username": "testun", "password": "testpw"}`,
		},
		{
			name:     "ec2hostcatalog",
			pb:       &hostpb.AwsEc2HostCatalogDetails{Regions: []string{"r1", "r2"}, AccessKey: &wrapperspb.StringValue{Value: "test"}},
			wantJson: `{"regions": ["r1", "r2"], "access_key": "test"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := ProtoToStruct(tc.pb)
			require.NoError(t, err)

			wantStruct := &structpb.Struct{}
			require.NoError(t, protojson.Unmarshal([]byte(tc.wantJson), wantStruct))
			assert.Empty(t, cmp.Diff(wantStruct, st, protocmp.Transform()))

			newPwAttr := tc.pb.ProtoReflect().New().Interface()
			StructToProto(st, newPwAttr)
			assert.Equal(t, tc.pb, newPwAttr)
		})
	}
}
