package handlers

import (
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestFilter(t *testing.T) {
	marsh := filterMashaler{&runtime.HTTPBodyMarshaler{
		Marshaler: &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				// Ensures the json marshaler uses the snake casing as defined in the proto field names.
				UseProtoNames: true,
				// Do not add fields set to zero value to json.
				EmitUnpopulated: false,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				// Allows requests to contain unknown fields.
				DiscardUnknown: true,
			},
		},
	}}

	lgr := &pbs.ListGroupsResponse{
		Items: []*pb.Group{
			{Name: &wrapperspb.StringValue{Value: "test1"}},
			{Name: &wrapperspb.StringValue{Value: "test2"}},
			{Name: &wrapperspb.StringValue{Value: "test3"}},
			{Name: &wrapperspb.StringValue{Value: "test4"}},
		},
		RequestedFilter: `"/name"=="test2"`,
	}

	b, err := marsh.Marshal(lgr)
	require.NoError(t, err)
	assert.EqualValues(t, `{"items":[{"name":"test2"}]}`, string(b))
}
