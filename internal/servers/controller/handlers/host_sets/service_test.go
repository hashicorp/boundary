package host_sets_test

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_sets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDelete(t *testing.T) {
	toMerge := &services.DeleteHostSetRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
		Id:            "4",
	}

	s := host_sets.Service{}
	cases := []struct {
		name    string
		req     *services.DeleteHostSetRequest
		res     *services.DeleteHostSetResponse
		errCode codes.Code
	}{
		{
			name:    "Delete succeeds even for non existing resources",
			req:     &services.DeleteHostSetRequest{Id: "this doesn't exist"},
			res:     &services.DeleteHostSetResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*services.DeleteHostSetRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.DeleteHostSet(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("DeleteHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHostSet(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}
