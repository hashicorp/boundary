package host_catalogs_test

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_catalogs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDelete(t *testing.T) {
	toMerge := &api.DeleteHostCatalogRequest{
		OrgId:     "1",
		ProjectId: "2",
		Id:        "3",
	}

	s := host_catalogs.Service{}
	cases := []struct {
		name    string
		req     *api.DeleteHostCatalogRequest
		res     *api.DeleteHostCatalogResponse
		errCode codes.Code
	}{
		{
			name:    "Delete always succeeds even for non existant catalogs",
			req:     &api.DeleteHostCatalogRequest{Id: "This doesn't exist."},
			res:     &api.DeleteHostCatalogResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*api.DeleteHostCatalogRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.DeleteHostCatalog(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("DeleteHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}
