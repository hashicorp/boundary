package host_catalogs

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
)

func TestDelete(t *testing.T) {
	toMerge := &api.DeleteHostCatalogRequest{
		Org:       "1",
		ProjectId: "2",
		Id:        "3",
	}

	s := Service{}
	cases := []struct {
		name string
		req  *api.DeleteHostCatalogRequest
		res  *api.DeleteHostCatalogResponse
		wErr error
	}{
		{
			name: "Default request",
			req:  &api.DeleteHostCatalogRequest{},
			res:  &api.DeleteHostCatalogResponse{},
			wErr: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*api.DeleteHostCatalogRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.DeleteHostCatalog(context.Background(), req)
			if gErr != tc.wErr {
				t.Errorf("DeleteHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.wErr)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}
