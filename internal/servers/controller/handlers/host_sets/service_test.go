package host_sets

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
)

func TestDelete(t *testing.T) {
	toMerge := &api.DeleteHostSetRequest{
		Org:           "1",
		ProjectId:     "2",
		HostCatalogId: "3",
		Id:            "4",
	}

	s := Service{}
	cases := []struct {
		name string
		req  *api.DeleteHostSetRequest
		res  *api.DeleteHostSetResponse
		wErr error
	}{
		{
			name: "Default request",
			req:  &api.DeleteHostSetRequest{},
			res:  &api.DeleteHostSetResponse{},
			wErr: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*api.DeleteHostSetRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.DeleteHostSet(context.Background(), req)
			if gErr != tc.wErr {
				t.Errorf("DeleteHostSet(%+v) got error %v, wanted %v", req, gErr, tc.wErr)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHostSet(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}
