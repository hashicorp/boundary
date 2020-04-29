package hosts

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
)

func TestDelete(t *testing.T) {
	toMerge := &api.DeleteHostRequest{
		Org:           "1",
		ProjectId:     "2",
		HostCatalogId: "3",
		Id:            "4",
	}

	s := Service{}
	cases := []struct {
		name string
		req  *api.DeleteHostRequest
		res  *api.DeleteHostResponse
		wErr error
	}{
		{
			name: "Default request",
			req:  &api.DeleteHostRequest{},
			res:  &api.DeleteHostResponse{},
			wErr: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*api.DeleteHostRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.DeleteHost(context.Background(), req)
			if gErr != tc.wErr {
				t.Errorf("DeleteHost(%+v) got error %v, wanted %v", req, gErr, tc.wErr)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHost(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}
