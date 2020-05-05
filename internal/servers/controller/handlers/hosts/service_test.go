package hosts_test

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/hosts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDelete(t *testing.T) {
	toMerge := &pbs.DeleteHostRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
		Id:            "4",
	}

	s := hosts.Service{}
	cases := []struct {
		name    string
		req     *pbs.DeleteHostRequest
		res     *pbs.DeleteHostResponse
		errCode codes.Code
	}{
		{
			name:    "Success even when doesn't exist",
			req:     &pbs.DeleteHostRequest{},
			res:     &pbs.DeleteHostResponse{},
			errCode: codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.DeleteHostRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.DeleteHost(context.Background(), req)

			if status.Code(gErr) != tc.errCode {
				t.Errorf("DeleteHost(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}

			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHost(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}

func TestList(t *testing.T) {
	toMerge := &pbs.ListHostsRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
	}

	s := hosts.Service{}
	cases := []struct {
		name    string
		req     *pbs.ListHostsRequest
		res     *pbs.ListHostsResponse
		errCode codes.Code
	}{
		{
			name: "List from a valid catalog id",
			req:  &pbs.ListHostsRequest{},
			// TODO: Update this when the List method is implemented
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Non Existant Host Catalog",
			req:     &pbs.ListHostsRequest{HostCatalogId: "this doesnt exist"},
			res:     nil,
			errCode: codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.ListHostsRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.ListHosts(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("ListHosts(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("ListHosts(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}

func TestGet(t *testing.T) {
	toMerge := &pbs.GetHostRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
	}

	s := hosts.Service{}
	cases := []struct {
		name    string
		req     *pbs.GetHostRequest
		res     *pbs.GetHostResponse
		errCode codes.Code
	}{
		// TODO: These cases need to be updated as the handlers get implemented.
		{
			name:    "Default request",
			req:     &pbs.GetHostRequest{},
			res:     nil,
			errCode: codes.Unimplemented,
		},
		{
			name: "Non Existant Host Catalog",
			req:  &pbs.GetHostRequest{HostCatalogId: "this doesnt exist"},
			// The response and error will need to change when this is implemented to be a 404 error
			res:     nil,
			errCode: codes.Unimplemented,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetHostRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.GetHost(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("ListHosts(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("ListHosts(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	toMerge := &pbs.UpdateHostRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
	}

	s := hosts.Service{}
	cases := []struct {
		name    string
		req     *pbs.UpdateHostRequest
		res     *pbs.UpdateHostResponse
		errCode codes.Code
	}{
		// TODO: These cases need to be updated as the handlers get implemented.
		{
			name:    "Default request",
			req:     &pbs.UpdateHostRequest{},
			res:     nil,
			errCode: codes.Unimplemented,
		},
		{
			name: "Non Existant Host Catalog",
			req:  &pbs.UpdateHostRequest{HostCatalogId: "this doesnt exist"},
			// The response and error will need to change when this is implemented to be a 404 error
			res:     nil,
			errCode: codes.Unimplemented,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.UpdateHostRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.UpdateHost(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("UpdateHost(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("UpdateHost(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}
