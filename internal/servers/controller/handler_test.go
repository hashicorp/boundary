package controller

import (
	"fmt"
	"net/http"
	"testing"
)

func TestHandleGrpcGateway(t *testing.T) {
	c := NewTestController(t, nil)
	defer c.Shutdown()

	cases := []struct {
		name string
		path string
		code int
	}{
		{
			"Non existent path",
			"v1/this-is-made-up",
			http.StatusNotFound,
		},
		{
			"Unimplemented path",
			"v1/orgs/1/projects/2/host-catalogs/3/host-sets/4",
			http.StatusMethodNotAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], tc.path)
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("Got error: %v when non was expected.", err)
			}
			if got, want := resp.StatusCode, tc.code; got != want {
				t.Errorf("GET on %q got code %d, wanted %d", tc.path, got, want)
			}
		})
	}
}
