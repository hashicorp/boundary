package controller

import (
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestHandleGrpcGateway(t *testing.T) {
	h := Handler(HandlerProperties{})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Couldn't listen: %v", err)
	}
	defer l.Close()
	go func() {
		http.Serve(l, h)
	}()

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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := fmt.Sprintf("http://%s/%s", l.Addr(), tc.path)
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
