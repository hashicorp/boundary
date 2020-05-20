package controller

import (
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestHandleGrpcGateway(t *testing.T) {
	var c Controller
	h := c.handler(HandlerProperties{})
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
		{
			"Unimplemented path",
			"v1/orgs/1/projects/2/host-catalogs/3/host-sets/4",
			http.StatusNotImplemented,
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

func TestHandler_cors(t *testing.T) {
	core, _, _ := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	// Enable CORS and allow from any origin for testing.
	corsConfig := core.CORSConfig()
	err := corsConfig.Enable(context.Background(), []string{addr}, nil)
	if err != nil {
		t.Fatalf("Error enabling CORS: %s", err)
	}

	req, err := http.NewRequest(http.MethodOptions, addr+"/v1/sys/seal-status", nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	req.Header.Set("Origin", "BAD ORIGIN")

	// Requests from unacceptable origins will be rejected with a 403.
	client := cleanhttp.DefaultClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Bad status:\nexpected: 403 Forbidden\nactual: %s", resp.Status)
	}

	//
	// Test preflight requests
	//

	// Set a valid origin
	req.Header.Set("Origin", addr)

	// Server should NOT accept arbitrary methods.
	req.Header.Set("Access-Control-Request-Method", "FOO")

	client = cleanhttp.DefaultClient()
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Fail if an arbitrary method is accepted.
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("Bad status:\nexpected: 405 Method Not Allowed\nactual: %s", resp.Status)
	}

	// Server SHOULD accept acceptable methods.
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)

	client = cleanhttp.DefaultClient()
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	//
	// Test that the CORS headers are applied correctly.
	//
	expHeaders := map[string]string{
		"Access-Control-Allow-Origin":  addr,
		"Access-Control-Allow-Headers": strings.Join(vault.StdAllowedHeaders, ","),
		"Access-Control-Max-Age":       "300",
		"Vary":                         "Origin",
	}

	for expHeader, expected := range expHeaders {
		actual := resp.Header.Get(expHeader)
		if actual == "" {
			t.Fatalf("bad:\nHeader: %#v was not on response.", expHeader)
		}

		if actual != expected {
			t.Fatalf("bad:\nExpected: %#v\nActual: %#v\n", expected, actual)
		}
	}
}
