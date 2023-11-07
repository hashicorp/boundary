package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
)

const hostHeader = "api.boundary.localhost"

type Client struct {
	client       *retryablehttp.Client
	unixHostPath string
}

// New returns a client which will always send requests over the unix socket
// specified in the provided address.  If the address doesn't have the "unix"
// schema or the path is unset, an error is returned.
func New(ctx context.Context, address *url.URL) (*Client, error) {
	const op = "client.New"
	switch {
	case address == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "address is nil")
	case address.Scheme != "unix":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "address does not have a unix schema")
	case address.Path == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "address path is empty")
	}
	c := &retryablehttp.Client{
		HTTPClient:   cleanhttp.DefaultClient(),
		RetryWaitMin: 100 * time.Millisecond,
		RetryWaitMax: 1500 * time.Millisecond,
		RetryMax:     6,
		CheckRetry:   retryablehttp.DefaultRetryPolicy,
		Backoff:      retryablehttp.DefaultBackoff,
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
	}
	transport := c.HTTPClient.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, n string, a string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "unix", address.Path)
	}
	return &Client{client: c, unixHostPath: address.Path}, nil
}

// Response returns the *http.Response as well as providing the body of the response
// through a call to Body().
type Response struct {
	*http.Response
	contents []byte
}

// Body returns the pre-read response body.
func (r Response) Body() []byte {
	return r.contents
}

// Get sends a GET http request to the provided path.  The vals provided are
// encoded and attached to the request if present.
func (c *Client) Get(ctx context.Context, path string, vals *url.Values) (*Response, *api.Error, error) {
	req := c.request(ctx, "GET", path)
	if vals != nil {
		req.URL.RawQuery = vals.Encode()
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	return parseReponse(resp)
}

// Post sends a POST http request to the provided path.  The body is marshaled
// to  json and added to the request body.
func (c *Client) Post(ctx context.Context, path string, body any) (*Response, *api.Error, error) {
	req := c.request(ctx, "POST", path)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("error marshaling body: %w", err)
		}
		req.SetBody(b)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	return parseReponse(resp)
}

// request returns a retryablehttp.Request with the url set to the domain socket
// associated with this client and proper headers set for client daemon requests.
func (c *Client) request(ctx context.Context, method, path string) *retryablehttp.Request {
	req := &http.Request{
		Method: method,
		URL: &url.URL{
			Scheme: "http",
			Host:   c.unixHostPath,
			Path:   path,
		},
		Host: hostHeader,
	}
	req.Header = http.Header{}
	req.Header.Set(daemon.VersionHeaderKey, version.Get().VersionNumber())
	req.Header.Set("content-type", "application/json")

	return &retryablehttp.Request{
		Request: req.Clone(ctx),
	}
}

// parseReponse takes the http.Response, reads and stores the response body
// and returns it, or if it detects an error, it returns the appropriate error
// or api.Error.
func parseReponse(resp *http.Response) (*Response, *api.Error, error) {
	body := bytes.Buffer{}
	if resp.Body != nil {
		if _, err := body.ReadFrom(resp.Body); err != nil {
			return nil, nil, fmt.Errorf("error reading response body: %w", err)
		}
	}

	ret := &Response{Response: resp, contents: body.Bytes()}
	switch {
	case resp.StatusCode == 404:
		return ret, api.ErrNotFound, nil
	case resp.StatusCode >= 400:
		apiErr := &api.Error{}
		reader := bytes.NewReader(ret.contents)
		dec := json.NewDecoder(reader)
		if err := dec.Decode(&apiErr); err != nil {
			return nil, nil, err
		}
		return ret, apiErr, nil
	}
	return ret, nil, nil
}
