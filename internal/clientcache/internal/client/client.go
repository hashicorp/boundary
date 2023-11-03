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
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
)

const hostHeader = "api.boundary.localhost"

type Client struct {
	client *retryablehttp.Client
	u      *url.URL
}

func New(ctx context.Context, address *url.URL) (*Client, error) {
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
	return &Client{client: c, u: address}, nil
}

type Response struct {
	*http.Response
	contents []byte
}

func (r Response) Body() []byte {
	return r.contents
}

// Get sends a GET http request to the provided path.  The vals provided are
// encoded and attached to the request if present.
func (c *Client) Get(ctx context.Context, path string, vals *url.Values) (*Response, *api.Error, error) {
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "http",
			Host:   c.u.Path,
			Path:   path,
		},
		Host: hostHeader,
	}
	if vals != nil {
		req.URL.RawQuery = vals.Encode()
	}
	req.Header = http.Header{}
	req.Header.Add(daemon.VersionHeaderKey, version.Get().VersionNumber())
	ret := &retryablehttp.Request{Request: req}
	resp, err := c.client.Do(ret)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	return parseReponse(resp)
}

// Post sends a POST http request to the provided path.  The body is marshaled
// to  json and added to the request body.
func (c *Client) Post(ctx context.Context, path string, body any) (*Response, *api.Error, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshaling body: %w", err)
	}

	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Scheme: "http",
			Host:   c.u.Path,
			Path:   path,
		},
		Host: hostHeader,
	}
	req.Header = http.Header{}
	req.Header.Add(daemon.VersionHeaderKey, version.Get().VersionNumber())

	ret := &retryablehttp.Request{
		Request: req,
	}
	ret.SetBody(b)
	resp, err := c.client.Do(ret)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	return parseReponse(resp)
}

func parseReponse(resp *http.Response) (*Response, *api.Error, error) {
	body := bytes.Buffer{}
	if resp.Body != nil {
		if _, err := body.ReadFrom(resp.Body); err != nil {
			return nil, nil, fmt.Errorf("error reading response body: %w", err)
		}
	}

	ret := &Response{Response: resp, contents: body.Bytes()}
	switch {
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
