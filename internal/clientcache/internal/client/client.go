// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package client

import (
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

const hostHeader = "clientcache.boundary.localhost"

type Client struct {
	client           *retryablehttp.Client
	domainSocketPath string
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
	return &Client{client: c, domainSocketPath: address.Path}, nil
}

// Get sends a GET http request to the provided path.  The vals provided are
// encoded and attached to the request if present.
func (c *Client) Get(ctx context.Context, path string, vals *url.Values, opt ...Option) (*api.Response, error) {
	req := request(ctx, "GET", path)
	if vals != nil {
		req.URL.RawQuery = vals.Encode()
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}
	if opts.withOutputCurlString {
		api.LastOutputStringError = api.NewOutputDomainSocketCurlStringError(req, c.domainSocketPath)
		return nil, api.LastOutputStringError
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	return api.NewResponse(resp), nil
}

// Post sends a POST http request to the provided path.  The body is marshaled
// to  json and added to the request body.
func (c *Client) Post(ctx context.Context, path string, body any, opt ...Option) (*api.Response, error) {
	req := request(ctx, "POST", path)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling body: %w", err)
		}
		req.SetBody(b)
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}
	if opts.withOutputCurlString {
		api.LastOutputStringError = api.NewOutputDomainSocketCurlStringError(req, c.domainSocketPath)
		return nil, api.LastOutputStringError
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	return api.NewResponse(resp), nil
}

// request returns a retryablehttp.Request with the url set to the domain socket
// associated with this client and proper headers set for client cache requests.
func request(ctx context.Context, method, path string) *retryablehttp.Request {
	req := &http.Request{
		Method: method,
		URL: &url.URL{
			Scheme: "http",
			Host:   hostHeader,
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
