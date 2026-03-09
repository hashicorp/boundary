// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"fmt"
	"os"
	"strings"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

const (
	ErrOutputStringRequest = "output a string, please"
)

var LastOutputStringError *OutputStringError

type OutputStringError struct {
	*retryablehttp.Request
	unixSocket       string
	parsingError     error
	parsedCurlString string
}

func NewOutputDomainSocketCurlStringError(req *retryablehttp.Request, socketAddr string) *OutputStringError {
	return &OutputStringError{
		Request:    req,
		unixSocket: socketAddr,
	}
}

func (d *OutputStringError) Error() string {
	if d.parsedCurlString == "" {
		d.parseRequest()
		if d.parsingError != nil {
			return d.parsingError.Error()
		}
	}

	return ErrOutputStringRequest
}

func (d *OutputStringError) parseRequest() {
	body, err := d.Request.BodyBytes()
	if err != nil {
		d.parsingError = err
		return
	}

	// Build cURL string
	d.parsedCurlString = "curl"
	if d.Request.Method != "GET" {
		d.parsedCurlString = fmt.Sprintf("%s -X %s", d.parsedCurlString, d.Request.Method)
	}
	if d.unixSocket != "" {
		d.parsedCurlString = fmt.Sprintf("%s --unix-socket %s", d.parsedCurlString, d.unixSocket)
	}
	for k, v := range d.Request.Header {
		for _, h := range v {
			if strings.ToLower(k) == "authorization" {
				tokenName := os.Getenv("BOUNDARY_TOKEN_NAME")
				keyringType := os.Getenv("BOUNDARY_KEYRING_TYPE")
				switch {
				case tokenName == "none" || keyringType == "none":
					h = `Bearer <token>`
				case tokenName == "" && keyringType == "":
					h = `Bearer $(boundary config get-token)`
				default:
					h = fmt.Sprintf("Bearer $(boundary config get-token -keyring-type %s -token-name %s)", keyringType, tokenName)
				}
			}
			d.parsedCurlString = fmt.Sprintf("%s -H \"%s: %s\"", d.parsedCurlString, k, h)
		}
	}

	if len(body) > 0 {
		// We need to escape single quotes since that's what we're using to
		// quote the body
		escapedBody := strings.Replace(string(body), "'", "'\"'\"'", -1)
		d.parsedCurlString = fmt.Sprintf("%s -d '%s'", d.parsedCurlString, escapedBody)
	}

	// Filters can have shell characters so we use single quotes to surround the URL
	d.parsedCurlString = fmt.Sprintf("%s '%s'", d.parsedCurlString, d.Request.URL.String())
}

func (d *OutputStringError) CurlString() string {
	if d.parsedCurlString == "" {
		d.parseRequest()
	}
	return d.parsedCurlString
}
