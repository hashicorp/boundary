// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
)

func (c *Client) Cancel(ctx context.Context, sessionId string, version uint32, opt ...Option) (*SessionUpdateResult, error) {
	if sessionId == "" {
		return nil, fmt.Errorf("empty sessionId value passed into Cancel request")
	}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into Cancel request")
		}
		existingSession, existingErr := c.Read(ctx, sessionId, opt...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingSession == nil {
			return nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingSession.Item == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingSession.Item.Version
	}

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("sessions/%s:cancel", sessionId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Cancel request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Cancel call: %w", err)
	}

	target := new(SessionUpdateResult)
	target.Item = new(Session)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Cancel response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}
