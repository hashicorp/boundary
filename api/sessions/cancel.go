package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
	"github.com/kr/pretty"
)

func (c *Client) Cancel(ctx context.Context, sessionId string, version uint32, opt ...Option) (*SessionUpdateResult, *api.Error, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("empty sessionId value passed into Cancel request")
	}
	if c.client == nil {
		return nil, nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into Cancel request")
		}
		existingSession, existingApiErr, existingErr := c.Read(ctx, sessionId, opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingSession == nil {
			return nil, nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingSession.Item == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingSession.Item.Version
	}

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("sessions/%s:cancel", sessionId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Cancel request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Cancel call: %w", err)
	}

	target := new(SessionUpdateResult)
	target.Item = new(Session)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Cancel response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	target.responseBody = resp.Body
	target.responseMap = resp.Map
	return target, apiErr, nil
}
