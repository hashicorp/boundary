package hostsets

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
	"github.com/kr/pretty"
)

func (c *Client) AddHosts2(ctx context.Context, hostSetId string, version uint32, hostIds []string, opt ...Option) (*HostSet, *api.Error, error) {
	if hostSetId == "" {
		return nil, nil, fmt.Errorf("empty hostSetId value passed into AddHosts request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into AddHosts request")
		}
		existingTarget, existingApiErr, existingErr := c.Read2(ctx, hostSetId, opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Version
	}

	opts.postMap["version"] = version

	if len(hostIds) > 0 {
		opts.postMap["host_ids"] = hostIds
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("host-sets/%s:add-hosts", hostSetId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AddHosts request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during AddHosts call: %w", err)
	}

	target := new(HostSet)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding AddHosts response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}

func (c *Client) SetHosts2(ctx context.Context, hostSetId string, version uint32, hostIds []string, opt ...Option) (*HostSet, *api.Error, error) {
	if hostSetId == "" {
		return nil, nil, fmt.Errorf("empty hostSetId value passed into SetHosts request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into SetHosts request")
		}
		existingTarget, existingApiErr, existingErr := c.Read2(ctx, hostSetId, opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Version
	}

	opts.postMap["version"] = version

	if len(hostIds) > 0 {
		opts.postMap["host_ids"] = hostIds
	} else if hostIds != nil {
		// In this function, a non-nil but empty list means clear out
		opts.postMap["host_ids"] = nil
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("host-sets/%s:set-hosts", hostSetId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SetHosts request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during SetHosts call: %w", err)
	}

	target := new(HostSet)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding SetHosts response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}

func (c *Client) RemoveHosts2(ctx context.Context, hostSetId string, version uint32, hostIds []string, opt ...Option) (*HostSet, *api.Error, error) {
	if hostSetId == "" {
		return nil, nil, fmt.Errorf("empty hostSetId value passed into RemoveHosts request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())

	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into RemoveHosts request")
		}
		existingTarget, existingApiErr, existingErr := c.Read2(ctx, hostSetId, opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Version
	}

	opts.postMap["version"] = version

	if len(hostIds) > 0 {
		opts.postMap["host_ids"] = hostIds
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("host-sets/%s:remove-hosts", hostSetId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating RemoveHosts request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during RemoveHosts call: %w", err)
	}

	target := new(HostSet)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding RemoveHosts response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}
