package roles

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
)

func (s Role) AddPrincipals(ctx context.Context, groups, users []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadRole request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"group_ids": groups,
		"user_ids":  users,
		"version":   s.Version,
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:add-principals", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadRole request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during AddPrincipals call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadRole repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Role) SetPrincipals(ctx context.Context, groups, users []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadRole request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"group_ids": groups,
		"user_ids":  users,
		"version":   s.Version,
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:set-principals", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadRole request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadRole call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadRole repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Role) RemovePrincipals(ctx context.Context, groups, users []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadRole request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"group_ids": groups,
		"user_ids":  users,
		"version":   s.Version,
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:remove-principals", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadRole request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadRole call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadRole repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}
