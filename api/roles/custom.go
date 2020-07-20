package roles

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
)

func (s Role) AddPrincipals(ctx context.Context, principalIds []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in AddPrincipals request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(principalIds) > 0 {
		body["principal_ids"] = principalIds
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:add-principals", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AddPrincipals request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during AddPrincipals call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding AddPrincipals repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Role) SetPrincipals(ctx context.Context, principalIds []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in SetPrincipals request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(principalIds) > 0 {
		body["principal_ids"] = principalIds
	} else if principalIds != nil {
		// In this function, a non-nil but empty list means clear out
		body["principal_ids"] = nil
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:set-principals", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SetPrincipals request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during SetPrincipals call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding SetPrincipals repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Role) RemovePrincipals(ctx context.Context, principalIds []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in RemovePrincipals request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(principalIds) > 0 {
		body["principal_ids"] = principalIds
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:remove-principals", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating RemovePrincipals request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during RemovePrincipals call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding RemovePrincipals repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Role) AddGrants(ctx context.Context, grants []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in AddGrants request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(grants) > 0 {
		body["grant_strings"] = grants
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:add-grants", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AddGrants request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during AddGrants call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding AddGrants repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Role) SetGrants(ctx context.Context, grants []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in SetGrants request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(grants) > 0 {
		body["grant_strings"] = grants
	} else if grants != nil {
		body["grant_strings"] = nil
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:set-grants", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SetGrants request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during SetGrants call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding SetGrants repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Role) RemoveGrants(ctx context.Context, grants []string) (*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in RemoveGrants request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(grants) > 0 {
		body["grant_strings"] = grants
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("roles/%s:remove-grants", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating RemoveGrants request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during RemoveGrants call: %w", err)
	}

	target := new(Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding RemoveGrants repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}
