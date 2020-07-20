package groups

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
)

func (s Group) AddMembers(ctx context.Context, memberIds []string) (*Group, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in AddMembers request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(memberIds) > 0 {
		body["member_ids"] = memberIds
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("groups/%s:add-members", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AddMembers request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during AddMembers call: %w", err)
	}

	target := new(Group)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding AddMembers repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Group) SetMembers(ctx context.Context, memberIds []string) (*Group, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in SetMembers request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(memberIds) > 0 {
		body["member_ids"] = memberIds
	} else if memberIds != nil {
		// In this function, a non-nil but empty list means clear out
		body["member_ids"] = nil
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("groups/%s:set-members", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SetMembers request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during SetMembers call: %w", err)
	}

	target := new(Group)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding SetMembers repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Group) RemoveMembers(ctx context.Context, memberIds []string) (*Group, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in RemoveMembers request")
	}
	// We assume that the client provided has the org and optionally the project id of the request.

	body := map[string]interface{}{
		"version": s.Version,
	}
	if len(memberIds) > 0 {
		body["member_ids"] = memberIds
	}

	req, err := s.Client.NewRequest(ctx, "POST", fmt.Sprintf("groups/%s:remove-members", s.Id), body)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating RemoveMembers request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during RemoveMembers call: %w", err)
	}

	target := new(Group)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding RemoveMembers repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}
