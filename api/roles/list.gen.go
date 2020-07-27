// Code generated by "make api"; DO NOT EDIT.
package roles

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
)

func (s Role) ListRoles(ctx context.Context) ([]*Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ListRole request")
	}

	var opts []api.Option
	if s.Scope.Id != "" {
		// If it's explicitly set here, override anything that might be in the
		// client
		opts = append(opts, api.WithScopeId(s.Scope.Id))
	}

	req, err := s.Client.NewRequest(ctx, "GET", "roles", nil, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ListRoles request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ListRoles call: %w", err)
	}

	type listResponse struct {
		Items []*Role
	}
	target := &listResponse{}

	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ListRoles response: %w", err)
	}

	for _, t := range target.Items {

		t.Client = s.Client

	}

	return target.Items, apiErr, nil
}
