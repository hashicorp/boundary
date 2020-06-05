// Code generated by "make api"; DO NOT EDIT.
package scopes

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/hosts"
	"github.com/hashicorp/watchtower/api/users"
)

// DeleteProject returns true iff the Project existed when the delete attempt was made.
func (s Organization) DeleteProject(ctx context.Context, r *Project) (bool, *api.Error, error) {
	if s.Client == nil {
		return false, nil, fmt.Errorf("nil client in DeleteProject request")
	}
	if s.Id == "" {

		// Assume the client has been configured with organization already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}
	if r.Id == "" {
		return false, nil, fmt.Errorf("empty Project ID field in DeleteProject request")
	}

	req, err := s.Client.NewRequest(ctx, "DELETE", fmt.Sprintf("%s/%s", "projects", r.Id), nil)
	if err != nil {
		return false, nil, fmt.Errorf("error creating DeleteProject request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("error performing client request during DeleteProject call: %w", err)
	}

	type deleteResponse struct {
		Existed bool
	}
	target := &deleteResponse{}

	apiErr, err := resp.Decode(target)
	if err != nil {
		return false, nil, fmt.Errorf("error decoding DeleteProject repsonse: %w", err)
	}

	return target.Existed, apiErr, nil
}

// DeleteUser returns true iff the users.User existed when the delete attempt was made.
func (s Organization) DeleteUser(ctx context.Context, r *users.User) (bool, *api.Error, error) {
	if s.Client == nil {
		return false, nil, fmt.Errorf("nil client in DeleteUser request")
	}
	if s.Id == "" {

		// Assume the client has been configured with organization already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}
	if r.Id == "" {
		return false, nil, fmt.Errorf("empty users.User ID field in DeleteUser request")
	}

	req, err := s.Client.NewRequest(ctx, "DELETE", fmt.Sprintf("%s/%s", "users", r.Id), nil)
	if err != nil {
		return false, nil, fmt.Errorf("error creating DeleteUser request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("error performing client request during DeleteUser call: %w", err)
	}

	type deleteResponse struct {
		Existed bool
	}
	target := &deleteResponse{}

	apiErr, err := resp.Decode(target)
	if err != nil {
		return false, nil, fmt.Errorf("error decoding DeleteUser repsonse: %w", err)
	}

	return target.Existed, apiErr, nil
}

// DeleteHostCatalog returns true iff the hosts.HostCatalog existed when the delete attempt was made.
func (s Project) DeleteHostCatalog(ctx context.Context, r *hosts.HostCatalog) (bool, *api.Error, error) {
	if s.Client == nil {
		return false, nil, fmt.Errorf("nil client in DeleteHostCatalog request")
	}
	if s.Id == "" {

		// Assume the client has been configured with project already and move
		// on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "project", s.Id)

	}
	if r.Id == "" {
		return false, nil, fmt.Errorf("empty hosts.HostCatalog ID field in DeleteHostCatalog request")
	}

	req, err := s.Client.NewRequest(ctx, "DELETE", fmt.Sprintf("%s/%s", "host-catalogs", r.Id), nil)
	if err != nil {
		return false, nil, fmt.Errorf("error creating DeleteHostCatalog request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("error performing client request during DeleteHostCatalog call: %w", err)
	}

	type deleteResponse struct {
		Existed bool
	}
	target := &deleteResponse{}

	apiErr, err := resp.Decode(target)
	if err != nil {
		return false, nil, fmt.Errorf("error decoding DeleteHostCatalog repsonse: %w", err)
	}

	return target.Existed, apiErr, nil
}
