// Code generated by "make api"; DO NOT EDIT.
package scopes

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/hosts"
	"github.com/hashicorp/watchtower/api/users"
)

func (s Organization) UpdateProject(ctx context.Context, r *Project) (*Project, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in CreateProject request")
	}
	if s.Id == "" {

		// Assume the client has been configured with organization already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}

	id := r.Id
	r.Id = ""

	req, err := s.Client.NewRequest(ctx, "PATCH", fmt.Sprintf("%s/%s", "projects", id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating CreateProject request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during UpdateProject call: %w", err)
	}

	target := new(Project)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding UpdateProject repsonse: %w", err)
	}

	target.Client = s.Client.Clone()
	target.Client.SetProject(target.Id)

	return target, apiErr, nil
}

func (s Project) UpdateHostCatalog(ctx context.Context, r *hosts.HostCatalog) (*hosts.HostCatalog, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in CreateHostCatalog request")
	}
	if s.Id == "" {

		// Assume the client has been configured with project already and move
		// on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "project", s.Id)

	}

	id := r.Id
	r.Id = ""

	req, err := s.Client.NewRequest(ctx, "PATCH", fmt.Sprintf("%s/%s", "host-catalogs", id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating CreateHostCatalog request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during UpdateHostCatalog call: %w", err)
	}

	target := new(hosts.HostCatalog)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding UpdateHostCatalog repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s User) UpdateUser(ctx context.Context, r *users.User) (*users.User, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in CreateUser request")
	}
	if s.Id == "" {

		return nil, nil, fmt.Errorf("missing User ID in CreateUser request")

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

	}

	id := r.Id
	r.Id = ""

	req, err := s.Client.NewRequest(ctx, "PATCH", fmt.Sprintf("%s/%s", "users", id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating CreateUser request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during UpdateUser call: %w", err)
	}

	target := new(users.User)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding UpdateUser repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}
