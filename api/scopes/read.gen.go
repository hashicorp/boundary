// Code generated by "make api"; DO NOT EDIT.
package scopes

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/authtokens"
	"github.com/hashicorp/watchtower/api/groups"
	"github.com/hashicorp/watchtower/api/hosts"
	"github.com/hashicorp/watchtower/api/roles"
	"github.com/hashicorp/watchtower/api/users"
)

func (s Org) ReadProject(ctx context.Context, r *Project) (*Project, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadProject request")
	}
	if s.Id == "" {

		// Assume the client has been configured with org already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}
	if r.Id == "" {
		return nil, nil, fmt.Errorf("empty Project ID field in ReadProject request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "projects", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadProject request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadProject call: %w", err)
	}

	target := new(Project)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadProject repsonse: %w", err)
	}

	target.Client = s.Client.Clone()
	target.Client.SetProject(target.Id)

	return target, apiErr, nil
}

func (s Org) ReadAuthToken(ctx context.Context, r *authtokens.AuthToken) (*authtokens.AuthToken, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadAuthToken request")
	}
	if s.Id == "" {

		// Assume the client has been configured with org already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}
	if r.Id == "" {
		return nil, nil, fmt.Errorf("empty authtokens.AuthToken ID field in ReadAuthToken request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "auth-tokens", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadAuthToken request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadAuthToken call: %w", err)
	}

	target := new(authtokens.AuthToken)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadAuthToken repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Org) ReadGroup(ctx context.Context, r *groups.Group) (*groups.Group, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadGroup request")
	}
	if s.Id == "" {

		// Assume the client has been configured with org already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}
	if r.Id == "" {
		return nil, nil, fmt.Errorf("empty groups.Group ID field in ReadGroup request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "groups", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadGroup request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadGroup call: %w", err)
	}

	target := new(groups.Group)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadGroup repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Org) ReadRole(ctx context.Context, r *roles.Role) (*roles.Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadRole request")
	}
	if s.Id == "" {

		// Assume the client has been configured with org already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}
	if r.Id == "" {
		return nil, nil, fmt.Errorf("empty roles.Role ID field in ReadRole request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "roles", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadRole request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadRole call: %w", err)
	}

	target := new(roles.Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadRole repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Org) ReadUser(ctx context.Context, r *users.User) (*users.User, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadUser request")
	}
	if s.Id == "" {

		// Assume the client has been configured with org already and
		// move on

	} else {
		// If it's explicitly set here, override anything that might be in the
		// client

		ctx = context.WithValue(ctx, "org", s.Id)

	}
	if r.Id == "" {
		return nil, nil, fmt.Errorf("empty users.User ID field in ReadUser request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "users", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadUser request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadUser call: %w", err)
	}

	target := new(users.User)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadUser repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Project) ReadGroup(ctx context.Context, r *groups.Group) (*groups.Group, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadGroup request")
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
		return nil, nil, fmt.Errorf("empty groups.Group ID field in ReadGroup request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "groups", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadGroup request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadGroup call: %w", err)
	}

	target := new(groups.Group)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadGroup repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Project) ReadRole(ctx context.Context, r *roles.Role) (*roles.Role, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadRole request")
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
		return nil, nil, fmt.Errorf("empty roles.Role ID field in ReadRole request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "roles", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadRole request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadRole call: %w", err)
	}

	target := new(roles.Role)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadRole repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}

func (s Project) ReadHostCatalog(ctx context.Context, r *hosts.HostCatalog) (*hosts.HostCatalog, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in ReadHostCatalog request")
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
		return nil, nil, fmt.Errorf("empty hosts.HostCatalog ID field in ReadHostCatalog request")
	}

	req, err := s.Client.NewRequest(ctx, "GET", fmt.Sprintf("%s/%s", "host-catalogs", r.Id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ReadHostCatalog request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during ReadHostCatalog call: %w", err)
	}

	target := new(hosts.HostCatalog)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding ReadHostCatalog repsonse: %w", err)
	}

	target.Client = s.Client

	return target, apiErr, nil
}
