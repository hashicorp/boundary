// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package targets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	targetspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type SessionAuthorizationResult struct {
	Item     *SessionAuthorization
	response *api.Response
}

func (n SessionAuthorizationResult) GetItem() any {
	return n.Item
}

func (n SessionAuthorizationResult) GetResponse() *api.Response {
	return n.response
}

func (n SessionAuthorizationResult) GetSessionAuthorization() (*SessionAuthorization, error) {
	result, ok := n.GetItem().(*SessionAuthorization)
	if !ok {
		return nil, fmt.Errorf("unable to interpret session authorization result as session authorization data")
	}
	return result, nil
}

func (n SessionAuthorization) GetSessionAuthorizationData() (*SessionAuthorizationData, error) {
	if n.AuthorizationToken == "" {
		return nil, fmt.Errorf("authorization token is empty")
	}
	marshaled, err := base58.FastBase58Decoding(n.AuthorizationToken)
	if err != nil {
		return nil, fmt.Errorf("unable to base58-decode authorization token: %w", err)
	}
	if len(marshaled) == 0 {
		return nil, errors.New("zero-length authorization information after decoding")
	}

	// Marshal using protojson and unmarshal using json, rather than statically
	// copying
	d := new(targetspb.SessionAuthorizationData)
	if err := proto.Unmarshal(marshaled, d); err != nil {
		return nil, fmt.Errorf("unable to unmarshal authorization data: %w", err)
	}
	jsBytes, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("error marshaling decoded proto as json: %w", err)
	}
	ret := &SessionAuthorizationData{
		Scope: &scopes.ScopeInfo{},
	}
	if err := json.Unmarshal(jsBytes, ret); err != nil {
		return nil, fmt.Errorf("error unmashaling protojson bytes: %w", err)
	}

	ret.WorkerInfo = make([]*WorkerInfo, len(d.WorkerInfo))
	for i, w := range d.WorkerInfo {
		ret.WorkerInfo[i] = &WorkerInfo{
			Address: w.Address,
		}
	}

	return ret, nil
}

func (c *Client) AuthorizeSession(ctx context.Context, targetId string, opt ...Option) (*SessionAuthorizationResult, error) {
	opts, apiOpts := getOpts(opt...)

	if targetId == "" {
		if opts.postMap["name"] == nil {
			return nil, fmt.Errorf("empty target name provided to AuthorizeSession request")
		}
		scopeIdEmpty := opts.postMap["scope_id"] == nil
		scopeNameEmpty := opts.postMap["scope_name"] == nil
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			return nil, fmt.Errorf("empty targetId value and no combination of target name and scope ID/name passed into AuthorizeSession request")
		case !scopeIdEmpty && !scopeNameEmpty:
			return nil, fmt.Errorf("both scope ID and scope name cannot be provided in AuthorizeSession request")
		default:
			// Name is not empty and only one of scope ID or name set
			targetId = opts.postMap["name"].(string)
		}
	}

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:authorize-session", targetId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AuthorizeSession request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during AuthorizeSession call: %w", err)
	}

	target := new(SessionAuthorizationResult)
	target.Item = new(SessionAuthorization)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AuthorizeSession response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
