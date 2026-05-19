// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/policies"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/session_recordings"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/sessions"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	"google.golang.org/protobuf/proto"
)

// resourceProtoMessages maps a resource type to its proto message,
// whose fields define the valid output fields for that resource.
var resourceProtoMessages = map[resource.Type]proto.Message{
	resource.Account:           (*accounts.Account)(nil),
	resource.Alias:             (*aliases.Alias)(nil),
	resource.AuthMethod:        (*authmethods.AuthMethod)(nil),
	resource.AuthToken:         (*authtokens.AuthToken)(nil),
	resource.Credential:        (*credentials.Credential)(nil),
	resource.CredentialLibrary: (*credentiallibraries.CredentialLibrary)(nil),
	resource.CredentialStore:   (*credentialstores.CredentialStore)(nil),
	resource.Group:             (*groups.Group)(nil),
	resource.Host:              (*hosts.Host)(nil),
	resource.HostCatalog:       (*hostcatalogs.HostCatalog)(nil),
	resource.HostSet:           (*hostsets.HostSet)(nil),
	resource.ManagedGroup:      (*managedgroups.ManagedGroup)(nil),
	resource.Policy:            (*policies.Policy)(nil),
	resource.Role:              (*roles.Role)(nil),
	resource.Scope:             (*scopes.Scope)(nil),
	resource.Session:           (*sessions.Session)(nil),
	resource.SessionRecording:  (*session_recordings.SessionRecording)(nil),
	resource.StorageBucket:     (*storagebuckets.StorageBucket)(nil),
	resource.Target:            (*targets.Target)(nil),
	resource.User:              (*users.User)(nil),
	resource.Worker:            (*workers.Worker)(nil),
}

// outputFieldsForResource returns the valid output fields for the given
// resource type, derived from its proto definition.
func outputFieldsForResource(typ resource.Type) []string {
	msg, ok := resourceProtoMessages[typ]
	if !ok {
		return nil
	}
	fields := msg.ProtoReflect().Descriptor().Fields()
	out := make([]string, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		out = append(out, string(fields.Get(i).Name()))
	}
	return out
}

// GrantSchema represents the schema of grants in the system,
// including the resource types and their associated actions, scopes.
type GrantSchema struct {
	ResourceTypes []ResourceTypeSchema `json:"resource_types"`
}

type ResourceTypeSchema struct {
	// Type is the string representation of the resource type
	Type string `json:"type"`

	// The collection actions that are valid for this resource type
	CollectionActions []string `json:"collection_actions,omitempty"`

	// The id actions that are valid for this resource type
	IdActions []string `json:"id_actions,omitempty"`

	// The scopes that are valid for this resource type
	Scopes []string `json:"scopes,omitempty"`

	// The ID prefixes that are valid for this resource type
	IdPrefixes []string `json:"id_prefixes,omitempty"`

	// The parent resource type, if any, omitted if no parent
	ParentType string `json:"parent_type,omitempty"`

	// The valid output fields that can be returned for this resource type
	OutputFields []string `json:"output_fields,omitempty"`
}

// BuildGrantSchema constructs the full grant schema from the registered
// resource types, actions, and scope definitions.
func BuildGrantSchema(ctx context.Context) (*GrantSchema, error) {
	const op = "perms.BuildGrantSchema"
	schema := &GrantSchema{}

	for name, typ := range resource.Map {
		// Skip resource types that aren't real grantable resources
		// These types will fail further lookups and aren't useful to include in the schema
		if typ == resource.Unknown || typ == resource.All || typ == resource.Controller {
			continue
		}

		// Collect all collection actions
		colActions, err := action.CollectionActionSetForResource(typ)
		if err != nil {
			return nil, fmt.Errorf("%s: error getting collection actions for %q: %w", op, name, err)
		}

		var colStrs []string
		for a := range colActions {
			colStrs = append(colStrs, a.String())
		}

		// Collect all id actions
		idActions, err := action.IdActionSetForResource(typ)
		if err != nil {
			return nil, fmt.Errorf("%s: error getting id actions for %q: %w", op, name, err)
		}

		var idStrs []string
		for a := range idActions {
			if a == action.NoOp {
				continue
			}
			idStrs = append(idStrs, a.String())
		}

		// Collect all scopes that can be applied to this resource type
		scopes, err := scope.AllowedIn(ctx, typ)
		if err != nil {
			return nil, fmt.Errorf("%s: error getting allowed scopes for %q: %w", op, name, err)
		}

		var scopeStrs []string
		for _, s := range scopes {
			scopeStrs = append(scopeStrs, s.String())
		}

		// Parent type is the resource's parent if one exists,
		// otherwise this will be an empty string.
		var parentType string
		if parent := typ.Parent(); parent != typ {
			parentType = parent.String()
		}

		schema.ResourceTypes = append(schema.ResourceTypes, ResourceTypeSchema{
			Type:              name,
			CollectionActions: colStrs,
			IdActions:         idStrs,
			Scopes:            scopeStrs,
			IdPrefixes:        globals.ResourcePrefixesFromType(typ),
			ParentType:        parentType,
			OutputFields:      outputFieldsForResource(typ),
		})
	}

	return schema, nil
}

// BuildGrantSchemaJSON builds the grant schema and marshals it to JSON
func BuildGrantSchemaJSON(ctx context.Context) ([]byte, error) {
	schema, err := BuildGrantSchema(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(schema)
}
