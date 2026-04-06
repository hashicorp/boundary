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
)

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
