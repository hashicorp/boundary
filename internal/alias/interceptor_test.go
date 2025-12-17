// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1
package alias

import (
	"context"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestRegisterAliasableFields(t *testing.T) {
	// When this package is imported the aliasable fields are registered so
	// we can immediately assert that some of the expected fields are present.

	successCases := []protoreflect.FullName{
		(&pbs.GetTargetRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.UpdateTargetRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.DeleteTargetRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.AddTargetHostSourcesRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.SetTargetHostSourcesRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.RemoveTargetHostSourcesRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.AddTargetCredentialSourcesRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.SetTargetCredentialSourcesRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.RemoveTargetCredentialSourcesRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.AuthorizeSessionRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
	}

	for _, c := range successCases {
		t.Run(string(c), func(t *testing.T) {
			_, ok := globalAliasableRegistry.Load(c)
			assert.Truef(t, ok, "expected field %q to be aliasable", c)
		})
	}

	failCases := []protoreflect.FullName{
		(&pbs.GetAccountRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.UpdateAccountRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
		(&pbs.DeleteAccountRequest{}).ProtoReflect().Descriptor().Fields().ByName("id").FullName(),
	}

	for _, c := range failCases {
		t.Run(string(c), func(t *testing.T) {
			_, ok := globalAliasableRegistry.Load(c)
			assert.Falsef(t, ok, "expected field %q to not be aliasable", c)
		})
	}
}

func TestResolveAliasFields(t *testing.T) {
	t.Run("no alias", func(t *testing.T) {
		ctx := context.Background()
		m := aliasMapping{m: make(map[string]*Alias)}
		req := &pbs.GetTargetRequest{Id: "foo"}
		ctx, err := ResolveRequestIds(ctx, req, m)
		assert.ErrorContains(t, err, "resource alias not found with value")
		assert.Nil(t, FromContext(ctx))
	})

	t.Run("alias", func(t *testing.T) {
		ctx := context.Background()
		m := aliasMapping{m: make(map[string]*Alias)}
		m.m["foo"] = &Alias{PublicId: "alt_1234", Value: "foo", DestinationId: "ttcp_mapped"}
		req := &pbs.GetTargetRequest{Id: "foo"}
		ctx, err := ResolveRequestIds(ctx, req, m)
		assert.NoError(t, err)
		assert.Equal(t, "ttcp_mapped", req.Id)
		assert.NotNil(t, FromContext(ctx))
	})

	t.Run("public id", func(t *testing.T) {
		ctx := context.Background()
		m := aliasMapping{m: make(map[string]*Alias)}
		m.m["foo"] = &Alias{PublicId: "alt_1234", Value: "foo", DestinationId: "ttcp_mapped"}
		req := &pbs.GetTargetRequest{Id: "ttcp_existing"}
		ctx, err := ResolveRequestIds(ctx, req, m)
		assert.NoError(t, err)
		assert.Equal(t, "ttcp_existing", req.Id)
		assert.Nil(t, FromContext(ctx))
	})

	t.Run("alias has no destination id", func(t *testing.T) {
		ctx := context.Background()
		m := aliasMapping{m: make(map[string]*Alias)}
		m.m["foo"] = &Alias{PublicId: "alt_1234", Value: "foo"}
		req := &pbs.GetTargetRequest{Id: "foo"}
		ctx, err := ResolveRequestIds(ctx, req, m)
		assert.ErrorContains(t, err, "resource not found for alias value")
		assert.Nil(t, FromContext(ctx))
	})

	// Authorize sessions allow target names to be passed in through the id field
	// the only way to tell if that is happening is if the scope id or scope name
	// are also present.
	t.Run("authorize session target name with scope id", func(t *testing.T) {
		ctx := context.Background()
		m := aliasMapping{m: make(map[string]*Alias)}
		m.m["foo"] = &Alias{PublicId: "alt_1234", Value: "foo", DestinationId: "ttcp_mapped"}
		req := &pbs.AuthorizeSessionRequest{Id: "foo", ScopeId: "scope_id"}
		ctx, err := ResolveRequestIds(ctx, req, m)
		assert.NoError(t, err)
		assert.Equal(t, "foo", req.Id)
		assert.Nil(t, FromContext(ctx))
	})

	t.Run("authorize session target name with scope name", func(t *testing.T) {
		ctx := context.Background()
		m := aliasMapping{m: make(map[string]*Alias)}
		m.m["foo"] = &Alias{PublicId: "alt_1234", Value: "foo", DestinationId: "ttcp_mapped"}
		req := &pbs.AuthorizeSessionRequest{Id: "foo", ScopeName: "scope_name"}
		ctx, err := ResolveRequestIds(ctx, req, m)
		assert.NoError(t, err)
		assert.Equal(t, "foo", req.Id)
		assert.Nil(t, FromContext(ctx))
	})

	t.Run("authorize session alias", func(t *testing.T) {
		ctx := context.Background()
		m := aliasMapping{m: make(map[string]*Alias)}
		m.m["foo"] = &Alias{PublicId: "alt_1234", Value: "foo", DestinationId: "ttcp_mapped"}
		req := &pbs.AuthorizeSessionRequest{Id: "foo"}
		ctx, err := ResolveRequestIds(ctx, req, m)
		assert.NoError(t, err)
		assert.Equal(t, "ttcp_mapped", req.Id)
		assert.NotNil(t, FromContext(ctx))
	})
}

type aliasMapping struct {
	m map[string]*Alias
}

func (a aliasMapping) lookupAliasByValue(ctx context.Context, value string) (*Alias, error) {
	return a.m[value], nil
}
