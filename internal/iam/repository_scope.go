package iam

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateScope will create a scope in the repository and return the written
// scope. Supported options include: WithPublicId and WithRandomReader.
func (r *Repository) CreateScope(ctx context.Context, s *Scope, userId string, opt ...Option) (*Scope, error) {
	if s == nil {
		return nil, fmt.Errorf("create scope: missing scope %w", db.ErrInvalidParameter)
	}
	if s.Scope == nil {
		return nil, fmt.Errorf("create scope: missing scope store %w", db.ErrInvalidParameter)
	}
	if s.PublicId != "" {
		return nil, fmt.Errorf("create scope: public id not empty: %w", db.ErrInvalidParameter)
	}

	var parentOplogWrapper wrapping.Wrapper
	var externalWrappers *kms.ExternalWrappers
	var err error
	switch s.Type {
	case scope.Unknown.String():
		return nil, fmt.Errorf("create scope: unknown type: %w", db.ErrInvalidParameter)
	case scope.Global.String():
		return nil, fmt.Errorf("create scope: invalid type: %w", db.ErrInvalidParameter)
	default:
		switch s.ParentId {
		case "":
			return nil, fmt.Errorf("create scope: missing parent id: %w", db.ErrInvalidParameter)
		case scope.Global.String():
			parentOplogWrapper, err = r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
		default:
			parentOplogWrapper, err = r.kms.GetWrapper(ctx, s.ParentId, kms.KeyPurposeOplog)
		}
		externalWrappers = r.kms.GetExternalWrappers()
	}
	if err != nil {
		return nil, fmt.Errorf("create scope: unable to get oplog wrapper: %w", err)
	}

	opts := getOpts(opt...)

	var scopePublicId string
	var scopeMetadata oplog.Metadata
	var scopeRaw interface{}
	{
		scopeType := scope.Map[s.Type]
		if opts.withPublicId != "" {
			if !strings.HasPrefix(opts.withPublicId, scopeType.Prefix()+"_") {
				return nil, fmt.Errorf("create scope: passed-in public ID %q has wrong prefix for type %q which uses prefix %q", opts.withPublicId, scopeType.String(), scopeType.Prefix())
			}
			scopePublicId = opts.withPublicId
		} else {
			scopePublicId, err = newScopeId(scopeType)
			if err != nil {
				return nil, fmt.Errorf("create scope: error generating public id for new scope: %w", err)
			}
		}
		sc := s.Clone().(*Scope)
		sc.PublicId = scopePublicId
		scopeRaw = sc
		scopeMetadata, err = r.stdMetadata(ctx, sc)
		if err != nil {
			return nil, fmt.Errorf("create scope: error getting metadata for scope create: %w", err)
		}
		scopeMetadata["op-type"] = []string{oplog.OpType_OP_TYPE_CREATE.String()}
	}

	var rolePublicId string
	var roleMetadata oplog.Metadata
	var role *Role
	var roleRaw interface{}
	switch {
	case userId == "",
		userId == "u_anon",
		userId == "u_auth",
		userId == "u_recovery",
		opts.withSkipRoleCreation:
		// TODO: Cause a log entry. The repo doesn't have a logger right now,
		// and ideally we will be using context to pass around log info scoped
		// to this request for grouped display in the server log. The only
		// reason this should ever happen anyways is via the administrative
		// recovery workflow so it's already a special case.

		// Also, stop linter from complaining
		_ = role

	default:
		role, err = NewRole(scopePublicId)
		if err != nil {
			return nil, fmt.Errorf("create scope: error instantiating new role: %w", err)
		}
		rolePublicId, err = newRoleId()
		if err != nil {
			return nil, fmt.Errorf("create scope: error generating public id for new role: %w", err)
		}
		role.PublicId = rolePublicId
		role.Name = "on-scope-creation"
		role.Description = fmt.Sprintf("Role created for administration of scope %s by user %s at its creation time", scopePublicId, userId)
		roleRaw = role
		roleMetadata = oplog.Metadata{
			"resource-public-id": []string{rolePublicId},
			"scope-id":           []string{scopePublicId},
			"scope-type":         []string{s.Type},
			"resource-type":      []string{resource.Role.String()},
			"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
		}
	}

	reader := opts.withRandomReader
	if reader == nil {
		reader = rand.Reader
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(dbr db.Reader, w db.Writer) error {
			if err := w.Create(
				ctx,
				scopeRaw,
				db.WithOplog(parentOplogWrapper, scopeMetadata),
			); err != nil {
				return fmt.Errorf("error creating scope: %w", err)
			}

			s := scopeRaw.(*Scope)

			// Create the scope's keys
			_, err = kms.CreateKeysTx(ctx, dbr, w, externalWrappers.Root(), reader, s.PublicId)
			if err != nil {
				return fmt.Errorf("error creating scope keys: %w", err)
			}

			kmsRepo, err := kms.NewRepository(dbr, w)
			if err != nil {
				return fmt.Errorf("error creating new kms repo: %w", err)
			}
			childOplogWrapper, err := r.kms.GetWrapper(ctx, s.PublicId, kms.KeyPurposeOplog, kms.WithRepository(kmsRepo))
			if err != nil {
				return fmt.Errorf("error fetching new scope oplog wrapper: %w", err)
			}

			// We create a new role, then set grants and principals on it. This
			// turns into a bunch of stuff sadly because the role is the
			// aggregate.
			if roleRaw != nil {
				if err := w.Create(
					ctx,
					roleRaw,
					db.WithOplog(childOplogWrapper, roleMetadata),
				); err != nil {
					return fmt.Errorf("error creating role: %w", err)
				}

				role = roleRaw.(*Role)

				msgs := make([]*oplog.Message, 0, 3)
				roleTicket, err := w.GetTicket(role)
				if err != nil {
					return fmt.Errorf("unable to get ticket: %w", err)
				}

				// We need to update the role version as that's the aggregate
				var roleOplogMsg oplog.Message
				rowsUpdated, err := w.Update(ctx, role, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&role.Version))
				if err != nil {
					return fmt.Errorf("unable to update role version for adding grant: %w", err)
				}
				if rowsUpdated != 1 {
					return fmt.Errorf("updated role but %d rows updated", rowsUpdated)
				}

				msgs = append(msgs, &roleOplogMsg)

				roleGrant, err := NewRoleGrant(rolePublicId, "id=*;actions=*")
				if err != nil {
					return fmt.Errorf("unable to create in memory role grant: %w", err)
				}
				roleGrantOplogMsgs := make([]*oplog.Message, 0, 1)
				if err := w.CreateItems(ctx, []interface{}{roleGrant}, db.NewOplogMsgs(&roleGrantOplogMsgs)); err != nil {
					return fmt.Errorf("unable to add grants: %w", err)
				}
				msgs = append(msgs, roleGrantOplogMsgs...)

				rolePrincipal, err := NewUserRole(rolePublicId, userId)
				if err != nil {
					return fmt.Errorf("unable to create in memory role user: %w", err)
				}
				roleUserOplogMsgs := make([]*oplog.Message, 0, 1)
				if err := w.CreateItems(ctx, []interface{}{rolePrincipal}, db.NewOplogMsgs(&roleUserOplogMsgs)); err != nil {
					return fmt.Errorf("unable to add grants: %w", err)
				}
				msgs = append(msgs, roleUserOplogMsgs...)

				metadata := oplog.Metadata{
					"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
					"scope-id":           []string{s.PublicId},
					"scope-type":         []string{s.Type},
					"resource-public-id": []string{role.PublicId},
				}
				if err := w.WriteOplogEntryWith(ctx, childOplogWrapper, roleTicket, metadata, msgs); err != nil {
					return fmt.Errorf("unable to write oplog: %w", err)
				}
			}

			return nil
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create scope: scope %s/%s already exists: %w", scopePublicId, s.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create scope: id %s got error: %w", scopePublicId, err)
	}
	return scopeRaw.(*Scope), nil
}

// UpdateScope will update a scope in the repository and return the written
// scope.  fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// and everything else is ignored.  If no updatable fields are included in the
// fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateScope(ctx context.Context, scope *Scope, version uint32, fieldMaskPaths []string, opt ...Option) (*Scope, int, error) {
	if scope == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: missing scope: %w", db.ErrInvalidParameter)
	}
	if scope.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: missing public id: %w", db.ErrInvalidParameter)
	}
	if contains(fieldMaskPaths, "ParentId") {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: you cannot change a scope's parent: %w", db.ErrInvalidFieldMask)
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"name":        scope.Name,
			"description": scope.Description,
		},
		fieldMaskPaths,
		nil,
	)
	// nada to update, so reload scope from db and return it
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: %w", db.ErrEmptyFieldMask)
	}

	resource, rowsUpdated, err := r.update(ctx, scope, version, dbMask, nullFields)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update scope: %s name %s already exists: %w", scope.PublicId, scope.Name, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: failed for public id %s: %w", scope.PublicId, err)
	}
	return resource.(*Scope), rowsUpdated, err
}

// LookupScope will look up a scope in the repository.  If the scope is not
// found, it will return nil, nil.
func (r *Repository) LookupScope(ctx context.Context, withPublicId string, opt ...Option) (*Scope, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup scope: missing public id %w", db.ErrInvalidParameter)
	}
	scope := allocScope()
	scope.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &scope); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup scope: failed %w fo %s", err, withPublicId)
	}
	return &scope, nil
}

// DeleteScope will delete a scope from the repository
func (r *Repository) DeleteScope(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete scope: missing public id %w", db.ErrInvalidParameter)
	}
	if withPublicId == scope.Global.String() {
		return db.NoRowsAffected, fmt.Errorf("delete scope: invalid to delete global scope: %w", db.ErrInvalidParameter)
	}
	scope := allocScope()
	scope.PublicId = withPublicId
	rowsDeleted, err := r.delete(ctx, &scope)
	if err != nil {
		if errors.Is(err, ErrMetadataScopeNotFound) {
			return 0, nil
		}
		return db.NoRowsAffected, fmt.Errorf("delete scope: failed %w for %s", err, withPublicId)
	}
	return rowsDeleted, nil
}

// ListProjects in an org and supports the WithLimit option.
func (r *Repository) ListProjects(ctx context.Context, withOrgId string, opt ...Option) ([]*Scope, error) {
	if withOrgId == "" {
		return nil, fmt.Errorf("list projects: missing org id %w", db.ErrInvalidParameter)
	}
	var projects []*Scope
	err := r.list(ctx, &projects, "parent_id = ? and type = ?", []interface{}{withOrgId, scope.Project.String()}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	return projects, nil
}

// ListOrgs and supports the WithLimit option.
func (r *Repository) ListOrgs(ctx context.Context, opt ...Option) ([]*Scope, error) {
	var orgs []*Scope
	err := r.list(ctx, &orgs, "parent_id = ? and type = ?", []interface{}{"global", scope.Org.String()}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list orgs: %w", err)
	}
	return orgs, nil
}
