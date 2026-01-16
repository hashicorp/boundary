// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"crypto/rand"
	"database/sql"
	stderr "errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateScope will create a scope in the repository and return the written
// scope. Supported options include: WithPublicId and WithRandomReader.
func (r *Repository) CreateScope(ctx context.Context, s *Scope, userId string, opt ...Option) (*Scope, error) {
	const op = "iam.(Repository).CreateScope"
	if s == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope")
	}
	if s.Scope == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope store")
	}
	if s.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}

	var parentOplogWrapper wrapping.Wrapper
	var err error
	switch s.Type {
	case scope.Unknown.String():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown type")
	case scope.Global.String():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid type")
	default:
		switch s.ParentId {
		case "":
			return nil, errors.New(ctx, errors.InvalidParameter, op, "missing parent id")
		case scope.Global.String():
			parentOplogWrapper, err = r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
		default:
			parentOplogWrapper, err = r.kms.GetWrapper(ctx, s.ParentId, kms.KeyPurposeOplog)
		}
	}
	if err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to get oplog wrapper")
	}

	opts := getOpts(opt...)

	var scopePublicId string
	var scopeMetadata oplog.Metadata
	var scopeRaw any
	{
		scopeType := scope.Map[s.Type]
		if opts.withPublicId != "" {
			if !strings.HasPrefix(opts.withPublicId, scopeType.Prefix()+"_") {
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix for type %q which uses prefix %q", opts.withPublicId, scopeType.String(), scopeType.Prefix()))
			}
			scopePublicId = opts.withPublicId
		} else {
			scopePublicId, err = newScopeId(ctx, scopeType)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
		}
		sc := s.Clone().(*Scope)
		sc.PublicId = scopePublicId
		scopeRaw = sc
		scopeMetadata, err = r.stdMetadata(ctx, sc)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		scopeMetadata["op-type"] = []string{oplog.OpType_OP_TYPE_CREATE.String()}
	}

	var adminRolePublicId string
	var adminRoleMetadata oplog.Metadata
	var adminRole Resource
	var adminRoleRaw any
	switch {
	case userId == "",
		userId == globals.AnonymousUserId,
		userId == globals.AnyAuthenticatedUserId,
		userId == globals.RecoveryUserId,
		opts.withSkipAdminRoleCreation:
		// TODO: Cause a log entry. The repo doesn't have a logger right now,
		// and ideally we will be using context to pass around log info scoped
		// to this request for grouped display in the server log. The only
		// reason this should ever happen anyways is via the administrative
		// recovery workflow so it's already a special case.

		// Also, stop linter from complaining
		_ = adminRole

	default:
		adminRolePublicId, err = newRoleId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating public id for new admin role"))
		}
		switch s.Type {
		case scope.Global.String():
			adminRole = &globalRole{
				GlobalRole: &store.GlobalRole{
					PublicId:           adminRolePublicId,
					ScopeId:            scopePublicId,
					Name:               "Administration",
					Description:        fmt.Sprintf("Role created for administration of scope %s by user %s at its creation time", scopePublicId, userId),
					GrantThisRoleScope: true,
					GrantScope:         globals.GrantScopeIndividual,
				},
			}
		case scope.Org.String():
			adminRole = &orgRole{
				OrgRole: &store.OrgRole{
					PublicId:           adminRolePublicId,
					ScopeId:            scopePublicId,
					Name:               "Administration",
					Description:        fmt.Sprintf("Role created for administration of scope %s by user %s at its creation time", scopePublicId, userId),
					GrantThisRoleScope: true,
					GrantScope:         globals.GrantScopeIndividual,
				},
			}
		case scope.Project.String():
			adminRole = &projectRole{
				ProjectRole: &store.ProjectRole{
					PublicId:           adminRolePublicId,
					ScopeId:            scopePublicId,
					GrantThisRoleScope: true,
					Name:               "Administration",
					Description:        fmt.Sprintf("Role created for administration of scope %s by user %s at its creation time", scopePublicId, userId),
				},
			}
		}

		adminRoleRaw = adminRole
		adminRoleMetadata = oplog.Metadata{
			"resource-public-id": []string{adminRolePublicId},
			"scope-id":           []string{scopePublicId},
			"scope-type":         []string{s.Type},
			"resource-type":      []string{resource.Role.String()},
			"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
		}
	}

	var defaultRolePublicId string
	var defaultRoleMetadata oplog.Metadata
	var defaultRole Resource
	var defaultRoleRaw any
	if !opts.withSkipDefaultRoleCreation {
		defaultRolePublicId, err = newRoleId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating public id for new default role"))
		}
		switch s.Type {
		case scope.Global.String():
			defaultRole = &globalRole{
				GlobalRole: &store.GlobalRole{
					PublicId:           defaultRolePublicId,
					ScopeId:            scopePublicId,
					Name:               "Login and Default Grants",
					Description:        fmt.Sprintf("Role created for login capability, account self-management, and other default grants for users of scope %s at its creation time", scopePublicId),
					GrantThisRoleScope: true,
					GrantScope:         globals.GrantScopeIndividual,
				},
			}
		case scope.Org.String():
			defaultRole = &orgRole{
				OrgRole: &store.OrgRole{
					PublicId:           defaultRolePublicId,
					ScopeId:            scopePublicId,
					Name:               "Login and Default Grants",
					Description:        fmt.Sprintf("Role created for login capability, account self-management, and other default grants for users of scope %s at its creation time", scopePublicId),
					GrantThisRoleScope: true,
					GrantScope:         globals.GrantScopeIndividual,
				},
			}
		case scope.Project.String():
			defaultRole = &projectRole{
				ProjectRole: &store.ProjectRole{
					PublicId:           defaultRolePublicId,
					ScopeId:            scopePublicId,
					Name:               "Default Grants",
					GrantThisRoleScope: true,
					Description:        fmt.Sprintf("Role created to provide default grants to users of scope %s at its creation time", scopePublicId),
				},
			}
		}
		defaultRoleRaw = defaultRole
		defaultRoleMetadata = oplog.Metadata{
			"resource-public-id": []string{defaultRolePublicId},
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
				return errors.Wrap(ctx, err, op, errors.WithMsg("error creating scope"))
			}

			s := scopeRaw.(*Scope)

			txnKms, err := kms.NewUsingReaderWriter(ctx, dbr, w)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error creating transaction's kms"))
			}
			if err := txnKms.AddExternalWrappers(ctx, kms.WithRootWrapper(r.kms.GetExternalWrappers(ctx).Root())); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error adding external root wrapper to transaction's kms"))
			}
			if err := txnKms.CreateKeys(ctx, s.PublicId, kms.WithRandomReader(reader), kms.WithReaderWriter(dbr, w)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error creating scope keys"))
			}
			childOplogWrapper, err := txnKms.GetWrapper(ctx, s.PublicId, kms.KeyPurposeOplog)
			if err != nil {
				return errors.New(ctx, errors.InvalidParameter, op, "unable to get oplog wrapper")
			}

			// We create a new role, then set grants and principals on it. This
			// turns into a bunch of stuff sadly because the role is the
			// aggregate.
			if adminRoleRaw != nil {
				if err := w.Create(
					ctx,
					adminRoleRaw,
					db.WithOplog(childOplogWrapper, adminRoleMetadata),
				); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("error creating role"))
				}

				var adminRoleVersion uint32
				switch s.Type {
				case scope.Global.String():
					adminRoleVersion = adminRoleRaw.(*globalRole).GetVersion()
					adminRole = adminRoleRaw.(*globalRole)
				case scope.Org.String():
					adminRoleVersion = adminRoleRaw.(*orgRole).GetVersion()
					adminRole = adminRoleRaw.(*orgRole)
				case scope.Project.String():
					adminRoleVersion = adminRoleRaw.(*projectRole).GetVersion()
					adminRole = adminRoleRaw.(*projectRole)
				}
				msgs := make([]*oplog.Message, 0, 4)
				roleTicket, err := w.GetTicket(ctx, adminRole)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
				}

				// We need to update the role version as that's the aggregate
				var roleOplogMsg oplog.Message
				rowsUpdated, err := w.Update(ctx, adminRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&adminRoleVersion))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version for adding grant"))
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role but %d rows updated", rowsUpdated))
				}

				msgs = append(msgs, &roleOplogMsg)

				roleGrant, err := NewRoleGrant(ctx, adminRolePublicId, "ids=*;type=*;actions=*")
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
				}
				roleGrantOplogMsgs := make([]*oplog.Message, 0, 1)
				if err := w.CreateItems(ctx, []*RoleGrant{roleGrant}, db.NewOplogMsgs(&roleGrantOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
				}
				msgs = append(msgs, roleGrantOplogMsgs...)

				rolePrincipal, err := NewUserRole(ctx, adminRolePublicId, userId)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role user"))
				}
				roleUserOplogMsgs := make([]*oplog.Message, 0, 1)
				if err := w.CreateItems(ctx, []*UserRole{rolePrincipal}, db.NewOplogMsgs(&roleUserOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
				}
				msgs = append(msgs, roleUserOplogMsgs...)

				metadata := oplog.Metadata{
					"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
					"scope-id":           []string{s.PublicId},
					"scope-type":         []string{s.Type},
					"resource-public-id": []string{adminRole.GetPublicId()},
				}
				if err := w.WriteOplogEntryWith(ctx, childOplogWrapper, roleTicket, metadata, msgs); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
				}
			}

			// We create a new role, then set grants and principals on it. This
			// turns into a bunch of stuff sadly because the role is the
			// aggregate.
			if defaultRoleRaw != nil {
				if err := w.Create(
					ctx,
					defaultRoleRaw,
					db.WithOplog(childOplogWrapper, defaultRoleMetadata),
				); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("error creating role"))
				}

				var defaultRoleVersion uint32
				switch s.Type {
				case scope.Global.String():
					defaultRoleVersion = defaultRoleRaw.(*globalRole).GetVersion()
				case scope.Org.String():
					defaultRoleVersion = defaultRoleRaw.(*orgRole).GetVersion()
				case scope.Project.String():
					defaultRoleVersion = defaultRoleRaw.(*projectRole).GetVersion()
				}

				msgs := make([]*oplog.Message, 0, 7)
				roleTicket, err := w.GetTicket(ctx, defaultRole)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
				}

				// We need to update the role version as that's the aggregate
				var roleOplogMsg oplog.Message
				rowsUpdated, err := w.Update(ctx, defaultRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&defaultRoleVersion))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version for adding grant"))
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role but %d rows updated", rowsUpdated))
				}
				msgs = append(msgs, &roleOplogMsg)

				// Grants
				{
					grants := []*RoleGrant{}

					switch s.Type {
					case scope.Project.String():
						roleGrant, err := NewRoleGrant(ctx, defaultRolePublicId, "ids=*;type=session;actions=list,read:self,cancel:self")
						if err != nil {
							return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
						}
						grants = append(grants, roleGrant)

						roleGrant, err = NewRoleGrant(ctx, defaultRolePublicId, "type=target;actions=list")
						if err != nil {
							return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
						}
						grants = append(grants, roleGrant)

					default:
						roleGrant, err := NewRoleGrant(ctx, defaultRolePublicId, "ids=*;type=scope;actions=list,no-op")
						if err != nil {
							return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
						}
						grants = append(grants, roleGrant)

						roleGrant, err = NewRoleGrant(ctx, defaultRolePublicId, "ids=*;type=auth-method;actions=authenticate,list")
						if err != nil {
							return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
						}
						grants = append(grants, roleGrant)

						roleGrant, err = NewRoleGrant(ctx, defaultRolePublicId, "ids={{.Account.Id}};actions=read,change-password")
						if err != nil {
							return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
						}
						grants = append(grants, roleGrant)

						roleGrant, err = NewRoleGrant(ctx, defaultRolePublicId, "ids=*;type=auth-token;actions=list,read:self,delete:self")
						if err != nil {
							return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
						}
						grants = append(grants, roleGrant)
					}

					roleGrantOplogMsgs := make([]*oplog.Message, 0, 3)
					if err := w.CreateItems(ctx, grants, db.NewOplogMsgs(&roleGrantOplogMsgs)); err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
					}
					msgs = append(msgs, roleGrantOplogMsgs...)
				}

				// Principals
				{
					principals := []*UserRole{}
					userId := globals.AnonymousUserId
					if s.Type == scope.Project.String() {
						userId = globals.AnyAuthenticatedUserId
					}
					rolePrincipal, err := NewUserRole(ctx, defaultRolePublicId, userId)
					if err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role user"))
					}
					principals = append(principals, rolePrincipal)

					roleUserOplogMsgs := make([]*oplog.Message, 0, 2)
					if err := w.CreateItems(ctx, principals, db.NewOplogMsgs(&roleUserOplogMsgs)); err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
					}
					msgs = append(msgs, roleUserOplogMsgs...)
				}

				metadata := oplog.Metadata{
					"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
					"scope-id":           []string{s.PublicId},
					"scope-type":         []string{s.Type},
					"resource-public-id": []string{defaultRole.GetPublicId()},
				}
				if err := w.WriteOplogEntryWith(ctx, childOplogWrapper, roleTicket, metadata, msgs); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
				}
			}

			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("scope %s/%s already exists", scopePublicId, s.Name))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", scopePublicId)))
	}
	return scopeRaw.(*Scope), nil
}

// UpdateScope will update a scope in the repository and return the written
// scope.  fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// and everything else is ignored.  If no updatable fields are included in the
// fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateScope(ctx context.Context, scope *Scope, version uint32, fieldMaskPaths []string, _ ...Option) (*Scope, int, error) {
	const op = "iam.(Repository).UpdateScope"
	if scope == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope")
	}
	if scope.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if contains(fieldMaskPaths, "ParentId") {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, "you cannot change a scope's parent")
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"name":                scope.Name,
			"description":         scope.Description,
			"PrimaryAuthMethodId": scope.PrimaryAuthMethodId, // gorm: it's important that the field start with a capital letter.
		},
		fieldMaskPaths,
		nil,
	)
	// nada to update, so reload scope from db and return it
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.E(ctx, errors.WithCode(errors.EmptyFieldMask), errors.WithOp(op))
	}
	resource, rowsUpdated, err := r.update(ctx, scope, version, dbMask, nullFields)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("%s name %s already exists", scope.PublicId, scope.Name))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for public id %s", scope.PublicId)))
	}
	var childComponentErrs error
	item := resource.(*Scope)
	if err := setScopeStoragePolicyId(ctx, r.reader, item); err != nil && !errors.IsNotFoundError(err) {
		childComponentErrs = stderr.Join(err)
	}
	if childComponentErrs != nil {
		return nil, rowsUpdated, errors.Wrap(ctx, childComponentErrs, op, errors.WithMsg(fmt.Sprintf("failed to fetch one or more child components for %s", item.PublicId)))
	}
	return resource.(*Scope), rowsUpdated, nil
}

// LookupScope will look up a scope in the repository.  If the scope is not
// found, it will return nil, nil.
func (r *Repository) LookupScope(ctx context.Context, withPublicId string, _ ...Option) (*Scope, error) {
	const op = "iam.(Repository).LookupScope"
	if withPublicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	scope := AllocScope()
	scope.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &scope); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", withPublicId)))
	}
	var childComponentErrs error
	if err := setScopeStoragePolicyId(ctx, r.reader, &scope); err != nil && !errors.IsNotFoundError(err) {
		childComponentErrs = stderr.Join(err)
	}
	if childComponentErrs != nil {
		return nil, errors.Wrap(ctx, childComponentErrs, op, errors.WithMsg(fmt.Sprintf("failed to fetch one or more child components for %s", scope.PublicId)))
	}
	return &scope, nil
}

// DeleteScope will delete a scope from the repository
func (r *Repository) DeleteScope(ctx context.Context, withPublicId string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteScope"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if withPublicId == scope.Global.String() {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "invalid to delete global scope")
	}
	scope := AllocScope()
	scope.PublicId = withPublicId
	rowsDeleted, err := r.delete(ctx, &scope)
	if err != nil {
		if errors.Is(err, ErrMetadataScopeNotFound) {
			return 0, nil
		}
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", withPublicId)))
	}
	return rowsDeleted, nil
}

// listScopes lists scopes in the given scopes and supports WithLimit option.
func (r *Repository) listScopes(ctx context.Context, withParentIds []string, opt ...Option) ([]*Scope, time.Time, error) {
	const op = "iam.(Repository).listScopes"
	if len(withParentIds) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing parent id")
	}
	opts := getOpts(opt...)

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "parent_id in @parent_ids"
	args = append(args, sql.Named("parent_ids", withParentIds))

	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}
	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc")}
	scopes, t, err := r.queryScopes(ctx, whereClause, args, dbOpts...)
	if err != nil {
		return scopes, t, err
	}

	var childComponentErrs error
	for _, scope := range scopes {
		if err := setScopeStoragePolicyId(ctx, r.reader, scope); err != nil && !errors.IsNotFoundError(err) {
			childComponentErrs = stderr.Join(err)
		}
	}
	if childComponentErrs != nil {
		return scopes, t, errors.Wrap(ctx, childComponentErrs, op, errors.WithMsg("failed to fetch one or more child components"))
	}

	return scopes, t, nil
}

// listScopesRefresh lists scopes in the given scopes and supports the
// WithLimit and WithStartPageAfterItem options.
func (r *Repository) listScopesRefresh(ctx context.Context, updatedAfter time.Time, withParentIds []string, opt ...Option) ([]*Scope, time.Time, error) {
	const op = "iam.(Repository).listScopesRefresh"

	switch {
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")

	case len(withParentIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing parent id")
	}

	opts := getOpts(opt...)

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "update_time > @updated_after_time and parent_id in @parent_ids"
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
		sql.Named("parent_ids", withParentIds),
	)
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(update_time, public_id) < (@last_item_update_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("update_time desc, public_id desc")}
	scopes, t, err := r.queryScopes(ctx, whereClause, args, dbOpts...)
	if err != nil {
		return scopes, t, err
	}

	var childComponentErrs error
	for _, scope := range scopes {
		if err := setScopeStoragePolicyId(ctx, r.reader, scope); err != nil && !errors.IsNotFoundError(err) {
			childComponentErrs = stderr.Join(err)
		}
	}
	if childComponentErrs != nil {
		return scopes, t, errors.Wrap(ctx, childComponentErrs, op, errors.WithMsg("failed to fetch one or more child components"))
	}

	return scopes, t, nil
}

func (r *Repository) queryScopes(ctx context.Context, whereClause string, args []any, opt ...db.Option) ([]*Scope, time.Time, error) {
	const op = "iam.(Repository).queryScopes"

	var transactionTimestamp time.Time
	var ret []*Scope
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		var inRet []*Scope
		if err := rd.SearchWhere(ctx, &inRet, whereClause, args, opt...); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		ret = inRet
		var err error
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return ret, transactionTimestamp, nil
}

// ListScopesRecursively allows for recursive listing of scopes based on a root scope
// ID. It returns the root scope ID as a part of the set.
func (r *Repository) ListScopesRecursively(ctx context.Context, rootScopeId string, opt ...Option) ([]*Scope, error) {
	const op = "iam.(Repository).ListRecursively"
	var scopes []*Scope
	var where string
	var args []any
	switch {
	case rootScopeId == scope.Global.String():
		// Nothing -- we want all scopes
	case strings.HasPrefix(rootScopeId, "o_"):
		// The org itself and any projects that have it as parent
		where = "public_id = ? or parent_id = ?"
		args = append(args, rootScopeId, rootScopeId)
	case strings.HasPrefix(rootScopeId, "p_"):
		// No scopes can (currently) live under projects, so just the project
		// itself
		where = "public_id = ?"
		args = append(args, rootScopeId)
	default:
		// We have no idea what scope type this is so bail
		return nil, errors.New(ctx, errors.InvalidPublicId, op+":TypeSwitch", "invalid scope ID")
	}
	err := r.list(ctx, &scopes, where, args, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op+":ListQuery")
	}
	var childComponentErrs error
	for _, scope := range scopes {
		if err := setScopeStoragePolicyId(ctx, r.reader, scope); err != nil && !errors.IsNotFoundError(err) {
			childComponentErrs = stderr.Join(err)
		}
	}
	if childComponentErrs != nil {
		return nil, errors.Wrap(ctx, childComponentErrs, op, errors.WithMsg("failed to fetch one or more child components"))
	}
	return scopes, nil
}

// listScopeDeletedIds lists the public IDs of any scopes deleted since the timestamp provided.
func (r *Repository) listScopeDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "iam.(Repository).listScopeDeletedIds"
	var deletedScopes []*deletedScope
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedScopes, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted scopes"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var scopeIds []string
	for _, user := range deletedScopes {
		scopeIds = append(scopeIds, user.PublicId)
	}
	return scopeIds, transactionTimestamp, nil
}

// estimatedScopeCount returns and estimate of the total number of items in the scopes table.
func (r *Repository) estimatedScopeCount(ctx context.Context) (int, error) {
	const op = "iam.(Repository).estimatedScopeCount"
	rows, err := r.reader.Query(ctx, estimateCountScopes, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total scopes"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total scopes"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total scopes"))
	}
	return count, nil
}
