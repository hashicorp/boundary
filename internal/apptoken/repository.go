// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
)

// Repository is the apptoken database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepository creates a new apptoken Repository
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "apptoken.NewRepository"
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}

	return &Repository{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}

// CreateToken creates the provided app token in the repository.
func (r *Repository) CreateAppToken(ctx context.Context, token *AppToken) (*AppToken, error) {
	const op = "apptoken.(Repository).CreateToken"
	if token == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token")
	}

	id, err := newAppTokenId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var globalAppToken *appTokenGlobal
	dbInserts := make([]interface{}, 0)
	switch {
	case strings.HasPrefix(token.GetScopeId(), globals.GlobalPrefix):
		globalAppToken = &appTokenGlobal{
			AppTokenGlobal: &store.AppTokenGlobal{
				PublicId:           id,
				ScopeId:            token.ScopeId,
				Name:               token.Name,
				Description:        token.Description,
				Revoked:            token.Revoked,
				CreatedByUserId:    token.CreatedByUserId,
				TimeToStaleSeconds: token.TimeToStaleSeconds,
				ExpirationTime:     token.ExpirationTime,
			},
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}
	// collect for batch insert
	dbInserts = append(dbInserts, globalAppToken)

	cipherToken, err := newToken(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to generate cipher token"))
	}
	atc := &appTokenCipher{
		AppTokenCipher: &store.AppTokenCipher{
			AppTokenId: id,
			Token:      cipherToken,
		},
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, token.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := atc.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	dbInserts = append(dbInserts, atc)

	// each permission uses the same permission ID for its grants and scopes
	// they're a composite key in the app_token_permission_grant table
	for _, perm := range token.Permissions {
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) && slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "only one of descendants or children grant scope can be specified")
		}
		// perm.GrantedScopes cannot contain globals.GrantScopeDescendants and also contain an individual project or org scope
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) && slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.ProjectPrefix) || strings.HasPrefix(s, globals.OrgPrefix)
		}) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "descendants grant scope cannot be combined with individual project grant scopes")
		}
		// perm.GrantedScopes cannot contain globals.GrantScopeChildren and also contain an individual org scope
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) && slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.OrgPrefix)
		}) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "children grant scope cannot be combined with individual org grant scopes")
		}

		// generate new permission ID
		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		grantThisScope := slices.Contains(perm.GrantedScopes, globals.GrantScopeThis)
		// if perm.GrantedScopes contains "children", set globalPermGrantScope to "children"
		// if perm.GrantedScopes contains "descendants", set globalPermGrantScope to "descendants"
		// if perm.GrantedScopes contains neither but does have at least one individual org or project,
		// set globalPermGrantScope to "individual" and create individual grant scope entries below
		globalPermGrantScope := globals.GrantScopeIndividual
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) {
			globalPermGrantScope = globals.GrantScopeChildren
		} else if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) {
			globalPermGrantScope = globals.GrantScopeDescendants
		}

		globalPermToCreate := &appTokenPermissionGlobal{
			AppTokenPermissionGlobal: &store.AppTokenPermissionGlobal{
				PrivateId:      permId,
				AppTokenId:     id,
				GrantThisScope: grantThisScope,
				GrantScope:     globalPermGrantScope,
				Description:    perm.Label,
			},
		}
		dbInserts = append(dbInserts, globalPermToCreate)

		for _, grant := range perm.Grants {
			// Validate that the grant parses successfully. Note that we fake the scope
			// here to avoid a lookup as the scope is only relevant at actual ACL
			// checking time and we just care that it parses correctly.
			parsedGrant, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: "o_abcd1234", GrantScopeId: "o_abcd1234", Grant: grant})
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("parsing grant string"))
			}
			// insert each grant in the permission to app_token_permission_grant
			permissionGrantToCreate := &appTokenPermissionGrant{
				AppTokenPermissionGrant: &store.AppTokenPermissionGrant{
					PermissionId:   permId,
					CanonicalGrant: parsedGrant.CanonicalString(),
					RawGrant:       grant,
				},
			}
			dbInserts = append(dbInserts, permissionGrantToCreate)
		}

		for _, gs := range perm.GrantedScopes {
			if gs == globals.GrantScopeThis ||
				gs == globals.GrantScopeChildren ||
				gs == globals.GrantScopeDescendants {
				continue
			}
			switch {
			case strings.HasPrefix(gs, globals.OrgPrefix):
				individualOrgGlobalPermToCreate := &appTokenPermissionGlobalIndividualOrgGrantScope{
					AppTokenPermissionGlobalIndividualOrgGrantScope: &store.AppTokenPermissionGlobalIndividualOrgGrantScope{
						PermissionId: permId,
						// this can only ever be individual for individual orgs in global grant scopes
						GrantScope: globalPermGrantScope,
						ScopeId:    gs,
					},
				}
				dbInserts = append(dbInserts, individualOrgGlobalPermToCreate)
			case strings.HasPrefix(gs, globals.ProjectPrefix):
				individualProjGlobalPermToCreate := &appTokenPermissionGlobalIndividualProjectGrantScope{
					AppTokenPermissionGlobalIndividualProjectGrantScope: &store.AppTokenPermissionGlobalIndividualProjectGrantScope{
						PermissionId: permId,
						GrantScope:   globalPermGrantScope,
						ScopeId:      gs,
					},
				}
				dbInserts = append(dbInserts, individualProjGlobalPermToCreate)
			default:
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid grant scope %s", gs))
			}
		}
	}

	// batch write all collected inserts
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			for _, appTokenObject := range dbInserts {
				if err := w.Create(ctx, appTokenObject); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating app token in database"))
	}

	newAppToken := &AppToken{
		PublicId:                  globalAppToken.PublicId,
		ScopeId:                   globalAppToken.ScopeId,
		ApproximateLastAccessTime: globalAppToken.ApproximateLastAccessTime,
		CreateTime:                globalAppToken.CreateTime,
		ExpirationTime:            globalAppToken.ExpirationTime,
		Revoked:                   globalAppToken.Revoked,
		Name:                      globalAppToken.Name,
		Description:               globalAppToken.Description,
		CreatedByUserId:           globalAppToken.CreatedByUserId,
		TimeToStaleSeconds:        globalAppToken.TimeToStaleSeconds,
		Permissions:               token.Permissions,
		Token:                     cipherToken,
	}
	return newAppToken, nil
}

// TODO: Implement additional fields in AppToken and complete this method
// getAppTokenById retrieves an AppToken by its public ID
func (r *Repository) getAppTokenById(ctx context.Context, id string) (*AppToken, error) {
	const op = "apptoken.(Repository).getAppTokenById"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing id")
	}

	rows, err := r.reader.Query(ctx, getAppTokenByIdQuery, []any{id})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var at AppToken
	if rows.Next() {
		if err := rows.Scan(&at.PublicId, &at.ScopeId); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if at.PublicId == "" {
		return nil, errors.New(ctx, errors.NotFound, op, "app token not found")
	}
	return &at, nil
}
