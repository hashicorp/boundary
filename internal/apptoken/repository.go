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
	token.PublicId = id

	var dbInserts []interface{}
	var createdToken appTokenSubtype
	switch {
	case strings.HasPrefix(token.GetScopeId(), globals.GlobalPrefix):
		createdToken, dbInserts, err = r.createAppTokenGlobal(ctx, token)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	case strings.HasPrefix(token.GetScopeId(), globals.OrgPrefix):
		createdToken, dbInserts, err = r.createAppTokenOrg(ctx, token)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	case strings.HasPrefix(token.GetScopeId(), globals.ProjectPrefix):
		createdToken, dbInserts, err = r.createAppTokenProject(ctx, token)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}

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
	dbInserts = append(dbInserts, []*appTokenCipher{atc})

	// batch write all collected inserts
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			for _, appTokenItems := range dbInserts {
				if err := w.CreateItems(ctx, appTokenItems); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating app token in database"))
	}

	newAppToken := createdToken.toAppToken()
	if newAppToken == nil {
		return nil, errors.New(ctx, errors.Internal, op, "failed to convert created app token to domain object")
	}
	newAppToken.Token = cipherToken

	return newAppToken, nil
}

func (r *Repository) createAppTokenGlobal(ctx context.Context, token *AppToken) (*appTokenGlobal, []interface{}, error) {
	const op = "apptoken.(Repository).createAppTokenGlobal"
	var globalInserts []interface{}
	// we collect inserts in their own slices so that we can use w.CreateItems above
	// to batch insert by type (say 10,000 permissions at once)
	var permissionInserts []*appTokenPermissionGlobal
	var permissionGrantInserts []*appTokenPermissionGrant
	var individualOrgInserts []*appTokenPermissionGlobalIndividualOrgGrantScope
	var individualProjInserts []*appTokenPermissionGlobalIndividualProjectGrantScope
	tokenToCreate := &appTokenGlobal{
		AppTokenGlobal: &store.AppTokenGlobal{
			PublicId:           token.PublicId,
			ScopeId:            token.ScopeId,
			Name:               token.Name,
			Description:        token.Description,
			Revoked:            token.Revoked,
			CreatedByUserId:    token.CreatedByUserId,
			TimeToStaleSeconds: token.TimeToStaleSeconds,
			ExpirationTime:     token.ExpirationTime,
		},
	}

	globalInserts = append(globalInserts, []*appTokenGlobal{tokenToCreate})

	// each permission uses the same permission ID for its grants and scopes
	// they're a composite key in the app_token_permission_grant table
	for _, perm := range token.Permissions {
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) && slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "only one of descendants or children grant scope can be specified")
		}
		// perm.GrantedScopes cannot contain globals.GrantScopeDescendants and also contain an individual project or org scope
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) && slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.ProjectPrefix) || strings.HasPrefix(s, globals.OrgPrefix)
		}) {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "descendants grant scope cannot be combined with individual project grant scopes")
		}
		// perm.GrantedScopes cannot contain globals.GrantScopeChildren and also contain an individual org scope
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) && slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.OrgPrefix)
		}) {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "children grant scope cannot be combined with individual org grant scopes")
		}

		// generate new permission ID
		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}

		grantThisScope := slices.Contains(perm.GrantedScopes, globals.GrantScopeThis)
		globalPermGrantScope := determineGrantScope(perm.GrantedScopes)
		globalPermToCreate := &appTokenPermissionGlobal{
			AppTokenPermissionGlobal: &store.AppTokenPermissionGlobal{
				PrivateId:      permId,
				AppTokenId:     token.PublicId,
				GrantThisScope: grantThisScope,
				GrantScope:     globalPermGrantScope,
				Description:    perm.Label,
			},
		}
		permissionInserts = append(permissionInserts, globalPermToCreate)
		// globalInserts = append(globalInserts, globalPermToCreate)

		grantInserts, err := processPermissionGrants(ctx, permId, perm.Grants)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		permissionGrantInserts = append(permissionGrantInserts, grantInserts...)
		// globalInserts = append(globalInserts, grantInserts...)

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
						GrantScope:   globalPermGrantScope,
						ScopeId:      gs,
					},
				}
				individualOrgInserts = append(individualOrgInserts, individualOrgGlobalPermToCreate)
			case strings.HasPrefix(gs, globals.ProjectPrefix):
				individualProjGlobalPermToCreate := &appTokenPermissionGlobalIndividualProjectGrantScope{
					AppTokenPermissionGlobalIndividualProjectGrantScope: &store.AppTokenPermissionGlobalIndividualProjectGrantScope{
						PermissionId: permId,
						GrantScope:   globalPermGrantScope,
						ScopeId:      gs,
					},
				}
				individualProjInserts = append(individualProjInserts, individualProjGlobalPermToCreate)
			default:
				return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid grant scope %s", gs))
			}
		}
	}
	// avoid appending empty slices
	if len(permissionInserts) > 0 {
		globalInserts = append(globalInserts, permissionInserts)
	}
	if len(permissionGrantInserts) > 0 {
		globalInserts = append(globalInserts, permissionGrantInserts)
	}
	if len(individualOrgInserts) > 0 {
		globalInserts = append(globalInserts, individualOrgInserts)
	}
	if len(individualProjInserts) > 0 {
		globalInserts = append(globalInserts, individualProjInserts)
	}

	return tokenToCreate, globalInserts, nil
}

func (r *Repository) createAppTokenOrg(ctx context.Context, token *AppToken) (*appTokenOrg, []interface{}, error) {
	const op = "apptoken.(Repository).createAppTokenOrg"
	var orgInserts []interface{}
	// we collect inserts in their own slices so that we can use w.CreateItems above
	// to batch insert by type (say 10,000 permissions at once)
	var permissionInserts []*appTokenPermissionOrg
	var permissionGrantInserts []*appTokenPermissionGrant
	var individualProjInserts []*appTokenPermissionOrgIndividualGrantScope

	tokenToCreate := &appTokenOrg{
		AppTokenOrg: &store.AppTokenOrg{
			PublicId:           token.PublicId,
			ScopeId:            token.ScopeId,
			Name:               token.Name,
			Description:        token.Description,
			Revoked:            token.Revoked,
			CreatedByUserId:    token.CreatedByUserId,
			TimeToStaleSeconds: token.TimeToStaleSeconds,
			ExpirationTime:     token.ExpirationTime,
		},
	}

	orgInserts = append(orgInserts, []*appTokenOrg{tokenToCreate})

	for _, perm := range token.Permissions {
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "org cannot have descendants grant scope")
		}
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) && slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.ProjectPrefix)
		}) {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "children grant scope cannot be combined with individual project grant scopes")
		}

		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}

		grantThisScope := slices.Contains(perm.GrantedScopes, globals.GrantScopeThis)
		orgPermGrantScope := determineGrantScope(perm.GrantedScopes)

		orgPermToCreate := &appTokenPermissionOrg{
			AppTokenPermissionOrg: &store.AppTokenPermissionOrg{
				PrivateId:      permId,
				AppTokenId:     token.PublicId,
				GrantThisScope: grantThisScope,
				GrantScope:     orgPermGrantScope,
				Description:    perm.Label,
			},
		}

		permissionInserts = append(permissionInserts, orgPermToCreate)

		grantInserts, err := processPermissionGrants(ctx, permId, perm.Grants)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		permissionGrantInserts = append(permissionGrantInserts, grantInserts...)

		for _, gs := range perm.GrantedScopes {
			if gs == globals.GrantScopeThis || gs == globals.GrantScopeChildren {
				continue
			}

			if strings.HasPrefix(gs, globals.ProjectPrefix) {
				individualProjOrgPermToCreate := &appTokenPermissionOrgIndividualGrantScope{
					AppTokenPermissionOrgIndividualGrantScope: &store.AppTokenPermissionOrgIndividualGrantScope{
						PermissionId: permId,
						GrantScope:   orgPermGrantScope,
						ScopeId:      gs,
					},
				}
				individualProjInserts = append(individualProjInserts, individualProjOrgPermToCreate)
			} else {
				return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid grant scope %s", gs))
			}
		}
	}

	if len(permissionInserts) > 0 {
		orgInserts = append(orgInserts, permissionInserts)
	}
	if len(permissionGrantInserts) > 0 {
		orgInserts = append(orgInserts, permissionGrantInserts)
	}
	if len(individualProjInserts) > 0 {
		orgInserts = append(orgInserts, individualProjInserts)
	}

	return tokenToCreate, orgInserts, nil
}

func (r *Repository) createAppTokenProject(ctx context.Context, token *AppToken) (*appTokenProject, []interface{}, error) {
	const op = "apptoken.(Repository).createAppTokenProject"
	var projectInserts []interface{}
	// we collect inserts in their own slices so that we can use w.CreateItems above
	// to batch insert by type (say 10,000 permissions at once)
	var permissionInserts []*appTokenPermissionProject
	var permissionGrantInserts []*appTokenPermissionGrant

	tokenToCreate := &appTokenProject{
		AppTokenProject: &store.AppTokenProject{
			PublicId:           token.PublicId,
			ScopeId:            token.ScopeId,
			Name:               token.Name,
			Description:        token.Description,
			Revoked:            token.Revoked,
			CreatedByUserId:    token.CreatedByUserId,
			TimeToStaleSeconds: token.TimeToStaleSeconds,
			ExpirationTime:     token.ExpirationTime,
		},
	}

	projectInserts = append(projectInserts, []*appTokenProject{tokenToCreate})

	for _, perm := range token.Permissions {
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) || slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "project can only contain individual grant scopes")
		}

		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}

		grantThisScope := slices.Contains(perm.GrantedScopes, globals.GrantScopeThis)

		projPermToCreate := &appTokenPermissionProject{
			AppTokenPermissionProject: &store.AppTokenPermissionProject{
				PrivateId:      permId,
				AppTokenId:     token.PublicId,
				GrantThisScope: grantThisScope,
				Description:    perm.Label,
			},
		}

		permissionInserts = append(permissionInserts, projPermToCreate)

		grantInserts, err := processPermissionGrants(ctx, permId, perm.Grants)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		permissionGrantInserts = append(permissionGrantInserts, grantInserts...)
	}
	if len(permissionInserts) > 0 {
		projectInserts = append(projectInserts, permissionInserts)
	}
	if len(permissionGrantInserts) > 0 {
		projectInserts = append(projectInserts, permissionGrantInserts)
	}

	return tokenToCreate, projectInserts, nil
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

// processPermissionGrants validates grants and creates grant objects for insertion
func processPermissionGrants(ctx context.Context, permId string, grants []string) ([]*appTokenPermissionGrant, error) {
	const op = "apptoken.processPermissionGrants"
	var grantInserts []*appTokenPermissionGrant
	for _, grant := range grants {
		// Validate that the grant parses successfully. Note that we fake the scope
		// here to avoid a lookup as the scope is only relevant at actual ACL
		// checking time and we just care that it parses correctly.
		parsedGrant, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: "o_abcd1234", GrantScopeId: "o_abcd1234", Grant: grant})
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("parsing grant string"))
		}
		permissionGrantToCreate := &appTokenPermissionGrant{
			AppTokenPermissionGrant: &store.AppTokenPermissionGrant{
				PermissionId:   permId,
				CanonicalGrant: parsedGrant.CanonicalString(),
				RawGrant:       grant,
			},
		}
		grantInserts = append(grantInserts, permissionGrantToCreate)
	}
	return grantInserts, nil
}

// determineGrantScope determines the appropriate grant scope value based on granted scopes
func determineGrantScope(grantedScopes []string) string {
	if slices.Contains(grantedScopes, globals.GrantScopeChildren) {
		return globals.GrantScopeChildren
	} else if slices.Contains(grantedScopes, globals.GrantScopeDescendants) {
		return globals.GrantScopeDescendants
	}
	return globals.GrantScopeIndividual
}
