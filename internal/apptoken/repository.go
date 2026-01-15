// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
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

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
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

	switch {
	case strings.HasPrefix(token.GetScopeId(), globals.GlobalPrefix):
		token, err = r.createAppTokenGlobal(ctx, token, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	case strings.HasPrefix(token.GetScopeId(), globals.OrgPrefix):
		token, err = r.createAppTokenOrg(ctx, token, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	case strings.HasPrefix(token.GetScopeId(), globals.ProjectPrefix):
		token, err = r.createAppTokenProject(ctx, token, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}

	cipherToken, err := newAppTokenCipher(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to generate cipher token"))
	}
	token.Token = cipherToken
	atc := &appTokenCipher{
		AppTokenCipher: &store.AppTokenCipher{
			AppTokenId: id,
			Token:      token.Token,
		},
	}
	databaseWrapper, err := r.kms.GetWrapper(context.Background(), token.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := atc.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// insert into app_token_cipher table
	err = r.writeToDb(ctx, atc)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return token, nil
}

func (r *Repository) createAppTokenGlobal(ctx context.Context, token *AppToken, publicId string) (*AppToken, error) {
	const op = "apptoken.(Repository).createAppTokenGlobal"
	tokenToCreate := &appTokenGlobal{
		AppTokenGlobal: &store.AppTokenGlobal{
			PublicId:           publicId,
			ScopeId:            token.ScopeId,
			Name:               token.Name,
			Description:        token.Description,
			Revoked:            token.Revoked,
			CreatedByUserId:    token.CreatedByUserId,
			TimeToStaleSeconds: token.TimeToStaleSeconds,
		},
	}

	// insert into app_token_global table
	err := r.writeToDb(ctx, tokenToCreate)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating app token"))
	}
	if err := r.reader.LookupByPublicId(ctx, tokenToCreate); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("app token lookup"))
	}
	token.PublicId = tokenToCreate.PublicId
	token.ApproximateLastAccessTime = tokenToCreate.ApproximateLastAccessTime
	token.CreateTime = tokenToCreate.CreateTime
	token.ExpirationTime = tokenToCreate.ExpirationTime
	token.Revoked = tokenToCreate.Revoked
	// each permission uses the same permission ID for its grants and scopes
	// they're a composite key in the app_token_permission_grant table
	for _, perm := range token.Permissions {
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) && slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "only one of descendants or children grant scope can be specified")
		}
		// perm.GrantedScopes cannot contain globals.GrantScopeDescendants and also contain an individual proj function
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) && slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.ProjectPrefix)
		}) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "descendants grant scope cannot be combined with individual project grant scopes")
		}
		// perm.GrantedScopes cannot contain globals.GrantScopeChildren and also contain an individual org function
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

		grantThisScope := slices.Contains(perm.GrantedScopes, "this")
		// if perm.GrantedScopes contains "children", set globalPermGrantScope to "children"
		// if perm.GrantedScopes contains "descendants", set globalPermGrantScope to "descendants"
		// if perm.GrantedScopes contains neither but does have at least one individual org or project,
		// set globalPermGrantScope to "individual" and create individual grant scope entries below
		globalPermGrantScope := "individual"
		if slices.Contains(perm.GrantedScopes, "children") {
			globalPermGrantScope = "children"
		} else if slices.Contains(perm.GrantedScopes, "descendants") {
			globalPermGrantScope = "descendants"
		}

		globalPermToCreate := &appTokenPermissionGlobal{
			AppTokenPermissionGlobal: &store.AppTokenPermissionGlobal{
				PrivateId:      permId,
				AppTokenId:     publicId,
				GrantThisScope: grantThisScope,
				GrantScope:     globalPermGrantScope,
			},
		}

		err = r.writeToDb(ctx, globalPermToCreate)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken global permission"))
		}

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
			err = r.writeToDb(ctx, permissionGrantToCreate)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken permission grant"))
			}
		}

		for _, gs := range perm.GrantedScopes {
			if gs == "this" || gs == "children" || gs == "descendants" || globalPermGrantScope == "descendants" {
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
				err = r.writeToDb(ctx, individualOrgGlobalPermToCreate)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken individual org grant scope"))
				}
			case strings.HasPrefix(gs, globals.ProjectPrefix):
				individualProjGlobalPermToCreate := &appTokenPermissionGlobalIndividualProjectGrantScope{
					AppTokenPermissionGlobalIndividualProjectGrantScope: &store.AppTokenPermissionGlobalIndividualProjectGrantScope{
						PermissionId: permId,
						GrantScope:   globalPermGrantScope,
						ScopeId:      gs,
					},
				}
				err = r.writeToDb(ctx, individualProjGlobalPermToCreate)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken individual project grant scope"))
				}
			default:
				return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid grant scope")
			}
		}
	}
	return token, nil
}

func (r *Repository) createAppTokenOrg(ctx context.Context, token *AppToken, publicId string) (*AppToken, error) {
	const op = "apptoken.(Repository).createAppTokenOrg"
	tokenToCreate := &appTokenOrg{
		AppTokenOrg: &store.AppTokenOrg{
			PublicId:           publicId,
			ScopeId:            token.ScopeId,
			Name:               token.Name,
			Description:        token.Description,
			Revoked:            token.Revoked,
			CreatedByUserId:    token.CreatedByUserId,
			TimeToStaleSeconds: token.TimeToStaleSeconds,
		},
	}

	// insert into app_token_org table
	err := r.writeToDb(ctx, tokenToCreate)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating app token"))
	}
	if err := r.reader.LookupByPublicId(ctx, tokenToCreate); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("app token lookup"))
	}
	token.PublicId = tokenToCreate.PublicId
	token.ApproximateLastAccessTime = tokenToCreate.ApproximateLastAccessTime
	token.CreateTime = tokenToCreate.CreateTime
	token.ExpirationTime = tokenToCreate.ExpirationTime
	token.Revoked = tokenToCreate.Revoked
	// each permission uses the same permission ID for its grants and scopes
	// they're a composite key in the app_token_permission_grant table
	for _, perm := range token.Permissions {
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "org cannot have descendants grant scope")
		}

		// generate new permission ID
		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		grantThisScope := slices.Contains(perm.GrantedScopes, "this")
		// if perm.GrantedScopes contains "children", set orgPermGrantScope to "children"
		// if perm.GrantedScopes contains neither but does have at least one individual project,
		// set orgPermGrantScope to "individual" and create individual grant scope entries below
		orgPermGrantScope := "individual"
		if slices.Contains(perm.GrantedScopes, "children") {
			orgPermGrantScope = "children"
		}

		orgPermToCreate := &appTokenPermissionOrg{
			AppTokenPermissionOrg: &store.AppTokenPermissionOrg{
				PrivateId:      permId,
				AppTokenId:     publicId,
				GrantThisScope: grantThisScope,
				GrantScope:     orgPermGrantScope,
			},
		}

		err = r.writeToDb(ctx, orgPermToCreate)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken org permission"))
		}

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
			err = r.writeToDb(ctx, permissionGrantToCreate)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken permission grant"))
			}
		}

		for _, gs := range perm.GrantedScopes {
			if gs == "this" || gs == "children" {
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
				err = r.writeToDb(ctx, individualProjOrgPermToCreate)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken individual project grant scope"))
				}
			} else {
				return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid grant scope")
			}
		}
	}
	return token, nil
}

func (r *Repository) createAppTokenProject(ctx context.Context, token *AppToken, publicId string) (*AppToken, error) {
	const op = "apptoken.(Repository).createAppTokenProject"
	tokenToCreate := &appTokenProject{
		AppTokenProject: &store.AppTokenProject{
			PublicId:           publicId,
			ScopeId:            token.ScopeId,
			Name:               token.Name,
			Description:        token.Description,
			Revoked:            token.Revoked,
			CreatedByUserId:    token.CreatedByUserId,
			TimeToStaleSeconds: token.TimeToStaleSeconds,
		},
	}

	// insert into app_token_org table
	err := r.writeToDb(ctx, tokenToCreate)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating app token"))
	}
	if err := r.reader.LookupByPublicId(ctx, tokenToCreate); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("app token lookup"))
	}
	token.PublicId = tokenToCreate.PublicId
	token.ApproximateLastAccessTime = tokenToCreate.ApproximateLastAccessTime
	token.CreateTime = tokenToCreate.CreateTime
	token.ExpirationTime = tokenToCreate.ExpirationTime
	token.Revoked = tokenToCreate.Revoked
	// each permission uses the same permission ID for its grants and scopes
	// they're a composite key in the app_token_permission_grant table
	for _, perm := range token.Permissions {
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) || slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "project can only contain individual grant scopes")
		}

		// generate new permission ID
		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		grantThisScope := slices.Contains(perm.GrantedScopes, "this")
		projPermToCreate := &appTokenPermissionProject{
			AppTokenPermissionProject: &store.AppTokenPermissionProject{
				PrivateId:      permId,
				AppTokenId:     publicId,
				GrantThisScope: grantThisScope,
			},
		}

		err = r.writeToDb(ctx, projPermToCreate)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken project permission"))
		}

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
			err = r.writeToDb(ctx, permissionGrantToCreate)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("while creating apptoken permission grant"))
			}
		}
	}
	return token, nil
}

func (r *Repository) writeToDb(ctx context.Context, tokenToCreate interface{}) error {
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			if err := w.Create(ctx, tokenToCreate); err != nil {
				return err
			}
			return nil
		},
	)
	return err
}
