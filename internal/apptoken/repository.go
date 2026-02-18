// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/util"
)

// Repository is the apptoken database repository
type Repository struct {
	reader       db.Reader
	writer       db.Writer
	kms          *kms.Kms
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

// lookupAppTokenResults represents the raw result of the app token lookup queries: [getAppTokenGlobalQuery], [getAppTokenOrgQuery], and [getAppTokenProjectQuery]
type lookupAppTokenResult struct {
	publicId                  string
	scopeId                   string
	name                      *string
	description               *string
	createTime                *timestamp.Timestamp
	updateTime                *timestamp.Timestamp
	approximateLastAccessTime *timestamp.Timestamp
	expirationTime            *timestamp.Timestamp
	timeToStaleSeconds        uint32
	createdByUserId           string
	revoked                   bool
	tokenBytes                []byte
	permissionsJSON           []byte
}

// appTokenPermissionResult represents the unpacked results of the [lookupAppTokenResult]'s permissionsJSON field
type appTokenPermissionResult struct {
	Label               string               `json:"label"`
	GrantThisScope      bool                 `json:"grant_this_scope"`
	Grants              []string             `json:"grants"`
	GrantScope          string               `json:"grant_scope"`
	ActiveGrantScopes   []string             `json:"active_grant_scopes"`
	DeletedGrantScopes  []string             `json:"deleted_grant_scopes"`
	DeletedScopeDetails []deletedScopeResult `json:"deleted_scope_details"`
}

// deletedScopeResult represents a scope which has been deleted from an AppTokenPermission.
type deletedScopeResult struct {
	ScopeId   string `json:"scope_id"`
	TimeStamp string `json:"delete_time"`
}

// LookupAppToken returns an AppToken for the id. Returns nil if no AppToken is found for id.
func (r *Repository) LookupAppToken(ctx context.Context, id string, opt ...Option) (*AppToken, error) {
	const op = "apptoken.(Repository).LookupAppToken"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	opts := getOpts(opt...)

	var at AppToken
	lookupFunc := func(reader db.Reader, w db.Writer) error {
		scopeId, err := getAppTokenScopeId(ctx, reader, id)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}

		var query string
		switch {
		case strings.HasPrefix(scopeId, globals.GlobalPrefix):
			query = getAppTokenGlobalQuery
		case strings.HasPrefix(scopeId, globals.OrgPrefix):
			query = getAppTokenOrgQuery
		case strings.HasPrefix(scopeId, globals.ProjectPrefix):
			query = getAppTokenProjectQuery
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown scope type for scope id: %s", scopeId))
		}

		rows, err := reader.Query(ctx, query, []any{
			sql.Named("app_token_id", id),
		})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}

		var (
			res            lookupAppTokenResult
			permissionsRes []appTokenPermissionResult
		)
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(
				&res.publicId,
				&res.scopeId,
				&res.name,
				&res.description,
				&res.revoked,
				&res.createTime,
				&res.updateTime,
				&res.createdByUserId,
				&res.approximateLastAccessTime,
				&res.timeToStaleSeconds,
				&res.expirationTime,
				&res.tokenBytes,
				&res.permissionsJSON,
			); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if res.publicId == "" {
				return errors.New(ctx, errors.NotFound, op, "app token not found")
			}

			// Unpack permissions JSON from query results
			if err := json.Unmarshal(res.permissionsJSON, &permissionsRes); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("failed to unmarshal permissions"))
			}
		}
		if err := rows.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		at.PublicId = res.publicId
		at.ScopeId = res.scopeId
		if res.name != nil {
			at.Name = *res.name
		}
		if res.description != nil {
			at.Description = *res.description
		}
		at.Revoked = res.revoked
		at.CreateTime = res.createTime
		at.UpdateTime = res.updateTime
		at.CreatedByUserId = res.createdByUserId
		at.ApproximateLastAccessTime = res.approximateLastAccessTime
		at.TimeToStaleSeconds = res.timeToStaleSeconds
		at.ExpirationTime = res.expirationTime

		// Build granted scopes list for each permission
		at.Permissions = make([]AppTokenPermission, len(permissionsRes))
		for i, permission := range permissionsRes {
			var grantedScopes []string

			// Add non-individual grant scopes (children, descendants)
			if permission.GrantScope == globals.GrantScopeChildren ||
				permission.GrantScope == globals.GrantScopeDescendants {
				grantedScopes = append(grantedScopes, permission.GrantScope)
			}
			// Add 'this' if grant_this_scope is true
			if permission.GrantThisScope {
				grantedScopes = append(grantedScopes, globals.GrantScopeThis)
			}
			// Add any active, individual grant scopes
			if len(permission.ActiveGrantScopes) > 0 {
				grantedScopes = append(grantedScopes, permission.ActiveGrantScopes...)
			}
			at.Permissions[i] = AppTokenPermission{
				Label:         permission.Label,
				Grants:        permission.Grants,
				GrantedScopes: grantedScopes,
			}
			if len(permission.DeletedScopeDetails) > 0 {

				at.Permissions[i].DeletedScopes = make([]DeletedScope, len(permission.DeletedScopeDetails))
				for j, detail := range permission.DeletedScopeDetails {
					ts, err := time.Parse("2006-01-02T15:04:05.999999999", detail.TimeStamp)
					if err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("failed to parse deleted scope timestamp"))
					}
					at.Permissions[i].DeletedScopes[j] = DeletedScope{
						ScopeId:   detail.ScopeId,
						TimeStamp: timestamp.New(ts),
					}
				}
			}
		}

		atc := &appTokenCipher{
			AppTokenCipher: &store.AppTokenCipher{
				AppTokenId: id,
				CtToken:    res.tokenBytes,
			},
		}
		databaseWrapper, err := r.kms.GetWrapper(ctx, at.ScopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := atc.decrypt(ctx, databaseWrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		at.Token = atc.Token

		return nil
	}

	var err error
	if !util.IsNil(opts.withReader) && !util.IsNil(opts.withWriter) {
		if !opts.withWriter.IsTx(ctx) {
			return nil, errors.New(ctx, errors.Internal, op, "writer is not in transaction")
		}
		err = lookupFunc(opts.withReader, opts.withWriter)
	} else {
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			lookupFunc,
		)
	}
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", id)))
	}
	return &at, nil
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

	// dbInserts is a slice of slices
	// each inner slice contains items of the same type (appTokenPermissionGlobal, for example)
	// to be batch inserted using CreateItems
	var dbInserts []interface{}
	switch {
	case strings.HasPrefix(token.GetScopeId(), globals.GlobalPrefix):
		dbInserts, err = createAppTokenGlobal(ctx, token)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	case strings.HasPrefix(token.GetScopeId(), globals.OrgPrefix):
		dbInserts, err = createAppTokenOrg(ctx, token)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	case strings.HasPrefix(token.GetScopeId(), globals.ProjectPrefix):
		dbInserts, err = createAppTokenProject(ctx, token)
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
	var newAppToken *AppToken
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, writer db.Writer) error {
			for _, appTokenItems := range dbInserts {
				if err := writer.CreateItems(ctx, appTokenItems); err != nil {
					return err
				}
			}
			// Do a fresh lookup to get all return values
			newAppToken, err = r.LookupAppToken(ctx, id, WithReaderWriter(reader, writer))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating app token in database"))
	}
	return newAppToken, nil
}

func createAppTokenGlobal(ctx context.Context, token *AppToken) ([]interface{}, error) {
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

		grantThisScope := slices.Contains(perm.GrantedScopes, globals.GrantScopeThis) || slices.Contains(perm.GrantedScopes, globals.GlobalPrefix)
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

		grantInserts, err := processPermissionGrants(ctx, permId, perm.Grants)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		permissionGrantInserts = append(permissionGrantInserts, grantInserts...)

		// Create a copy of GrantedScopes before filtering to avoid mutating it
		grantedScopes := slices.Clone(perm.GrantedScopes)
		trimmedScopes := slices.DeleteFunc(grantedScopes, func(s string) bool {
			return s == globals.GrantScopeThis ||
				s == globals.GrantScopeChildren ||
				s == globals.GrantScopeDescendants ||
				s == globals.GlobalPrefix
		})

		for _, gs := range trimmedScopes {
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
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid grant scope %s", gs))
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

	return globalInserts, nil
}

func createAppTokenOrg(ctx context.Context, token *AppToken) ([]interface{}, error) {
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
		if slices.Contains(perm.GrantedScopes, globals.GlobalPrefix) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "org cannot have global grant scope")
		}
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "org cannot have descendants grant scope")
		}
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) && slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.ProjectPrefix)
		}) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "children grant scope cannot be combined with individual project grant scopes")
		}

		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		grantThisScope := slices.Contains(perm.GrantedScopes, globals.GrantScopeThis) || slices.Contains(perm.GrantedScopes, token.GetScopeId())
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
			return nil, errors.Wrap(ctx, err, op)
		}
		permissionGrantInserts = append(permissionGrantInserts, grantInserts...)

		// Create a copy of GrantedScopes before filtering to avoid mutating it
		grantedScopes := slices.Clone(perm.GrantedScopes)

		// remove GrantScopeThis and GrantScopeChildren from perm.GrantedScopes as they've already been processed
		trimmedScopes := slices.DeleteFunc(grantedScopes, func(s string) bool {
			return s == globals.GrantScopeThis || s == globals.GrantScopeChildren || s == token.GetScopeId()
		})

		for _, gs := range trimmedScopes {
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
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid grant scope %s", gs))
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

	return orgInserts, nil
}

func createAppTokenProject(ctx context.Context, token *AppToken) ([]interface{}, error) {
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
		if slices.Contains(perm.GrantedScopes, globals.GrantScopeDescendants) ||
			slices.Contains(perm.GrantedScopes, globals.GrantScopeChildren) ||
			slices.Contains(perm.GrantedScopes, globals.GlobalPrefix) ||
			slices.ContainsFunc(perm.GrantedScopes, func(s string) bool { return strings.HasPrefix(s, globals.OrgPrefix) }) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "project can only contain individual project grant scopes")
		}
		if slices.ContainsFunc(perm.GrantedScopes, func(s string) bool {
			return strings.HasPrefix(s, globals.ProjectPrefix) && s != token.GetScopeId()
		}) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "project cannot contain individual grant scopes for other projects")
		}

		permId, err := newAppTokenPermissionId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		// true if slices contains only the individual project scope that matches the token's scope ID or `this`
		grantThisScope := slices.Contains(perm.GrantedScopes, globals.GrantScopeThis) || slices.Contains(perm.GrantedScopes, token.GetScopeId())

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
			return nil, errors.Wrap(ctx, err, op)
		}
		permissionGrantInserts = append(permissionGrantInserts, grantInserts...)
	}
	if len(permissionInserts) > 0 {
		projectInserts = append(projectInserts, permissionInserts)
	}
	if len(permissionGrantInserts) > 0 {
		projectInserts = append(projectInserts, permissionGrantInserts)
	}

	return projectInserts, nil
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

// listAppTokens lists tokens across all three token subtypes (global, org, proj).
// Cipher information and permissions are not included when listing a token.
func (r *Repository) listAppTokens(ctx context.Context, withScopeIds []string, opt ...Option) ([]*AppToken, time.Time, error) {
	const op = "apptoken.(Repository).listAppTokens"
	if len(withScopeIds) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)

	limit := r.defaultLimit
	if opts.withLimit != 0 {
		limit = opts.withLimit
	}

	args := []any{sql.Named("scope_ids", withScopeIds)}
	whereClause := "scope_id in @scope_ids"
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc")}

	return r.queryAppTokens(ctx, whereClause, args, dbOpts...)
}

// listAppTokenRefresh lists tokens across all three token subtypes (global, org, proj) that have been
// updated after the provided time. Cipher information and permissions are not included when listing a token.
// App Tokens are considered updated when
//   - update_time is after updatedAfter
//   - expiration_time is after updatedAfter but before now
//   - last_approximate_access_time + time_to_stale_seconds is (before now and before expiration_time) and after updatedAfter
func (r *Repository) listAppTokensRefresh(ctx context.Context, updatedAfter time.Time, withScopeIds []string, opt ...Option) ([]*AppToken, time.Time, error) {
	const op = "apptoken.(Repository).listAppTokenRefresh"

	switch {
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updatedAfter time")

	case len(withScopeIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	opts := getOpts(opt...)

	limit := r.defaultLimit
	if opts.withLimit != 0 {
		limit = opts.withLimit
	}

	args := []any{
		sql.Named("scope_ids", withScopeIds),
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
	}
	whereClause := "scope_id in @scope_ids and " +
		"(update_time > @updated_after_time or " +
		"(expiration_time > @updated_after_time and expiration_time <= CURRENT_TIMESTAMP) or " +
		"( (approximate_last_access_time is not null and time_to_stale_seconds is not null) and " +
		"( (approximate_last_access_time + (time_to_stale_seconds || ' seconds')::interval) <= CURRENT_TIMESTAMP) and " +
		"( (approximate_last_access_time + (time_to_stale_seconds || ' seconds')::interval) > @updated_after_time) and " +
		"(expiration_time is null or (approximate_last_access_time + (time_to_stale_seconds || ' seconds')::interval) < expiration_time) ))"
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(update_time, public_id) < (@last_item_update_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("update_time desc, public_id desc")}
	return r.queryAppTokens(ctx, whereClause, args, dbOpts...)
}

func (r *Repository) queryAppTokens(ctx context.Context, whereClause string, args []any, opt ...db.Option) ([]*AppToken, time.Time, error) {
	const op = "apptoken.(Repository).queryAppTokens"

	var transactionTimestamp time.Time
	var appTokens []*AppToken
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		var atvs []*appTokenView
		err := rd.SearchWhere(ctx, &atvs, whereClause, args, opt...)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		appTokens = make([]*AppToken, 0, len(atvs))
		for _, atv := range atvs {
			appTokens = append(appTokens, atv.toAppToken())
		}
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return appTokens, transactionTimestamp, nil
}

// listDeletedIds lists the public IDs of any app tokens deleted since the timestamp provided.
func (r *Repository) listDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "apptoken.(Repository).listDeletedIds"
	var deletedAppTokens []*deletedAppToken
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedAppTokens, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted app tokens"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var deletedIds []string
	for _, at := range deletedAppTokens {
		deletedIds = append(deletedIds, at.PublicId)
	}
	return deletedIds, transactionTimestamp, nil
}

// estimatedCount returns an estimate of the total number of items in the global, org, and project app token tables.
func (r *Repository) estimatedCount(ctx context.Context) (int, error) {
	const op = "apptoken.(Repository).estimatedCount"
	rows, err := r.reader.Query(ctx, estimateCountAppTokens, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total app tokens"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total app tokens"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total app tokens"))
	}
	return count, nil
}

// getAppTokenScopeId returns the scope id of the app token
func getAppTokenScopeId(ctx context.Context, reader db.Reader, id string) (string, error) {
	const op = "apptoken.getAppTokenScopeId"
	if id == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing app token id")
	}
	if reader == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	}
	rows, err := reader.Query(ctx, scopeIdFromAppTokenIdQuery, []any{sql.Named("public_id", id)})
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to lookup app token scope for id: %s", id)))
	}
	defer rows.Close()

	var scopeId string
	for rows.Next() {
		if err := reader.ScanRows(ctx, rows, &scopeId); err != nil {
			return "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed scan results from querying app token scope for id: %s", id)))
		}
	}
	if err := rows.Err(); err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unexpected error scanning results from querying app token scope for id: %s", id)))
	}

	if scopeId == "" {
		return "", errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("app token %s not found", id))
	}
	return scopeId, nil
}
