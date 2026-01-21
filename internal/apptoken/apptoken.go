// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

const (
	appTokenCipherTableName          = "app_token_cipher"
	appTokenPermissionGrantTableName = "app_token_permission_grant"

	appTokenGlobalTableName                                      = "app_token_global"
	appTokenPermissionGlobalTableName                            = "app_token_permission_global"
	appTokenPermissionGlobalIndividualOrgGrantScopeTableName     = "app_token_permission_global_individual_org_grant_scope"
	appTokenPermissionGlobalIndividualProjectGrantScopeTableName = "app_token_permission_global_individual_project_grant_scope"

	appTokenOrgTableName                               = "app_token_org"
	appTokenPermissionOrgTableName                     = "app_token_permission_org"
	appTokenPermissionOrgIndividualGrantScopeTableName = "app_token_permission_org_individual_grant_scope"

	// The version prefix is used to differentiate token versions just for future proofing.
	tokenValueVersionPrefix = "0"
	tokenLength             = 24
)

// An AppToken is an application token used for machine-to-machine authentication.
type AppToken struct {
	PublicId                  string
	ScopeId                   string
	Name                      string
	Description               string
	CreateTime                *timestamp.Timestamp
	UpdateTime                *timestamp.Timestamp
	ApproximateLastAccessTime *timestamp.Timestamp
	ExpirationTime            *timestamp.Timestamp
	TimeToStaleSeconds        uint32
	Token                     string // Token is a plaintext value of the token
	CreatedByUserId           string
	KeyId                     string
	Revoked                   bool
	Permissions               []AppTokenPermission
}

func (at *AppToken) GetScopeId() string {
	if at == nil {
		return ""
	}
	return at.ScopeId
}

// IsActive returns true if the app token is active (not revoked and not expired)
// An AppToken is considered inactive if:
//   - Token is revoked
//   - time.Now() is after expiration time
//   - time.Now() is after lastAccess + timeToStaleSeconds
func (at *AppToken) IsActive() bool {
	now := time.Now()

	switch {
	case at.Revoked:
		return false
	case at.ExpirationTime != nil && now.After(at.ExpirationTime.AsTime()):
		return false
	case at.TimeToStaleSeconds > 0 && at.ApproximateLastAccessTime != nil &&
		now.After(at.ApproximateLastAccessTime.AsTime().Add(time.Duration(at.TimeToStaleSeconds)*time.Second)):
		return false
	default:
		return true
	}
}

// GetPublicId returns the public id of the AppToken
func (at *AppToken) GetPublicId() string {
	return at.PublicId
}

// GetResourceType returns the resource type of the AppToken
func (at AppToken) GetResourceType() resource.Type {
	return resource.AppToken
}

// GetUpdateTime returns the AppToken update time
func (at AppToken) GetUpdateTime() *timestamp.Timestamp {
	return at.UpdateTime
}

// GetCreateTime returns the AppToken create time
func (at AppToken) GetCreateTime() *timestamp.Timestamp {
	return at.CreateTime
}

// GetDescription returns the AppToken description
func (at AppToken) GetDescription() string {
	return at.Description
}

// GetName returns the AppToken name
func (at AppToken) GetName() string {
	return at.Name
}

// GetVersion returns 0 so that
// AppToken will satisfy resource requirements
func (at AppToken) GetVersion() uint32 {
	return 0
}

// appTokenView is used to query the app_token_view database view
// which unions the app_token_global, app_token_org, and app_token_project tables.
type appTokenView struct {
	*store.AppToken
	tableName string `gorm:"-"`
}

func (atv *appTokenView) toAppToken() *AppToken {
	return &AppToken{
		PublicId:                  atv.PublicId,
		ScopeId:                   atv.ScopeId,
		Name:                      atv.Name,
		Description:               atv.Description,
		Revoked:                   atv.Revoked,
		CreateTime:                atv.CreateTime,
		ApproximateLastAccessTime: atv.ApproximateLastAccessTime,
		ExpirationTime:            atv.ExpirationTime,
		TimeToStaleSeconds:        atv.TimeToStaleSeconds,
		CreatedByUserId:           atv.CreatedByUserId,
	}
}

// AppTokenPermission represents the permissions granted to an AppToken.
// The individual scopes granted to an AppTokenPermission will remain constant over time.
// When a scope is removed, it is moved from GrantedScopes to DeletedScopes.
// The union of GrantedScopes and DeletedScopes will always equal the original set of granted scopes.
type AppTokenPermission struct {
	Label         string
	Grants        []string
	GrantedScopes []string
	DeletedScopes []DeletedScope
}

// DeletedScope represents a scope which has been deleted from an AppTokenPermission.
type DeletedScope struct {
	ScopeId   string
	TimeStamp *timestamp.Timestamp
}

// newToken generates a new in-memory token for the app token.
func newToken(ctx context.Context) (string, error) {
	const op = "apptoken.newToken"
	token, err := base62.Random(tokenLength)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithCode(errors.Io))
	}

	return fmt.Sprintf("%s%s", tokenValueVersionPrefix, token), nil
}

// for app_token_global (triggers an insert to app_token)
type appTokenGlobal struct {
	*store.AppTokenGlobal
	tableName string
}

// TableName returns the table name.
func (atg *appTokenGlobal) TableName() string {
	if atg.tableName != "" {
		return atg.tableName
	}
	return appTokenGlobalTableName
}

// SetTableName sets the table name.
func (atg *appTokenGlobal) SetTableName(n string) {
	atg.tableName = n
}

// for app_token_org (triggers an insert to app_token)
type appTokenOrg struct {
	*store.AppTokenOrg
	tableName string
}

// TableName returns the table name.
func (ato *appTokenOrg) TableName() string {
	if ato.tableName != "" {
		return ato.tableName
	}
	return appTokenOrgTableName
}

// SetTableName sets the table name.
func (ato *appTokenOrg) SetTableName(n string) {
	ato.tableName = n
}

// for app_token_cipher
type appTokenCipher struct {
	*store.AppTokenCipher
	tableName string
}

// TableName returns the table name.
func (atc *appTokenCipher) TableName() string {
	if atc.tableName != "" {
		return atc.tableName
	}
	return appTokenCipherTableName
}

// SetTableName sets the table name.
func (atc *appTokenCipher) SetTableName(n string) {
	atc.tableName = n
}

// for app_token_permission_global (triggers an insert to app_token_permission)
type appTokenPermissionGlobal struct {
	*store.AppTokenPermissionGlobal
	tableName string
}

// TableName returns the table name.
func (atpg *appTokenPermissionGlobal) TableName() string {
	if atpg.tableName != "" {
		return atpg.tableName
	}
	return appTokenPermissionGlobalTableName
}

// SetTableName sets the table name.
func (atpg *appTokenPermissionGlobal) SetTableName(n string) {
	atpg.tableName = n
}

type appTokenPermissionGlobalIndividualOrgGrantScope struct {
	*store.AppTokenPermissionGlobalIndividualOrgGrantScope
	tableName string
}

// TableName returns the table name.
func (atgo *appTokenPermissionGlobalIndividualOrgGrantScope) TableName() string {
	if atgo.tableName != "" {
		return atgo.tableName
	}
	return appTokenPermissionGlobalIndividualOrgGrantScopeTableName
}

// SetTableName sets the table name.
func (atgo *appTokenPermissionGlobalIndividualOrgGrantScope) SetTableName(n string) {
	atgo.tableName = n
}

type appTokenPermissionGlobalIndividualProjectGrantScope struct {
	*store.AppTokenPermissionGlobalIndividualProjectGrantScope
	tableName string
}

// TableName returns the table name.
func (atgp *appTokenPermissionGlobalIndividualProjectGrantScope) TableName() string {
	if atgp.tableName != "" {
		return atgp.tableName
	}
	return appTokenPermissionGlobalIndividualProjectGrantScopeTableName
}

// SetTableName sets the table name.
func (atgp *appTokenPermissionGlobalIndividualProjectGrantScope) SetTableName(n string) {
	atgp.tableName = n
}

// for app_token_permission_org (triggers an insert to app_token_permission)
type appTokenPermissionOrg struct {
	*store.AppTokenPermissionOrg
	tableName string
}

// TableName returns the table name.
func (atpo *appTokenPermissionOrg) TableName() string {
	if atpo.tableName != "" {
		return atpo.tableName
	}
	return appTokenPermissionOrgTableName
}

// SetTableName sets the table name.
func (atpo *appTokenPermissionOrg) SetTableName(n string) {
	atpo.tableName = n
}

type appTokenPermissionOrgIndividualGrantScope struct {
	*store.AppTokenPermissionOrgIndividualGrantScope
	tableName string
}

// TableName returns the table name.
func (atop *appTokenPermissionOrgIndividualGrantScope) TableName() string {
	if atop.tableName != "" {
		return atop.tableName
	}
	return appTokenPermissionOrgIndividualGrantScopeTableName
}

// SetTableName sets the table name.
func (atop *appTokenPermissionOrgIndividualGrantScope) SetTableName(n string) {
	atop.tableName = n
}

// for app_token_permission_grant (triggers an insert to iam_grant and iam_grant_resource_enm)
type appTokenPermissionGrant struct {
	*store.AppTokenPermissionGrant
	tableName string
}

// TableName returns the table name.
func (atpg *appTokenPermissionGrant) TableName() string {
	if atpg.tableName != "" {
		return atpg.tableName
	}
	return appTokenPermissionGrantTableName
}

// SetTableName sets the table name.
func (atpg *appTokenPermissionGrant) SetTableName(n string) {
	atpg.tableName = n
}

// encrypt the entry's data using the provided cipher (wrapping.Wrapper)
func (atc *appTokenCipher) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "AppToken.(appTokenCipher).encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, cipher, atc.AppTokenCipher, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get cipher key id"))
	}
	atc.KeyId = keyId
	return nil
}

// decrypt will decrypt the apptoken's value using the provided cipher (wrapping.Wrapper)
func (atc *appTokenCipher) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "AppToken.(appTokenCipher).decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, atc.AppTokenCipher, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
