// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests migration:
//
//	migrations/oss/2/10_auth.up.sql
func Test_AuthMethodSubtypes(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres", db.WithTemplate("template1"))
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)

	// test oidc subtype insert
	oidcAm, err := oidc.NewAuthMethod(ctx, org.PublicId, "alice-rp", "fido", oidc.WithName("alice"))
	require.NoError(err)
	oidcAm, err = oidcRepo.CreateAuthMethod(ctx, oidcAm)
	require.NoError(err)
	oidcParent, err := findParent(t, rw, oidcAm.PublicId)
	require.NoError(err)
	assert.Equal(oidcAm.Name, oidcParent.Name)

	// test oidc subtype update
	updatedOidc := oidcAm.Clone()
	updatedOidc.Name = "eve's least favorite"
	updatedOidc, _, err = oidcRepo.UpdateAuthMethod(ctx, oidcAm, oidcAm.Version, []string{"Name"})
	require.NoError(err)
	assert.Equal(updatedOidc.Name, oidcAm.Name)
	oidcParent, err = findParent(t, rw, updatedOidc.PublicId)
	require.NoError(err)
	assert.Equal(updatedOidc.Name, oidcParent.Name)

	// test password subtype insert
	pw, err := password.NewAuthMethod(ctx, org.PublicId, password.WithName("eve's favorite"))
	require.NoError(err)
	passRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	pw, err = passRepo.CreateAuthMethod(ctx, pw)
	require.NoError(err)
	pwParent, err := findParent(t, rw, pw.PublicId)
	require.NoError(err)
	require.Equal(pwParent.PublicId, pw.PublicId)
	assert.Equal("eve's favorite", pwParent.Name)

	// test password subtype update
	updatedPw := pw.Clone()
	updatedPw.Name = "new name"
	updatedPw, _, err = passRepo.UpdateAuthMethod(ctx, updatedPw, updatedPw.Version, []string{"Name"})
	require.NoError(err)
	pwParent, err = findParent(t, rw, updatedPw.PublicId)
	require.NoError(err)
	require.Equal(pwParent.PublicId, updatedPw.PublicId)
	assert.Equal(updatedPw.Name, pwParent.Name)

	// // test non-unique names across subtypes
	notUnique := updatedPw.Clone()
	notUnique.Name = updatedOidc.Name
	_, _, err = passRepo.UpdateAuthMethod(ctx, notUnique, notUnique.Version, []string{"Name"})
	require.Error(err)
	assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "expected error code %s and got error: %q", errors.NotUnique, err)

	// test password subtype delete
	_, err = passRepo.DeleteAuthMethod(ctx, updatedPw.ScopeId, updatedPw.PublicId)
	require.NoError(err)
	pwParent, err = findParent(t, rw, updatedPw.PublicId)
	require.Error(err)
	assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "expected error code %s and got error: %q", errors.RecordNotFound, err)
	assert.Nil(pwParent)

	// test oidc subtype delete
	_, err = oidcRepo.DeleteAuthMethod(ctx, updatedOidc.PublicId)
	require.NoError(err)
	oidcParent, err = findParent(t, rw, updatedOidc.PublicId)
	assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "expected error code %s and got error: %q", errors.RecordNotFound, err)
	assert.Nil(oidcParent)
}

type parent struct {
	PublicId string
	ScopeId  string
	Name     string
}

func (p *parent) GetPublicId() string { return p.PublicId }
func (p *parent) TableName() string   { return "auth_method" }

func findParent(t *testing.T, r db.Reader, authMethodId string) (*parent, error) {
	ctx := context.Background()
	t.Helper()
	p := &parent{
		PublicId: authMethodId,
	}
	err := r.LookupByPublicId(ctx, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}
