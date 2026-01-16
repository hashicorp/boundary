// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/globals"
	aliastar "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth/password"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	credstore "github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

func (b *Server) CreateInitialLoginRole(ctx context.Context) (*iam.Role, error) {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
	if err != nil {
		return nil, fmt.Errorf("unable to create repo for initial login role: %w", err)
	}

	pr, err := iam.NewRole(ctx,
		scope.Global.String(),
		iam.WithName("Login Grants"),
		iam.WithDescription(`Role created for login capability for unauthenticated users`),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating in memory role for generated grants: %w", err)
	}
	role, _, _, _, err := iamRepo.CreateRole(ctx, pr)
	if err != nil {
		return nil, fmt.Errorf("error creating role for default generated grants: %w", err)
	}
	if _, err := iamRepo.AddRoleGrants(ctx, role.PublicId, role.Version, []string{
		"ids=*;type=scope;actions=list,no-op",
		"ids=*;type=auth-method;actions=list,authenticate",
		"ids=*;type=auth-token;actions=read:self,delete:self",
	}); err != nil {
		return nil, fmt.Errorf("error creating grant for initial login grants: %w", err)
	}
	if _, err := iamRepo.AddPrincipalRoles(ctx, role.PublicId, role.Version+1, []string{globals.AnonymousUserId}); err != nil {
		return nil, fmt.Errorf("error adding principal to role for initial login grants: %w", err)
	}
	if _, _, err := iamRepo.SetRoleGrantScopes(ctx, role.PublicId, role.Version+2, []string{"this", "descendants"}); err != nil {
		return nil, fmt.Errorf("error adding scope grants to role for initial login grants: %w", err)
	}

	return role, nil
}

func (b *Server) CreateInitialAuthenticatedUserRole(ctx context.Context, opt ...Option) (*iam.Role, error) {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
	if err != nil {
		return nil, fmt.Errorf("unable to create repo for initial login role: %w", err)
	}

	pr, err := iam.NewRole(ctx,
		scope.Global.String(),
		iam.WithName("Authenticated User Grants"),
		iam.WithDescription(`Role created for account self-management, and other initial authenticated user grants`),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating in memory role for generated grants: %w", err)
	}
	role, _, _, _, err := iamRepo.CreateRole(ctx, pr)
	if err != nil {
		return nil, fmt.Errorf("error creating role for default generated grants: %w", err)
	}
	grants := []string{
		"ids=*;type=scope;actions=read",
		"ids=*;type=auth-token;actions=list",
		"ids={{.Account.Id}};actions=read,change-password",
		"ids=*;type=session;actions=list,read:self,cancel:self",
		"ids={{.User.Id}};type=user;actions=list-resolvable-aliases",
	}
	opts := GetOpts(opt...)
	if opts.withAuthUserTargetAuthorizeSessionGrant {
		grants = append(grants, "ids=*;type=target;actions=list,read,authorize-session")
	} else {
		grants = append(grants, "ids=*;type=target;actions=list,read")
	}
	if _, err := iamRepo.AddRoleGrants(ctx, role.PublicId, role.Version, grants); err != nil {
		return nil, fmt.Errorf("error creating grant for initial authenticated user grants: %w", err)
	}
	if _, err := iamRepo.AddPrincipalRoles(ctx, role.PublicId, role.Version+1, []string{globals.AnyAuthenticatedUserId}); err != nil {
		return nil, fmt.Errorf("error adding principal to role for initial authenticated user grants: %w", err)
	}
	if _, _, err := iamRepo.SetRoleGrantScopes(ctx, role.PublicId, role.Version+2, []string{"this", "descendants"}); err != nil {
		return nil, fmt.Errorf("error adding scope grants to role for initial authenticated user grants: %w", err)
	}

	return role, nil
}

func (b *Server) CreateInitialPasswordAuthMethod(ctx context.Context) (*password.AuthMethod, *iam.User, error) {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	// Create the dev auth method
	pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache, password.WithRandomReader(b.SecureRandomReader))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating password repo: %w", err)
	}
	authMethod, err := password.NewAuthMethod(ctx, scope.Global.String(),
		password.WithName("Generated global scope initial password auth method"),
		password.WithDescription("Provides initial administrative and unprivileged authentication into Boundary"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory auth method: %w", err)
	}
	if b.DevPasswordAuthMethodId == "" {
		b.DevPasswordAuthMethodId, err = db.NewPublicId(ctx, globals.PasswordAuthMethodPrefix)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating initial auth method id: %w", err)
		}
	}

	am, err := pwRepo.CreateAuthMethod(ctx, authMethod,
		password.WithPublicId(b.DevPasswordAuthMethodId))
	if err != nil {
		return nil, nil, fmt.Errorf("error saving auth method to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated password auth method id")
	b.Info["generated password auth method id"] = b.DevPasswordAuthMethodId

	// we'll designate the initial password auth method as the primary auth
	// method id for the global scope, which means the auth method will create
	// users on first login.  Otherwise, the operator would have to create both
	// a password account and a user associated with the new account, before
	// users could successfully login.
	iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create iam repo: %w", err)
	}
	globalScope, err := iamRepo.LookupScope(ctx, scope.Global.String())
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup global scope: %w", err)
	}
	globalScope.PrimaryAuthMethodId = am.PublicId
	if _, _, err := iamRepo.UpdateScope(ctx, globalScope, globalScope.Version, []string{"PrimaryAuthMethodId"}); err != nil {
		return nil, nil, fmt.Errorf("unable to set primary auth method for global scope: %w", err)
	}

	createUser := func(loginName, loginPassword, userId, accountId string, admin bool) (*iam.User, error) {
		// Create the dev admin user
		if loginName == "" {
			return nil, fmt.Errorf("empty login name")
		}
		if loginPassword == "" {
			return nil, fmt.Errorf("empty login name")
		}
		if userId == "" {
			return nil, fmt.Errorf("empty user id")
		}
		typeStr := "admin"
		if !admin {
			typeStr = "unprivileged"
		}
		b.InfoKeys = append(b.InfoKeys, fmt.Sprintf("generated %s password", typeStr))
		b.Info[fmt.Sprintf("generated %s password", typeStr)] = loginPassword

		acct, err := password.NewAccount(ctx, am.PublicId, password.WithLoginName(loginName))
		if err != nil {
			return nil, fmt.Errorf("error creating new in memory password auth account: %w", err)
		}
		acct, err = pwRepo.CreateAccount(
			ctx,
			scope.Global.String(),
			acct,
			password.WithPassword(loginPassword),
			password.WithPublicId(accountId),
			password.WithRandomReader(b.SecureRandomReader),
		)
		if err != nil {
			return nil, fmt.Errorf("error saving auth account to the db: %w", err)
		}
		b.InfoKeys = append(b.InfoKeys, fmt.Sprintf("generated %s login name", typeStr))
		b.Info[fmt.Sprintf("generated %s login name", typeStr)] = acct.GetLoginName()

		iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
		if err != nil {
			return nil, fmt.Errorf("unable to create iam repo: %w", err)
		}

		// Create a new user and associate it with the account
		opts := []iam.Option{
			iam.WithPublicId(userId),
		}
		if admin {
			opts = append(opts,
				iam.WithName("admin"),
				iam.WithDescription(fmt.Sprintf(`Initial admin user within the "%s" scope`, scope.Global.String())),
			)
		} else {
			opts = append(opts,
				iam.WithName("user"),
				iam.WithDescription("Initial unprivileged user"),
			)
		}
		u, err := iam.NewUser(ctx, scope.Global.String(), opts...)
		if err != nil {
			return nil, fmt.Errorf("error creating in memory user: %w", err)
		}
		if u, err = iamRepo.CreateUser(ctx, u, opts...); err != nil {
			return nil, fmt.Errorf("error creating initial %s user: %w", typeStr, err)
		}
		if _, err = iamRepo.AddUserAccounts(ctx, u.GetPublicId(), u.GetVersion(), []string{acct.GetPublicId()}); err != nil {
			return nil, fmt.Errorf("error associating initial %s user with account: %w", typeStr, err)
		}
		if !admin {
			return u, nil
		}
		// Create a role tying them together
		pr, err := iam.NewRole(ctx,
			scope.Global.String(),
			iam.WithName("Administration"),
			iam.WithDescription("Provides admin grants within all scopes to the initial admin user"),
		)
		if err != nil {
			return nil, fmt.Errorf("error creating in memory role for generated grants: %w", err)
		}
		adminRole, _, _, _, err := iamRepo.CreateRole(ctx, pr)
		if err != nil {
			return nil, fmt.Errorf("error creating role for default generated grants: %w", err)
		}
		if _, err := iamRepo.AddRoleGrants(ctx, adminRole.PublicId, adminRole.Version, []string{"ids=*;type=*;actions=*"}); err != nil {
			return nil, fmt.Errorf("error creating grant for default generated grants: %w", err)
		}
		if _, err := iamRepo.AddPrincipalRoles(ctx, adminRole.PublicId, adminRole.Version+1, []string{u.GetPublicId()}, nil); err != nil {
			return nil, fmt.Errorf("error adding principal to role for default generated grants: %w", err)
		}
		if _, _, err := iamRepo.SetRoleGrantScopes(ctx, adminRole.PublicId, adminRole.Version+2, []string{"this", "descendants"}); err != nil {
			return nil, fmt.Errorf("error adding scope grants to role for default generated grants: %w", err)
		}
		return u, nil
	}

	switch {
	case b.DevUnprivilegedLoginName == "",
		b.DevUnprivilegedPassword == "",
		b.DevUnprivilegedUserId == "":
	default:
		_, err := createUser(b.DevUnprivilegedLoginName, b.DevUnprivilegedPassword, b.DevUnprivilegedUserId, b.DevUnprivilegedPasswordAccountId, false)
		if err != nil {
			return nil, nil, err
		}
	}
	if b.DevLoginName == "" {
		b.DevLoginName, err = base62.Random(10)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate login name: %w", err)
		}
		b.DevLoginName = strings.ToLower(b.DevLoginName)
	}
	if b.DevPassword == "" {
		b.DevPassword, err = base62.Random(20)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate password: %w", err)
		}
	}
	if b.DevUserId == "" {
		b.DevUserId, err = db.NewPublicId(ctx, globals.UserPrefix)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating initial user id: %w", err)
		}
	}
	u, err := createUser(b.DevLoginName, b.DevPassword, b.DevUserId, b.DevPasswordAccountId, true)
	if err != nil {
		return nil, nil, err
	}

	return am, u, nil
}

func (b *Server) CreateInitialScopes(ctx context.Context, opt ...Option) (*iam.Scope, *iam.Scope, error) {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	opts := GetOpts(opt...)

	iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating scopes repository: %w", err)
	}

	// Create the scopes
	if b.DevOrgId == "" {
		b.DevOrgId, err = db.NewPublicId(ctx, scope.Org.Prefix())
		if err != nil {
			return nil, nil, fmt.Errorf("error generating initial org id: %w", err)
		}
	}
	iamOpts := []iam.Option{
		iam.WithName("Generated org scope"),
		iam.WithDescription("Provides an initial org scope in Boundary"),
		iam.WithRandomReader(b.SecureRandomReader),
		iam.WithPublicId(b.DevOrgId),
	}
	if len(opts.withIamOptions) > 0 {
		iamOpts = append(iamOpts, opts.withIamOptions...)
	}
	orgScope, err := iam.NewOrg(ctx, iamOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory org scope: %w", err)
	}
	orgScope, err = iamRepo.CreateScope(ctx, orgScope, b.DevUserId, iamOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error saving org scope to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated org scope id")
	b.Info["generated org scope id"] = b.DevOrgId

	if b.DevProjectId == "" {
		b.DevProjectId, err = db.NewPublicId(ctx, scope.Project.Prefix())
		if err != nil {
			return nil, nil, fmt.Errorf("error generating initial project id: %w", err)
		}
	}
	iamOpts = []iam.Option{
		iam.WithName("Generated project scope"),
		iam.WithDescription("Provides an initial project scope in Boundary"),
		iam.WithRandomReader(b.SecureRandomReader),
		iam.WithPublicId(b.DevProjectId),
	}
	if len(opts.withIamOptions) > 0 {
		iamOpts = append(iamOpts, opts.withIamOptions...)
	}
	projScope, err := iam.NewProject(ctx, b.DevOrgId, iamOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory project scope: %w", err)
	}
	projScope, err = iamRepo.CreateScope(ctx, projScope, b.DevUserId, iamOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error saving project scope to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated project scope id")
	b.Info["generated project scope id"] = b.DevProjectId

	return orgScope, projScope, nil
}

func (b *Server) CreateInitialHostResources(ctx context.Context) (*static.HostCatalog, *static.HostSet, *static.Host, error) {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, nil, nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	staticRepo, err := static.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating static repository: %w", err)
	}

	// Host Catalog
	if b.DevHostCatalogId == "" {
		b.DevHostCatalogId, err = db.NewPublicId(ctx, globals.StaticHostCatalogPrefix)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error generating initial host catalog id: %w", err)
		}
	}
	opts := []static.Option{
		static.WithName("Generated host catalog"),
		static.WithDescription("Provides an initial host catalog in Boundary"),
		static.WithPublicId(b.DevHostCatalogId),
	}
	hc, err := static.NewHostCatalog(ctx, b.DevProjectId, opts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating in memory host catalog: %w", err)
	}
	if hc, err = staticRepo.CreateCatalog(ctx, hc, opts...); err != nil {
		return nil, nil, nil, fmt.Errorf("error saving host catalog to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated host catalog id")
	b.Info["generated host catalog id"] = b.DevHostCatalogId

	// Host
	if b.DevHostId == "" {
		b.DevHostId, err = db.NewPublicId(ctx, globals.StaticHostPrefix)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error generating initial host id: %w", err)
		}
	}
	if b.DevHostAddress == "" {
		b.DevHostAddress = "localhost"
	}
	opts = []static.Option{
		static.WithName("Generated host"),
		static.WithDescription("Provides an initial host in Boundary"),
		static.WithAddress(b.DevHostAddress),
		static.WithPublicId(b.DevHostId),
	}
	h, err := static.NewHost(ctx, hc.PublicId, opts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating in memory host: %w", err)
	}
	if h, err = staticRepo.CreateHost(ctx, b.DevProjectId, h, opts...); err != nil {
		return nil, nil, nil, fmt.Errorf("error saving host to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated host id")
	b.Info["generated host id"] = b.DevHostId

	// Host Set
	if b.DevHostSetId == "" {
		b.DevHostSetId, err = db.NewPublicId(ctx, globals.StaticHostSetPrefix)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error generating initial host set id: %w", err)
		}
	}
	opts = []static.Option{
		static.WithName("Generated host set"),
		static.WithDescription("Provides an initial host set in Boundary"),
		static.WithPublicId(b.DevHostSetId),
	}
	hs, err := static.NewHostSet(ctx, hc.PublicId, opts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating in memory host set: %w", err)
	}
	if hs, err = staticRepo.CreateSet(ctx, b.DevProjectId, hs, opts...); err != nil {
		return nil, nil, nil, fmt.Errorf("error saving host set to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated host set id")
	b.Info["generated host set id"] = b.DevHostSetId

	// Associate members
	if _, err := staticRepo.AddSetMembers(ctx, b.DevProjectId, b.DevHostSetId, hs.GetVersion(), []string{h.GetPublicId()}); err != nil {
		return nil, nil, nil, fmt.Errorf("error associating host set to host in the db: %w", err)
	}

	return hc, hs, h, nil
}

func (b *Server) CreateInitialTargetWithAddress(ctx context.Context) (target.Target, error) {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(ctx, kms.WithRootWrapper(b.RootKms)); err != nil {
		return nil, fmt.Errorf("failed to add config keys to kms: %w", err)
	}

	targetRepo, err := target.NewRepository(ctx, rw, rw, kmsCache, target.WithRandomReader(b.SecureRandomReader))
	if err != nil {
		return nil, fmt.Errorf("failed to create target repository: %w", err)
	}

	// When this function is not called as part of boundary dev (eg: as part of
	// boundary database init or tests), generate random target ids.
	if len(b.DevTargetId) == 0 {
		b.DevTargetId, err = db.NewPublicId(ctx, globals.TcpTargetPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to generate initial target id: %w", err)
		}
	}
	if b.DevTargetDefaultPort == 0 {
		b.DevTargetDefaultPort = 22
	}
	if len(b.DevTargetAddress) == 0 {
		b.DevTargetAddress = "127.0.0.1"
	}
	opts := []target.Option{
		target.WithName("Generated target with a direct address"),
		target.WithDescription("Provides an initial target using an address in Boundary"),
		target.WithDefaultPort(uint32(b.DevTargetDefaultPort)),
		target.WithSessionMaxSeconds(uint32(b.DevTargetSessionMaxSeconds)),
		target.WithSessionConnectionLimit(int32(b.DevTargetSessionConnectionLimit)),
		target.WithPublicId(b.DevTargetId),
		target.WithAddress(b.DevTargetAddress),
	}
	tt, err := b.createTarget(ctx, targetRepo, opts...)
	if err != nil {
		return nil, err
	}
	b.InfoKeys = append(b.InfoKeys, "generated target with address id")
	b.Info["generated target with address id"] = b.DevTargetId

	return tt, nil
}

func (b *Server) createTarget(ctx context.Context, targetRepo *target.Repository, opts ...target.Option) (target.Target, error) {
	t, err := target.New(ctx, tcp.Subtype, b.DevProjectId, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create target object: %w", err)
	}
	tt, err := targetRepo.CreateTarget(ctx, t, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to save target to the db: %w", err)
	}

	return tt, nil
}

func (b *Server) CreateInitialTargetWithHostSources(ctx context.Context) (target.Target, error) {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, fmt.Errorf("failed to add config keys to kms: %w", err)
	}

	targetRepo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return nil, fmt.Errorf("failed to create target repository: %w", err)
	}

	// When this function is not called as part of boundary dev (eg: as part of
	// boundary database init or tests), generate random target ids.
	if len(b.DevSecondaryTargetId) == 0 {
		b.DevSecondaryTargetId, err = db.NewPublicId(ctx, globals.TcpTargetPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to generate initial secondary target id: %w", err)
		}
	}
	if b.DevTargetDefaultPort == 0 {
		b.DevTargetDefaultPort = 22
	}

	opts := []target.Option{
		target.WithName("Generated target using host sources"),
		target.WithDescription("Provides a target using host sources in Boundary"),
		target.WithDefaultPort(uint32(b.DevTargetDefaultPort)),
		target.WithSessionMaxSeconds(uint32(b.DevTargetSessionMaxSeconds)),
		target.WithSessionConnectionLimit(int32(b.DevTargetSessionConnectionLimit)),
		target.WithPublicId(b.DevSecondaryTargetId),
	}
	tt, err := b.createTarget(ctx, targetRepo, opts...)
	if err != nil {
		return nil, err
	}
	tt, err = targetRepo.AddTargetHostSources(ctx, tt.GetPublicId(), tt.GetVersion(), []string{b.DevHostSetId})
	if err != nil {
		return nil, fmt.Errorf("failed to add host source %q to target: %w", b.DevHostSetId, err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated target with host source id")
	b.Info["generated target with host source id"] = b.DevSecondaryTargetId

	return tt, nil
}

// Create targets that can be connected to using an alias. The three targets created are:
//   - "postgres.boundary.dev": the Boundary dev postgres instance. Uses brokered credentials
//   - "www.hashicorp.com": a web target
//   - "ssh.boundary.dev": A localhost ssh target
func (b *Server) CreateInitialTargetsWithAlias(ctx context.Context) error {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return fmt.Errorf("failed to create kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return fmt.Errorf("failed to add config keys to kms: %w", err)
	}

	targetRepo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return fmt.Errorf("failed to create target repository: %w", err)
	}

	credsRepo, err := credstatic.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return fmt.Errorf("failed to create creds repository: %w", err)
	}

	aliasRepo, err := aliastar.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return fmt.Errorf("failed to create alias repository: %w", err)
	}

	err = b.createPostgresAliasTarget(ctx, targetRepo, aliasRepo, credsRepo)
	if err != nil {
		return fmt.Errorf("failed to create postgres alias target: %w", err)
	}

	err = b.createWebTarget(ctx, targetRepo, aliasRepo)
	if err != nil {
		return fmt.Errorf("failed to create web target: %w", err)
	}

	err = b.createSshAliasTarget(ctx, targetRepo, aliasRepo)
	if err != nil {
		return fmt.Errorf("failed to create ssh target: %w", err)
	}

	return nil
}

func (b *Server) createSshAliasTarget(ctx context.Context, targetRepo *target.Repository, aliasRepo *aliastar.Repository) error {
	opts := []target.Option{
		target.WithName("Generated localhost ssh target with an alias"),
		target.WithDescription("Provides an initial localhost target to SSH to using an alias in Boundary"),
		target.WithDefaultPort(22),
		target.WithSessionMaxSeconds(uint32(b.DevTargetSessionMaxSeconds)),
		target.WithSessionConnectionLimit(int32(b.DevTargetSessionConnectionLimit)),
		target.WithAddress("127.0.0.1"),
	}
	t, err := b.createTarget(ctx, targetRepo, opts...)
	if err != nil {
		return err
	}

	sshAlias := "ssh.boundary.dev"
	a, err := aliastar.NewAlias(ctx, "global", sshAlias, aliastar.WithDestinationId(t.GetPublicId()))
	if err != nil {
		return fmt.Errorf("failed to create alias object %w", err)
	}
	_, err = aliasRepo.CreateAlias(ctx, a)
	if err != nil {
		return fmt.Errorf("failed to save alias to the db %w", err)
	}

	b.InfoKeys = append(b.InfoKeys, "generated ssh target with alias")
	b.Info["generated ssh target with alias"] = sshAlias
	return nil
}

func (b *Server) createPostgresAliasTarget(ctx context.Context,
	targetRepo *target.Repository,
	aliasRepo *aliastar.Repository,
	credsRepo *credstatic.Repository,
) error {
	u, err := url.Parse(b.DatabaseUrl)
	if err != nil {
		return fmt.Errorf("failed to parse DB url: %w", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("failed to split host port from DB url: %w", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return fmt.Errorf("failed to parse postgres port from DB url: %w", err)
	}

	dbname := strings.Trim(u.Path, "/")

	opts := []target.Option{
		target.WithName("Generated local postgres target with alias"),
		target.WithDescription(fmt.Sprintf("Provides a local postgres target using aliasing in Boundary. Connect using the flag `-dbname %s`", dbname)),
		target.WithDefaultPort(uint32(port)),
		target.WithAddress(host),
		target.WithSessionMaxSeconds(uint32(b.DevTargetSessionMaxSeconds)),
		target.WithSessionConnectionLimit(int32(b.DevTargetSessionConnectionLimit)),
	}
	t, err := b.createTarget(ctx, targetRepo, opts...)
	if err != nil {
		return err
	}

	cs, err := credsRepo.CreateCredentialStore(ctx,
		&credstatic.CredentialStore{
			CredentialStore: &credstore.CredentialStore{
				ProjectId: b.DevProjectId,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create cred store: %w", err)
	}
	cred, err := credstatic.NewUsernamePasswordCredential(cs.PublicId, "postgres", "password")
	if err != nil {
		return fmt.Errorf("failed to create cred: %w", err)
	}
	upCred, err := credsRepo.CreateUsernamePasswordCredential(ctx, b.DevProjectId, cred)
	if err != nil {
		return fmt.Errorf("failed to store cred: %w", err)
	}
	_, err = targetRepo.AddTargetCredentialSources(
		ctx,
		t.GetPublicId(),
		t.GetVersion(),
		target.CredentialSources{
			BrokeredCredentialIds: []string{upCred.PublicId},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to associate cred to target: %w", err)
	}

	postgresAlias := "postgres.boundary.dev"
	a, err := aliastar.NewAlias(ctx, "global", postgresAlias, aliastar.WithDestinationId(t.GetPublicId()))
	if err != nil {
		return fmt.Errorf("failed to create alias object %w", err)
	}
	_, err = aliasRepo.CreateAlias(ctx, a)
	if err != nil {
		return fmt.Errorf("failed to save alias to the db %w", err)
	}

	b.InfoKeys = append(b.InfoKeys, "generated postgres target with alias")
	b.Info["generated postgres target with alias"] = postgresAlias

	return nil
}

func (b *Server) createWebTarget(ctx context.Context,
	targetRepo *target.Repository,
	aliasRepo *aliastar.Repository,
) error {
	opts := []target.Option{
		target.WithName("www.hashicorp.com"),
		target.WithDescription("Provides an initial web target using an address in Boundary. Note: Only HTTPS is supported, as this target uses port 443. Alias names for web targets should match the URL for the target."),
		target.WithDefaultPort(443),
		target.WithSessionMaxSeconds(5),
		target.WithSessionConnectionLimit(int32(b.DevTargetSessionConnectionLimit)),
		target.WithAddress("www.hashicorp.com"),
	}
	t, err := b.createTarget(ctx, targetRepo, opts...)
	if err != nil {
		return err
	}

	webAlias := "www.hashicorp.com"
	a, err := aliastar.NewAlias(ctx, "global", webAlias, aliastar.WithDestinationId(t.GetPublicId()))
	if err != nil {
		return fmt.Errorf("failed to create alias object %w", err)
	}
	_, err = aliasRepo.CreateAlias(ctx, a)
	if err != nil {
		return fmt.Errorf("failed to save alias to the db %w", err)
	}

	b.InfoKeys = append(b.InfoKeys, "generated web target with alias")
	b.Info["generated web target with alias"] = webAlias

	return nil
}

// RegisterPlugin creates a plugin in the database if not present, and flags
// the plugin type based on the flags parameter. If the PluginTypeHost flag is
// set, it also registers the plugin in the shared map of running plugins.
// Since all boundary provided plugins must have a name, a name is required
// when calling RegisterPlugin and will be used even if WithName is provided.
// hostClient must not be nil when host flag is included.
func (b *Server) RegisterPlugin(ctx context.Context, name string, hostClient plgpb.HostPluginServiceClient, flags []plugin.PluginType, opt ...plugin.Option) (*plugin.Plugin, error) {
	const op = "base.(Server).RegisterPlugin"
	switch {
	case len(flags) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "plugins must be initialized with at least one plugin type")
	case name == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no name provided when creating plugin")
	}

	rw := db.New(b.Database)

	if b.Kms == nil {
		var err error
		if b.Kms, err = kms.New(ctx, rw, rw); err != nil {
			return nil, fmt.Errorf("error creating kms cache: %w", err)
		}
	}
	if err := b.Kms.AddExternalWrappers(
		ctx,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	hpRepo, err := plugin.NewRepository(ctx, rw, rw, b.Kms)
	if err != nil {
		return nil, fmt.Errorf("error creating plugin repository: %w", err)
	}

	plg, err := hpRepo.LookupPluginByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("error looking up plugin by name: %w", err)
	}

	if plg == nil {
		opt = append(opt, plugin.WithName(name))
		plg = plugin.NewPlugin(opt...)
		plg, err = hpRepo.CreatePlugin(ctx, plg, opt...)
		if err != nil {
			return nil, fmt.Errorf("error creating plugin: %w", err)
		}
	}

	// TODO: support flags should be moved to the create/update repo calls before plugins are exposed to users
	for _, flag := range flags {
		switch flag {
		case plugin.PluginTypeHost:
			if util.IsNil(hostClient) {
				return nil, errors.New(ctx, errors.InvalidParameter, op, "no host client provided when initializing host plugin")
			}
			if err := hpRepo.AddSupportFlag(ctx, plg, plugin.PluginTypeHost); err != nil {
				return nil, err
			}
			if b.HostPlugins == nil {
				b.HostPlugins = make(map[string]plgpb.HostPluginServiceClient)
			}
			b.HostPlugins[plg.GetPublicId()] = hostClient
		case plugin.PluginTypeStorage:
			if err := hpRepo.AddSupportFlag(ctx, plg, plugin.PluginTypeStorage); err != nil {
				return nil, err
			}
		}
	}

	return plg, nil
}
