// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/target"
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
		iam.WithName("Login and Default Grants"),
		iam.WithDescription(`Role created for login capability, account self-management, and other default grants for users of the global scope at its creation time`),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating in memory role for generated grants: %w", err)
	}
	role, err := iamRepo.CreateRole(ctx, pr)
	if err != nil {
		return nil, fmt.Errorf("error creating role for default generated grants: %w", err)
	}
	if _, err := iamRepo.AddRoleGrants(ctx, role.PublicId, role.Version, []string{
		"id=*;type=scope;actions=list,no-op",
		"id=*;type=auth-method;actions=authenticate,list",
		"id={{.Account.Id}};actions=read,change-password",
		"id=*;type=auth-token;actions=list,read:self,delete:self",
	}); err != nil {
		return nil, fmt.Errorf("error creating grant for default generated grants: %w", err)
	}
	if _, err := iamRepo.AddPrincipalRoles(ctx, role.PublicId, role.Version+1, []string{globals.AnonymousUserId}, nil); err != nil {
		return nil, fmt.Errorf("error adding principal to role for default generated grants: %w", err)
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
	pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
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
			iam.WithDescription(fmt.Sprintf(`Provides admin grants within the "%s" scope to the initial user`, scope.Global.String())),
		)
		if err != nil {
			return nil, fmt.Errorf("error creating in memory role for generated grants: %w", err)
		}
		defPermsRole, err := iamRepo.CreateRole(ctx, pr)
		if err != nil {
			return nil, fmt.Errorf("error creating role for default generated grants: %w", err)
		}
		if _, err := iamRepo.AddRoleGrants(ctx, defPermsRole.PublicId, defPermsRole.Version, []string{"id=*;type=*;actions=*"}); err != nil {
			return nil, fmt.Errorf("error creating grant for default generated grants: %w", err)
		}
		if _, err := iamRepo.AddPrincipalRoles(ctx, defPermsRole.PublicId, defPermsRole.Version+1, []string{u.GetPublicId()}, nil); err != nil {
			return nil, fmt.Errorf("error adding principal to role for default generated grants: %w", err)
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

func (b *Server) CreateInitialScopes(ctx context.Context) (*iam.Scope, *iam.Scope, error) {
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
	opts := []iam.Option{
		iam.WithName("Generated org scope"),
		iam.WithDescription("Provides an initial org scope in Boundary"),
		iam.WithRandomReader(b.SecureRandomReader),
		iam.WithPublicId(b.DevOrgId),
	}
	orgScope, err := iam.NewOrg(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory org scope: %w", err)
	}
	orgScope, err = iamRepo.CreateScope(ctx, orgScope, b.DevUserId, opts...)
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
	opts = []iam.Option{
		iam.WithName("Generated project scope"),
		iam.WithDescription("Provides an initial project scope in Boundary"),
		iam.WithRandomReader(b.SecureRandomReader),
		iam.WithPublicId(b.DevProjectId),
	}
	projScope, err := iam.NewProject(ctx, b.DevOrgId, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory project scope: %w", err)
	}
	projScope, err = iamRepo.CreateScope(ctx, projScope, b.DevUserId, opts...)
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

	targetRepo, err := target.NewRepository(ctx, rw, rw, kmsCache)
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
	t, err := target.New(ctx, globals.TcpSubtype, b.DevProjectId, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create target object: %w", err)
	}
	tt, err := targetRepo.CreateTarget(ctx, t, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to save target to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated target with address id")
	b.Info["generated target with address id"] = b.DevTargetId

	if b.DevUnprivilegedUserId != "" {
		iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
		if err != nil {
			return nil, fmt.Errorf("failed to create iam repository: %w", err)
		}
		err = unprivilegedDevUserRoleSetup(ctx, iamRepo, b.DevUnprivilegedUserId, b.DevProjectId, b.DevTargetId)
		if err != nil {
			return nil, fmt.Errorf("failed to set up unprivileged dev user: %w", err)
		}
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
	t, err := target.New(ctx, globals.TcpSubtype, b.DevProjectId, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create target object: %w", err)
	}
	tt, err := targetRepo.CreateTarget(ctx, t, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to save target to the db: %w", err)
	}
	tt, err = targetRepo.AddTargetHostSources(ctx, tt.GetPublicId(), tt.GetVersion(), []string{b.DevHostSetId})
	if err != nil {
		return nil, fmt.Errorf("failed to add host source %q to target: %w", b.DevHostSetId, err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated target with host source id")
	b.Info["generated target with host source id"] = b.DevSecondaryTargetId

	if b.DevUnprivilegedUserId != "" {
		iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
		if err != nil {
			return nil, fmt.Errorf("failed to create iam repository: %w", err)
		}
		err = unprivilegedDevUserRoleSetup(ctx, iamRepo, b.DevUnprivilegedUserId, b.DevProjectId, b.DevSecondaryTargetId)
		if err != nil {
			return nil, fmt.Errorf("failed to set up unprivileged dev user: %w", err)
		}
	}

	return tt, nil
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

// unprivilegedDevUserRoleSetup adds dev user to the role that grants
// list/read:self/cancel:self on sessions and read:self/delete:self/list on
// tokens. It also creates a role with an `authorize-session` grant for the
// provided targetId.
func unprivilegedDevUserRoleSetup(ctx context.Context, repo *iam.Repository, userId, projectId, targetId string) error {
	roles, err := repo.ListRoles(ctx, []string{projectId})
	if err != nil {
		return fmt.Errorf("failed to list existing roles for project id %q: %w", projectId, err)
	}

	// Look for default grants role to set unprivileged user as a principal.
	defaultRoleIdx := -1
	for i, r := range roles {
		// Hacky, I know, but saves a DB trip to look up other
		// characteristics like "if any principals are currently attached".
		// No matter what we pick here it's a bit heuristical.
		if r.Name == "Default Grants" {
			defaultRoleIdx = i
			break
		}
	}
	if defaultRoleIdx == -1 {
		return fmt.Errorf("couldn't find default grants role for project id %q", projectId)
	}
	defaultRole := roles[defaultRoleIdx]

	// This function may be called more than once for the same boundary
	// deployment (eg: if we're creating more than one target), so we need to
	// check if the unprivileged user is not already a principal for the default
	// role in this project, as attempting to add an existing principal is an
	// error.
	principals, err := repo.ListPrincipalRoles(ctx, defaultRole.GetPublicId())
	if err != nil {
		return fmt.Errorf("failed to list principals for default project role: %w", err)
	}
	found := false
	for _, p := range principals {
		if p.PrincipalId == userId {
			found = true
		}
	}
	if !found {
		_, err = repo.AddPrincipalRoles(ctx, defaultRole.GetPublicId(), defaultRole.GetVersion(), []string{userId})
		if err != nil {
			return fmt.Errorf("failed to add %q as principal for role id %q", userId, defaultRole.GetPublicId())
		}
		defaultRole.Version++ // The above call increments the role version in the database, so we must also track that with our state.
	}

	// Create a new role for the "authorize-session" grant and add the
	// unprivileged user as a principal.
	asRole, err := iam.NewRole(ctx,
		projectId,
		iam.WithName(fmt.Sprintf("Session authorization for %s", targetId)),
		iam.WithDescription(fmt.Sprintf("Provides grants within the dev project scope to allow the initial unprivileged user to authorize sessions against %s", targetId)),
	)
	if err != nil {
		return fmt.Errorf("failed to create role object: %w", err)
	}

	asRole, err = repo.CreateRole(ctx, asRole)
	if err != nil {
		return fmt.Errorf("failed to create role for unprivileged user: %w", err)
	}
	if _, err := repo.AddPrincipalRoles(ctx, asRole.GetPublicId(), asRole.GetVersion(), []string{userId}, nil); err != nil {
		return fmt.Errorf("failed to add unprivileged user as principal to new role: %w", err)
	}
	asRole.Version++

	_, err = repo.AddRoleGrants(ctx, asRole.GetPublicId(), asRole.GetVersion(), []string{fmt.Sprintf("id=%s;actions=authorize-session", targetId)})
	if err != nil {
		return fmt.Errorf("failed to add authorize-session grant for unprivileged user: %w", err)
	}

	return nil
}
