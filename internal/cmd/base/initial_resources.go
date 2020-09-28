package base

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/vault/sdk/helper/base62"
)

func (b *Server) CreateInitialAuthMethod(ctx context.Context) (*password.AuthMethod, *iam.User, error) {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo, kms.WithLogger(b.Logger.Named("kms")))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	// Create the dev auth method
	pwRepo, err := password.NewRepository(rw, rw, kmsCache)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating password repo: %w", err)
	}
	authMethod, err := password.NewAuthMethod(scope.Global.String(),
		password.WithName("Generated global scope initial auth method"),
		password.WithDescription("Provides initial administrative authentication into Boundary"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory auth method: %w", err)
	}
	if b.DevAuthMethodId == "" {
		b.DevAuthMethodId, err = db.NewPublicId(password.AuthMethodPrefix)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating initial auth method id: %w", err)
		}
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-b.ShutdownCh
		cancel()
	}()

	am, err := pwRepo.CreateAuthMethod(cancelCtx, authMethod,
		password.WithPublicId(b.DevAuthMethodId))
	if err != nil {
		return nil, nil, fmt.Errorf("error saving auth method to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated auth method id")
	b.Info["generated auth method id"] = b.DevAuthMethodId

	// Create the dev user
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
	b.InfoKeys = append(b.InfoKeys, "generated auth method password")
	b.Info["generated auth method password"] = b.DevPassword

	acct, err := password.NewAccount(b.DevAuthMethodId, password.WithLoginName(b.DevLoginName))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory auth account: %w", err)
	}
	acct, err = pwRepo.CreateAccount(cancelCtx, scope.Global.String(), acct, password.WithPassword(b.DevPassword))
	if err != nil {
		return nil, nil, fmt.Errorf("error saving auth account to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated auth method login name")
	b.Info["generated auth method login name"] = acct.GetLoginName()

	iamRepo, err := iam.NewRepository(rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create repo for org id: %w", err)
	}

	// Create a new user and associate it with the account
	if b.DevUserId == "" {
		b.DevUserId, err = db.NewPublicId(iam.UserPrefix)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating initial user id: %w", err)
		}
	}
	opts := []iam.Option{
		iam.WithName("admin"),
		iam.WithDescription(`Initial admin user within the "global" scope`),
		iam.WithPublicId(b.DevUserId),
	}
	u, err := iam.NewUser(scope.Global.String(), opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating in memory user: %w", err)
	}
	if u, err = iamRepo.CreateUser(cancelCtx, u, opts...); err != nil {
		return nil, nil, fmt.Errorf("error creating initial admin user: %w", err)
	}
	if _, err = iamRepo.AddUserAccounts(cancelCtx, u.GetPublicId(), u.GetVersion(), []string{acct.GetPublicId()}); err != nil {
		return nil, nil, fmt.Errorf("error associating initial admin user with account: %w", err)
	}
	// Create a role tying them together
	pr, err := iam.NewRole(scope.Global.String(),
		iam.WithName("Generated global scope admin role"),
		iam.WithDescription(`Provides admin grants within the "global" scope to the initial user`),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating in memory role for generated grants: %w", err)
	}
	defPermsRole, err := iamRepo.CreateRole(cancelCtx, pr)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating role for default generated grants: %w", err)
	}
	if _, err := iamRepo.AddRoleGrants(cancelCtx, defPermsRole.PublicId, defPermsRole.Version, []string{"id=*;actions=*"}); err != nil {
		return nil, nil, fmt.Errorf("error creating grant for default generated grants: %w", err)
	}
	if _, err := iamRepo.AddPrincipalRoles(cancelCtx, defPermsRole.PublicId, defPermsRole.Version+1, []string{u.GetPublicId()}, nil); err != nil {
		return nil, nil, fmt.Errorf("error adding principal to role for default generated grants: %w", err)
	}

	return am, u, nil
}

func (b *Server) CreateInitialScopes(ctx context.Context) (*iam.Scope, *iam.Scope, error) {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo, kms.WithLogger(b.Logger.Named("kms")))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-b.ShutdownCh
		cancel()
	}()

	iamRepo, err := iam.NewRepository(rw, rw, kmsCache)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating scopes repository: %w", err)
	}

	// Create the scopes
	if b.DevOrgId == "" {
		b.DevOrgId, err = db.NewPublicId(scope.Org.Prefix())
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
	orgScope, err := iam.NewOrg(opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory org scope: %w", err)
	}
	orgScope, err = iamRepo.CreateScope(cancelCtx, orgScope, b.DevUserId, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error saving org scope to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated org scope id")
	b.Info["generated org scope id"] = b.DevOrgId

	if b.DevProjectId == "" {
		b.DevProjectId, err = db.NewPublicId(scope.Project.Prefix())
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
	projScope, err := iam.NewProject(b.DevOrgId, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating new in memory project scope: %w", err)
	}
	projScope, err = iamRepo.CreateScope(cancelCtx, projScope, b.DevUserId, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error saving project scope to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated project scope id")
	b.Info["generated project scope id"] = b.DevProjectId

	return orgScope, projScope, nil
}

func (b *Server) CreateInitialHostResources(ctx context.Context) (*static.HostCatalog, *static.HostSet, *static.Host, error) {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo, kms.WithLogger(b.Logger.Named("kms")))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, nil, nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-b.ShutdownCh
		cancel()
	}()

	staticRepo, err := static.NewRepository(rw, rw, kmsCache)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating static repository: %w", err)
	}

	// Host Catalog
	if b.DevHostCatalogId == "" {
		b.DevHostCatalogId, err = db.NewPublicId(static.HostCatalogPrefix)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error generating initial host catalog id: %w", err)
		}
	}
	opts := []static.Option{
		static.WithName("Generated host catalog"),
		static.WithDescription("Provides an initial host catalog in Boundary"),
		static.WithPublicId(b.DevHostCatalogId),
	}
	hc, err := static.NewHostCatalog(b.DevProjectId, opts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating in memory host catalog: %w", err)
	}
	if hc, err = staticRepo.CreateCatalog(cancelCtx, hc, opts...); err != nil {
		return nil, nil, nil, fmt.Errorf("error saving host catalog to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated host catalog id")
	b.Info["generated host catalog id"] = b.DevHostCatalogId

	// Host
	if b.DevHostId == "" {
		b.DevHostId, err = db.NewPublicId(static.HostPrefix)
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
	h, err := static.NewHost(hc.PublicId, opts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating in memory host: %w", err)
	}
	if h, err = staticRepo.CreateHost(cancelCtx, b.DevProjectId, h, opts...); err != nil {
		return nil, nil, nil, fmt.Errorf("error saving host to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated host id")
	b.Info["generated host id"] = b.DevHostId

	// Host Set
	if b.DevHostSetId == "" {
		b.DevHostSetId, err = db.NewPublicId(static.HostSetPrefix)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error generating initial host set id: %w", err)
		}
	}
	opts = []static.Option{
		static.WithName("Generated host set"),
		static.WithDescription("Provides an initial host set in Boundary"),
		static.WithPublicId(b.DevHostSetId),
	}
	hs, err := static.NewHostSet(hc.PublicId, opts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating in memory host set: %w", err)
	}
	if hs, err = staticRepo.CreateSet(cancelCtx, b.DevProjectId, hs, opts...); err != nil {
		return nil, nil, nil, fmt.Errorf("error saving host set to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated host set id")
	b.Info["generated host set id"] = b.DevHostSetId

	// Associate members
	if _, err := staticRepo.AddSetMembers(cancelCtx, b.DevProjectId, b.DevHostSetId, hs.GetVersion(), []string{h.GetPublicId()}); err != nil {
		return nil, nil, nil, fmt.Errorf("error associating host set to host in the db: %w", err)
	}

	return hc, hs, h, nil
}

func (b *Server) CreateInitialTarget(ctx context.Context) (target.Target, error) {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return nil, fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo, kms.WithLogger(b.Logger.Named("kms")))
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-b.ShutdownCh
		cancel()
	}()

	targetRepo, err := target.NewRepository(rw, rw, kmsCache)
	if err != nil {
		return nil, fmt.Errorf("error creating target repository: %w", err)
	}

	// Host Catalog
	if b.DevTargetId == "" {
		b.DevTargetId, err = db.NewPublicId(target.TcpTargetPrefix)
		if err != nil {
			return nil, fmt.Errorf("error generating initial target id: %w", err)
		}
	}
	if b.DevTargetDefaultPort == 0 {
		b.DevTargetDefaultPort = 22
	}
	opts := []target.Option{
		target.WithName("Generated target"),
		target.WithDescription("Provides an initial target in Boundary"),
		target.WithDefaultPort(uint32(b.DevTargetDefaultPort)),
		target.WithHostSets([]string{b.DevHostSetId}),
		target.WithSessionMaxSeconds(uint32(b.DevTargetSessionMaxSeconds)),
		target.WithSessionConnectionLimit(int32(b.DevTargetSessionConnectionLimit)),
		target.WithPublicId(b.DevTargetId),
	}
	t, err := target.NewTcpTarget(b.DevProjectId, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating in memory target: %w", err)
	}
	tt, _, err := targetRepo.CreateTcpTarget(cancelCtx, t, opts...)
	if err != nil {
		return nil, fmt.Errorf("error saving target to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated target id")
	b.Info["generated target id"] = b.DevTargetId

	return tt, nil
}
