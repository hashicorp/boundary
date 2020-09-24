package base

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/vault/sdk/helper/base62"
)

func (b *Server) CreateInitialAuthMethod(ctx context.Context) error {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo, kms.WithLogger(b.Logger.Named("kms")))
	if err != nil {
		return fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return fmt.Errorf("error adding config keys to kms: %w", err)
	}

	// Create the dev auth method
	pwRepo, err := password.NewRepository(rw, rw, kmsCache)
	if err != nil {
		return fmt.Errorf("error creating password repo: %w", err)
	}
	authMethod, err := password.NewAuthMethod(scope.Global.String())
	if err != nil {
		return fmt.Errorf("error creating new in memory auth method: %w", err)
	}
	if b.DevAuthMethodId == "" {
		b.DevAuthMethodId, err = db.NewPublicId(password.AuthMethodPrefix)
		if err != nil {
			return fmt.Errorf("error generating initial auth method id: %w", err)
		}
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-b.ShutdownCh
		cancel()
	}()

	_, err = pwRepo.CreateAuthMethod(cancelCtx, authMethod,
		password.WithName("Generated global scope initial auth method"),
		password.WithDescription("Provides initial administrative authentication into Boundary"),
		password.WithPublicId(b.DevAuthMethodId))
	if err != nil {
		return fmt.Errorf("error saving auth method to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated auth method id")
	b.Info["generated auth method id"] = b.DevAuthMethodId

	// Create the dev user
	if b.DevLoginName == "" {
		b.DevLoginName, err = base62.Random(10)
		if err != nil {
			return fmt.Errorf("unable to generate login name: %w", err)
		}
		b.DevLoginName = strings.ToLower(b.DevLoginName)
	}
	if b.DevPassword == "" {
		b.DevPassword, err = base62.Random(20)
		if err != nil {
			return fmt.Errorf("unable to generate password: %w", err)
		}
	}
	b.InfoKeys = append(b.InfoKeys, "generated auth method password")
	b.Info["generated auth method password"] = b.DevPassword

	acct, err := password.NewAccount(b.DevAuthMethodId, password.WithLoginName(b.DevLoginName))
	if err != nil {
		return fmt.Errorf("error creating new in memory auth account: %w", err)
	}
	acct, err = pwRepo.CreateAccount(cancelCtx, scope.Global.String(), acct, password.WithPassword(b.DevPassword))
	if err != nil {
		return fmt.Errorf("error saving auth account to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated auth method login name")
	b.Info["generated auth method login name"] = acct.GetLoginName()

	iamRepo, err := iam.NewRepository(rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
	if err != nil {
		return fmt.Errorf("unable to create repo for org id: %w", err)
	}

	// Create a new user and associate it with the account
	u, err := iam.NewUser(scope.Global.String(),
		iam.WithName("admin"),
		iam.WithDescription(`Initial admin user within the "global" scope`),
	)
	if err != nil {
		return fmt.Errorf("error creating in memory user: %w", err)
	}
	if u, err = iamRepo.CreateUser(cancelCtx, u, iam.WithPublicId(b.DevUserId)); err != nil {
		return fmt.Errorf("error creating initial admin user: %w", err)
	}
	if u, err = iamRepo.AssociateUserWithAccount(cancelCtx, u.GetPublicId(), acct.GetPublicId()); err != nil {
		return fmt.Errorf("error associating initial admin user with account: %w", err)
	}

	// Create a role tying them together
	pr, err := iam.NewRole(scope.Global.String(),
		iam.WithName("Generated global scope admin role"),
		iam.WithDescription(`Provides admin grants within the "global" scope to the initial user`),
	)
	if err != nil {
		return fmt.Errorf("error creating in memory role for generated grants: %w", err)
	}
	defPermsRole, err := iamRepo.CreateRole(cancelCtx, pr)
	if err != nil {
		return fmt.Errorf("error creating role for default generated grants: %w", err)
	}
	if _, err := iamRepo.AddRoleGrants(cancelCtx, defPermsRole.PublicId, defPermsRole.Version, []string{"id=*;actions=*"}); err != nil {
		return fmt.Errorf("error creating grant for default generated grants: %w", err)
	}
	if _, err := iamRepo.AddPrincipalRoles(cancelCtx, defPermsRole.PublicId, defPermsRole.Version+1, []string{u.GetPublicId()}, nil); err != nil {
		return fmt.Errorf("error adding principal to role for default generated grants: %w", err)
	}

	return nil
}

func (b *Server) CreateInitialScopes(ctx context.Context) error {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo, kms.WithLogger(b.Logger.Named("kms")))
	if err != nil {
		return fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return fmt.Errorf("error adding config keys to kms: %w", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-b.ShutdownCh
		cancel()
	}()

	// Create the org scope
	iamRepo, err := iam.NewRepository(rw, rw, kmsCache)
	if err != nil {
		return fmt.Errorf("error creating scopes: %w", err)
	}
	opts := []iam.Option{
		iam.WithName("Generated org scope"),
		iam.WithDescription("Provides an initial org scope in Boundary"),
		iam.WithRandomReader(b.SecureRandomReader),
	}
	orgScope, err := iam.NewOrg(opts...)
	if err != nil {
		return fmt.Errorf("error creating new in memory org scope: %w", err)
	}
	if b.DevOrgId == "" {
		b.DevOrgId, err = db.NewPublicId(scope.Org.Prefix())
		if err != nil {
			return fmt.Errorf("error generating initial org id: %w", err)
		}
	}
	opts = []iam.Option{iam.WithPublicId(b.DevOrgId)}
	_, err = iamRepo.CreateScope(cancelCtx, orgScope, b.DevUserId, opts...)
	if err != nil {
		return fmt.Errorf("error saving org scope to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated org scope id")
	b.Info["generated org scope id"] = b.DevOrgId

	opts = []iam.Option{
		iam.WithName("Generated project scope"),
		iam.WithDescription("Provides an initial project scope in Boundary"),
		iam.WithRandomReader(b.SecureRandomReader),
	}
	projScope, err := iam.NewProject(b.DevOrgId, opts...)
	if err != nil {
		return fmt.Errorf("error creating new in memory project scope: %w", err)
	}
	if b.DevProjectId == "" {
		b.DevProjectId, err = db.NewPublicId(scope.Project.Prefix())
		if err != nil {
			return fmt.Errorf("error generating initial project id: %w", err)
		}
	}
	opts = []iam.Option{iam.WithPublicId(b.DevProjectId)}
	_, err = iamRepo.CreateScope(cancelCtx, projScope, b.DevUserId, opts...)
	if err != nil {
		return fmt.Errorf("error saving project scope to the db: %w", err)
	}
	b.InfoKeys = append(b.InfoKeys, "generated project scope id")
	b.Info["generated project scope id"] = b.DevProjectId
	/*
		// Create the dev user
		if b.DevLoginName == "" {
			b.DevLoginName, err = base62.Random(10)
			if err != nil {
				return fmt.Errorf("unable to generate login name: %w", err)
			}
			b.DevLoginName = strings.ToLower(b.DevLoginName)
		}
		if b.DevPassword == "" {
			b.DevPassword, err = base62.Random(20)
			if err != nil {
				return fmt.Errorf("unable to generate password: %w", err)
			}
		}
		b.InfoKeys = append(b.InfoKeys, "generated password")
		b.Info["generated password"] = b.DevPassword

		acct, err := password.NewAccount(b.DevAuthMethodId, password.WithLoginName(b.DevLoginName))
		if err != nil {
			return fmt.Errorf("error creating new in memory auth account: %w", err)
		}
		acct, err = pwRepo.CreateAccount(cancelCtx, scope.Global.String(), acct, password.WithPassword(b.DevPassword))
		if err != nil {
			return fmt.Errorf("error saving auth account to the db: %w", err)
		}
		b.InfoKeys = append(b.InfoKeys, "generated login name")
		b.Info["generated login name"] = acct.GetLoginName()

		// Create a role tying them together
		iamRepo, err := iam.NewRepository(rw, rw, kmsCache, iam.WithRandomReader(b.SecureRandomReader))
		if err != nil {
			return fmt.Errorf("unable to create repo for org id: %w", err)
		}
		pr, err := iam.NewRole(scope.Global.String())
		if err != nil {
			return fmt.Errorf("error creating in memory role for generated grants: %w", err)
		}
		pr.Name = "Generated Global Scope Admin Role"
		pr.Description = `Provides admin grants to all authenticated users within the "global" scope`
		defPermsRole, err := iamRepo.CreateRole(cancelCtx, pr)
		if err != nil {
			return fmt.Errorf("error creating role for default generated grants: %w", err)
		}
		if _, err := iamRepo.AddRoleGrants(cancelCtx, defPermsRole.PublicId, defPermsRole.Version, []string{"id=*;actions=*"}); err != nil {
			return fmt.Errorf("error creating grant for default generated grants: %w", err)
		}
		if _, err := iamRepo.AddPrincipalRoles(cancelCtx, defPermsRole.PublicId, defPermsRole.Version+1, []string{"u_auth"}, nil); err != nil {
			return fmt.Errorf("error adding principal to role for default generated grants: %w", err)
		}
	*/
	return nil
}
