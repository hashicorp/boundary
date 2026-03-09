// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"github.com/hashicorp/boundary/internal/alias"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/billing"
	"github.com/hashicorp/boundary/internal/credential"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/host"
	pluginhost "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	pluginstorage "github.com/hashicorp/boundary/internal/storage/plugin"
)

type (
	AuthTokenRepoFactory           = oidc.AuthTokenRepoFactory
	VaultCredentialRepoFactory     = func() (*vault.Repository, error)
	StaticCredentialRepoFactory    = func() (*credstatic.Repository, error)
	CredentialStoreRepoFactory     func() (*credential.StoreRepository, error)
	HostCatalogRepoFactory         func() (*host.CatalogRepository, error)
	IamRepoFactory                 = iam.IamRepoFactory
	OidcAuthRepoFactory            = oidc.OidcRepoFactory
	LdapAuthRepoFactory            = ldap.RepoFactory
	PasswordAuthRepoFactory        func() (*password.Repository, error)
	AuthMethodRepoFactory          func() (*auth.AuthMethodRepository, error)
	ServersRepoFactory             func() (*server.Repository, error)
	StaticRepoFactory              func() (*static.Repository, error)
	PluginHostRepoFactory          func() (*pluginhost.Repository, error)
	PluginRepoFactory              func() (*plugin.Repository, error)
	ConnectionRepoFactory          func() (*session.ConnectionRepository, error)
	WorkerAuthRepoStorageFactory   func() (*server.WorkerAuthRepositoryStorage, error)
	PluginStorageBucketRepoFactory func() (*pluginstorage.Repository, error)
	BillingRepoFactory             func() (*billing.Repository, error)
	AliasRepoFactory               func() (*alias.Repository, error)
	TargetAliasRepoFactory         func() (*target.Repository, error)
)
