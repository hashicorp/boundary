// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/credential"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
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
	LibraryServiceFactory          func(*vault.Repository) (*credential.LibraryService, error)
	StoreServiceFactory            func(*vault.Repository, *credstatic.Repository) (*credential.StoreService, error)
	IamRepoFactory                 = iam.IamRepoFactory
	OidcAuthRepoFactory            = oidc.OidcRepoFactory
	LdapAuthRepoFactory            = ldap.RepoFactory
	PasswordAuthRepoFactory        func() (*password.Repository, error)
	ServersRepoFactory             func() (*server.Repository, error)
	StaticRepoFactory              func() (*static.Repository, error)
	PluginHostRepoFactory          func() (*pluginhost.Repository, error)
	PluginRepoFactory              func() (*plugin.Repository, error)
	ConnectionRepoFactory          func() (*session.ConnectionRepository, error)
	WorkerAuthRepoStorageFactory   func() (*server.WorkerAuthRepositoryStorage, error)
	PluginStorageBucketRepoFactory func() (*pluginstorage.Repository, error)
)

// Downstreamers provides at least a minimum interface that must be met by a
// Controller.downstreamWorkers field which is far better than allowing any (empty
// interface)
type Downstreamers interface {
	// RootId returns the root ID of the downstreamers' graph
	RootId() string
}
