// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"fmt"
	"strconv"
)

// Scope contains information about the scope of a Boundary domain object
type Scope struct {
	PublicId            string
	Name                string // optional
	Description         string // optional
	Type                string
	ParentId            string // optional
	PrimaryAuthMethodId string // optional
}

func (s Scope) writeMeta(ctx context.Context, c *container, domainObj string) error {
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_scope_publicId", domainObj), s.PublicId)
	if err != nil {
		return err
	}
	if s.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_name", domainObj), s.Name)
		if err != nil {
			return err
		}
	}
	if s.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_description", domainObj), s.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_type", domainObj), s.Type)
	if err != nil {
		return err
	}
	if s.ParentId != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_parentId", domainObj), s.ParentId)
		if err != nil {
			return err
		}
	}
	if s.PrimaryAuthMethodId != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_scope_primaryAuthMethodId", domainObj), s.PrimaryAuthMethodId)
		if err != nil {
			return err
		}
	}

	return nil
}

// User contains information about user who initiated this session
type User struct {
	PublicId    string
	Scope       Scope
	Name        string // optional field
	Description string // optional field
}

func (u User) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "user_publicId", u.PublicId)
	if err != nil {
		return err
	}
	err = u.Scope.writeMeta(ctx, c, "user")
	if err != nil {
		return err
	}
	if u.Name != "" {
		_, err = c.WriteMeta(ctx, "user_name", u.Name)
		if err != nil {
			return err
		}
	}
	if u.Description != "" {
		_, err = c.WriteMeta(ctx, "user_description", u.Description)
		if err != nil {
			return err
		}
	}

	return nil
}

// Target contains information about the target for this session
type Target struct {
	PublicId               string
	Scope                  Scope
	Name                   string // optional field
	Description            string // optional field
	DefaultPort            uint32
	SessionMaxSeconds      uint32
	SessionConnectionLimit int32
	WorkerFilter           string // optional field
	EgressWorkerFilter     string // optional field
	IngressWorkerFilter    string // optional field
}

func (t Target) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "target_publicId", t.PublicId)
	if err != nil {
		return err
	}
	err = t.Scope.writeMeta(ctx, c, "target")
	if err != nil {
		return err
	}
	if t.Name != "" {
		_, err = c.WriteMeta(ctx, "target_name", t.Name)
		if err != nil {
			return err
		}
	}
	if t.Description != "" {
		_, err = c.WriteMeta(ctx, "target_description", t.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "target_defaultPort", fmt.Sprintf("%d", t.DefaultPort))
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "target_sessionMaxSeconds", fmt.Sprintf("%d", t.SessionMaxSeconds))
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "target_sessionConnectionLimit", fmt.Sprintf("%d", t.SessionConnectionLimit))
	if err != nil {
		return err
	}
	if t.WorkerFilter != "" {
		_, err = c.WriteMeta(ctx, "target_workerFilter", t.WorkerFilter)
		if err != nil {
			return err
		}
	}
	if t.IngressWorkerFilter != "" {
		_, err = c.WriteMeta(ctx, "target_ingressWorkerFilter", t.IngressWorkerFilter)
		if err != nil {
			return err
		}
	}
	if t.EgressWorkerFilter != "" {
		_, err = c.WriteMeta(ctx, "target_egressWorkerFilter", t.EgressWorkerFilter)
		if err != nil {
			return err
		}
	}

	return nil
}

// Worker contains information about the worker used to record this session
type Worker struct {
	PublicId string
	Version  string
	Sha      string
}

func (w Worker) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "worker_publicId", w.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "worker_version", w.Version)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "worker_sha", w.Sha)
	if err != nil {
		return err
	}
	return nil
}

// StaticHostCatalog contains information about the static host catalog for this session
type StaticHostCatalog struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
}

func (h StaticHostCatalog) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "staticHostCatalog_publicId", h.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "staticHostCatalog_projectId", h.ProjectId)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "staticHostCatalog_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "staticHostCatalog_description", h.Description)
		if err != nil {
			return err
		}
	}

	return nil
}

// StaticHost contains information about the static host for this session
type StaticHost struct {
	PublicId    string
	Catalog     StaticHostCatalog
	Name        string // optional field
	Description string // optional field
	Address     string
}

func (h StaticHost) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "staticHost_publicId", h.PublicId)
	if err != nil {
		return err
	}
	err = h.Catalog.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "staticHost_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "staticHost_description", h.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "staticHost_address", h.Address)
	if err != nil {
		return err
	}

	return nil
}

// DynamicHostCatalog contains information about the dynamic host catalog for this session
type DynamicHostCatalog struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
	PluginId    string
	Attributes  string
}

func (h DynamicHostCatalog) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "dynamicHostCatalog_publicId", h.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "dynamicHostCatalog_projectId", h.ProjectId)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "dynamicHostCatalog_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "dynamicHostCatalog_description", h.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "dynamicHostCatalog_pluginId", h.PluginId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "dynamicHostCatalog_attributes", h.Attributes)
	if err != nil {
		return err
	}

	return nil
}

// DynamicHost contains information about the dynamic host for this session
type DynamicHost struct {
	PublicId    string
	Catalog     DynamicHostCatalog
	Name        string // optional field
	Description string // optional field
	ExternalId  string
}

func (h DynamicHost) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "dynamicHost_publicId", h.PublicId)
	if err != nil {
		return err
	}
	err = h.Catalog.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	if h.Name != "" {
		_, err = c.WriteMeta(ctx, "dynamicHost_name", h.Name)
		if err != nil {
			return err
		}
	}
	if h.Description != "" {
		_, err = c.WriteMeta(ctx, "dynamicHost_description", h.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, "dynamicHost_externalId", h.ExternalId)
	if err != nil {
		return err
	}

	return nil
}

// StaticCredentialStore represents a static credential store used for this session
type StaticCredentialStore struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
	Credentials []StaticCredential
}

func (s StaticCredentialStore) writeMeta(ctx context.Context, c *container) error {
	prefix := fmt.Sprintf("%s_staticCredentialStore", s.PublicId)
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_publicId", prefix), s.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_projectId", prefix), s.ProjectId)
	if err != nil {
		return err
	}
	if s.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_name", prefix), s.Name)
		if err != nil {
			return err
		}
	}
	if s.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_description", prefix), s.Description)
		if err != nil {
			return err
		}
	}
	if len(s.Credentials) > 0 {
		credentialPrefix := fmt.Sprintf("%s_credential", prefix)
		for _, sc := range s.Credentials {
			err = sc.writeStaticCredentialMeta(ctx, c, credentialPrefix)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// StaticCredential represents a static credential used for this session
type StaticCredential interface {
	writeStaticCredentialMeta(ctx context.Context, c *container, prefix string) error
}

// StaticJsonCredential represents a static json credential used for this session
type StaticJsonCredential struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
	ObjectHmac  []byte
}

func (s StaticJsonCredential) writeStaticCredentialMeta(ctx context.Context, c *container, p string) error {
	prefix := fmt.Sprintf("%s_%s_staticJsonCredential", p, s.PublicId)
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_publicId", prefix), s.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_projectId", prefix), s.ProjectId)
	if err != nil {
		return err
	}
	if s.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_name", prefix), s.Name)
		if err != nil {
			return err
		}
	}
	if s.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_description", prefix), s.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_objectHmac", prefix), string(s.ObjectHmac))
	if err != nil {
		return err
	}
	return nil
}

// StaticUsernamePasswordCredential represents a Static username password credential used for this session
type StaticUsernamePasswordCredential struct {
	PublicId     string
	ProjectId    string
	Name         string // optional field
	Description  string // optional field
	PasswordHmac []byte
}

func (s StaticUsernamePasswordCredential) writeStaticCredentialMeta(ctx context.Context, c *container, p string) error {
	prefix := fmt.Sprintf("%s_%s_staticUsernamePasswordCredential", p, s.PublicId)
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_publicId", prefix), s.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_projectId", prefix), s.ProjectId)
	if err != nil {
		return err
	}
	if s.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_name", prefix), s.Name)
		if err != nil {
			return err
		}
	}
	if s.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_description", prefix), s.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_passwordHmac", prefix), string(s.PasswordHmac))
	if err != nil {
		return err
	}
	return nil
}

// StaticSshPrivateKeyCredential represents a Static Ssh private key credential used for this session
type StaticSshPrivateKeyCredential struct {
	PublicId                 string
	ProjectId                string
	Name                     string // optional field
	Description              string // optional field
	PrivateKeyHmac           []byte
	PrivateKeyPassphraseHmac []byte // optional field
}

func (s StaticSshPrivateKeyCredential) writeStaticCredentialMeta(ctx context.Context, c *container, p string) error {
	prefix := fmt.Sprintf("%s_%s_staticSshPrivateKeyCredential", p, s.PublicId)
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_publicId", prefix), s.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_projectId", prefix), s.ProjectId)
	if err != nil {
		return err
	}
	if s.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_name", prefix), s.Name)
		if err != nil {
			return err
		}
	}
	if s.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_description", prefix), s.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_privateKeyHmac", prefix), string(s.PrivateKeyHmac))
	if err != nil {
		return err
	}
	if len(s.PrivateKeyPassphraseHmac) > 0 {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_privateKeyPassphraseHmac", prefix), string(s.PrivateKeyPassphraseHmac))
		if err != nil {
			return err
		}
	}
	return nil
}

// VaultCredentialStore represents a Vault credential store used for this session
type VaultCredentialStore struct {
	PublicId            string
	ProjectId           string
	Name                string // optional field
	Description         string // optional field
	VaultAddress        string
	Namespace           string
	TlsServerName       string
	TlsSkipVerify       bool
	WorkerFilter        string // optional field
	CredentialLibraries []DynamicCredentialLibraries
}

func (v VaultCredentialStore) writeMeta(ctx context.Context, c *container) error {
	prefix := fmt.Sprintf("%s_vaultCredentialStore", v.PublicId)
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_publicId", prefix), v.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_projectId", prefix), v.ProjectId)
	if err != nil {
		return err
	}
	if v.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_name", prefix), v.Name)
		if err != nil {
			return err
		}
	}
	if v.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_description", prefix), v.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_vaultAddress", prefix), v.VaultAddress)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_namespace", prefix), v.Namespace)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_tlsServerName", prefix), v.TlsServerName)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_tlsSkipVerify", prefix), strconv.FormatBool(v.TlsSkipVerify))
	if err != nil {
		return err
	}
	if v.WorkerFilter != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_workerFilter", prefix), v.WorkerFilter)
		if err != nil {
			return err
		}
	}
	if len(v.CredentialLibraries) > 0 {
		credentialPrefix := fmt.Sprintf("%s_credential", prefix)
		for _, cl := range v.CredentialLibraries {
			err = cl.writeDynamicCredentialLibraryMeta(ctx, c, credentialPrefix)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// DynamicCredentialLibraries represents a dynamic credential library used for this session
type DynamicCredentialLibraries interface {
	writeDynamicCredentialLibraryMeta(ctx context.Context, c *container, prefix string) error
}

// VaultLibrary contains information about the Vault library used for this session
type VaultLibrary struct {
	PublicId        string
	ProjectId       string
	Name            string // optional field
	Description     string // optional field
	VaultPath       string
	HttpMethod      string
	HttpRequestBody []byte // optional field
	CredentialType  string
}

func (v VaultLibrary) writeDynamicCredentialLibraryMeta(ctx context.Context, c *container, p string) error {
	prefix := fmt.Sprintf("%s_%s_vaultLibrary", p, v.PublicId)
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_publicId", prefix), v.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_projectId", prefix), v.ProjectId)
	if err != nil {
		return err
	}
	if v.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_name", prefix), v.Name)
		if err != nil {
			return err
		}
	}
	if v.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_description", prefix), v.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_vaultPath", prefix), v.VaultPath)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_httpMethod", prefix), v.HttpMethod)
	if err != nil {
		return err
	}
	if len(v.HttpRequestBody) > 0 {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_httpRequestBody", prefix), string(v.HttpRequestBody))
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_credentialType", prefix), v.CredentialType)
	if err != nil {
		return err
	}
	return nil
}

// VaultSshCertLibrary contains information about a Vault Ssh Cert library for this session
type VaultSshCertLibrary struct {
	PublicId        string
	ProjectId       string
	Name            string // optional field
	Description     string // optional field
	VaultPath       string
	Username        string
	KeyType         string
	KeyBits         int
	Ttl             string // optional field
	CriticalOptions []byte // optional field
	Extensions      []byte // optional field
	CredentialType  string // optional field
}

func (v VaultSshCertLibrary) writeDynamicCredentialLibraryMeta(ctx context.Context, c *container, p string) error {
	prefix := fmt.Sprintf("%s_%s_vaultSshCertLibrary", p, v.PublicId)
	_, err := c.WriteMeta(ctx, fmt.Sprintf("%s_publicId", prefix), v.PublicId)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_projectId", prefix), v.ProjectId)
	if err != nil {
		return err
	}
	if v.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_name", prefix), v.Name)
		if err != nil {
			return err
		}
	}
	if v.Description != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_description", prefix), v.Description)
		if err != nil {
			return err
		}
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_vaultPath", prefix), v.VaultPath)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_username", prefix), v.Username)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_keyType", prefix), v.KeyType)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_keyBits", prefix), strconv.Itoa(v.KeyBits))
	if err != nil {
		return err
	}
	if v.Ttl != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_ttl", prefix), v.Ttl)
		if err != nil {
			return err
		}
	}
	if len(v.CriticalOptions) > 0 {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_criticalOptions", prefix), string(v.CriticalOptions))
		if err != nil {
			return err
		}
	}
	if len(v.Extensions) > 0 {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_extensions", prefix), string(v.Extensions))
		if err != nil {
			return err
		}
	}
	if v.Name != "" {
		_, err = c.WriteMeta(ctx, fmt.Sprintf("%s_credentialType", prefix), v.CredentialType)
		if err != nil {
			return err
		}
	}
	return nil
}

// SessionMeta contains metadata about a session in a BSR.
// Most fields are written to the meta file as k:v pairs
// Slice fields are written to the meta file as id_k:v
// Nested slice fields are written as parentId_parentKey_id_k:v
type SessionMeta struct {
	Id       string
	Protocol Protocol
	User     *User
	Target   *Target
	Worker   *Worker
	// StaticHost and DynamicHost are mutually exclusive
	StaticHost  *StaticHost
	DynamicHost *DynamicHost

	StaticCredentialStore []StaticCredentialStore
	VaultCredentialStore  []VaultCredentialStore

	connections map[string]bool
}

func (s SessionMeta) writeMeta(ctx context.Context, c *container) error {
	_, err := c.WriteMeta(ctx, "id", s.Id)
	if err != nil {
		return err
	}
	_, err = c.WriteMeta(ctx, "protocol", s.Protocol.ToText())
	if err != nil {
		return err
	}
	err = s.User.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	err = s.Target.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	err = s.Worker.writeMeta(ctx, c)
	if err != nil {
		return err
	}
	if s.StaticHost != nil {
		err = s.StaticHost.writeMeta(ctx, c)
		if err != nil {
			return err
		}
	}
	if s.DynamicHost != nil {
		err = s.DynamicHost.writeMeta(ctx, c)
		if err != nil {
			return err
		}
	}
	if len(s.StaticCredentialStore) > 0 {
		for _, sc := range s.StaticCredentialStore {
			err = sc.writeMeta(ctx, c)
			if err != nil {
				return err
			}
		}
	}
	if len(s.VaultCredentialStore) > 0 {
		for _, dc := range s.VaultCredentialStore {
			err = dc.writeMeta(ctx, c)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
