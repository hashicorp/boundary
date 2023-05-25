// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

// Scope contains information about the scope of a Boundary domain object
type Scope struct {
	PublicId            string
	Name                string // optional
	Description         string // optional
	Type                string
	ParentId            string // optional
	PrimaryAuthMethodId string // optional
}

// User contains information about user who initiated this session
type User struct {
	PublicId    string
	Scope       Scope
	Name        string // optional field
	Description string // optional field
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

// Worker contains information about the worker used to record this session
type Worker struct {
	PublicId string
	Version  string
	Sha      string
}

// StaticHostCatalog contains information about the static host catalog for this session
type StaticHostCatalog struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
}

// StaticHost contains information about the static host for this session
type StaticHost struct {
	PublicId    string
	Catalog     StaticHostCatalog
	Name        string // optional field
	Description string // optional field
	Address     string
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

// DynamicHost contains information about the dynamic host for this session
type DynamicHost struct {
	PublicId    string
	Catalog     DynamicHostCatalog
	Name        string // optional field
	Description string // optional field
	ExternalId  string
}

// StaticCredentialStore represents a static credential store used for this session
type StaticCredentialStore struct {
	PublicId    string
	ProjectId   string
	Name        string // optional field
	Description string // optional field
}

// StaticJsonCredential represents a static json credential used for this session
type StaticJsonCredential struct {
	PublicId        string
	ProjectId       string
	Name            string // optional field
	Description     string // optional field
	ObjectHmac      []byte
	Purposes        []string
	CredentialStore StaticCredentialStore
}

// StaticUsernamePasswordCredential represents a Static username password credential used for this session
type StaticUsernamePasswordCredential struct {
	PublicId        string
	ProjectId       string
	Name            string // optional field
	Description     string // optional field
	PasswordHmac    []byte
	Purposes        []string
	CredentialStore StaticCredentialStore
}

// StaticSshPrivateKeyCredential represents a Static Ssh private key credential used for this session
type StaticSshPrivateKeyCredential struct {
	PublicId                 string
	ProjectId                string
	Name                     string // optional field
	Description              string // optional field
	PrivateKeyHmac           []byte
	PrivateKeyPassphraseHmac []byte // optional field
	Purposes                 []string
	CredentialStore          StaticCredentialStore
}

// VaultCredentialStore represents a Vault credential store used for this session
type VaultCredentialStore struct {
	PublicId      string
	ProjectId     string
	Name          string // optional field
	Description   string // optional field
	VaultAddress  string
	Namespace     string
	TlsServerName string
	TlsSkipVerify bool
	WorkerFilter  string // optional field
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
	Purposes        []string
	CredentialStore VaultCredentialStore
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
	Purposes        []string
	CredentialStore VaultCredentialStore
}

// SessionMeta contains metadata about a session in a BSR.
type SessionMeta struct {
	PublicId string
	Endpoint string
	User     *User
	Target   *Target
	Worker   *Worker
	// StaticHost and DynamicHost are mutually exclusive
	StaticHost  *StaticHost
	DynamicHost *DynamicHost

	StaticJSONCredentials             []StaticJsonCredential
	StaticUsernamePasswordCredentials []StaticUsernamePasswordCredential
	StaticSshPrivateKeyCredentials    []StaticSshPrivateKeyCredential
	VaultLibraries                    []VaultLibrary
	VaultSshCertLibraries             []VaultSshCertLibrary
}
