package database

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
)

type AuthMethodInfo struct {
	AuthMethodId string `json:"auth_method_id"`
	LoginName    string `json:"login_name"`
	Password     string `json:"password"`
	ScopeId      string `json:"scope_id"`
	UserId       string `json:"user_id"`
}

func generateInitialAuthMethodTableOutput(in *AuthMethodInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Scope ID":       in.ScopeId,
		"Auth Method ID": in.AuthMethodId,
		"Login Name":     in.LoginName,
		"Password":       in.Password,
		"User ID":        in.UserId,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial auth method information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type ScopeInfo struct {
	ScopeId string `json:"scope_id"`
	Type    string `json:"type"`
}

func generateInitialScopeTableOutput(in *ScopeInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Scope ID": in.ScopeId,
		"Type":     in.Type,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		fmt.Sprintf("Initial %s scope information:", in.Type),
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type HostInfo struct {
	HostCatalogId string `json:"host_catalog_id"`
	HostSetId     string `json:"host_set_id"`
	HostId        string `json:"host_id"`
	Type          string `json:"type"`
	ScopeId       string `json:"scope_id"`
}

func generateInitialHostResourcesTableOutput(in *HostInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Host Catalog ID": in.HostCatalogId,
		"Host Set ID":     in.HostSetId,
		"Host ID":         in.HostId,
		"Type":            in.Type,
		"Scope ID":        in.ScopeId,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial host resources information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type TargetInfo struct {
	TargetId               string `json:"target_id"`
	DefaultPort            uint32 `json:"default_port"`
	SessionMaxSeconds      uint32 `json:"session_max_seconds"`
	SessionConnectionLimit int32  `json:"session_connection_limit"`
	Type                   string `json:"type"`
	ScopeId                string `json:"scope_id"`
}

func generateInitialTargetTableOutput(in *TargetInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Target ID":                in.TargetId,
		"Default Port":             in.DefaultPort,
		"Session Max Seconds":      in.SessionMaxSeconds,
		"Session Connection Limit": in.SessionConnectionLimit,
		"Type":                     in.Type,
		"Scope ID":                 in.ScopeId,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial target information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}
