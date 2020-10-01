package database

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
)

type RoleInfo struct {
	RoleId string `json:"scope_id"`
	Name   string `json:"name"`
}

func generateInitialRoleTableOutput(in *RoleInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Role ID": in.RoleId,
		"Name":    in.Name,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial login role information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type AuthInfo struct {
	AuthMethodId   string `json:"auth_method_id"`
	AuthMethodName string `json:"auth_method_name"`
	LoginName      string `json:"login_name"`
	Password       string `json:"password"`
	ScopeId        string `json:"scope_id"`
	UserId         string `json:"user_id"`
	UserName       string `json:"user_name"`
}

func generateInitialAuthTableOutput(in *AuthInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Scope ID":         in.ScopeId,
		"Auth Method ID":   in.AuthMethodId,
		"Auth Method Name": in.AuthMethodName,
		"Login Name":       in.LoginName,
		"Password":         in.Password,
		"User ID":          in.UserId,
		"User Name":        in.UserName,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial auth information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type ScopeInfo struct {
	ScopeId string `json:"scope_id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
}

func generateInitialScopeTableOutput(in *ScopeInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Scope ID": in.ScopeId,
		"Type":     in.Type,
		"Name":     in.Name,
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
	HostCatalogId   string `json:"host_catalog_id"`
	HostSetId       string `json:"host_set_id"`
	HostId          string `json:"host_id"`
	Type            string `json:"type"`
	ScopeId         string `json:"scope_id"`
	HostCatalogName string `json:"host_catalog_name"`
	HostSetName     string `json:"host_set_name"`
	HostName        string `json:"host_name"`
}

func generateInitialHostResourcesTableOutput(in *HostInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Host Catalog ID":   in.HostCatalogId,
		"Host Catalog Name": in.HostCatalogName,
		"Host Set ID":       in.HostSetId,
		"Host Set Name":     in.HostSetName,
		"Host ID":           in.HostId,
		"Host Name":         in.HostName,
		"Type":              in.Type,
		"Scope ID":          in.ScopeId,
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
	Name                   string `json:"name"`
}

func generateInitialTargetTableOutput(in *TargetInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Target ID":                in.TargetId,
		"Default Port":             in.DefaultPort,
		"Session Max Seconds":      in.SessionMaxSeconds,
		"Session Connection Limit": in.SessionConnectionLimit,
		"Type":                     in.Type,
		"Scope ID":                 in.ScopeId,
		"Name":                     in.Name,
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
