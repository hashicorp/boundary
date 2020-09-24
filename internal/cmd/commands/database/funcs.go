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
}

func generateInitialAuthMethodTableOutput(in *AuthMethodInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Scope ID":       in.ScopeId,
		"Auth Method ID": in.AuthMethodId,
		"Login Name":     in.LoginName,
		"Password":       in.Password,
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
