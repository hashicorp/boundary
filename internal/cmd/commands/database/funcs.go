package database

import (
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

	ret := []string{"", "Initial auth method information:"}

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}
