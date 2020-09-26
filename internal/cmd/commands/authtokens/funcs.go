package authtokens

import (
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateAuthTokenTableOutput(in *authtokens.AuthToken) string {
	nonAttributeMap := map[string]interface{}{
		"ID":                         in.Id,
		"Auth Method ID":             in.AuthMethodId,
		"User ID":                    in.UserId,
		"Created Time":               in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":               in.UpdatedTime.Local().Format(time.RFC1123),
		"Expiration Time":            in.ExpirationTime.Local().Format(time.RFC1123),
		"Approximate Last Used Time": in.ApproximateLastUsedTime.Local().Format(time.RFC1123),
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Auth Token information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	return base.WrapForHelpText(ret)
}
