package authtokens

import (
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateAuthTokenTableOutput(in *authtokens.AuthToken) string {
	nonAttributeMap := map[string]interface{}{
		"ID":                         in.Id,
		"Scope ID":                   in.Scope.Id,
		"Auth Method ID":             in.AuthMethodId,
		"User ID":                    in.UserId,
		"Created Time":               in.CreatedTime.Local().Format(time.RFC3339),
		"Updated Time":               in.UpdatedTime.Local().Format(time.RFC3339),
		"Expiration Time":            in.ExpirationTime.Local().Format(time.RFC3339),
		"Approximate Last Used Time": in.ApproximateLastUsedTime.Local().Format(time.RFC3339),
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{"", "Auth Token information:"}

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}
