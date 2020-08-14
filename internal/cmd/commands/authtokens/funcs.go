package authtokens

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateAuthTokenTableOutput(in *authtokens.AuthToken) string {
	var ret []string
	ret = append(ret, []string{
		"",
		"Auth Token information:",
		fmt.Sprintf("  ID:                         %s", in.Id),
		fmt.Sprintf("  Scope ID:                   %s", in.Scope.Id),
		fmt.Sprintf("  Auth Method ID:             %s", in.AuthMethodId),
		fmt.Sprintf("  User ID:                    %s", in.UserId),
		fmt.Sprintf("  Expiration Time:            %s", in.ExpirationTime.Local().Format(time.RFC3339)),
		fmt.Sprintf("  Approximate Last Used Time: %s", in.ApproximateLastUsedTime.Local().Format(time.RFC3339)),
		fmt.Sprintf("  Created Time:               %s", in.CreatedTime.Local().Format(time.RFC3339)),
		fmt.Sprintf("  Updated Time:               %s", in.UpdatedTime.Local().Format(time.RFC3339)),
	}...,
	)

	return base.WrapForHelpText(ret)
}
