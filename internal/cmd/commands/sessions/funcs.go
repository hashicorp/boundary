package sessions

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateSessionTableOutput(in *sessions.Session) string {
	nonAttributeMap := map[string]interface{}{
		"ID":              in.Id,
		"Target ID":       in.TargetId,
		"Scope ID":        in.Scope.Id,
		"Created Time":    in.CreatedTime.Local().Format(time.RFC3339),
		"Updated Time":    in.UpdatedTime.Local().Format(time.RFC3339),
		"Expiration Time": in.ExpirationTime.Local().Format(time.RFC3339),
		"Version":         in.Version,
		"Type":            in.Type,
		"Auth Token ID":   in.AuthTokenId,
		"User ID":         in.UserId,
		"Host Set ID":     in.HostSetId,
		"Host ID":         in.HostId,
		"Endpoint":        in.Endpoint,
		"Status":          in.Status,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	var statesMaps []map[string]interface{}
	if len(in.States) > 0 {
		for _, state := range in.States {
			m := map[string]interface{}{
				"Status":     state.Status,
				"Start Time": state.StartTime.Local().Format(time.RFC3339),
				"End Time":   state.EndTime.Local().Format(time.RFC3339),
			}
			statesMaps = append(statesMaps, m)
		}
		if l := len("Start Time"); l > maxLength {
			maxLength = l
		}
	}

	var workerInfoMaps []map[string]interface{}
	if len(in.WorkerInfo) > 0 {
		for _, wi := range in.WorkerInfo {
			m := map[string]interface{}{
				"Address": wi.Address,
			}
			workerInfoMaps = append(workerInfoMaps, m)
		}
		if l := len("Address"); l > maxLength {
			maxLength = l
		}
	}

	ret := []string{"", "Session information:"}

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	if len(in.States) > 0 {
		ret = append(ret,
			fmt.Sprintf("  States:   %s", ""),
		)
		for _, m := range statesMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	if len(in.WorkerInfo) > 0 {
		ret = append(ret,
			fmt.Sprintf("  Worker Info:   %s", ""),
		)
		for _, m := range workerInfoMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	return base.WrapForHelpText(ret)
}
