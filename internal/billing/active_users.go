// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing

import "time"

// The ActiveUsersCount field is the number of unique users
// counted between the start and end dates.
// The start date is inclusive and the end date is exclusive.
type ActiveUsers struct {
	StartTime        time.Time
	EndTime          time.Time
	ActiveUsersCount uint32
}
