// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import "time"

func init() {
	rdpDefaultTimeout = 30 * time.Second
}
