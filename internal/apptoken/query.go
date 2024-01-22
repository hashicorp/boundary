// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

const (
	lookupAppTokenTemplate = `
	select * 
	from app_token_agg 
	where public_id = @public_id
	limit %d
`
)
