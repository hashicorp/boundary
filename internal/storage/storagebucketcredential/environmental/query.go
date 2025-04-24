// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package environmental

// CreateStorageBucketCredentialEnvironmentalQuery is the query to create a storage bucket credential environmental
const CreateStorageBucketCredentialEnvironmentalQuery = `
	insert into storage_bucket_credential_environmental (
		storage_bucket_id
	) values (
		@storage_bucket_id -- storage_bucket_id
	)
	returning *;
`
