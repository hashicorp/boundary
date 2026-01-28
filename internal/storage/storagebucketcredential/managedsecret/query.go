// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managedsecret

// CreateStorageBucketCredentialManagedSecretQuery is the query to create a storage bucket credential managed secret
const CreateStorageBucketCredentialManagedSecretQuery = `
	insert into storage_bucket_credential_managed_secret (
		storage_bucket_id,
		secrets_encrypted,
		key_id
	) values (
		@storage_bucket_id, -- storage_bucket_id
		@secrets_encrypted, -- secrets_encrypted
		@key_id -- key_id
	)
	returning *;
`
