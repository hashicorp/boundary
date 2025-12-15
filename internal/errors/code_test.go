// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCode_Both_String_Info(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    Code
		want Code
	}{
		{
			name: "undefined-code",
			c:    Code(4294967295),
			want: Unknown,
		},
		{
			name: "default-value",
			want: Unknown,
		},
		{
			name: "Unknown",
			c:    Unknown,
			want: Unknown,
		},
		{
			name: "InvalidParameter",
			c:    InvalidParameter,
			want: InvalidParameter,
		},
		{
			name: "InvalidAddress",
			c:    InvalidAddress,
			want: InvalidAddress,
		},
		{
			name: "InvalidPublicId",
			c:    InvalidPublicId,
			want: InvalidPublicId,
		},
		{
			name: "InvalidFieldMask",
			c:    InvalidFieldMask,
			want: InvalidFieldMask,
		},
		{
			name: "EmptyFieldMask",
			c:    EmptyFieldMask,
			want: EmptyFieldMask,
		},
		{
			name: "KeyNotFound",
			c:    KeyNotFound,
			want: KeyNotFound,
		},
		{
			name: "TicketAlreadyRedeemed",
			c:    TicketAlreadyRedeemed,
			want: TicketAlreadyRedeemed,
		},
		{
			name: "TicketNotFound",
			c:    TicketNotFound,
			want: TicketNotFound,
		},
		{
			name: "Io",
			c:    Io,
			want: Io,
		},
		{
			name: "InvalidTimeStamp",
			c:    InvalidTimeStamp,
			want: InvalidTimeStamp,
		},
		{
			name: "SessionNotFound",
			c:    SessionNotFound,
			want: SessionNotFound,
		},
		{
			name: "InvalidSessionState",
			c:    InvalidSessionState,
			want: InvalidSessionState,
		},
		{
			name: "TokenMismatch",
			c:    TokenMismatch,
			want: TokenMismatch,
		},
		{
			name: "TooShort",
			c:    TooShort,
			want: TooShort,
		},
		{
			name: "AccountAlreadyAssociated",
			c:    AccountAlreadyAssociated,
			want: AccountAlreadyAssociated,
		},
		{
			name: "InvalidJobRunState",
			c:    InvalidJobRunState,
			want: InvalidJobRunState,
		},
		{
			name: "JobAlreadyRunning",
			c:    JobAlreadyRunning,
			want: JobAlreadyRunning,
		},
		{
			name: "SubtypeAlreadyRegistered",
			c:    SubtypeAlreadyRegistered,
			want: SubtypeAlreadyRegistered,
		},
		{
			name: "InvalidDynamicCredential",
			c:    InvalidDynamicCredential,
			want: InvalidDynamicCredential,
		},
		{
			name: "InternalError",
			c:    Internal,
			want: Internal,
		},
		{
			name: "Forbidden",
			c:    Forbidden,
			want: Forbidden,
		},
		{
			name: "AuthMethodInactive",
			c:    AuthMethodInactive,
			want: AuthMethodInactive,
		},
		{
			name: "AuthAttemptExpired",
			c:    AuthAttemptExpired,
			want: AuthAttemptExpired,
		},
		{
			name: "PasswordTooShort",
			c:    PasswordTooShort,
			want: PasswordTooShort,
		},
		{
			name: "PasswordUnsupportedConfiguration",
			c:    PasswordUnsupportedConfiguration,
			want: PasswordUnsupportedConfiguration,
		},
		{
			name: "PasswordInvalidConfiguration",
			c:    PasswordInvalidConfiguration,
			want: PasswordInvalidConfiguration,
		},
		{
			name: "PasswordsEqual",
			c:    PasswordsEqual,
			want: PasswordsEqual,
		},
		{
			name: "Encrypt",
			c:    Encrypt,
			want: Encrypt,
		},
		{
			name: "Decrypt",
			c:    Decrypt,
			want: Decrypt,
		},
		{
			name: "Encode",
			c:    Encode,
			want: Encode,
		},
		{
			name: "Decode",
			c:    Decode,
			want: Decode,
		},
		{
			name: "GenKey",
			c:    GenKey,
			want: GenKey,
		},
		{
			name: "GenCert",
			c:    GenCert,
			want: GenCert,
		},
		{
			name: "CheckConstraint",
			c:    CheckConstraint,
			want: CheckConstraint,
		},
		{
			name: "NotNull",
			c:    NotNull,
			want: NotNull,
		},
		{
			name: "NotUnique",
			c:    NotUnique,
			want: NotUnique,
		},
		{
			name: "RecordNotFound",
			c:    RecordNotFound,
			want: RecordNotFound,
		},
		{
			name: "ColumnNotFound",
			c:    ColumnNotFound,
			want: ColumnNotFound,
		},
		{
			name: "MaxRetries",
			c:    MaxRetries,
			want: MaxRetries,
		},
		{
			name: "Exception",
			c:    Exception,
			want: Exception,
		},
		{
			name: "VersionMismatch",
			c:    VersionMismatch,
			want: VersionMismatch,
		},
		{
			name: "MultipleRecords",
			c:    MultipleRecords,
			want: MultipleRecords,
		},
		{
			name: "NotSpecificIntegrity",
			c:    NotSpecificIntegrity,
			want: NotSpecificIntegrity,
		},
		{
			name: "MissingTable",
			c:    MissingTable,
			want: MissingTable,
		},
		{
			name: "MigrationIntegrity",
			c:    MigrationIntegrity,
			want: MigrationIntegrity,
		},
		{
			name: "MigrationLock",
			c:    MigrationLock,
			want: MigrationLock,
		},
		{
			name: "Unavailable",
			c:    Unavailable,
			want: Unavailable,
		},
		{
			name: "VaultTokenNotOrphan",
			c:    VaultTokenNotOrphan,
			want: VaultTokenNotOrphan,
		},
		{
			name: "VaultTokenNotPeriodic",
			c:    VaultTokenNotPeriodic,
			want: VaultTokenNotPeriodic,
		},
		{
			name: "VaultTokenNotRenewable",
			c:    VaultTokenNotRenewable,
			want: VaultTokenNotRenewable,
		},
		{
			name: "VaultCredentialRequest",
			c:    VaultCredentialRequest,
			want: VaultCredentialRequest,
		},
		{
			name: "VaultEmptySecret",
			c:    VaultEmptySecret,
			want: VaultEmptySecret,
		},
		{
			name: "VaultInvalidMappingOverride",
			c:    VaultInvalidMappingOverride,
			want: VaultInvalidMappingOverride,
		},
		{
			name: "VaultInvalidCredentialMapping",
			c:    VaultInvalidCredentialMapping,
			want: VaultInvalidCredentialMapping,
		},
		{
			name: "VaultTokenMissingCapabilities",
			c:    VaultTokenMissingCapabilities,
			want: VaultTokenMissingCapabilities,
		},
		{
			name: "OidcProviderCallbackError",
			c:    OidcProviderCallbackError,
			want: OidcProviderCallbackError,
		},
		{
			name: "GracefullyAborted",
			c:    GracefullyAborted,
			want: GracefullyAborted,
		},
		{
			name: "UnexpectedRowsAffected",
			c:    UnexpectedRowsAffected,
			want: UnexpectedRowsAffected,
		},
		{
			name: "NoPathFound",
			c:    NoPathFound,
			want: NoPathFound,
		},
		{
			name: "CycleFound",
			c:    CycleFound,
			want: CycleFound,
		},
		{
			name: "WorkerNotFound",
			c:    WorkerNotFound,
			want: WorkerNotFound,
		},
		{
			name: "WorkerConnNotFound",
			c:    WorkerConnNotFound,
			want: WorkerConnNotFound,
		},
		{
			name: "KmsWorkerUnsupportedOperation",
			c:    KmsWorkerUnsupportedOperation,
			want: KmsWorkerUnsupportedOperation,
		},
		{
			name: "RetryLimitExceeded",
			c:    RetryLimitExceeded,
			want: RetryLimitExceeded,
		},
		{
			name: "QueueIsFull",
			c:    QueueIsFull,
			want: QueueIsFull,
		},
		{
			name: "NotFound",
			c:    NotFound,
			want: NotFound,
		},
		{
			name: "StorageFileClose",
			c:    StorageFileClosed,
			want: StorageFileClosed,
		},
		{
			name: "StorageContainerClosed",
			c:    StorageContainerClosed,
			want: StorageContainerClosed,
		},
		{
			name: "StorageFileReadOnly",
			c:    StorageFileReadOnly,
			want: StorageFileReadOnly,
		},
		{
			name: "StorageFileWriteOnly",
			c:    StorageFileWriteOnly,
			want: StorageFileWriteOnly,
		},
		{
			name: "StorageFileAlreadyExists",
			c:    StorageFileAlreadyExists,
			want: StorageFileAlreadyExists,
		},
		{
			name: "StorageContainerReadOnly",
			c:    StorageContainerReadOnly,
			want: StorageContainerReadOnly,
		},
		{
			name: "StorageContainerWriteOnly",
			c:    StorageContainerWriteOnly,
			want: StorageContainerWriteOnly,
		},
		{
			name: "WorkerNotFoundForRequest",
			c:    WorkerNotFoundForRequest,
			want: WorkerNotFoundForRequest,
		},
		{
			name: "Closed",
			c:    Closed,
			want: Closed,
		},
		{
			name: "ExternalPlugin",
			c:    ExternalPlugin,
			want: ExternalPlugin,
		},
		{
			name: "ChecksumMismatch",
			c:    ChecksumMismatch,
			want: ChecksumMismatch,
		},
		{
			name: "InvalidConfiguration",
			c:    InvalidConfiguration,
			want: InvalidConfiguration,
		},
		{
			name: "InvalidListToken",
			c:    InvalidListToken,
			want: InvalidListToken,
		},
		{
			name: "InvalidTextRepresentation",
			c:    InvalidTextRepresentation,
			want: InvalidTextRepresentation,
		},
		{
			name: "Sign",
			c:    Sign,
			want: Sign,
		},
		{
			name: "Verify",
			c:    Verify,
			want: Verify,
		},
		{
			name: "Unauthorized",
			c:    Unauthorized,
			want: Unauthorized,
		},
		{
			name: "Conflict",
			c:    Conflict,
			want: Conflict,
		},
		{
			name: "Paused",
			c:    Paused,
			want: Paused,
		},
		{
			name: "WindowsRDPClientEarlyDisconnection",
			c:    WindowsRDPClientEarlyDisconnection,
			want: WindowsRDPClientEarlyDisconnection,
		},
		{
			name: "ImmutableColumn",
			c:    ImmutableColumn,
			want: ImmutableColumn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(errorCodeInfo[tt.want], tt.c.Info())
			assert.Equal(errorCodeInfo[tt.want].Message, tt.c.String())
		})
	}
}
