package vault

// These constants are the field names used in the vault related field masks.
const (
	nameField        = "Name"
	descriptionField = "Description"

	vaultPathField       = "VaultPath"
	httpMethodField      = "HttpMethod"
	httpRequestBodyField = "HttpRequestBody"

	certificateField    = "Certificate"
	certificateKeyField = "CertificateKey"
	vaultAddressField   = "VaultAddress"
	namespaceField      = "Namespace"
	caCertField         = "CaCert"
	tlsServerNameField  = "TlsServerName"
	tlsSkipVerifyField  = "TlsSkipVerify"
	tokenField          = "Token"

	// MappingOverrideField represents the field mask indicating a mapping override
	// update has been requested.
	MappingOverrideField = "MappingOverride"
)
