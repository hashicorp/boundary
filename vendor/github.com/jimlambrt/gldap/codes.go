// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

// ldap result codes
const (
	ResultSuccess                            = 0
	ResultOperationsError                    = 1
	ResultProtocolError                      = 2
	ResultTimeLimitExceeded                  = 3
	ResultSizeLimitExceeded                  = 4
	ResultCompareFalse                       = 5
	ResultCompareTrue                        = 6
	ResultAuthMethodNotSupported             = 7
	ResultStrongAuthRequired                 = 8
	ResultReferral                           = 10
	ResultAdminLimitExceeded                 = 11
	ResultUnavailableCriticalExtension       = 12
	ResultConfidentialityRequired            = 13
	ResultSaslBindInProgress                 = 14
	ResultNoSuchAttribute                    = 16
	ResultUndefinedAttributeType             = 17
	ResultInappropriateMatching              = 18
	ResultConstraintViolation                = 19
	ResultAttributeOrValueExists             = 20
	ResultInvalidAttributeSyntax             = 21
	ResultNoSuchObject                       = 32
	ResultAliasProblem                       = 33
	ResultInvalidDNSyntax                    = 34
	ResultIsLeaf                             = 35
	ResultAliasDereferencingProblem          = 36
	ResultInappropriateAuthentication        = 48
	ResultInvalidCredentials                 = 49
	ResultInsufficientAccessRights           = 50
	ResultBusy                               = 51
	ResultUnavailable                        = 52
	ResultUnwillingToPerform                 = 53
	ResultLoopDetect                         = 54
	ResultSortControlMissing                 = 60
	ResultOffsetRangeError                   = 61
	ResultNamingViolation                    = 64
	ResultObjectClassViolation               = 65
	ResultNotAllowedOnNonLeaf                = 66
	ResultNotAllowedOnRDN                    = 67
	ResultEntryAlreadyExists                 = 68
	ResultObjectClassModsProhibited          = 69
	ResultResultsTooLarge                    = 70
	ResultAffectsMultipleDSAs                = 71
	ResultVirtualListViewErrorOrControlError = 76
	ResultOther                              = 80
	ResultServerDown                         = 81
	ResultLocalError                         = 82
	ResultEncodingError                      = 83
	ResultDecodingError                      = 84
	ResultTimeout                            = 85
	ResultAuthUnknown                        = 86
	ResultFilterError                        = 87
	ResultUserCanceled                       = 88
	ResultParamError                         = 89
	ResultNoMemory                           = 90
	ResultConnectError                       = 91
	ResultNotSupported                       = 92
	ResultControlNotFound                    = 93
	ResultNoResultsReturned                  = 94
	ResultMoreResultsToReturn                = 95
	ResultClientLoop                         = 96
	ResultReferralLimitExceeded              = 97
	ResultInvalidResponse                    = 100
	ResultAmbiguousResponse                  = 101
	ResultTLSNotSupported                    = 112
	ResultIntermediateResponse               = 113
	ResultUnknownType                        = 114
	ResultCanceled                           = 118
	ResultNoSuchOperation                    = 119
	ResultTooLate                            = 120
	ResultCannotCancel                       = 121
	ResultAssertionFailed                    = 122
	ResultAuthorizationDenied                = 123
	ResultSyncRefreshRequired                = 4096
)

// ResultCodeMap contains string descriptions for ldap result codes
var ResultCodeMap = map[uint16]string{
	ResultSuccess:                            "Success",
	ResultOperationsError:                    "Operations Error",
	ResultProtocolError:                      "Protocol Error",
	ResultTimeLimitExceeded:                  "Time Limit Exceeded",
	ResultSizeLimitExceeded:                  "Size Limit Exceeded",
	ResultCompareFalse:                       "Compare False",
	ResultCompareTrue:                        "Compare True",
	ResultAuthMethodNotSupported:             "Auth Method Not Supported",
	ResultStrongAuthRequired:                 "Strong Auth Required",
	ResultReferral:                           "Referral",
	ResultAdminLimitExceeded:                 "Admin Limit Exceeded",
	ResultUnavailableCriticalExtension:       "Unavailable Critical Extension",
	ResultConfidentialityRequired:            "Confidentiality Required",
	ResultSaslBindInProgress:                 "Sasl Bind In Progress",
	ResultNoSuchAttribute:                    "No Such Attribute",
	ResultUndefinedAttributeType:             "Undefined Attribute Type",
	ResultInappropriateMatching:              "Inappropriate Matching",
	ResultConstraintViolation:                "Constraint Violation",
	ResultAttributeOrValueExists:             "Attribute Or Value Exists",
	ResultInvalidAttributeSyntax:             "Invalid Attribute Syntax",
	ResultNoSuchObject:                       "No Such Object",
	ResultAliasProblem:                       "Alias Problem",
	ResultInvalidDNSyntax:                    "Invalid DN Syntax",
	ResultIsLeaf:                             "Is Leaf",
	ResultAliasDereferencingProblem:          "Alias Dereferencing Problem",
	ResultInappropriateAuthentication:        "Inappropriate Authentication",
	ResultInvalidCredentials:                 "Invalid Credentials",
	ResultInsufficientAccessRights:           "Insufficient Access Rights",
	ResultBusy:                               "Busy",
	ResultUnavailable:                        "Unavailable",
	ResultUnwillingToPerform:                 "Unwilling To Perform",
	ResultLoopDetect:                         "Loop Detect",
	ResultSortControlMissing:                 "Sort Control Missing",
	ResultOffsetRangeError:                   "Result Offset Range Error",
	ResultNamingViolation:                    "Naming Violation",
	ResultObjectClassViolation:               "Object Class Violation",
	ResultResultsTooLarge:                    "Results Too Large",
	ResultNotAllowedOnNonLeaf:                "Not Allowed On Non Leaf",
	ResultNotAllowedOnRDN:                    "Not Allowed On RDN",
	ResultEntryAlreadyExists:                 "Entry Already Exists",
	ResultObjectClassModsProhibited:          "Object Class Mods Prohibited",
	ResultAffectsMultipleDSAs:                "Affects Multiple DSAs",
	ResultVirtualListViewErrorOrControlError: "Failed because of a problem related to the virtual list view",
	ResultOther:                              "Other",
	ResultServerDown:                         "Cannot establish a connection",
	ResultLocalError:                         "An error occurred",
	ResultEncodingError:                      " encountered an error while encoding",
	ResultDecodingError:                      " encountered an error while decoding",
	ResultTimeout:                            " timeout while waiting for a response from the server",
	ResultAuthUnknown:                        "The auth method requested in a bind request is unknown",
	ResultFilterError:                        "An error occurred while encoding the given search filter",
	ResultUserCanceled:                       "The user canceled the operation",
	ResultParamError:                         "An invalid parameter was specified",
	ResultNoMemory:                           "Out of memory error",
	ResultConnectError:                       "A connection to the server could not be established",
	ResultNotSupported:                       "An attempt has been made to use a feature not supported ",
	ResultControlNotFound:                    "The controls required to perform the requested operation were not found",
	ResultNoResultsReturned:                  "No results were returned from the server",
	ResultMoreResultsToReturn:                "There are more results in the chain of results",
	ResultClientLoop:                         "A loop has been detected. For example when following referrals",
	ResultReferralLimitExceeded:              "The referral hop limit has been exceeded",
	ResultCanceled:                           "Operation was canceled",
	ResultNoSuchOperation:                    "Server has no knowledge of the operation requested for cancellation",
	ResultTooLate:                            "Too late to cancel the outstanding operation",
	ResultCannotCancel:                       "The identified operation does not support cancellation or the cancel operation cannot be performed",
	ResultAssertionFailed:                    "An assertion control given in the  operation evaluated to false causing the operation to not be performed",
	ResultSyncRefreshRequired:                "Refresh Required",
	ResultInvalidResponse:                    "Invalid Response",
	ResultAmbiguousResponse:                  "Ambiguous Response",
	ResultTLSNotSupported:                    "Tls Not Supported",
	ResultIntermediateResponse:               "Intermediate Response",
	ResultUnknownType:                        "Unknown Type",
	ResultAuthorizationDenied:                "Authorization Denied",
}

// ldap application codes
const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDelRequest            = 10
	ApplicationDelResponse           = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24
)

// ApplicationCodeMap contains human readable descriptions of ldap application codes
var ApplicationCodeMap = map[uint8]string{
	ApplicationBindRequest:           "Bind Request",
	ApplicationBindResponse:          "Bind Response",
	ApplicationUnbindRequest:         "Unbind Request",
	ApplicationSearchRequest:         "Search Request",
	ApplicationSearchResultEntry:     "Search Result Entry",
	ApplicationSearchResultDone:      "Search Result Done",
	ApplicationModifyRequest:         "Modify Request",
	ApplicationModifyResponse:        "Modify Response",
	ApplicationAddRequest:            "Add Request",
	ApplicationAddResponse:           "Add Response",
	ApplicationDelRequest:            "Del Request",
	ApplicationDelResponse:           "Del Response",
	ApplicationModifyDNRequest:       "Modify DN Request",
	ApplicationModifyDNResponse:      "Modify DN Response",
	ApplicationCompareRequest:        "Compare Request",
	ApplicationCompareResponse:       "Compare Response",
	ApplicationAbandonRequest:        "Abandon Request",
	ApplicationSearchResultReference: "Search Result Reference",
	ApplicationExtendedRequest:       "Extended Request",
	ApplicationExtendedResponse:      "Extended Response",
}
