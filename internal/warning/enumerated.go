// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package warning

import pb "github.com/hashicorp/boundary/internal/gen/controller/api"

type apiWarning uint32

// The set of warnings that boundary ever returns as a result of API requests.
// Besides zzzKeepThisLastSentinel, the warnings should keep the numbers they
// are initially released with because the enumerated number is used to uniquely
// identify them and potentially provide additional information in documentation.
const (
	Unknown                                apiWarning = 0
	FieldDeprecatedTargetWorkerFilters     apiWarning = 1
	OidcAuthMethodInactiveCannotBeUsed     apiWarning = 2
	DeletingKmsLedWorkersMayNotBePermanent apiWarning = 3

	// This is a sentinel value that captures the largest apiWarning id currently
	// known.  Add all warnings above this line.
	zzzKeepThisLastSentinel
)

func (a apiWarning) toProto() *pb.Warning {
	nw := &pb.Warning{
		Code: uint32(a),
	}
	switch a {
	case FieldDeprecatedTargetWorkerFilters:
		nw.Warning = &pb.Warning_RequestField{RequestField: &pb.FieldWarning{
			Name:    "worker_filter",
			Warning: "This field is deprecated. Please use ingress_worker_filter and/or egress_worker_filter",
		}}
	case OidcAuthMethodInactiveCannotBeUsed:
		nw.Warning = &pb.Warning_Behavior{Behavior: &pb.BehaviorWarning{
			Warning: "OIDC Auth Methods cannot be authenticated until they have been made active.",
		}}
	case DeletingKmsLedWorkersMayNotBePermanent:
		nw.Warning = &pb.Warning_Behavior{Behavior: &pb.BehaviorWarning{
			Warning: "A KMS worker may be automatically recreated after deletion if it is still running.",
		}}
	default:
		// don't add any unknown warning to the warner
		return nil
	}
	return nw
}
