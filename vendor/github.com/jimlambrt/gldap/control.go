// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"fmt"
	"strconv"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	// ControlTypePaging - https://www.ietf.org/rfc/rfc2696.txt
	ControlTypePaging = "1.2.840.113556.1.4.319"
	// ControlTypeBeheraPasswordPolicy - https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
	ControlTypeBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"
	// ControlTypeVChuPasswordMustChange - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"
	// ControlTypeVChuPasswordWarning - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordWarning = "2.16.840.1.113730.3.4.5"
	// ControlTypeManageDsaIT - https://tools.ietf.org/html/rfc3296
	ControlTypeManageDsaIT = "2.16.840.1.113730.3.4.2"
	// ControlTypeWhoAmI - https://tools.ietf.org/html/rfc4532
	ControlTypeWhoAmI = "1.3.6.1.4.1.4203.1.11.3"

	// ControlTypeMicrosoftNotification - https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
	ControlTypeMicrosoftNotification = "1.2.840.113556.1.4.528"
	// ControlTypeMicrosoftShowDeleted - https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
	ControlTypeMicrosoftShowDeleted = "1.2.840.113556.1.4.417"
	// ControlTypeMicrosoftServerLinkTTL - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f4f523a8-abc0-4b3a-a471-6b2fef135481?redirectedfrom=MSDN
	ControlTypeMicrosoftServerLinkTTL = "1.2.840.113556.1.4.2309"
)

// ControlTypeMap maps controls to text descriptions
var ControlTypeMap = map[string]string{
	ControlTypePaging:                 "Paging",
	ControlTypeBeheraPasswordPolicy:   "Password Policy - Behera Draft",
	ControlTypeManageDsaIT:            "Manage DSA IT",
	ControlTypeMicrosoftNotification:  "Change Notification - Microsoft",
	ControlTypeMicrosoftShowDeleted:   "Show Deleted Objects - Microsoft",
	ControlTypeMicrosoftServerLinkTTL: "Return TTL-DNs for link values with associated expiry times - Microsoft",
}

// Ldap Behera Password Policy Draft 10 (https://tools.ietf.org/html/draft-behera-ldap-password-policy-10)
const (
	BeheraPasswordExpired             = 0
	BeheraAccountLocked               = 1
	BeheraChangeAfterReset            = 2
	BeheraPasswordModNotAllowed       = 3
	BeheraMustSupplyOldPassword       = 4
	BeheraInsufficientPasswordQuality = 5
	BeheraPasswordTooShort            = 6
	BeheraPasswordTooYoung            = 7
	BeheraPasswordInHistory           = 8
)

// BeheraPasswordPolicyErrorMap contains human readable descriptions of Behera Password Policy error codes
var BeheraPasswordPolicyErrorMap = map[int8]string{
	BeheraPasswordExpired:             "Password expired",
	BeheraAccountLocked:               "Account locked",
	BeheraChangeAfterReset:            "Password must be changed",
	BeheraPasswordModNotAllowed:       "Policy prevents password modification",
	BeheraMustSupplyOldPassword:       "Policy requires old password in order to change password",
	BeheraInsufficientPasswordQuality: "Password fails quality checks",
	BeheraPasswordTooShort:            "Password is too short for policy",
	BeheraPasswordTooYoung:            "Password has been changed too recently",
	BeheraPasswordInHistory:           "New password is in list of old passwords",
}

// Control defines a common interface for all ldap controls
type Control interface {
	// GetControlType returns the OID
	GetControlType() string
	// Encode returns the ber packet representation
	Encode() *ber.Packet
	// String returns a human-readable description
	String() string
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Encode())
	}
	return packet
}

func decodeControl(packet *ber.Packet) (Control, error) {
	const op = "gldap.decodeControl"
	var (
		ControlType = ""
		Criticality = false
		value       *ber.Packet
	)
	if packet == nil {
		return nil, fmt.Errorf("%s: packet is nil: %w", op, ErrInvalidParameter)
	}

	switch len(packet.Children) {
	case 0:
		// at least one child is required for a control type
		return nil, fmt.Errorf("%s: at least one child is required for control type", op)
	case 1:
		// just type, no critically or value
		packet.Children[0].Description = "Control Type (" + ControlTypeMap[ControlType] + ")"
		ControlType = packet.Children[0].Value.(string)
	case 2:
		packet.Children[0].Description = "Control Type (" + ControlTypeMap[ControlType] + ")"
		ControlType = packet.Children[0].Value.(string)

		// Children[1] could be criticality or value (both are optional)
		// duck-type on whether this is a boolean
		if _, ok := packet.Children[1].Value.(bool); ok {
			packet.Children[1].Description = "Criticality"
			Criticality = packet.Children[1].Value.(bool)
		} else {
			packet.Children[1].Description = "Control Value"
			value = packet.Children[1]
		}
	case 3:
		packet.Children[0].Description = "Control Type (" + ControlTypeMap[ControlType] + ")"
		ControlType = packet.Children[0].Value.(string)

		packet.Children[1].Description = "Criticality"
		Criticality = packet.Children[1].Value.(bool)

		packet.Children[2].Description = "Control Value"
		value = packet.Children[2]
	default:
		// more than 3 children is invalid
		return nil, fmt.Errorf("%s: more than 3 children is invalid for controls", op)
	}
	switch ControlType {
	case ControlTypeManageDsaIT:
		return NewControlManageDsaIT(WithCriticality(Criticality))
	case ControlTypePaging:
		if value == nil {
			return new(ControlPaging), nil
		}
		value.Description += " (Paging)"
		c := new(ControlPaging)
		if value.Value != nil {
			valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
			if err != nil {
				return nil, fmt.Errorf("%s, failed to decode data bytes: %w", op, err)
			}
			value.Data.Truncate(0)
			value.Value = nil
			value.AppendChild(valueChildren)
		}
		if len(value.Children) < 1 {
			return nil, fmt.Errorf("%s: paging control value must have a least 1 child: %w", op, ErrInvalidParameter)
		}
		value = value.Children[0]
		value.Description = "Search Control Value"
		value.Children[0].Description = "Paging Size"
		value.Children[1].Description = "Cookie"
		c.PagingSize = uint32(value.Children[0].Value.(int64))
		c.Cookie = value.Children[1].Data.Bytes()
		value.Children[1].Value = c.Cookie
		return c, nil
	case ControlTypeBeheraPasswordPolicy:
		if value == nil {
			c, err := NewControlBeheraPasswordPolicy()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			return c, nil
		}
		value.Description += " (Password Policy - Behera)"
		c, err := NewControlBeheraPasswordPolicy()
		if err != nil {
			return nil, fmt.Errorf("%s: failed to create behera password control", op)
		}
		if value.Value != nil {
			valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
			if err != nil {
				return nil, fmt.Errorf("%s: failed to decode data bytes: %w", op, err)
			}
			value.Data.Truncate(0)
			value.Value = nil
			value.AppendChild(valueChildren)
		}
		if len(value.Children) == 0 {
			return nil, fmt.Errorf("%s: behera control value must have a least 1 child: %w", op, ErrInvalidParameter)
		}

		sequence := value.Children[0]

		for _, child := range sequence.Children {
			if child.Tag == 0 {
				// Warning
				warningPacket := child.Children[0]
				val, err := ber.ParseInt64(warningPacket.Data.Bytes())
				if err != nil {
					return nil, fmt.Errorf("%s: failed to decode data bytes: %w", op, err)
				}
				if warningPacket.Tag == 0 {
					// timeBeforeExpiration
					c.expire = val
					warningPacket.Value = c.expire
				} else if warningPacket.Tag == 1 {
					// graceAuthNsRemaining
					c.grace = val
					warningPacket.Value = c.grace
				}
			} else if child.Tag == 1 {
				// Error
				bs := child.Data.Bytes()
				if len(bs) != 1 || bs[0] > 8 {
					return nil, fmt.Errorf("%s: failed to decode data bytes: %s", "invalid PasswordPolicyResponse enum value", op)
				}
				val := int8(bs[0])
				c.error = val
				child.Value = c.error
				c.errorString = BeheraPasswordPolicyErrorMap[c.error]
			}
		}
		return c, nil
	case ControlTypeVChuPasswordMustChange:
		c := &ControlVChuPasswordMustChange{MustChange: true}
		return c, nil
	case ControlTypeVChuPasswordWarning:
		if value == nil {
			return &ControlVChuPasswordWarning{Expire: -1}, nil
		}
		c := &ControlVChuPasswordWarning{Expire: -1}
		expireStr := ber.DecodeString(value.Data.Bytes())

		expire, err := strconv.ParseInt(expireStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to parse value as int: %w", op, err)
		}
		c.Expire = expire
		value.Value = c.Expire
		return c, nil
	case ControlTypeMicrosoftNotification:
		return NewControlMicrosoftNotification()
	case ControlTypeMicrosoftShowDeleted:
		return NewControlMicrosoftShowDeleted()
	case ControlTypeMicrosoftServerLinkTTL:
		return NewControlMicrosoftServerLinkTTL()
	default:
		c := new(ControlString)
		c.ControlType = ControlType
		c.Criticality = Criticality
		if value != nil {
			c.ControlValue = value.Value.(string)
		}
		return c, nil
	}
}

// ControlString implements the Control interface for simple controls
type ControlString struct {
	ControlType  string
	Criticality  bool
	ControlValue string
}

// GetControlType returns the OID
func (c *ControlString) GetControlType() string {
	return c.ControlType
}

// Encode returns the ber packet representation
func (c *ControlString) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlType, "Control Type ("+ControlTypeMap[c.ControlType]+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	if c.ControlValue != "" {
		packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.ControlValue), "Control Value"))
	}
	return packet
}

// String returns a human-readable description
func (c *ControlString) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t  Control Value: %s", ControlTypeMap[c.ControlType], c.ControlType, c.Criticality, c.ControlValue)
}

// NewControlString returns a generic control.  Options supported:
// WithCriticality and WithControlValue
func NewControlString(controlType string, opt ...Option) (*ControlString, error) {
	const op = "gldap.NewControlString"
	if controlType == "" {
		return nil, fmt.Errorf("%s: missing control type: %w", op, ErrInvalidParameter)
	}
	opts := getControlOpts(opt...)
	return &ControlString{
		ControlType:  controlType,
		Criticality:  opts.withCriticality,
		ControlValue: opts.withControlValue,
	}, nil
}

// ControlManageDsaIT implements the control described in https://tools.ietf.org/html/rfc3296
type ControlManageDsaIT struct {
	// Criticality indicates if this control is required
	Criticality bool
}

// Encode returns the ber packet representation
func (c *ControlManageDsaIT) Encode() *ber.Packet {
	// FIXME
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeManageDsaIT, "Control Type ("+ControlTypeMap[ControlTypeManageDsaIT]+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	return packet
}

// GetControlType returns the OID
func (c *ControlManageDsaIT) GetControlType() string {
	return ControlTypeManageDsaIT
}

// String returns a human-readable description
func (c *ControlManageDsaIT) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t",
		ControlTypeMap[ControlTypeManageDsaIT],
		ControlTypeManageDsaIT,
		c.Criticality)
}

// NewControlManageDsaIT returns a ControlManageDsaIT control.  Supported
// options: WithCriticality
func NewControlManageDsaIT(opt ...Option) (*ControlManageDsaIT, error) {
	opts := getControlOpts(opt...)
	return &ControlManageDsaIT{Criticality: opts.withCriticality}, nil
}

// ControlMicrosoftNotification implements the control described in https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
type ControlMicrosoftNotification struct{}

// GetControlType returns the OID
func (c *ControlMicrosoftNotification) GetControlType() string {
	return ControlTypeMicrosoftNotification
}

// Encode returns the ber packet representation
func (c *ControlMicrosoftNotification) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeMicrosoftNotification, "Control Type ("+ControlTypeMap[ControlTypeMicrosoftNotification]+")"))

	return packet
}

// String returns a human-readable description
func (c *ControlMicrosoftNotification) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)",
		ControlTypeMap[ControlTypeMicrosoftNotification],
		ControlTypeMicrosoftNotification)
}

// NewControlMicrosoftNotification returns a ControlMicrosoftNotification
// control.  No options are currently supported.
func NewControlMicrosoftNotification(_ ...Option) (*ControlMicrosoftNotification, error) {
	return &ControlMicrosoftNotification{}, nil
}

// ControlMicrosoftServerLinkTTL implements the control described in https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f4f523a8-abc0-4b3a-a471-6b2fef135481?redirectedfrom=MSDN
type ControlMicrosoftServerLinkTTL struct{}

// GetControlType returns the OID
func (c *ControlMicrosoftServerLinkTTL) GetControlType() string {
	return ControlTypeMicrosoftServerLinkTTL
}

// Encode returns the ber packet representation
func (c *ControlMicrosoftServerLinkTTL) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeMicrosoftServerLinkTTL, "Control Type ("+ControlTypeMap[ControlTypeMicrosoftServerLinkTTL]+")"))

	return packet
}

// String returns a human-readable description
func (c *ControlMicrosoftServerLinkTTL) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)",
		ControlTypeMap[ControlTypeMicrosoftServerLinkTTL],
		ControlTypeMicrosoftServerLinkTTL)
}

// NewControlMicrosoftServerLinkTTL returns a ControlMicrosoftServerLinkTTL
// control.  No options are currently supported.
func NewControlMicrosoftServerLinkTTL(_ ...Option) (*ControlMicrosoftServerLinkTTL, error) {
	return &ControlMicrosoftServerLinkTTL{}, nil
}

// ControlMicrosoftShowDeleted implements the control described in https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
type ControlMicrosoftShowDeleted struct{}

// GetControlType returns the OID
func (c *ControlMicrosoftShowDeleted) GetControlType() string {
	return ControlTypeMicrosoftShowDeleted
}

// Encode returns the ber packet representation
func (c *ControlMicrosoftShowDeleted) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeMicrosoftShowDeleted, "Control Type ("+ControlTypeMap[ControlTypeMicrosoftShowDeleted]+")"))

	return packet
}

// String returns a human-readable description
func (c *ControlMicrosoftShowDeleted) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)",
		ControlTypeMap[ControlTypeMicrosoftShowDeleted],
		ControlTypeMicrosoftShowDeleted)
}

// NewControlMicrosoftShowDeleted returns a ControlMicrosoftShowDeleted control.
// No options are currently supported.
func NewControlMicrosoftShowDeleted(_ ...Option) (*ControlMicrosoftShowDeleted, error) {
	return &ControlMicrosoftShowDeleted{}, nil
}

// ControlBeheraPasswordPolicy implements the control described in https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
type ControlBeheraPasswordPolicy struct {
	// expire contains the number of seconds before a password will expire
	expire int64
	// grace indicates the remaining number of times a user will be allowed to authenticate with an expired password
	grace int64
	// error indicates the error code
	error int8
	// errorString is a human readable error
	errorString string
}

// Grace returns the remaining number of times a user will be allowed to
// authenticate with an expired password. A value of -1 indicates it hasn't been
// set.
func (c *ControlBeheraPasswordPolicy) Grace() int {
	return int(c.grace)
}

// Expire contains the number of seconds before a password will expire. A value
// of -1 indicates it hasn't been set.
func (c *ControlBeheraPasswordPolicy) Expire() int {
	return int(c.expire)
}

// ErrorCode is the error code and a human readable string.  A value of -1 and
// empty string indicates it hasn't been set.
func (c *ControlBeheraPasswordPolicy) ErrorCode() (int, string) {
	return int(c.error), c.errorString
}

// GetControlType returns the OID
func (c *ControlBeheraPasswordPolicy) GetControlType() string {
	return ControlTypeBeheraPasswordPolicy
}

// Encode returns the ber packet representation
func (c *ControlBeheraPasswordPolicy) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeBeheraPasswordPolicy, "Control Type ("+ControlTypeMap[ControlTypeBeheraPasswordPolicy]+")"))

	switch {
	case c.grace >= 0:
		// control value packet for GraceAuthNsRemaining
		valuePacket := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "")
		sequencePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")

		// it's a warning. so it's the end of a context (ber.TagEOC)
		contextPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x00, nil, "")
		// "0x01" tag indicates an grace logins
		contextPacket.AppendChild(ber.NewInteger(ber.ClassContext, ber.TypePrimitive, 0x01, c.grace, ""))
		sequencePacket.AppendChild(contextPacket)

		valuePacket.AppendChild(sequencePacket)
		packet.AppendChild(valuePacket)
		return packet // I believe you can only have either Grace or Expire for a response.... not both.
	case c.expire >= 0:
		// control value packet for timeBeforeExpiration
		valuePacket := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "")
		sequencePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")

		// it's a warning. so it's the end of a context (ber.TagEOC)
		contextPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0x00, nil, "")
		// "0x00" tag indicates an expires in
		contextPacket.AppendChild(ber.NewInteger(ber.ClassContext, ber.TypePrimitive, 0x00, c.expire, ""))
		sequencePacket.AppendChild(contextPacket)

		valuePacket.AppendChild(sequencePacket)
		packet.AppendChild(valuePacket)
		return packet // I believe you can only have either Grace or Expire for a response.... not both.
	case c.error >= 0:
		valuePacket := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "")
		sequencePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")

		contextPacket := ber.NewInteger(ber.ClassContext, ber.TypePrimitive, 0x01, c.error, "")
		sequencePacket.AppendChild(contextPacket)

		valuePacket.AppendChild(sequencePacket)
		packet.AppendChild(valuePacket)

	}
	return packet
}

// String returns a human-readable description
func (c *ControlBeheraPasswordPolicy) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Expire: %d  Grace: %d  Error: %d, ErrorString: %s",
		ControlTypeMap[ControlTypeBeheraPasswordPolicy],
		ControlTypeBeheraPasswordPolicy,
		false,
		c.expire,
		c.grace,
		c.error,
		c.errorString)
}

// NewControlBeheraPasswordPolicy returns a ControlBeheraPasswordPolicy.
// Options supported: WithExpire, WithGrace, WithErrorCode
func NewControlBeheraPasswordPolicy(opt ...Option) (*ControlBeheraPasswordPolicy, error) {
	const op = "NewControlBeheraPolicy"
	opts := getControlOpts(opt...)
	switch {
	case opts.withGrace != -1 && opts.withExpire != -1:
		return nil, fmt.Errorf("%s: behera policies cannot have both grace and expire set: %w", op, ErrInvalidParameter)
	case opts.withGrace != -1 && opts.withErrorCode != -1:
		return nil, fmt.Errorf("%s: behera policies cannot have both grace and error codes set: %w", op, ErrInvalidParameter)
	case opts.withExpire != -1 && opts.withErrorCode != -1:
		return nil, fmt.Errorf("%s: behera polices cannot have both expire and error codes set: %w", op, ErrInvalidParameter)
	case opts.withErrorCode > 8:
		return nil, fmt.Errorf("%s: %d is not a valid behera policy error code (must be between 0-8: %w", op, opts.withErrorCode, ErrInvalidParameter)
	}
	c := &ControlBeheraPasswordPolicy{
		expire: int64(opts.withExpire),
		grace:  int64(opts.withGrace),
		error:  int8(opts.withErrorCode),
	}
	if opts.withErrorCode != -1 {
		c.errorString = BeheraPasswordPolicyErrorMap[int8(opts.withErrorCode)]
	}
	return c, nil
}

// ControlVChuPasswordMustChange implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type ControlVChuPasswordMustChange struct {
	// MustChange indicates if the password is required to be changed
	MustChange bool
}

// GetControlType returns the OID
func (c *ControlVChuPasswordMustChange) GetControlType() string {
	return ControlTypeVChuPasswordMustChange
}

// Encode returns the ber packet representation
func (c *ControlVChuPasswordMustChange) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	// I believe, just the control type child is require... not criticality or
	// value is require...
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeVChuPasswordMustChange, "Control Type ("+ControlTypeMap[ControlTypeVChuPasswordMustChange]+")"))
	return packet
}

// String returns a human-readable description
func (c *ControlVChuPasswordMustChange) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  MustChange: %v",
		ControlTypeMap[ControlTypeVChuPasswordMustChange],
		ControlTypeVChuPasswordMustChange,
		false,
		c.MustChange)
}

// ControlVChuPasswordWarning implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type ControlVChuPasswordWarning struct {
	// Expire indicates the time in seconds until the password expires
	Expire int64
}

// GetControlType returns the OID
func (c *ControlVChuPasswordWarning) GetControlType() string {
	return ControlTypeVChuPasswordWarning
}

// Encode returns the ber packet representation
func (c *ControlVChuPasswordWarning) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeVChuPasswordWarning, "Control Type ("+ControlTypeMap[ControlTypeVChuPasswordWarning]+")"))
	// I believe, it's a string in the spec
	expStr := strconv.FormatInt(c.Expire, 10)
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, expStr, "Control Value"))
	return packet
}

// String returns a human-readable description
func (c *ControlVChuPasswordWarning) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Expire: %d",
		ControlTypeMap[ControlTypeVChuPasswordWarning],
		ControlTypeVChuPasswordWarning,
		false,
		c.Expire)
}

// ControlPaging implements the paging control described in https://www.ietf.org/rfc/rfc2696.txt
type ControlPaging struct {
	// PagingSize indicates the page size
	PagingSize uint32
	// Cookie is an opaque value returned by the server to track a paging cursor
	Cookie []byte
}

// GetControlType returns the OID
func (c *ControlPaging) GetControlType() string {
	return ControlTypePaging
}

// Encode returns the ber packet representation
func (c *ControlPaging) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypePaging, "Control Type ("+ControlTypeMap[ControlTypePaging]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.PagingSize), "Paging Size"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

// String returns a human-readable description
func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  PagingSize: %d  Cookie: %q",
		ControlTypeMap[ControlTypePaging],
		ControlTypePaging,
		false,
		c.PagingSize,
		c.Cookie)
}

// SetCookie stores the given cookie in the paging control
func (c *ControlPaging) SetCookie(cookie []byte) {
	c.Cookie = cookie
}

// NewControlPaging returns a paging control
func NewControlPaging(pagingSize uint32, _ ...Option) (*ControlPaging, error) {
	return &ControlPaging{PagingSize: pagingSize}, nil
}

func addControlDescriptions(packet *ber.Packet) error {
	const op = "gldap.addControlDescriptions"
	if packet == nil {
		return fmt.Errorf("%s: missing packet: %w", op, ErrInvalidParameter)
	}
	packet.Description = "Controls"
	for _, child := range packet.Children {
		var value *ber.Packet
		controlType := ""
		child.Description = "Control"
		switch len(child.Children) {
		case 0:
			// at least one child is required for control type
			return fmt.Errorf("at least one child is required for a control type")

		case 1:
			// just type, no criticality or value
			controlType = child.Children[0].Value.(string)
			child.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"

		case 2:
			controlType = child.Children[0].Value.(string)
			child.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"
			// Children[1] could be criticality or value (both are optional)
			// duck-type on whether this is a boolean
			if _, ok := child.Children[1].Value.(bool); ok {
				child.Children[1].Description = "Criticality"
			} else {
				child.Children[1].Description = "Control Value"
				value = child.Children[1]
			}

		case 3:
			// criticality and value present
			controlType = child.Children[0].Value.(string)
			child.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"
			child.Children[1].Description = "Criticality"
			child.Children[2].Description = "Control Value"
			value = child.Children[2]

		default:
			// more than 3 children is invalid
			return fmt.Errorf("more than 3 children for control packet found")
		}

		if value == nil {
			continue
		}
		switch controlType {
		case ControlTypePaging:
			value.Description += " (Paging)"
			if value.Value != nil {
				valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
				}
				value.Data.Truncate(0)
				value.Value = nil
				valueChildren.Children[1].Value = valueChildren.Children[1].Data.Bytes()
				value.AppendChild(valueChildren)
			}
			value.Children[0].Description = "Real Search Control Value"
			value.Children[0].Children[0].Description = "Paging Size"
			value.Children[0].Children[1].Description = "Cookie"

		case ControlTypeBeheraPasswordPolicy:
			value.Description += " (Password Policy - Behera Draft)"
			if value.Value != nil {
				valueChildren, err := ber.DecodePacketErr(value.Data.Bytes())
				if err != nil {
					return fmt.Errorf("failed to decode data bytes: %s", err)
				}
				value.Data.Truncate(0)
				value.Value = nil
				value.AppendChild(valueChildren)
			}
			sequence := value.Children[0]
			for _, child := range sequence.Children {
				if child.Tag == 0 {
					// Warning
					warningPacket := child.Children[0]
					val, err := ber.ParseInt64(warningPacket.Data.Bytes())
					if err != nil {
						return fmt.Errorf("failed to decode data bytes: %s", err)
					}
					if warningPacket.Tag == 0 {
						// timeBeforeExpiration
						value.Description += " (TimeBeforeExpiration)"
						warningPacket.Value = val
					} else if warningPacket.Tag == 1 {
						// graceAuthNsRemaining
						value.Description += " (GraceAuthNsRemaining)"
						warningPacket.Value = val
					}
				} else if child.Tag == 1 {
					// Error
					bs := child.Data.Bytes()
					if len(bs) != 1 || bs[0] > 8 {
						return fmt.Errorf("failed to decode data bytes: %s", "invalid PasswordPolicyResponse enum value")
					}
					val := int8(bs[0])
					child.Description = "Error"
					child.Value = val
				}
			}
		}
	}
	return nil
}
