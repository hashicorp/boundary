package node

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/eventlogger"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"google.golang.org/protobuf/proto"
)

const (

	// RedactedData is the value that replaces redacted data (secrets)
	RedactedData = "<REDACTED>"

	// DataClassificationTagName is the tag name for classifying data into
	// DataClassification's
	DataClassificationTagName = "classified"
)

// DataClassification defines a type for classification of data into categories
// like: public, sensitive, secret, etc.  DataClassifications are used with as
// values for tags using DataClassificationTagName to declare a type of
// classification.
type DataClassification string

const (
	UnknownClassification DataClassification = "unknown"

	// PublicClassification declares a field as public data.  No filter
	// operations are ever performed on public data.
	PublicClassification DataClassification = "public"

	// SensitiveClassification declares a field as sensitive data.  By default,
	// sensitive data is encrypted unless the tag includes an overriding FilterOperation.
	SensitiveClassification DataClassification = "sensitive"

	// SecretClassification declares a field as secret data.  By default,
	// secret data is redacted unless the tag includes an overriding FilterOperation.
	SecretClassification DataClassification = "secret"
)

// FilterOperation defines a type for filtering operations like: redact,
// encrypt, hmac-sha256, etc.  Used in combination with a DataClassification, it
// allows developers to override the default filter operations on tag fields.

type FilterOperation string

const (
	NoOperation         FilterOperation = ""
	UnknownOperation    FilterOperation = "unknown"
	RedactOperation     FilterOperation = "redact"
	EncryptOperation    FilterOperation = "encrypt"
	HmacSha256Operation FilterOperation = "hmac-sha256"
)

// WrapperPayload defines an interface for eventlogger payloads which include
// wrapping.Wrapper fields.  This interface allows the AuditEncryptFilter to
// support per event wrappers and hmac salt/info.
type WrapperPayload interface {

	// Wrapper to use for the event encryption or hmac-sha256 operations
	Wrapper() wrapping.Wrapper

	// HmacSalt to use for the event hmac-sha256 operations
	HmacSalt() []byte

	// HmacInfo to use for the event hmac-sha256 operations
	HmacInfo() []byte
}

// AuditEncryptFilter is an eventlogger Filter Node which will filter string and
// []byte fields in an event.  Fields with tags that designate
// SecretClassification will be redacted. Fields with tags that designate
// SensitiveClassification will either be encrypted or hmac-sha256.
type AuditEncryptFilter struct {
	// Wrapper to encrypt or hmac-sha256 string and []byte fields which are
	// tagged as SensitiveClassification.  This wrapper may be overridden on a
	// per event basis when the event has a WrapperPayload which contains a
	// wrapper to use for the specific event.
	Wrapper wrapping.Wrapper

	// Salt for deriving a hmac-sha256 operations key (can be nil).  This salt
	// may be overridden on a per event basis when the event has a
	// WrapperPayload which contains salt to use for the specific event.
	HmacSalt []byte

	// Info for deriving a hmac-sha256 operations key (can be nil). This info
	// may be overridden on a per event basis when the event has a
	// WrapperPayload which contains info to use for the specific event.
	HmacInfo []byte

	l sync.RWMutex
}

// Reopen is a no op for AuditEncryptFilters.
func (af *AuditEncryptFilter) Reopen() error {
	return nil
}

// Type describes the type of the node as a Filter.
func (ef *AuditEncryptFilter) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeFilter
}

// Process will encrypt or hmac-sha256 string and []byte fields which are tagged
// as SensitiveClassification.  Fields that are tagged SecretClassification will
// be redacted.
//
// If the event payload satisfies the WrapperPayload interface, then the
// payloads Wrapper(), HmacSalt() and HmacInfo() will be used for
// encryption/hmac-sha256 operations on that specific event.
func (ef *AuditEncryptFilter) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	const op = "event.(EncryptFilter).Process"
	if e == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing event")
	}

	var opts []option
	var optWrapper wrapping.Wrapper
	if i, ok := e.Payload.(WrapperPayload); ok {
		optWrapper := i.Wrapper()
		opts = append(opts, withWrapper(optWrapper))
		opts = append(opts, withInfo(i.HmacInfo()))
		opts = append(opts, withSalt(i.HmacSalt()))
	}

	if ef.Wrapper == nil && optWrapper == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing wrapper")
	}

	// Get both the value and the type of what the payload points to. Value is
	// used to mutate underlying data and Type is used to get the name of the
	// field.
	payloadValue := reflect.ValueOf(e.Payload).Elem()

	if err := ef.filterField(ctx, payloadValue, opts...); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return e, nil
}

// filterField will recursively iterate over all the field for a value and
// filter them based on their DataClassification
func (ef *AuditEncryptFilter) filterField(ctx context.Context, v reflect.Value, opt ...option) error {
	const op = "event.(AuditEncryptFilter).filterField"
	for i := 0; i < v.Type().NumField(); i++ {
		field := v.Field(i)
		fkind := field.Kind()
		ftype := field.Type()

		isPtrToSlice := fkind == reflect.Ptr && field.Elem().Kind() == reflect.Slice
		isPtrToStruct := fkind == reflect.Ptr && field.Elem().Kind() == reflect.Struct
		isSlice := fkind == reflect.Slice

		switch {
		// if the field is a string or []byte then we just need to sanitize it
		case ftype == reflect.TypeOf("") || ftype == reflect.TypeOf([]uint8{}):
			classificationTag, err := getClassificationFromTag(v.Type().Field(i).Tag)
			if err != nil {
				return errors.Wrap(err, op)
			}
			if err := ef.filterValue(ctx, field, classificationTag, opt...); err != nil {
				return errors.Wrap(err, op)
			}
		// if the field is a slice
		case isSlice || isPtrToSlice:
			switch {
			// if the field is a slice of string or slice of []byte
			case ftype == reflect.TypeOf([]string{}) || ftype == reflect.TypeOf([][]uint8{}):
				classificationTag, err := getClassificationFromTag(v.Type().Field(i).Tag)
				if err != nil {
					return errors.Wrap(err, op)
				}
				if err := ef.filterSlice(ctx, classificationTag, field, opt...); err != nil {
					return err
				}
			// if the field is a slice of structs, recurse through them...
			default:
				if isPtrToSlice {
					field = field.Elem()
				}
				for i := 0; i < field.Len(); i++ {
					f := field.Index(i)
					if f.Kind() == reflect.Ptr {
						f = f.Elem()
					}
					if f.Kind() != reflect.Struct {
						continue
					}
					if err := ef.filterField(ctx, f, opt...); err != nil {
						return err
					}
				}

			}
		// if the field is a struct
		case fkind == reflect.Struct || isPtrToStruct:
			if isPtrToStruct {
				field = field.Elem()
			}
			if err := ef.filterField(ctx, field, opt...); err != nil {
				return err
			}
		}
	}
	return nil
}

// filterSlice will filter a slice reflect.Value
func (ef *AuditEncryptFilter) filterSlice(ctx context.Context, classificationTag *tagInfo, slice reflect.Value, opt ...option) error {
	const op = "event.(AuditEncryptFilter).filterSlice"
	if classificationTag.Classification == PublicClassification {
		return nil
	}
	if slice.Len() == 0 {
		return nil
	}
	if slice.Kind() == reflect.Ptr && !slice.IsNil() {
		slice = slice.Elem()
	}
	for i := 0; i < slice.Len(); i++ {
		fv := slice.Index(i)
		if err := ef.filterValue(ctx, fv, classificationTag); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}

// filterValue will filter a value based on it's DataClassification
func (ef *AuditEncryptFilter) filterValue(ctx context.Context, fv reflect.Value, classificationTag *tagInfo, opt ...option) error {
	const op = "event.(AuditEncryptFilter).filterValue"
	ftype := fv.Type()
	if ftype != reflect.TypeOf("") && ftype != reflect.TypeOf([]uint8(nil)) {
		return errors.New(errors.InvalidParameter, op, "field value is not a string or []byte")
	}

	switch classificationTag.Classification {
	case PublicClassification:
		return nil
	case SecretClassification, SensitiveClassification:
		var raw []byte
		switch ftype {
		case reflect.TypeOf(""):
			raw = []byte(fv.String())
		default:
			raw = fv.Bytes()
		}

		var data string
		var err error
		switch classificationTag.Operation {
		case EncryptOperation:
			if data, err = ef.encrypt(ctx, raw, opt...); err != nil {
				return errors.Wrap(err, op)
			}
		case HmacSha256Operation:
			if data, err = ef.hmacSha256(ctx, raw, opt...); err != nil {
				return errors.Wrap(err, op)
			}
		case RedactOperation:
			data = RedactedData
		default: // catch UnknownOperation, NoOperation and everything else
			return errors.New(errors.InvalidParameter, op, "unknown filter operation for field")
		}
		if err := setValue(fv, data); err != nil {
			return errors.Wrap(err, op)
		}
	default:
		if err := setValue(fv, RedactedData); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}

func (ef *AuditEncryptFilter) encrypt(ctx context.Context, value []byte, opt ...option) (string, error) {
	const op = "event.(EncryptFilter).encrypt"
	ef.l.Lock()
	defer ef.l.Unlock()
	opts := getOpts(opt...)
	if ef.Wrapper == nil && opts.withWrapper == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	var w wrapping.Wrapper
	switch {
	case opts.withWrapper != nil:
		w = opts.withWrapper
	default:
		w = ef.Wrapper
	}
	blobInfo, err := w.Encrypt(ctx, value, nil)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", fmt.Errorf("error marshaling encrypted blob: %w", err)
	}
	return "encrypted:" + base64.RawURLEncoding.EncodeToString(marshaledBlob), nil
}

func (ef *AuditEncryptFilter) hmacSha256(ctx context.Context, data []byte, opt ...option) (string, error) {
	const op = "event.(EncryptFilter).hmacField"
	ef.l.Lock()
	defer ef.l.Unlock()
	opts := getOpts(opt...)
	if ef.Wrapper == nil && opts.withWrapper == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	var w wrapping.Wrapper
	var salt []byte
	var info []byte
	switch {
	case opts.withWrapper != nil:
		w = opts.withWrapper
	default:
		w = ef.Wrapper
	}
	switch {
	case opts.withSalt != nil:
		copy(salt, opts.withSalt)
	default:
		copy(salt, ef.HmacSalt)
	}
	switch {
	case opts.withInfo != nil:
		copy(info, opts.withInfo)
	default:
		copy(info, ef.HmacInfo)
	}
	reader, err := kms.NewDerivedReader(w, 32, salt, info)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	key, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return "", errors.New(errors.Encrypt, op, "unable to generate derived key")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return "hmac-sh256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func setValue(fv reflect.Value, newVal string) error {
	const op = "event.(EncryptFilter).setValue"
	ftype := fv.Type()
	isByteArray := ftype == reflect.TypeOf([]uint8(nil))
	isString := ftype == reflect.TypeOf("")
	if !isString && !isByteArray {
		return errors.New(errors.InvalidParameter, op, "field value is not a string or []byte")
	}
	switch {
	case isByteArray:
		fv.SetBytes([]byte(newVal))
	case isString:
		fv.SetString(newVal)
	default:
		return errors.New(errors.InvalidParameter, op, "unable to redact field value since is not a string or []byte")
	}
	return nil

}

type tagInfo struct {
	Classification DataClassification
	Operation      FilterOperation
}

func getClassificationFromTag(f reflect.StructTag) (*tagInfo, error) {
	t, ok := f.Lookup(DataClassificationTagName)

	if !ok {
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}, nil
	}
	return getClassificationFromTagString(t)
}

func getClassificationFromTagString(tag string) (*tagInfo, error) {
	const op = "node.getClassificationFromTagString"
	segs := strings.Split(tag, ",")

	if len(segs) == 0 {
		return &tagInfo{
			Classification: UnknownClassification,
			Operation:      UnknownOperation,
		}, nil
	}
	classification := DataClassification(segs[0])
	if classification == UnknownClassification {
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid tag: classification of %s is unknown", classification))
	}

	var operation FilterOperation
	switch len(segs) {
	case 0, 1:
		operation = NoOperation
	default:
		operation = convertToOperation(segs[1])
	}
	if operation == UnknownOperation {
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid tag: filter operation of %s is unknown", operation))
	}

	switch classification {
	case PublicClassification:
		return &tagInfo{
			Classification: PublicClassification,
			Operation:      NoOperation,
		}, nil
	case SensitiveClassification:
		if operation == NoOperation {
			// set a default
			operation = EncryptOperation
		}
		return &tagInfo{
			Classification: SensitiveClassification,
			Operation:      operation,
		}, nil
	case SecretClassification:
		if operation == NoOperation {
			// set a default
			operation = RedactOperation
		}
		return &tagInfo{
			Classification: SecretClassification,
			Operation:      operation,
		}, nil
	default:
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid tag: classification of %s is unknown", classification))
	}
}

func convertToOperation(seg string) FilterOperation {
	seg = strings.ToLower(seg)
	switch FilterOperation(seg) {
	case NoOperation:
		return NoOperation
	case HmacSha256Operation:
		return HmacSha256Operation
	case EncryptOperation:
		return EncryptOperation
	default:
		return UnknownOperation
	}
}
