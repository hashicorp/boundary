package node

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/eventlogger"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"google.golang.org/protobuf/proto"
)

// AuditEncryptFilter is an eventlogger Filter Node which will filter string and
// []byte fields in an event.  Fields with tags that designate
// SecretClassification will be redacted. Fields with tags that designate
// SensitiveClassification will either be encrypted or hmac-sha256.
type AuditEncryptFilter struct {
	// Wrapper to encrypt or hmac-sha256 string and []byte fields which are
	// tagged as SensitiveClassification.  This may be rotated with an event
	// that has a payload satisfying the RotateWrapper interface.  If an
	// event's payload satisfies the EventWrapperInfo interface, an event
	// specify wrapper will be derived from this wrapper using that
	// EventWrapperInfo.
	Wrapper wrapping.Wrapper

	// Salt for deriving a hmac-sha256 operations key (can be nil). This may be
	// rotated with an event that has a payload satisfying the RotateWrapper
	// interface. If an event's payload satisfies the EventWrapperInfo
	// interface, event specific HmacSalt will be used for operations on that
	// specific event.
	HmacSalt []byte

	// Info for deriving a hmac-sha256 operations key (can be nil). This may be
	// rotated with an event that has a payload satisfying the RotateWrapper
	// interface.  If an event's payload satisfies the
	// EventWrapperInfointerface, event specific HmacSalt will be used for
	// operations on that
	// specific event.
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

// Rotate supports rotating the filter's wrapper, salt and info via the options:
// WithWrapper, WithSalt, WithInfo
func (ef *AuditEncryptFilter) Rotate(opt ...Option) {
	opts := getOpts(opt...)
	ef.l.Lock()
	defer ef.l.Unlock()
	if opts.withWrapper != nil {
		ef.Wrapper = opts.withWrapper
	}
	if opts.withSalt != nil {
		ef.HmacSalt = opts.withSalt
	}
	if opts.withInfo != nil {
		ef.HmacInfo = opts.withInfo
	}
}

// Process will encrypt or hmac-sha256 string and []byte fields which are tagged
// as SensitiveClassification.  Fields that are tagged SecretClassification will
// be redacted.
//
// If the event payload satisfies the WrapperPayload interface, then the
// payload's Wrapper(), HmacSalt() and HmacInfo() will be used to rotate the
// filter's wrappers for ongoing filtering operations.  Events matching this
// WrapperPayload interface are not sent along in the pipeline and a nil with no
// errors is immediately returned after the wrapper has been rotated.
//
// If the event payload satisfies the EventWrapperInfo interface, then the
// payload's EventId(), HmacSalt() and HmacInfo() will be used to for filtering
// operations for just the single event being processed.
func (ef *AuditEncryptFilter) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	const op = "event.(EncryptFilter).Process"
	if e == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing event")
	}
	if i, ok := e.Payload.(RotateWrapper); ok {
		ef.l.Lock()
		defer ef.l.Unlock()
		if i.Wrapper() != nil {
			ef.Wrapper = i.Wrapper()
		}
		if i.HmacSalt() != nil {
			ef.HmacSalt = i.HmacSalt()
		}
		if i.HmacInfo() != nil {
			ef.HmacSalt = i.HmacInfo()
		}
		return nil, nil
	}

	var opts []Option
	var optWrapper wrapping.Wrapper
	if i, ok := e.Payload.(EventWrapperInfo); ok {
		ef.l.RLock()
		w, err := NewEventWrapper(ef.Wrapper, i.EventId())
		ef.l.RUnlock()
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		optWrapper := w
		opts = append(opts, WithWrapper(optWrapper))
		opts = append(opts, WithInfo(i.HmacInfo()))
		opts = append(opts, WithSalt(i.HmacSalt()))
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
func (ef *AuditEncryptFilter) filterField(ctx context.Context, v reflect.Value, opt ...Option) error {
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
			classificationTag := getClassificationFromTag(v.Type().Field(i).Tag)
			if err := ef.filterValue(ctx, field, classificationTag, opt...); err != nil {
				return errors.Wrap(err, op)
			}
		// if the field is a slice
		case isSlice || isPtrToSlice:
			switch {
			// if the field is a slice of string or slice of []byte
			case ftype == reflect.TypeOf([]string{}) || ftype == reflect.TypeOf([][]uint8{}):
				classificationTag := getClassificationFromTag(v.Type().Field(i).Tag)
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
func (ef *AuditEncryptFilter) filterSlice(ctx context.Context, classificationTag *tagInfo, slice reflect.Value, opt ...Option) error {
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
func (ef *AuditEncryptFilter) filterValue(ctx context.Context, fv reflect.Value, classificationTag *tagInfo, opt ...Option) error {
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

func (ef *AuditEncryptFilter) encrypt(ctx context.Context, value []byte, opt ...Option) (string, error) {
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

func (ef *AuditEncryptFilter) hmacSha256(ctx context.Context, data []byte, opt ...Option) (string, error) {
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
