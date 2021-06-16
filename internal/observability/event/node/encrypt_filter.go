package node

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/eventlogger"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/mitchellh/pointerstructure"
	"google.golang.org/protobuf/proto"
)

// EncryptFilter is an eventlogger Filter Node which will filter string and
// []byte fields in an event.  Fields with tags that designate
// SecretClassification will be redacted. Fields with tags that designate
// SensitiveClassification will either be encrypted or hmac-sha256.
type EncryptFilter struct {
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

	// FilterOperationOverrides provide an optional a set of runtime overrides
	// for the FilterOperations to be applied to DataClassifications.
	//
	// Normally, the filter operation applied to a field is determined by the
	// operation specified in it's "classified" tag. If no operation is
	// specified in the tag, then a set of reasonable default filter operations
	// are applied.
	//
	// FilterOperationOverrides provides the ability to override an event's
	// "classified" tag settings.
	FilterOperationOverrides map[DataClassification]FilterOperation

	l sync.RWMutex
}

// Reopen is a no op for EncryptFilters.
func (af *EncryptFilter) Reopen() error {
	return nil
}

// Type describes the type of the node as a Filter.
func (ef *EncryptFilter) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeFilter
}

// Rotate supports rotating the filter's wrapper, salt and info via the options:
// WithWrapper, WithSalt, WithInfo
func (ef *EncryptFilter) Rotate(opt ...Option) {
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
func (ef *EncryptFilter) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	const op = "event.(EncryptFilter).Process"
	if e == nil {
		return nil, fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	if i, ok := e.Payload.(RotateWrapper); ok {
		ef.l.Lock()
		defer ef.l.Unlock()
		if i.Wrapper() != nil {
			ef.Wrapper = i.Wrapper()
		}
		if i.HmacSalt() != nil {
			ef.HmacSalt = make([]byte, len(i.HmacSalt()))
			copy(ef.HmacSalt, i.HmacSalt())
		}
		if i.HmacInfo() != nil {
			ef.HmacInfo = make([]byte, len(i.HmacInfo()))
			copy(ef.HmacInfo, i.HmacInfo())
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
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		optWrapper := w
		opts = append(opts, WithWrapper(optWrapper))
		opts = append(opts, WithInfo(i.HmacInfo()))
		opts = append(opts, WithSalt(i.HmacSalt()))
	}

	if ef.Wrapper == nil && optWrapper == nil {
		return nil, fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}

	if e.Payload == nil {
		return e, nil
	}

	// Get both the value and the type of what the payload points to. Value is
	// used to mutate underlying data and Type is used to get the name of the
	// field.
	payloadValue := reflect.ValueOf(e.Payload)
	switch payloadValue.Kind() {
	case reflect.Ptr, reflect.Interface:
		payloadValue = reflect.ValueOf(e.Payload).Elem()
	}

	pType := payloadValue.Type()
	pKind := payloadValue.Kind()

	taggedInterface, isTaggable := payloadValue.Interface().(Taggable)

	switch {
	case pType == reflect.TypeOf("") || pType == reflect.TypeOf([]uint8{}):
		if !payloadValue.CanSet() {
			return nil, fmt.Errorf("%s: unable to redact string payload (not setable): %w", op, ErrInvalidParameter)
		}
		ef.l.RLock()
		classificationTag := getClassificationFromTagString(string(SecretClassification), withFilterOperations(ef.FilterOperationOverrides))
		ef.l.RUnlock()
		if err := ef.filterValue(ctx, payloadValue, classificationTag, opts...); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	case isTaggable:
		if err := ef.filterTaggable(ctx, taggedInterface, opts...); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	case pKind == reflect.Slice:
		switch {
		// if the field is a slice of string or slice of []byte
		case pType == reflect.TypeOf([]string{}) || pType == reflect.TypeOf([]*string{}) || pType == reflect.TypeOf([][]uint8{}):
			ef.l.RLock()
			classificationTag := getClassificationFromTagString(string(SecretClassification), withFilterOperations(ef.FilterOperationOverrides))
			ef.l.RUnlock()
			if err := ef.filterSlice(ctx, classificationTag, payloadValue, opts...); err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
		// if the field is a slice of structs, recurse through them...
		default:
			for i := 0; i < payloadValue.Len(); i++ {
				f := payloadValue.Index(i)
				if f.Kind() == reflect.Ptr {
					f = f.Elem()
				}
				if f.Kind() != reflect.Struct {
					continue
				}
				if err := ef.filterField(ctx, f, opts...); err != nil {
					return nil, fmt.Errorf("%s: %w", op, err)
				}
			}
		}
	case pKind == reflect.Struct:
		if err := ef.filterField(ctx, payloadValue, opts...); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	return e, nil
}

// filterField will recursively iterate over all the fields for a struct value
// and filter them based on their DataClassification
func (ef *EncryptFilter) filterField(ctx context.Context, v reflect.Value, opt ...Option) error {
	const op = "event.(EncryptFilter).filterField"
	// check for nil value (prevent panics)
	if v == reflect.ValueOf(nil) {
		return nil
	}

	for i := 0; i < v.Type().NumField(); i++ {
		field := v.Field(i)

		switch v.Field(i).Kind() {
		case reflect.Ptr, reflect.Interface:
			field = v.Field(i).Elem()
			if field == reflect.ValueOf(nil) {
				continue
			}
		}

		fkind := field.Kind()
		ftype := field.Type()

		var taggedInterface Taggable
		var isTaggable bool
		// check exported fields to see if they implement the Taggable interface
		if field.CanSet() {
			taggedInterface, isTaggable = v.Field(i).Interface().(Taggable)
		}

		switch {
		// if the field is a string or []byte then we just need to sanitize it
		case ftype == reflect.TypeOf("") || ftype == reflect.TypeOf([]uint8{}):
			ef.l.RLock() // passing a ref to the FilterOperationOverrides map
			classificationTag := getClassificationFromTag(v.Type().Field(i).Tag, withFilterOperations(ef.FilterOperationOverrides))
			ef.l.RUnlock()
			if err := ef.filterValue(ctx, field, classificationTag, opt...); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
		// if the field is a slice
		case fkind == reflect.Slice:
			switch {
			// if the field is a slice of string or slice of []byte
			case ftype == reflect.TypeOf([]string{}) || ftype == reflect.TypeOf([][]uint8{}):
				ef.l.RLock() // passing a ref to the FilterOperationOverrides map
				classificationTag := getClassificationFromTag(v.Type().Field(i).Tag, withFilterOperations(ef.FilterOperationOverrides))
				ef.l.RUnlock()
				if err := ef.filterSlice(ctx, classificationTag, field, opt...); err != nil {
					return err
				}
			// if the field is a slice of structs, recurse through them...
			default:
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
		case fkind == reflect.Struct:
			if err := ef.filterField(ctx, field, opt...); err != nil {
				return err
			}

		case isTaggable:
			if err := ef.filterTaggable(ctx, taggedInterface, opt...); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
		}
	}
	return nil
}

// filterTaggable will filter data that implements the Taggable interface
func (ef *EncryptFilter) filterTaggable(ctx context.Context, t Taggable, _ ...Option) error {
	const op = "event.(EncryptFilter).filterTaggable"
	if t == nil {
		return fmt.Errorf("%s: missing taggable interface: %w", op, ErrInvalidParameter)
	}
	tags, err := t.Tags()
	if err != nil {
		return fmt.Errorf("%s: unable to get tags from taggable interface: %w", op, err)
	}
	for _, pt := range tags {
		value, err := pointerstructure.Get(t, pt.Pointer)
		if err != nil {
			if errors.Is(err, pointerstructure.ErrNotFound) {
				continue
			} else {
				return fmt.Errorf("%s: unable to get value using tag pointer structure (pointer == %s): %w", op, pt.Pointer, err)
			}
		}
		rv := reflect.Indirect(reflect.ValueOf(value))
		info := &tagInfo{
			Classification: pt.Classification,
			Operation:      pt.Filter,
		}
		if err = ef.filterValue(ctx, rv, info, withPointer(t, pt.Pointer)); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// filterSlice will filter a slice reflect.Value
func (ef *EncryptFilter) filterSlice(ctx context.Context, classificationTag *tagInfo, slice reflect.Value, opt ...Option) error {
	const op = "event.(EncryptFilter).filterSlice"
	if classificationTag == nil {
		return fmt.Errorf("%s: missing classification tag: %w", op, ErrInvalidParameter)
	}
	// check for nil value (prevent panics)
	if slice == reflect.ValueOf(nil) {
		return nil
	}

	if slice.Kind() == reflect.Ptr && !slice.IsNil() {
		slice = slice.Elem()
	}

	ftype := slice.Type()
	if ftype != reflect.TypeOf([]string{}) && ftype != reflect.TypeOf([]*string{}) && ftype != reflect.TypeOf([][]uint8{}) {
		return fmt.Errorf("%s: slice parameter is not a []string or [][]byte: (%s): %w", op, slice.String(), ErrInvalidParameter)
	}
	if classificationTag.Classification == PublicClassification {
		return nil
	}
	if slice.Len() == 0 {
		return nil
	}

	for i := 0; i < slice.Len(); i++ {
		if err := ef.filterValue(ctx, slice.Index(i), classificationTag); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// filterValue will filter a value based on it's DataClassification
func (ef *EncryptFilter) filterValue(ctx context.Context, fv reflect.Value, classificationTag *tagInfo, opt ...Option) error {
	const op = "event.(EncryptFilter).filterValue"
	if classificationTag == nil {
		return fmt.Errorf("%s: missing classification tag: %w", op, ErrInvalidParameter)
	}

	// check for nil value (prevent panics)
	if fv == reflect.ValueOf(nil) {
		return nil
	}

	if fv.Kind() == reflect.Ptr && fv.Elem().Kind() == reflect.String {
		fv = fv.Elem()
	}

	opts := getOpts(opt...)
	ftype := fv.Type()
	if ftype != reflect.TypeOf("") && ftype != reflect.TypeOf([]uint8(nil)) && opts.withPointerstructureInfo == nil {
		return fmt.Errorf("%s: field value is not a string, []byte or tagged map value: %s :%w", op, fv.String(), ErrInvalidParameter)
	}

	// check to see if it's an exported struct field
	if opts.withPointerstructureInfo == nil && !fv.CanSet() {
		return nil
	}

	// make sure it's not a []uint8 nil ptr
	if ftype == reflect.TypeOf([]uint8(nil)) && fv.IsNil() {
		return nil
	}

	switch classificationTag.Classification {
	case PublicClassification:
		return nil
	case SecretClassification, SensitiveClassification:
		var raw []byte
		switch {
		case opts.withPointerstructureInfo != nil:
			i, err := pointerstructure.Get(opts.withPointerstructureInfo.i, opts.withPointerstructureInfo.pointer)
			if err != nil {
				return fmt.Errorf("%s: unable to get value from taggable interface using pointer: %s: %w", op, opts.withPointerstructureInfo.pointer, err)
			}
			raw = []byte(fmt.Sprintf("%s", i))
		case fv.Type() == reflect.TypeOf(""):
			raw = []byte(fv.String())
		case fv.Type() == reflect.TypeOf([]uint8(nil)):
			raw = fv.Bytes()
		default:
			// should be unreachable based on parameter checks
			return fmt.Errorf("%s: unable to get data to filter for type: %s: %w", op, fv.Type(), ErrInvalidParameter)
		}

		var data string
		var err error
		switch classificationTag.Operation {
		case EncryptOperation:
			if data, err = ef.encrypt(ctx, raw, opt...); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
		case HmacSha256Operation:
			if data, err = ef.hmacSha256(ctx, raw, opt...); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
		case RedactOperation:
			data = RedactedData
		default: // catch UnknownOperation, NoOperation and everything else
			return fmt.Errorf("%s: unknown filter operation for field: %s: %w", op, classificationTag.Operation, ErrInvalidParameter)
		}
		if opts.withPointerstructureInfo != nil {
			if _, err := pointerstructure.Set(opts.withPointerstructureInfo.i, opts.withPointerstructureInfo.pointer, data); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
		} else {
			if err := setValue(fv, data); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
		}
	default:
		if err := setValue(fv, RedactedData); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

func (ef *EncryptFilter) encrypt(ctx context.Context, data []byte, opt ...Option) (string, error) {
	const op = "event.(EncryptFilter).encrypt"
	if data == nil {
		return "", fmt.Errorf("%s: missing data: %w", op, ErrInvalidParameter)
	}
	ef.l.Lock()
	defer ef.l.Unlock()
	opts := getOpts(opt...)
	if ef.Wrapper == nil && opts.withWrapper == nil {
		return "", fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	var w wrapping.Wrapper
	switch {
	case opts.withWrapper != nil:
		w = opts.withWrapper
	default:
		w = ef.Wrapper
	}
	blobInfo, err := w.Encrypt(ctx, data, nil)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", fmt.Errorf("error marshaling encrypted blob: %w", err)
	}
	return "encrypted:" + base64.RawURLEncoding.EncodeToString(marshaledBlob), nil
}

func (ef *EncryptFilter) hmacSha256(ctx context.Context, data []byte, opt ...Option) (string, error) {
	const op = "event.(EncryptFilter).hmacField"
	if data == nil {
		return "", fmt.Errorf("%s: missing data: %w", op, ErrInvalidParameter)
	}
	ef.l.Lock()
	defer ef.l.Unlock()
	opts := getOpts(opt...)
	if ef.Wrapper == nil && opts.withWrapper == nil {
		return "", fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	var w wrapping.Wrapper
	switch {
	case opts.withWrapper != nil:
		w = opts.withWrapper
	default:
		w = ef.Wrapper
	}

	var salt []byte
	switch {
	case opts.withSalt != nil:
		salt = make([]byte, len(opts.withSalt))
		copy(salt, opts.withSalt)
	default:
		salt = make([]byte, len(ef.HmacSalt))
		copy(salt, ef.HmacSalt)
	}

	var info []byte
	switch {
	case opts.withInfo != nil:
		info = make([]byte, len(opts.withInfo))
		copy(info, opts.withInfo)
	default:
		info = make([]byte, len(ef.HmacInfo))
		copy(info, ef.HmacInfo)
	}

	reader, err := kms.NewDerivedReader(w, 32, salt, info)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	key, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return "hmac-sh256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func setValue(fv reflect.Value, newVal string) error {
	const op = "event.(EncryptFilter).setValue"
	if !fv.CanSet() {
		return fmt.Errorf("%s: unable to set value for: %s: %w", op, fv.String(), ErrInvalidParameter)
	}
	ftype := fv.Type()
	isByteArray := ftype == reflect.TypeOf([]uint8(nil))
	isString := ftype == reflect.TypeOf("")
	if !isString && !isByteArray {
		return fmt.Errorf("%s: field value is not a string or []byte: %s: %w", op, fv.String(), ErrInvalidParameter)
	}
	switch {
	case isByteArray:
		fv.SetBytes([]byte(newVal))
	case isString:
		fv.SetString(newVal)
	default:
		// should not be reachable based on current parameter checking
		return fmt.Errorf("%s: unable to set field value since is not a string or []byte: %s: %w", op, fv.String(), ErrInvalidParameter)
	}
	return nil
}
