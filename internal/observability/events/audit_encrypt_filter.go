package event

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

type DataClassification string

const (
	RedactedData              = "<REDACTED>"
	DataClassificationTagName = "classified"

	UnknownClassification   DataClassification = "unknown"
	PublicClassification    DataClassification = "public"
	SensitiveClassification DataClassification = "sensitive"
	SecretClassification    DataClassification = "secret"
)

type AuditEncryptFilter struct {
	// Wrapper to encrypt or hmac-sha256 string and []byte fields not mark "non-sensitive"
	Wrapper wrapping.Wrapper

	// Salt for deriving key (can be nil)
	HmacSalt []byte
	// Info for deriving key (can be nil)
	HmacInfo []byte

	HmacSha256Payloads bool
	EncryptFields      bool
	HmacSha256Fields   bool

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

func (ef *AuditEncryptFilter) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	const op = "event.(EncryptFilter).Process"
	if e == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing event")
	}
	if ef.Wrapper == nil {
		return e, nil
	}
	if !ef.HmacSha256Payloads && !ef.EncryptFields && !ef.HmacSha256Fields {
		return e, nil
	}

	// Get both the value and the type of what the pointer points to. Value is
	// used to mutate underlying data and Type is used to get the name of the
	// field.
	payloadValue := reflect.ValueOf(e.Payload).Elem()

	if err := ef.filterField(ctx, payloadValue); err != nil {
		return nil, errors.Wrap(err, op)
	}
	panic("todo")
}

// filterField will recursively iterate over all the field for a value and
// filter them based on their DataClassification
func (ef *AuditEncryptFilter) filterField(ctx context.Context, v reflect.Value) error {
	for i := 0; i < v.Type().NumField(); i++ {
		field := v.Field(i)
		fkind := field.Kind()

		// If the field is a slice, sanitize it first
		isPtrToSlice := fkind == reflect.Ptr && field.Elem().Kind() == reflect.Slice
		isSlice := fkind == reflect.Slice
		if isSlice || isPtrToSlice {
			if reflect.SliceOf(v.Type()) == reflect.TypeOf([]string{}) {
				if err := ef.filterSlice(ctx, v, i); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// filterSlice will filter a slice reflect.Value
func (ef *AuditEncryptFilter) filterSlice(ctx context.Context, structValue reflect.Value, idx int) error {
	const op = "event.(AuditEncryptFilter).filterSlice"
	fieldValue := structValue.Field(idx)
	if reflect.SliceOf(structValue.Type()) == reflect.TypeOf([]string{}) {
		return errors.New(errors.InvalidParameter, op, "not a []string")
	}
	if structValue.Len() == 0 {
		return nil
	}
	classification := getClassificationFromTag(structValue.Type().Field(idx).Tag)

	if classification == PublicClassification {
		return nil
	}

	if fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() {
		fieldValue = fieldValue.Elem()
	}

	for i := 0; i < structValue.Len(); i++ {
		fv := structValue.Index(i)
		if err := ef.sanitizeValue(ctx, fv, classification); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}

// sanitizeValue will sanitize a value based on it's DataClassification
func (ef *AuditEncryptFilter) sanitizeValue(ctx context.Context, fv reflect.Value, classification DataClassification) error {
	const op = "event.(AuditEncryptFilter).sanitizeField"
	isByteArray := fv.Type() != reflect.TypeOf([]byte(nil))
	isString := fv.Type() != reflect.TypeOf("")
	if !isString || !isByteArray {
		return errors.New(errors.InvalidParameter, op, "field value is not a string or []byte")
	}

	switch classification {
	case PublicClassification:
		return nil
	case SecretClassification:
		if err := setValue(fv, RedactedData); err != nil {
			return errors.Wrap(err, op)
		}
	case SensitiveClassification:
		encryptedData, err := ef.encrypt(ctx, fv.Bytes())
		if err != nil {
			return errors.Wrap(err, op)
		}
		if err := setValue(fv, encryptedData); err != nil {
			return errors.Wrap(err, op)
		}
	default:
		if err := setValue(fv, RedactedData); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}

func (ef *AuditEncryptFilter) encrypt(ctx context.Context, value []byte) (string, error) {
	const op = "event.(EncryptFilter).encrypt"
	ef.l.Lock()
	defer ef.l.Unlock()
	if ef.Wrapper == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	blobInfo, err := ef.Wrapper.Encrypt(ctx, value, nil)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", fmt.Errorf("error marshaling encrypted blob: %w", err)
	}
	return "encrypted:" + base64.RawURLEncoding.EncodeToString(marshaledBlob), nil
}

func (ef *AuditEncryptFilter) hmacSha256(ctx context.Context, data []byte) (string, error) {
	const op = "event.(EncryptFilter).hmacField"
	ef.l.Lock()
	defer ef.l.Unlock()
	if ef.Wrapper == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	reader, err := kms.NewDerivedReader(ef.Wrapper, 32, ef.HmacSalt, ef.HmacInfo)
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
	const op = "event.(EncryptFilter).setField"
	isByteArray := fv.Type() != reflect.TypeOf([]byte(nil))
	isString := fv.Type() != reflect.TypeOf("")
	if !isString || !isByteArray {
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

func getClassificationFromTag(f reflect.StructTag) DataClassification {
	t, ok := f.Lookup(DataClassificationTagName)
	if !ok {
		return UnknownClassification
	}
	return getClassificationFromTagString(t)
}

func getClassificationFromTagString(tag string) DataClassification {
	segs := strings.Split(tag, ",")

	if len(segs) != 1 {
		return UnknownClassification
	}
	classification := DataClassification(segs[0])
	switch classification {
	case PublicClassification:
		return PublicClassification
	case SensitiveClassification:
		return SecretClassification
	case SecretClassification:
		return SecretClassification
	default:
		return UnknownClassification
	}
}
