package targets

import (
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"google.golang.org/protobuf/proto"
)

// Attributes represent the subtype specific request/response attributes.
type Attributes interface {
	proto.Message

	// Options create target.Options to be used to create a target.Target.
	Options() []target.Option
	// Vet validates the Attributes and returns a map of fields to error messages
	// if any fields are invalid.
	Vet() map[string]string
}

type attributeFunc func(target.Target) Attributes

type registryEntry struct {
	maskManager handlers.MaskManager
	attrFunc    attributeFunc
}

type registry struct {
	sync.Map
}

func (r registry) get(s subtypes.Subtype) (*registryEntry, error) {
	v, ok := r.Load(s)
	if !ok {
		return nil, fmt.Errorf("subtype %q not registered", s)
	}

	re, ok := v.(*registryEntry)
	if !ok {
		return nil, fmt.Errorf("malformed registry subtypye %q registered as incorrect type %T", s, v)
	}
	return re, nil
}

func (r registry) maskManager(s subtypes.Subtype) (handlers.MaskManager, error) {
	re, err := r.get(s)
	if err != nil {
		return nil, err
	}

	return re.maskManager, nil
}

// newAttribute creates an Attribute for the given subtype. It delegates the
// allocation of the Attribute to the registered attrFunc for the given
// subtype. An error is returned if the provided subtype is not registered. It
// supports the options of:
//
// - withTarget: The Attribute will be initialized based on the given
// target.Target. This initialization is delegated to the attrFunc.
//
// - withStruct: The Attribute will be initialized based on the given
// structpb.Struct. This is *not* delegated.
//
// These two options are mutually exclusive. If both are provided, and error is returned.
// If no options are provided an empty Attribute will be returned.
func (r registry) newAttribute(s subtypes.Subtype, opt ...option) (Attributes, error) {
	re, err := r.get(s)
	if err != nil {
		return nil, err
	}

	opts := getOpts(opt...)
	if opts.withTarget != nil && opts.withStruct != nil {
		return nil, fmt.Errorf("cannot use both withTarget and withStruct")
	}

	attr := re.attrFunc(opts.withTarget)
	if opts.withStruct != nil {
		if err := handlers.StructToProto(opts.withStruct, attr); err != nil {
			return nil, fmt.Errorf("Provided attributes don't match expected format.")
		}
	}

	return attr, nil
}

var subtypeRegistry = registry{}

// Register registers a subtype for used by the service handler.
func Register(s subtypes.Subtype, maskManager handlers.MaskManager, af attributeFunc) {
	if _, existed := subtypeRegistry.LoadOrStore(s, &registryEntry{
		maskManager: maskManager,
		attrFunc:    af,
	}); existed {
		panic(fmt.Sprintf("subtype %s already registered", s))
	}
}
