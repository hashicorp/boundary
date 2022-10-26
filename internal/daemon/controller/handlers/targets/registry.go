package targets

import (
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
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

	// VetForUpdate validates the Attributes for an updated resource with the
	// provided mask paths and returns a map of fields to error messages if any
	// fields are invalid.
	VetForUpdate([]string) map[string]string
}

type attributeFunc func(interface{}) Attributes

type setAttributeFunc func(target.Target, *pb.Target) error

type registryEntry struct {
	maskManager handlers.MaskManager
	attrFunc    attributeFunc
	setAttrFunc setAttributeFunc
}

type registry struct {
	*sync.Map
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
// subtype. An error is returned if the provided subtype is not registered
func (r registry) newAttribute(s subtypes.Subtype, m interface{}) (Attributes, error) {
	re, err := r.get(s)
	if err != nil {
		return nil, err
	}

	attr := re.attrFunc(m)

	return attr, nil
}

// setAttributes is used to set the Attrs field on a pb.Target. It delegates the
// setting of the specific attribute type to the registered setAttributeFunc for
// the given subtype. An error is returned if the provided subtype is not
// registered.
func (r registry) setAttributes(s subtypes.Subtype, in target.Target, out *pb.Target) error {
	re, err := r.get(s)
	if err != nil {
		return err
	}

	return re.setAttrFunc(in, out)
}

var subtypeRegistry = registry{
	Map: new(sync.Map),
}

// Register registers a subtype for used by the service handler.
func Register(s subtypes.Subtype, maskManager handlers.MaskManager, af attributeFunc, sf setAttributeFunc) {
	if _, existed := subtypeRegistry.LoadOrStore(s, &registryEntry{
		maskManager: maskManager,
		attrFunc:    af,
		setAttrFunc: sf,
	}); existed {
		panic(fmt.Sprintf("subtype %s already registered", s))
	}
}
