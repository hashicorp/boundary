package policies

const (
	attributesField  = "attributes"
	deleteAfterField = "delete_after"
	retainForField   = "retain_for"
	daysField        = "days"
	overridableField = "overridable"
)

func WithStoragePolicyDeleteAfter(inDeleteAfter map[string]any) Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val[deleteAfterField] = inDeleteAfter
		o.postMap[attributesField] = val
	}
}

func DefaultStoragePolicyDeleteAfter() Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val[deleteAfterField] = nil
		o.postMap[attributesField] = val
	}
}

func WithStoragePolicyDeleteAfterDays(inDays int32) Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[deleteAfterField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[daysField] = inDays
		val[deleteAfterField] = deleteAfter
		o.postMap[attributesField] = val
	}
}

func DefaultStoragePolicyDeleteAfterDays() Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[deleteAfterField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[daysField] = 0
		val[deleteAfterField] = deleteAfter
		o.postMap[attributesField] = val
	}
}

func WithStoragePolicyDeleteAfterOverridable(inOverridable bool) Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[deleteAfterField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[overridableField] = inOverridable
		val[deleteAfterField] = deleteAfter
		o.postMap[attributesField] = val
	}
}

func DefaultStoragePolicyDeleteAfterOverridable() Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[deleteAfterField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[overridableField] = false
		val[deleteAfterField] = deleteAfter
		o.postMap[attributesField] = val
	}
}

func WithStoragePolicyRetainFor(inDeleteAfter map[string]any) Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val[retainForField] = inDeleteAfter
		o.postMap[attributesField] = val
	}
}

func DefaultStoragePolicyRetainFor() Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val[retainForField] = nil
		o.postMap[attributesField] = val
	}
}

func WithStoragePolicyRetainForDays(inDays int32) Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[retainForField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[daysField] = inDays
		val[retainForField] = deleteAfter
		o.postMap[attributesField] = val
	}
}

func DefaultStoragePolicyRetainForDays() Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[retainForField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[daysField] = 0
		val[retainForField] = deleteAfter
		o.postMap[attributesField] = val
	}
}

func WithStoragePolicyRetainForOverridable(inOverridable bool) Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[retainForField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[overridableField] = inOverridable
		val[retainForField] = deleteAfter
		o.postMap[attributesField] = val
	}
}

func DefaultStoragePolicyRetainForOverridable() Option {
	return func(o *options) {
		raw, ok := o.postMap[attributesField]
		if !ok {
			raw = interface{}(map[string]any{})
		}
		val := raw.(map[string]any)
		rawDeleteAfter, ok := val[retainForField]
		if !ok {
			rawDeleteAfter = interface{}(map[string]any{})
		}
		deleteAfter := rawDeleteAfter.(map[string]any)
		deleteAfter[overridableField] = false
		val[retainForField] = deleteAfter
		o.postMap[attributesField] = val
	}
}
