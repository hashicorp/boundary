// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

var (
	ConfigureWrapper             = configureWrapper
	CreateSecureRandomReaderFunc = createSecureRandomReader
)

// Entropy contains Entropy configuration for the server
type EntropyMode int

const (
	EntropyUnknown EntropyMode = iota
	EntropyAugmentation
)

type Entropy struct {
	Mode EntropyMode
}

// KMS contains KMS configuration for the server
type KMS struct {
	Type string
	// Purpose can be used to allow a string-based specification of what this
	// KMS is designated for, in situations where we want to allow more than
	// one KMS to be specified
	Purpose []string `hcl:"-"`

	// Disabled can be used by an application to understand intent. This was
	// mostly for Vault to enable seal migration and should be considered
	// deprecated in favor of using purposes.
	Disabled bool

	// PluginPath can be used, if using a file on disk as a wrapper plugin, to
	// specify a path to the file. This can also be specified via pluginutil
	// options from the application.
	PluginPath string `hcl:"plugin_path"`
	// PluginChecksum is a hex-encoded checksum using the specified
	// PluginHashMethod. Required when specifying a file path. It's hex-encoded
	// since most command-line tools output e.g. SHA sums as hex so it's
	// generally easier for the user to specify.
	PluginChecksum      string `hcl:"plugin_checksum"`
	pluginChecksumBytes []byte `hcl:"-"` // To store decoded checksum bytes
	// PluginHashMethod specifies the hash algorithm to use. See pluginutil
	// for currently-supported hash mechanisms and their string representations.
	// Empty will default to "sha2-256".
	PluginHashMethod string `hcl:"plugin_hash_method"`

	// Config is passed to the underlying wrappers
	Config map[string]string
}

func (k *KMS) GoString() string {
	return fmt.Sprintf("*%#v", *k)
}

func parseKMS(result *[]*KMS, list *ast.ObjectList, blockName string, opt ...Option) error {
	opts, err := getOpts(opt...)
	if err != nil {
		return err
	}

	switch {
	case opts.withMaxKmsBlocks > 0:
		if len(list.Items) > int(opts.withMaxKmsBlocks) {
			return fmt.Errorf("only %d or less %q blocks are permitted", opts.withMaxKmsBlocks, blockName)
		}
	default:
		// Allow unlimited
	}

	seals := make([]*KMS, 0, len(list.Items))
	for _, item := range list.Items {
		key := blockName
		if len(item.Keys) > 0 {
			key = item.Keys[0].Token.Value().(string)
		}

		// We first decode into a map[string]interface{} because purpose isn't
		// necessarily a string. Then we migrate everything else over to
		// map[string]string and error if it doesn't work.
		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
		}

		var purpose []string
		var err error
		if v, ok := m["purpose"]; ok {
			if purpose, err = parseutil.ParseCommaStringSlice(v); err != nil {
				return multierror.Prefix(fmt.Errorf("unable to parse 'purpose' in kms type %q: %w", key, err), fmt.Sprintf("%s.%s:", blockName, key))
			}
			for i, p := range purpose {
				purpose[i] = strings.ToLower(p)
			}
			delete(m, "purpose")
		}

		var disabled bool
		if v, ok := m["disabled"]; ok {
			disabled, err = parseutil.ParseBool(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			delete(m, "disabled")
		}

		seal := &KMS{
			Type:     strings.ToLower(key),
			Purpose:  purpose,
			Disabled: disabled,
		}

		const (
			pluginPath       = "plugin_path"
			pluginChecksum   = "plugin_checksum"
			pluginHashMethod = "plugin_hash_method"
		)
		for _, v := range []string{pluginPath, pluginChecksum, pluginHashMethod} {
			currVal := m[v]
			if currVal == nil {
				continue
			}
			s, err := parseutil.ParseString(currVal)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			switch v {
			case pluginPath:
				seal.PluginPath = s
				delete(m, pluginPath)
			case pluginChecksum:
				seal.PluginChecksum = s
				delete(m, pluginChecksum)
				seal.pluginChecksumBytes, err = hex.DecodeString(seal.PluginChecksum)
				if err != nil {
					return multierror.Prefix(fmt.Errorf("error parsing %s as hex: %w", pluginChecksum, err), fmt.Sprintf("%s.%s:", blockName, key))
				}
			case pluginHashMethod:
				seal.PluginHashMethod = s
				delete(m, pluginHashMethod)
			}
		}
		switch {
		case seal.PluginPath != "" && seal.PluginChecksum == "":
			return multierror.Prefix(fmt.Errorf("%s specified but %s empty", pluginPath, pluginChecksum), fmt.Sprintf("%s.%s:", blockName, key))
		case seal.PluginPath == "" && seal.PluginChecksum != "":
			return multierror.Prefix(fmt.Errorf("%s specified but %s empty", pluginChecksum, pluginPath), fmt.Sprintf("%s.%s:", blockName, key))
		}

		// Put the rest into config
		strMap := make(map[string]string, len(m))
		for k, v := range m {
			s, err := parseutil.ParseString(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			strMap[k] = s
		}
		if len(strMap) > 0 {
			seal.Config = strMap
		}

		seals = append(seals, seal)
	}

	*result = append(*result, seals...)

	return nil
}

// ParseKMSes loads KMS configuration from the provided string.
// Supported options:
//   - WithMaxKmsBlocks
func ParseKMSes(d string, opt ...Option) ([]*KMS, error) {
	// Parse!
	obj, err := hcl.Parse(d)
	if err != nil {
		return nil, err
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Start building the result
	var result struct {
		Seals []*KMS `hcl:"-"`
	}

	if err := hcl.DecodeObject(&result, obj); err != nil {
		return nil, err
	}

	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("error parsing: file doesn't contain a root object")
	}

	return filterKMSes(list, opts.withMaxKmsBlocks)
}

// filterKMSes unifies the logic formerly in ParseConfig and ParseKMSes to
// populate the actual KMSes once the HCL decoding has been performed
func filterKMSes(list *ast.ObjectList, maxBlocks int) ([]*KMS, error) {
	seals := new([]*KMS)

	maxHsmKmsBlocks := maxBlocks
	maxSealKmsBlocks := maxBlocks
	maxKmsBlocks := maxBlocks
	if maxBlocks == 0 {
		maxHsmKmsBlocks = 2
		maxSealKmsBlocks = 3
		maxKmsBlocks = 5
	}
	// opt is used after the WithMaxKmsBlocks option so that what a user passes
	// in can override the defaults here
	if o := list.Filter("hsm"); len(o.Items) > 0 {
		if err := parseKMS(seals, o, "hsm", WithMaxKmsBlocks(maxHsmKmsBlocks)); err != nil {
			return nil, fmt.Errorf("error parsing 'seal': %w", err)
		}
	}
	if o := list.Filter("seal"); len(o.Items) > 0 {
		if err := parseKMS(seals, o, "seal", WithMaxKmsBlocks(maxSealKmsBlocks)); err != nil {
			return nil, fmt.Errorf("error parsing 'seal': %w", err)
		}
	}
	if o := list.Filter("kms"); len(o.Items) > 0 {
		if err := parseKMS(seals, o, "kms", WithMaxKmsBlocks(maxKmsBlocks)); err != nil {
			return nil, fmt.Errorf("error parsing 'kms': %w", err)
		}
	}

	return *seals, nil
}

// configureWrapper takes in the KMS configuration, info values, and plugins in
// an fs.FS (for external plugins) or an instantiation map (for internal
// functions) and returns a wrapper, a cleanup function to execute on shutdown
// of the enclosing program, and an error.
func configureWrapper(
	ctx context.Context,
	configKMS *KMS,
	infoKeys *[]string,
	info *map[string]string,
	opt ...Option,
) (
	wrapper wrapping.Wrapper,
	cleanup func() error,
	retErr error,
) {
	defer func() {
		if retErr != nil && cleanup != nil {
			_ = cleanup()
		}
	}()

	if configKMS == nil {
		return nil, nil, fmt.Errorf("nil kms configuration passed in")
	}
	kmsType := strings.ToLower(configKMS.Type)

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing config options: %w", err)
	}

	// If the KMS block contained plugin file information, add it
	pluginOpts := opts.withPluginOptions
	switch {
	case configKMS.PluginPath == "" && configKMS.PluginChecksum == "":
	case configKMS.PluginPath == "" && configKMS.PluginChecksum != "":
		return nil, nil, errors.New("plugin checksum specified in kms but plugin path empty")
	case configKMS.PluginPath != "" && configKMS.PluginChecksum == "" && len(configKMS.pluginChecksumBytes) == 0:
		return nil, nil, errors.New("plugin path specified in kms but plugin checksum empty")
	default:
		if len(configKMS.pluginChecksumBytes) == 0 {
			configKMS.pluginChecksumBytes, err = hex.DecodeString(configKMS.PluginChecksum)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing plugin checksum as hex: %w", err)
			}
		}
		pluginOpts = append(pluginOpts, pluginutil.WithPluginFile(
			pluginutil.PluginFileInfo{
				Name:       configKMS.Type,
				Path:       configKMS.PluginPath,
				Checksum:   configKMS.pluginChecksumBytes,
				HashMethod: pluginutil.HashMethod(configKMS.PluginHashMethod),
			},
		))
	}

	// First, scan available plugins and build info
	pluginMap, err := pluginutil.BuildPluginMap(
		append(
			pluginOpts,
			pluginutil.WithPluginClientCreationFunc(
				func(pluginPath string, rtOpt ...pluginutil.Option) (*plugin.Client, error) {
					rtOpts, err := pluginutil.GetOpts(rtOpt...)
					if err != nil {
						return nil, fmt.Errorf("error parsing round-tripped plugin client options: %w", err)
					}
					return gkwp.NewWrapperClient(pluginPath,
						gkwp.WithLogger(opts.withLogger),
						gkwp.WithSecureConfig(rtOpts.WithSecureConfig),
					)
				}),
		)...)
	if err != nil {
		return nil, nil, fmt.Errorf("error building plugin map: %w", err)
	}

	// Now, find the right plugin
	var plug *pluginutil.PluginInfo
	switch kmsType {
	case wrapping.WrapperTypeShamir.String():
		return nil, nil, nil
	default:
		plug = pluginMap[kmsType]
	}

	// Create the plugin and cleanup func
	plugClient, cleanup, err := pluginutil.CreatePlugin(plug, pluginOpts...)
	if err != nil {
		return nil, cleanup, err
	}

	// Figure out whether it was internal and directly handles that interface or
	// if we need to dispense a plugin instance
	var raw interface{}
	switch client := plugClient.(type) {
	case plugin.ClientProtocol:
		raw, err = client.Dispense("wrapping")
		if err != nil {
			return nil, cleanup, fmt.Errorf("error dispensing kms plugin: %w", err)
		}
	case wrapping.Wrapper:
		raw = client
	default:
		return nil, cleanup, fmt.Errorf("unable to understand type %T of raw plugin", raw)
	}

	// Set configuration and parse info to be friendlier
	var ok bool
	wrapper, ok = raw.(wrapping.Wrapper)
	if !ok {
		return nil, cleanup, fmt.Errorf("error converting rpc kms wrapper of type %T to normal wrapper", raw)
	}
	wrapperConfigResult, err := wrapper.SetConfig(ctx,
		wrapping.WithKeyId(configKMS.Config["key_id"]),
		wrapping.WithConfigMap(configKMS.Config))
	if err != nil {
		return nil, cleanup, fmt.Errorf("error setting configuration on the kms plugin: %w", err)
	}
	kmsInfo := wrapperConfigResult.GetMetadata()
	if len(kmsInfo) > 0 && infoKeys != nil && info != nil && *info != nil {
		populateInfo(configKMS, infoKeys, info, kmsInfo)
	}

	return wrapper, cleanup, nil
}

// populateInfo is a shared function to populate some common information
func populateInfo(kms *KMS, infoKeys *[]string, info *map[string]string, kmsInfo map[string]string) {
	parsedInfo := make(map[string]string)
	switch kms.Type {
	case wrapping.WrapperTypeAead.String():
		str := "AEAD Type"
		if len(kms.Purpose) > 0 {
			str = fmt.Sprintf("%v %s", kms.Purpose, str)
		}
		parsedInfo[str] = kmsInfo["aead_type"]

	case wrapping.WrapperTypeAliCloudKms.String():
		parsedInfo["AliCloud KMS Region"] = kmsInfo["region"]
		parsedInfo["AliCloud KMS KeyID"] = kmsInfo["kms_key_id"]
		if domain, ok := kmsInfo["domain"]; ok {
			parsedInfo["AliCloud KMS Domain"] = domain
		}

	case wrapping.WrapperTypeAwsKms.String():
		parsedInfo["AWS KMS Region"] = kmsInfo["region"]
		parsedInfo["AWS KMS KeyID"] = kmsInfo["kms_key_id"]
		if endpoint, ok := kmsInfo["endpoint"]; ok {
			parsedInfo["AWS KMS Endpoint"] = endpoint
		}

	case wrapping.WrapperTypeAzureKeyVault.String():
		parsedInfo["Azure Environment"] = kmsInfo["environment"]
		parsedInfo["Azure Vault Name"] = kmsInfo["vault_name"]
		parsedInfo["Azure Key Name"] = kmsInfo["key_name"]

	case wrapping.WrapperTypeGcpCkms.String():
		parsedInfo["GCP KMS Project"] = kmsInfo["project"]
		parsedInfo["GCP KMS Region"] = kmsInfo["region"]
		parsedInfo["GCP KMS Key Ring"] = kmsInfo["key_ring"]
		parsedInfo["GCP KMS Crypto Key"] = kmsInfo["crypto_key"]

	case wrapping.WrapperTypeOciKms.String():
		parsedInfo["OCI KMS KeyID"] = kmsInfo["key_id"]
		parsedInfo["OCI KMS Crypto Endpoint"] = kmsInfo["crypto_endpoint"]
		parsedInfo["OCI KMS Management Endpoint"] = kmsInfo["management_endpoint"]
		parsedInfo["OCI KMS Principal Type"] = kmsInfo["principal_type"]

	case wrapping.WrapperTypeTransit.String():
		parsedInfo["Transit Address"] = kmsInfo["address"]
		parsedInfo["Transit Mount Path"] = kmsInfo["mount_path"]
		parsedInfo["Transit Key Name"] = kmsInfo["key_name"]
		if namespace, ok := kmsInfo["namespace"]; ok {
			parsedInfo["Transit Namespace"] = namespace
		}
	}

	if infoKeys != nil && info != nil {
		for k, v := range parsedInfo {
			*infoKeys = append(*infoKeys, k)
			(*info)[k] = v
		}
	}
}

func createSecureRandomReader(conf *SharedConfig, wrapper wrapping.Wrapper) (io.Reader, error) {
	return rand.Reader, nil
}
