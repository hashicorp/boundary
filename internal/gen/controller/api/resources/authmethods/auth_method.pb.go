// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.12.4
// source: controller/api/resources/authmethods/v1/auth_method.proto

package authmethods

import (
	_struct "github.com/golang/protobuf/ptypes/struct"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	scopes "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	_ "github.com/hashicorp/boundary/internal/gen/controller/protooptions"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// AuthMethod contains all fields related to an Auth Method resource
type AuthMethod struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. The ID of the Auth Method.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
	// The ID of the Scope of which this Auth Method is a part.
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,proto3" json:"scope_id,omitempty"`
	// Output only. Scope information for this Auth method.
	Scope *scopes.ScopeInfo `protobuf:"bytes,30,opt,name=scope,proto3" json:"scope,omitempty"`
	// Optional name for identification purposes.
	Name *wrappers.StringValue `protobuf:"bytes,40,opt,name=name,proto3" json:"name,omitempty"`
	// Optional user-set description for identification purposes.
	Description *wrappers.StringValue `protobuf:"bytes,50,opt,name=description,proto3" json:"description,omitempty"`
	// Output only. The time this resource was created.
	CreatedTime *timestamp.Timestamp `protobuf:"bytes,60,opt,name=created_time,proto3" json:"created_time,omitempty"`
	// Output only. The time this resource was last updated.
	UpdatedTime *timestamp.Timestamp `protobuf:"bytes,70,opt,name=updated_time,proto3" json:"updated_time,omitempty"`
	// Version is used in mutation requests, after the initial creation, to ensure this resource has not changed.
	// The mutation will fail if the version does not match the latest known good version.
	Version uint32 `protobuf:"varint,80,opt,name=version,proto3" json:"version,omitempty"`
	// The Auth Method type.
	Type string `protobuf:"bytes,90,opt,name=type,proto3" json:"type,omitempty"`
	// The attributes that are applicable for the specific Auth Method type.
	Attributes *_struct.Struct `protobuf:"bytes,100,opt,name=attributes,proto3" json:"attributes,omitempty"`
	// Output only. The available actions on this resource for this user.
	AuthorizedActions []string `protobuf:"bytes,300,rep,name=authorized_actions,proto3" json:"authorized_actions,omitempty"`
	// Output only. The authorized actions for the scope's collections.
	AuthorizedCollectionActions map[string]*_struct.ListValue `protobuf:"bytes,310,rep,name=authorized_collection_actions,proto3" json:"authorized_collection_actions,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *AuthMethod) Reset() {
	*x = AuthMethod{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthMethod) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthMethod) ProtoMessage() {}

func (x *AuthMethod) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthMethod.ProtoReflect.Descriptor instead.
func (*AuthMethod) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescGZIP(), []int{0}
}

func (x *AuthMethod) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *AuthMethod) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *AuthMethod) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *AuthMethod) GetName() *wrappers.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *AuthMethod) GetDescription() *wrappers.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *AuthMethod) GetCreatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *AuthMethod) GetUpdatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *AuthMethod) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *AuthMethod) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *AuthMethod) GetAttributes() *_struct.Struct {
	if x != nil {
		return x.Attributes
	}
	return nil
}

func (x *AuthMethod) GetAuthorizedActions() []string {
	if x != nil {
		return x.AuthorizedActions
	}
	return nil
}

func (x *AuthMethod) GetAuthorizedCollectionActions() map[string]*_struct.ListValue {
	if x != nil {
		return x.AuthorizedCollectionActions
	}
	return nil
}

// The attributes of a password typed auth method.
type PasswordAuthMethodAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The minimum length allowed for user names for Accounts in this Auth Method.
	MinLoginNameLength uint32 `protobuf:"varint,10,opt,name=min_login_name_length,proto3" json:"min_login_name_length,omitempty"`
	// The minimum length allowed for passwords for Accounts in this Auth Method.
	MinPasswordLength uint32 `protobuf:"varint,20,opt,name=min_password_length,proto3" json:"min_password_length,omitempty"`
}

func (x *PasswordAuthMethodAttributes) Reset() {
	*x = PasswordAuthMethodAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordAuthMethodAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordAuthMethodAttributes) ProtoMessage() {}

func (x *PasswordAuthMethodAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordAuthMethodAttributes.ProtoReflect.Descriptor instead.
func (*PasswordAuthMethodAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescGZIP(), []int{1}
}

func (x *PasswordAuthMethodAttributes) GetMinLoginNameLength() uint32 {
	if x != nil {
		return x.MinLoginNameLength
	}
	return 0
}

func (x *PasswordAuthMethodAttributes) GetMinPasswordLength() uint32 {
	if x != nil {
		return x.MinPasswordLength
	}
	return 0
}

// The attributes of an OIDC typed auth method.
type OidcAuthMethodAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. Will be "inactive", "active-private", or "active-public"
	State string `protobuf:"bytes,10,opt,name=state,proto3" json:"state,omitempty"`
	// A URL where the OIDC provider's configuration can be retrieved. Boundary
	// expects only the schema, host, and port and will strip off
	// "/.well-known/openid-configuration" if present
	DiscoveryUrl *wrappers.StringValue `protobuf:"bytes,20,opt,name=discovery_url,proto3" json:"discovery_url,omitempty"`
	// An OAuth 2.0 Client Identifier valid at the Authorization Server.
	ClientId *wrappers.StringValue `protobuf:"bytes,30,opt,name=client_id,proto3" json:"client_id,omitempty"`
	// Input only. The client's secret.
	ClientSecret *wrappers.StringValue `protobuf:"bytes,40,opt,name=client_secret,proto3" json:"client_secret,omitempty"`
	// Output only. The hashed value of the clients secret to indicate whether the client secret has changed.
	ClientSecretHmac string `protobuf:"bytes,50,opt,name=client_secret_hmac,proto3" json:"client_secret_hmac,omitempty"`
	// The elapsed time in seconds before the end user should be forced to re-authenticate. 0 is invalid, -1 indicates
	// an immediate need to reauthenticate.
	MaxAge *wrappers.Int32Value `protobuf:"bytes,60,opt,name=max_age,proto3" json:"max_age,omitempty"`
	// The signing algorithms allowed for an oidc auth method
	SigningAlgorithms []string `protobuf:"bytes,70,rep,name=signing_algorithms,proto3" json:"signing_algorithms,omitempty"`
	// The callback url prefixes used by the OIDC provider in the authentication flow.  Changes to this list
	// are reflected in the callback_urls read only field.
	CallbackUrlPrefixes []string `protobuf:"bytes,80,rep,name=callback_url_prefixes,proto3" json:"callback_url_prefixes,omitempty"`
	// Output only. The callback url used by the OIDC provider in the authentication flow. These values will have
	// boundary's callback api path appended too them.
	CallbackUrls []string `protobuf:"bytes,90,rep,name=callback_urls,proto3" json:"callback_urls,omitempty"`
	// certificates are optional PEM encoded x509 certificates that can be
	// used as trust anchors when connecting to an OIDC provider.
	Certificates []string `protobuf:"bytes,100,rep,name=certificates,proto3" json:"certificates,omitempty"`
	// The audience claims for this oidc typed auth method.
	AllowedAudiences []string `protobuf:"bytes,110,rep,name=allowed_audiences,proto3" json:"allowed_audiences,omitempty"`
}

func (x *OidcAuthMethodAttributes) Reset() {
	*x = OidcAuthMethodAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OidcAuthMethodAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OidcAuthMethodAttributes) ProtoMessage() {}

func (x *OidcAuthMethodAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OidcAuthMethodAttributes.ProtoReflect.Descriptor instead.
func (*OidcAuthMethodAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescGZIP(), []int{2}
}

func (x *OidcAuthMethodAttributes) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *OidcAuthMethodAttributes) GetDiscoveryUrl() *wrappers.StringValue {
	if x != nil {
		return x.DiscoveryUrl
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetClientId() *wrappers.StringValue {
	if x != nil {
		return x.ClientId
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetClientSecret() *wrappers.StringValue {
	if x != nil {
		return x.ClientSecret
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetClientSecretHmac() string {
	if x != nil {
		return x.ClientSecretHmac
	}
	return ""
}

func (x *OidcAuthMethodAttributes) GetMaxAge() *wrappers.Int32Value {
	if x != nil {
		return x.MaxAge
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetSigningAlgorithms() []string {
	if x != nil {
		return x.SigningAlgorithms
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetCallbackUrlPrefixes() []string {
	if x != nil {
		return x.CallbackUrlPrefixes
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetCallbackUrls() []string {
	if x != nil {
		return x.CallbackUrls
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetCertificates() []string {
	if x != nil {
		return x.Certificates
	}
	return nil
}

func (x *OidcAuthMethodAttributes) GetAllowedAudiences() []string {
	if x != nil {
		return x.AllowedAudiences
	}
	return nil
}

var File_controller_api_resources_authmethods_v1_auth_method_proto protoreflect.FileDescriptor

var file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc = []byte{
	0x0a, 0x39, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,
	0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f,
	0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76,
	0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xcb, 0x06, 0x0a, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x1a,
	0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53,
	0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12,
	0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x14, 0xa0, 0xda, 0x29,
	0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x4e, 0x61, 0x6d,
	0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0, 0xda, 0x29, 0x01,
	0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x0b, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a, 0x0c, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e, 0x0a, 0x0c, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x46, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x50, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x5a, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x37, 0x0a, 0x0a, 0x61, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x64, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x73, 0x12, 0x2f, 0x0a, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64,
	0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xac, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x12, 0x9b, 0x01, 0x0a, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
	0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb6, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x54, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x6d, 0x65, 0x74, 0x68,
	0x6f, 0x64, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x4d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x43, 0x6f, 0x6c, 0x6c,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x63,
	0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x1a, 0x6a, 0x0a, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x43,
	0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x30, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x83, 0x02,
	0x0a, 0x1c, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x41, 0x75, 0x74, 0x68, 0x4d, 0x65,
	0x74, 0x68, 0x6f, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x74,
	0x0a, 0x15, 0x6d, 0x69, 0x6e, 0x5f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
	0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x42, 0x3e, 0xa0,
	0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x36, 0x0a, 0x20, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x2e, 0x6d, 0x69, 0x6e, 0x5f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x12, 0x12, 0x4d, 0x69, 0x6e, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x52, 0x15, 0x6d,
	0x69, 0x6e, 0x5f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x6c, 0x65,
	0x6e, 0x67, 0x74, 0x68, 0x12, 0x6d, 0x0a, 0x13, 0x6d, 0x69, 0x6e, 0x5f, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x14, 0x20, 0x01, 0x28,
	0x0d, 0x42, 0x3b, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x33, 0x0a, 0x1e, 0x61, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x6d, 0x69, 0x6e, 0x5f, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x12, 0x11, 0x4d, 0x69, 0x6e,
	0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x52, 0x13,
	0x6d, 0x69, 0x6e, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f, 0x6c, 0x65, 0x6e,
	0x67, 0x74, 0x68, 0x22, 0xc1, 0x07, 0x0a, 0x18, 0x4f, 0x69, 0x64, 0x63, 0x41, 0x75, 0x74, 0x68,
	0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73,
	0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x74, 0x0a, 0x0d, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76,
	0x65, 0x72, 0x79, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x30, 0xa0, 0xda, 0x29,
	0x01, 0xc2, 0xdd, 0x29, 0x28, 0x0a, 0x18, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65,
	0x73, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x75, 0x72, 0x6c, 0x12,
	0x0c, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x55, 0x72, 0x6c, 0x52, 0x0d, 0x64,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x75, 0x72, 0x6c, 0x12, 0x64, 0x0a, 0x09,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x28, 0xa0,
	0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x20, 0x0a, 0x14, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x2e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x12, 0x08, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x52, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f,
	0x69, 0x64, 0x12, 0x74, 0x0a, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63,
	0x72, 0x65, 0x74, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69,
	0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x30, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29,
	0x28, 0x0a, 0x18, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x0c, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x52, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x2e, 0x0a, 0x12, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x18, 0x32,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63,
	0x72, 0x65, 0x74, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x12, 0x5b, 0x0a, 0x07, 0x6d, 0x61, 0x78, 0x5f,
	0x61, 0x67, 0x65, 0x18, 0x3c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x49, 0x6e, 0x74, 0x33,
	0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x24, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1c,
	0x0a, 0x12, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x6d, 0x61, 0x78,
	0x5f, 0x61, 0x67, 0x65, 0x12, 0x06, 0x4d, 0x61, 0x78, 0x41, 0x67, 0x65, 0x52, 0x07, 0x6d, 0x61,
	0x78, 0x5f, 0x61, 0x67, 0x65, 0x12, 0x64, 0x0a, 0x12, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x18, 0x46, 0x20, 0x03, 0x28,
	0x09, 0x42, 0x34, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x2c, 0x0a, 0x1d, 0x61, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f,
	0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x12, 0x0b, 0x53, 0x69, 0x67, 0x6e,
	0x69, 0x6e, 0x67, 0x41, 0x6c, 0x67, 0x73, 0x52, 0x12, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x12, 0x6e, 0x0a, 0x15, 0x63,
	0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x75, 0x72, 0x6c, 0x5f, 0x70, 0x72, 0x65, 0x66,
	0x69, 0x78, 0x65, 0x73, 0x18, 0x50, 0x20, 0x03, 0x28, 0x09, 0x42, 0x38, 0xa0, 0xda, 0x29, 0x01,
	0xc2, 0xdd, 0x29, 0x30, 0x0a, 0x20, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73,
	0x2e, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x75, 0x72, 0x6c, 0x5f, 0x70, 0x72,
	0x65, 0x66, 0x69, 0x78, 0x65, 0x73, 0x12, 0x0c, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b,
	0x55, 0x72, 0x6c, 0x73, 0x52, 0x15, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x75,
	0x72, 0x6c, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x65, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x63,
	0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x75, 0x72, 0x6c, 0x73, 0x18, 0x5a, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x0d, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x75, 0x72, 0x6c,
	0x73, 0x12, 0x53, 0x0a, 0x0c, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x73, 0x18, 0x64, 0x20, 0x03, 0x28, 0x09, 0x42, 0x2f, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29,
	0x27, 0x0a, 0x17, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x63, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x12, 0x0c, 0x43, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x52, 0x0c, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x12, 0x5f, 0x0a, 0x11, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65,
	0x64, 0x5f, 0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x18, 0x6e, 0x20, 0x03, 0x28,
	0x09, 0x42, 0x31, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x29, 0x0a, 0x1c, 0x61, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x5f,
	0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x12, 0x09, 0x41, 0x75, 0x64, 0x43, 0x6c,
	0x61, 0x69, 0x6d, 0x73, 0x52, 0x11, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x5f, 0x61, 0x75,
	0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x42, 0x5d, 0x5a, 0x5b, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f,
	0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61,
	0x75, 0x74, 0x68, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x3b, 0x61, 0x75, 0x74, 0x68, 0x6d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescOnce sync.Once
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData = file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc
)

func file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescGZIP() []byte {
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData)
	})
	return file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData
}

var file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controller_api_resources_authmethods_v1_auth_method_proto_goTypes = []interface{}{
	(*AuthMethod)(nil),                   // 0: controller.api.resources.authmethods.v1.AuthMethod
	(*PasswordAuthMethodAttributes)(nil), // 1: controller.api.resources.authmethods.v1.PasswordAuthMethodAttributes
	(*OidcAuthMethodAttributes)(nil),     // 2: controller.api.resources.authmethods.v1.OidcAuthMethodAttributes
	nil,                                  // 3: controller.api.resources.authmethods.v1.AuthMethod.AuthorizedCollectionActionsEntry
	(*scopes.ScopeInfo)(nil),             // 4: controller.api.resources.scopes.v1.ScopeInfo
	(*wrappers.StringValue)(nil),         // 5: google.protobuf.StringValue
	(*timestamp.Timestamp)(nil),          // 6: google.protobuf.Timestamp
	(*_struct.Struct)(nil),               // 7: google.protobuf.Struct
	(*wrappers.Int32Value)(nil),          // 8: google.protobuf.Int32Value
	(*_struct.ListValue)(nil),            // 9: google.protobuf.ListValue
}
var file_controller_api_resources_authmethods_v1_auth_method_proto_depIdxs = []int32{
	4,  // 0: controller.api.resources.authmethods.v1.AuthMethod.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	5,  // 1: controller.api.resources.authmethods.v1.AuthMethod.name:type_name -> google.protobuf.StringValue
	5,  // 2: controller.api.resources.authmethods.v1.AuthMethod.description:type_name -> google.protobuf.StringValue
	6,  // 3: controller.api.resources.authmethods.v1.AuthMethod.created_time:type_name -> google.protobuf.Timestamp
	6,  // 4: controller.api.resources.authmethods.v1.AuthMethod.updated_time:type_name -> google.protobuf.Timestamp
	7,  // 5: controller.api.resources.authmethods.v1.AuthMethod.attributes:type_name -> google.protobuf.Struct
	3,  // 6: controller.api.resources.authmethods.v1.AuthMethod.authorized_collection_actions:type_name -> controller.api.resources.authmethods.v1.AuthMethod.AuthorizedCollectionActionsEntry
	5,  // 7: controller.api.resources.authmethods.v1.OidcAuthMethodAttributes.discovery_url:type_name -> google.protobuf.StringValue
	5,  // 8: controller.api.resources.authmethods.v1.OidcAuthMethodAttributes.client_id:type_name -> google.protobuf.StringValue
	5,  // 9: controller.api.resources.authmethods.v1.OidcAuthMethodAttributes.client_secret:type_name -> google.protobuf.StringValue
	8,  // 10: controller.api.resources.authmethods.v1.OidcAuthMethodAttributes.max_age:type_name -> google.protobuf.Int32Value
	9,  // 11: controller.api.resources.authmethods.v1.AuthMethod.AuthorizedCollectionActionsEntry.value:type_name -> google.protobuf.ListValue
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_controller_api_resources_authmethods_v1_auth_method_proto_init() }
func file_controller_api_resources_authmethods_v1_auth_method_proto_init() {
	if File_controller_api_resources_authmethods_v1_auth_method_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthMethod); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordAuthMethodAttributes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OidcAuthMethodAttributes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_authmethods_v1_auth_method_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_authmethods_v1_auth_method_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes,
	}.Build()
	File_controller_api_resources_authmethods_v1_auth_method_proto = out.File
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc = nil
	file_controller_api_resources_authmethods_v1_auth_method_proto_goTypes = nil
	file_controller_api_resources_authmethods_v1_auth_method_proto_depIdxs = nil
}
