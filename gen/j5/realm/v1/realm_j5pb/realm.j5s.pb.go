// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: j5/realm/v1/realm.j5s.proto

package realm_j5pb

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	_ "github.com/pentops/j5/gen/j5/ext/v1/ext_j5pb"
	_ "github.com/pentops/j5/gen/j5/list/v1/list_j5pb"
	psm_j5pb "github.com/pentops/j5/gen/j5/state/v1/psm_j5pb"
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

type RealmStatus int32

const (
	RealmStatus_REALM_STATUS_UNSPECIFIED RealmStatus = 0
	RealmStatus_REALM_STATUS_ACTIVE      RealmStatus = 1
)

// Enum value maps for RealmStatus.
var (
	RealmStatus_name = map[int32]string{
		0: "REALM_STATUS_UNSPECIFIED",
		1: "REALM_STATUS_ACTIVE",
	}
	RealmStatus_value = map[string]int32{
		"REALM_STATUS_UNSPECIFIED": 0,
		"REALM_STATUS_ACTIVE":      1,
	}
)

func (x RealmStatus) Enum() *RealmStatus {
	p := new(RealmStatus)
	*p = x
	return p
}

func (x RealmStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RealmStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_j5_realm_v1_realm_j5s_proto_enumTypes[0].Descriptor()
}

func (RealmStatus) Type() protoreflect.EnumType {
	return &file_j5_realm_v1_realm_j5s_proto_enumTypes[0]
}

func (x RealmStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use RealmStatus.Descriptor instead.
func (RealmStatus) EnumDescriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{0}
}

type RealmKeys struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RealmId string `protobuf:"bytes,1,opt,name=realm_id,json=realmId,proto3" json:"realm_id,omitempty"`
}

func (x *RealmKeys) Reset() {
	*x = RealmKeys{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmKeys) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmKeys) ProtoMessage() {}

func (x *RealmKeys) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmKeys.ProtoReflect.Descriptor instead.
func (*RealmKeys) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{0}
}

func (x *RealmKeys) GetRealmId() string {
	if x != nil {
		return x.RealmId
	}
	return ""
}

type RealmData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Spec *RealmSpec `protobuf:"bytes,1,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *RealmData) Reset() {
	*x = RealmData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmData) ProtoMessage() {}

func (x *RealmData) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmData.ProtoReflect.Descriptor instead.
func (*RealmData) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{1}
}

func (x *RealmData) GetSpec() *RealmSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

type RealmState struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata *psm_j5pb.StateMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
	Keys     *RealmKeys              `protobuf:"bytes,2,opt,name=keys,proto3" json:"keys,omitempty"`
	Data     *RealmData              `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	Status   RealmStatus             `protobuf:"varint,4,opt,name=status,proto3,enum=j5.realm.v1.RealmStatus" json:"status,omitempty"`
}

func (x *RealmState) Reset() {
	*x = RealmState{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmState) ProtoMessage() {}

func (x *RealmState) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmState.ProtoReflect.Descriptor instead.
func (*RealmState) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{2}
}

func (x *RealmState) GetMetadata() *psm_j5pb.StateMetadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *RealmState) GetKeys() *RealmKeys {
	if x != nil {
		return x.Keys
	}
	return nil
}

func (x *RealmState) GetData() *RealmData {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *RealmState) GetStatus() RealmStatus {
	if x != nil {
		return x.Status
	}
	return RealmStatus_REALM_STATUS_UNSPECIFIED
}

type RealmEventType struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Type:
	//
	//	*RealmEventType_Created_
	//	*RealmEventType_Updated_
	Type isRealmEventType_Type `protobuf_oneof:"type"`
}

func (x *RealmEventType) Reset() {
	*x = RealmEventType{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmEventType) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmEventType) ProtoMessage() {}

func (x *RealmEventType) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmEventType.ProtoReflect.Descriptor instead.
func (*RealmEventType) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{3}
}

func (m *RealmEventType) GetType() isRealmEventType_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (x *RealmEventType) GetCreated() *RealmEventType_Created {
	if x, ok := x.GetType().(*RealmEventType_Created_); ok {
		return x.Created
	}
	return nil
}

func (x *RealmEventType) GetUpdated() *RealmEventType_Updated {
	if x, ok := x.GetType().(*RealmEventType_Updated_); ok {
		return x.Updated
	}
	return nil
}

type isRealmEventType_Type interface {
	isRealmEventType_Type()
}

type RealmEventType_Created_ struct {
	Created *RealmEventType_Created `protobuf:"bytes,1,opt,name=created,proto3,oneof"`
}

type RealmEventType_Updated_ struct {
	Updated *RealmEventType_Updated `protobuf:"bytes,2,opt,name=updated,proto3,oneof"`
}

func (*RealmEventType_Created_) isRealmEventType_Type() {}

func (*RealmEventType_Updated_) isRealmEventType_Type() {}

type RealmEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata *psm_j5pb.EventMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
	Keys     *RealmKeys              `protobuf:"bytes,2,opt,name=keys,proto3" json:"keys,omitempty"`
	Event    *RealmEventType         `protobuf:"bytes,3,opt,name=event,proto3" json:"event,omitempty"`
}

func (x *RealmEvent) Reset() {
	*x = RealmEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmEvent) ProtoMessage() {}

func (x *RealmEvent) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmEvent.ProtoReflect.Descriptor instead.
func (*RealmEvent) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{4}
}

func (x *RealmEvent) GetMetadata() *psm_j5pb.EventMetadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *RealmEvent) GetKeys() *RealmKeys {
	if x != nil {
		return x.Keys
	}
	return nil
}

func (x *RealmEvent) GetEvent() *RealmEventType {
	if x != nil {
		return x.Event
	}
	return nil
}

type RealmSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name        string            `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Type        string            `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	BaseUrl     string            `protobuf:"bytes,3,opt,name=base_url,json=baseUrl,proto3" json:"base_url,omitempty"`
	TenantTypes []*TenantType     `protobuf:"bytes,4,rep,name=tenant_types,json=tenantTypes,proto3" json:"tenant_types,omitempty"`
	Metadata    map[string]string `protobuf:"bytes,5,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *RealmSpec) Reset() {
	*x = RealmSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmSpec) ProtoMessage() {}

func (x *RealmSpec) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmSpec.ProtoReflect.Descriptor instead.
func (*RealmSpec) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{5}
}

func (x *RealmSpec) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RealmSpec) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *RealmSpec) GetBaseUrl() string {
	if x != nil {
		return x.BaseUrl
	}
	return ""
}

func (x *RealmSpec) GetTenantTypes() []*TenantType {
	if x != nil {
		return x.TenantTypes
	}
	return nil
}

func (x *RealmSpec) GetMetadata() map[string]string {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type TenantType struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Label string `protobuf:"bytes,2,opt,name=label,proto3" json:"label,omitempty"`
	// the tenant-type has exactly one tenant ID in the realm.
	// In multi-tenant environments, this tenant type is has global access across all tenants
	// If this is the only tenant-type in the realm, the realm itself is single-tenant.
	Singular bool `protobuf:"varint,3,opt,name=singular,proto3" json:"singular,omitempty"`
}

func (x *TenantType) Reset() {
	*x = TenantType{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TenantType) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TenantType) ProtoMessage() {}

func (x *TenantType) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TenantType.ProtoReflect.Descriptor instead.
func (*TenantType) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{6}
}

func (x *TenantType) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *TenantType) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

func (x *TenantType) GetSingular() bool {
	if x != nil {
		return x.Singular
	}
	return false
}

type RealmEventType_Created struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Spec *RealmSpec `protobuf:"bytes,1,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *RealmEventType_Created) Reset() {
	*x = RealmEventType_Created{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmEventType_Created) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmEventType_Created) ProtoMessage() {}

func (x *RealmEventType_Created) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmEventType_Created.ProtoReflect.Descriptor instead.
func (*RealmEventType_Created) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{3, 0}
}

func (x *RealmEventType_Created) GetSpec() *RealmSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

type RealmEventType_Updated struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Spec *RealmSpec `protobuf:"bytes,1,opt,name=spec,proto3" json:"spec,omitempty"`
}

func (x *RealmEventType_Updated) Reset() {
	*x = RealmEventType_Updated{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RealmEventType_Updated) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RealmEventType_Updated) ProtoMessage() {}

func (x *RealmEventType_Updated) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_realm_j5s_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RealmEventType_Updated.ProtoReflect.Descriptor instead.
func (*RealmEventType_Updated) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_realm_j5s_proto_rawDescGZIP(), []int{3, 1}
}

func (x *RealmEventType_Updated) GetSpec() *RealmSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

var File_j5_realm_v1_realm_j5s_proto protoreflect.FileDescriptor

var file_j5_realm_v1_realm_j5s_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x6a, 0x35, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65,
	0x61, 0x6c, 0x6d, 0x2e, 0x6a, 0x35, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6a,
	0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x62, 0x75, 0x66, 0x2f,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x6a, 0x35, 0x2f, 0x65, 0x78, 0x74, 0x2f,
	0x76, 0x31, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x6a, 0x35, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x2f, 0x76, 0x31,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1a, 0x6a, 0x35, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x2f,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5b,
	0x0a, 0x09, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x4b, 0x65, 0x79, 0x73, 0x12, 0x37, 0x0a, 0x08, 0x72,
	0x65, 0x61, 0x6c, 0x6d, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1c, 0xba,
	0x48, 0x08, 0xc8, 0x01, 0x01, 0x72, 0x03, 0xb0, 0x01, 0x01, 0xc2, 0xff, 0x8e, 0x02, 0x05, 0xb2,
	0x02, 0x02, 0x08, 0x02, 0xea, 0x85, 0x8f, 0x02, 0x02, 0x08, 0x01, 0x52, 0x07, 0x72, 0x65, 0x61,
	0x6c, 0x6d, 0x49, 0x64, 0x3a, 0x15, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0xea, 0x85, 0x8f,
	0x02, 0x09, 0x0a, 0x05, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x10, 0x01, 0x22, 0x5d, 0x0a, 0x09, 0x52,
	0x65, 0x61, 0x6c, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x12, 0x39, 0x0a, 0x04, 0x73, 0x70, 0x65, 0x63,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c,
	0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x53, 0x70, 0x65, 0x63, 0x42, 0x0d,
	0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x52, 0x04, 0x73,
	0x70, 0x65, 0x63, 0x3a, 0x15, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0xea, 0x85, 0x8f, 0x02,
	0x09, 0x0a, 0x05, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x10, 0x04, 0x22, 0xb5, 0x02, 0x0a, 0x0a, 0x52,
	0x65, 0x61, 0x6c, 0x6d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x45, 0x0a, 0x08, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x6a, 0x35,
	0x2e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x42, 0x0d, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0xc2,
	0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x12, 0x3b, 0x0a, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16,
	0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61,
	0x6c, 0x6d, 0x4b, 0x65, 0x79, 0x73, 0x42, 0x0f, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0xc2, 0xff,
	0x8e, 0x02, 0x04, 0x52, 0x02, 0x08, 0x01, 0x52, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x12, 0x39, 0x0a,
	0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x6a, 0x35,
	0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x44,
	0x61, 0x74, 0x61, 0x42, 0x0d, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0xc2, 0xff, 0x8e, 0x02, 0x02,
	0x52, 0x00, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x51, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65,
	0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x42, 0x1f, 0xba, 0x48, 0x08, 0xc8, 0x01, 0x01, 0x82, 0x01, 0x02, 0x10, 0x01, 0xc2,
	0xff, 0x8e, 0x02, 0x02, 0x5a, 0x00, 0x8a, 0xf7, 0x98, 0xc6, 0x02, 0x07, 0xa2, 0x01, 0x04, 0x52,
	0x02, 0x08, 0x01, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x3a, 0x15, 0xc2, 0xff, 0x8e,
	0x02, 0x02, 0x52, 0x00, 0xea, 0x85, 0x8f, 0x02, 0x09, 0x0a, 0x05, 0x72, 0x65, 0x61, 0x6c, 0x6d,
	0x10, 0x02, 0x22, 0xc7, 0x02, 0x0a, 0x0e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x45, 0x76, 0x65, 0x6e,
	0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x48, 0x0a, 0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c,
	0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x54,
	0x79, 0x70, 0x65, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x07, 0xc2, 0xff, 0x8e,
	0x02, 0x02, 0x52, 0x00, 0x48, 0x00, 0x52, 0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x12,
	0x48, 0x0a, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x23, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52,
	0x65, 0x61, 0x6c, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x64, 0x42, 0x07, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x48, 0x00,
	0x52, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x1a, 0x47, 0x0a, 0x07, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x12, 0x33, 0x0a, 0x04, 0x73, 0x70, 0x65, 0x63, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x16, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31,
	0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x53, 0x70, 0x65, 0x63, 0x42, 0x07, 0xc2, 0xff, 0x8e, 0x02,
	0x02, 0x52, 0x00, 0x52, 0x04, 0x73, 0x70, 0x65, 0x63, 0x3a, 0x07, 0xc2, 0xff, 0x8e, 0x02, 0x02,
	0x52, 0x00, 0x1a, 0x47, 0x0a, 0x07, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x12, 0x33, 0x0a,
	0x04, 0x73, 0x70, 0x65, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x6a, 0x35,
	0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x53,
	0x70, 0x65, 0x63, 0x42, 0x07, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x52, 0x04, 0x73, 0x70,
	0x65, 0x63, 0x3a, 0x07, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x3a, 0x07, 0xc2, 0xff, 0x8e,
	0x02, 0x02, 0x5a, 0x00, 0x42, 0x06, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x22, 0xf6, 0x01, 0x0a,
	0x0a, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x45, 0x0a, 0x08, 0x6d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x6a, 0x35, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x76, 0x65, 0x6e,
	0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x42, 0x0d, 0xba, 0x48, 0x03, 0xc8, 0x01,
	0x01, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x12, 0x3b, 0x0a, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x16, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52,
	0x65, 0x61, 0x6c, 0x6d, 0x4b, 0x65, 0x79, 0x73, 0x42, 0x0f, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01,
	0xc2, 0xff, 0x8e, 0x02, 0x04, 0x52, 0x02, 0x08, 0x01, 0x52, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x12,
	0x4d, 0x0a, 0x05, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b,
	0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61,
	0x6c, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x42, 0x1a, 0xba, 0x48, 0x03,
	0xc8, 0x01, 0x01, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x62, 0x00, 0x8a, 0xf7, 0x98, 0xc6, 0x02, 0x07,
	0xaa, 0x01, 0x04, 0x52, 0x02, 0x08, 0x01, 0x52, 0x05, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x3a, 0x15,
	0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0xea, 0x85, 0x8f, 0x02, 0x09, 0x0a, 0x05, 0x72, 0x65,
	0x61, 0x6c, 0x6d, 0x10, 0x03, 0x22, 0xd1, 0x02, 0x0a, 0x09, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x53,
	0x70, 0x65, 0x63, 0x12, 0x22, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x0e, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0xc2, 0xff, 0x8e, 0x02, 0x03, 0xf2, 0x01,
	0x00, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2f, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1b, 0xba, 0x48, 0x10, 0x72, 0x0e, 0x32, 0x0c, 0x5e, 0x5b,
	0x61, 0x2d, 0x7a, 0x30, 0x2d, 0x39, 0x2d, 0x5d, 0x2b, 0x24, 0xc2, 0xff, 0x8e, 0x02, 0x03, 0xf2,
	0x01, 0x00, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x23, 0x0a, 0x08, 0x62, 0x61, 0x73, 0x65,
	0x5f, 0x75, 0x72, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x08, 0xc2, 0xff, 0x8e, 0x02,
	0x03, 0xf2, 0x01, 0x00, 0x52, 0x07, 0x62, 0x61, 0x73, 0x65, 0x55, 0x72, 0x6c, 0x12, 0x44, 0x0a,
	0x0c, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x18, 0x04, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76,
	0x31, 0x2e, 0x54, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x42, 0x08, 0xc2, 0xff,
	0x8e, 0x02, 0x03, 0xaa, 0x01, 0x00, 0x52, 0x0b, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x54, 0x79,
	0x70, 0x65, 0x73, 0x12, 0x40, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d,
	0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x53, 0x70, 0x65, 0x63, 0x2e, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x1a, 0x39, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x0b, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x12, 0x17, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x08, 0xc2, 0xff, 0x8e, 0x02, 0x03, 0xf2, 0x01, 0x00, 0x3a, 0x02, 0x38, 0x01,
	0x3a, 0x07, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x22, 0x8c, 0x01, 0x0a, 0x0a, 0x54, 0x65,
	0x6e, 0x61, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x2f, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1b, 0xba, 0x48, 0x10, 0x72, 0x0e, 0x32, 0x0c, 0x5e,
	0x5b, 0x61, 0x2d, 0x7a, 0x30, 0x2d, 0x39, 0x2d, 0x5d, 0x2b, 0x24, 0xc2, 0xff, 0x8e, 0x02, 0x03,
	0xf2, 0x01, 0x00, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1e, 0x0a, 0x05, 0x6c, 0x61, 0x62,
	0x65, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x08, 0xc2, 0xff, 0x8e, 0x02, 0x03, 0xf2,
	0x01, 0x00, 0x52, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x24, 0x0a, 0x08, 0x73, 0x69, 0x6e,
	0x67, 0x75, 0x6c, 0x61, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x42, 0x08, 0xc2, 0xff, 0x8e,
	0x02, 0x03, 0x8a, 0x02, 0x00, 0x52, 0x08, 0x73, 0x69, 0x6e, 0x67, 0x75, 0x6c, 0x61, 0x72, 0x3a,
	0x07, 0xc2, 0xff, 0x8e, 0x02, 0x02, 0x52, 0x00, 0x2a, 0x44, 0x0a, 0x0b, 0x52, 0x65, 0x61, 0x6c,
	0x6d, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1c, 0x0a, 0x18, 0x52, 0x45, 0x41, 0x4c, 0x4d,
	0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46,
	0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x52, 0x45, 0x41, 0x4c, 0x4d, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x41, 0x43, 0x54, 0x49, 0x56, 0x45, 0x10, 0x01, 0x42, 0x36,
	0x5a, 0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x65, 0x6e,
	0x74, 0x6f, 0x70, 0x73, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x73, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x6a, 0x35, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x61, 0x6c,
	0x6d, 0x5f, 0x6a, 0x35, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_j5_realm_v1_realm_j5s_proto_rawDescOnce sync.Once
	file_j5_realm_v1_realm_j5s_proto_rawDescData = file_j5_realm_v1_realm_j5s_proto_rawDesc
)

func file_j5_realm_v1_realm_j5s_proto_rawDescGZIP() []byte {
	file_j5_realm_v1_realm_j5s_proto_rawDescOnce.Do(func() {
		file_j5_realm_v1_realm_j5s_proto_rawDescData = protoimpl.X.CompressGZIP(file_j5_realm_v1_realm_j5s_proto_rawDescData)
	})
	return file_j5_realm_v1_realm_j5s_proto_rawDescData
}

var file_j5_realm_v1_realm_j5s_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_j5_realm_v1_realm_j5s_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_j5_realm_v1_realm_j5s_proto_goTypes = []any{
	(RealmStatus)(0),               // 0: j5.realm.v1.RealmStatus
	(*RealmKeys)(nil),              // 1: j5.realm.v1.RealmKeys
	(*RealmData)(nil),              // 2: j5.realm.v1.RealmData
	(*RealmState)(nil),             // 3: j5.realm.v1.RealmState
	(*RealmEventType)(nil),         // 4: j5.realm.v1.RealmEventType
	(*RealmEvent)(nil),             // 5: j5.realm.v1.RealmEvent
	(*RealmSpec)(nil),              // 6: j5.realm.v1.RealmSpec
	(*TenantType)(nil),             // 7: j5.realm.v1.TenantType
	(*RealmEventType_Created)(nil), // 8: j5.realm.v1.RealmEventType.Created
	(*RealmEventType_Updated)(nil), // 9: j5.realm.v1.RealmEventType.Updated
	nil,                            // 10: j5.realm.v1.RealmSpec.MetadataEntry
	(*psm_j5pb.StateMetadata)(nil), // 11: j5.state.v1.StateMetadata
	(*psm_j5pb.EventMetadata)(nil), // 12: j5.state.v1.EventMetadata
}
var file_j5_realm_v1_realm_j5s_proto_depIdxs = []int32{
	6,  // 0: j5.realm.v1.RealmData.spec:type_name -> j5.realm.v1.RealmSpec
	11, // 1: j5.realm.v1.RealmState.metadata:type_name -> j5.state.v1.StateMetadata
	1,  // 2: j5.realm.v1.RealmState.keys:type_name -> j5.realm.v1.RealmKeys
	2,  // 3: j5.realm.v1.RealmState.data:type_name -> j5.realm.v1.RealmData
	0,  // 4: j5.realm.v1.RealmState.status:type_name -> j5.realm.v1.RealmStatus
	8,  // 5: j5.realm.v1.RealmEventType.created:type_name -> j5.realm.v1.RealmEventType.Created
	9,  // 6: j5.realm.v1.RealmEventType.updated:type_name -> j5.realm.v1.RealmEventType.Updated
	12, // 7: j5.realm.v1.RealmEvent.metadata:type_name -> j5.state.v1.EventMetadata
	1,  // 8: j5.realm.v1.RealmEvent.keys:type_name -> j5.realm.v1.RealmKeys
	4,  // 9: j5.realm.v1.RealmEvent.event:type_name -> j5.realm.v1.RealmEventType
	7,  // 10: j5.realm.v1.RealmSpec.tenant_types:type_name -> j5.realm.v1.TenantType
	10, // 11: j5.realm.v1.RealmSpec.metadata:type_name -> j5.realm.v1.RealmSpec.MetadataEntry
	6,  // 12: j5.realm.v1.RealmEventType.Created.spec:type_name -> j5.realm.v1.RealmSpec
	6,  // 13: j5.realm.v1.RealmEventType.Updated.spec:type_name -> j5.realm.v1.RealmSpec
	14, // [14:14] is the sub-list for method output_type
	14, // [14:14] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_j5_realm_v1_realm_j5s_proto_init() }
func file_j5_realm_v1_realm_j5s_proto_init() {
	if File_j5_realm_v1_realm_j5s_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_j5_realm_v1_realm_j5s_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*RealmKeys); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*RealmData); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*RealmState); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*RealmEventType); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*RealmEvent); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*RealmSpec); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*TenantType); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*RealmEventType_Created); i {
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
		file_j5_realm_v1_realm_j5s_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*RealmEventType_Updated); i {
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
	file_j5_realm_v1_realm_j5s_proto_msgTypes[3].OneofWrappers = []any{
		(*RealmEventType_Created_)(nil),
		(*RealmEventType_Updated_)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_j5_realm_v1_realm_j5s_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_j5_realm_v1_realm_j5s_proto_goTypes,
		DependencyIndexes: file_j5_realm_v1_realm_j5s_proto_depIdxs,
		EnumInfos:         file_j5_realm_v1_realm_j5s_proto_enumTypes,
		MessageInfos:      file_j5_realm_v1_realm_j5s_proto_msgTypes,
	}.Build()
	File_j5_realm_v1_realm_j5s_proto = out.File
	file_j5_realm_v1_realm_j5s_proto_rawDesc = nil
	file_j5_realm_v1_realm_j5s_proto_goTypes = nil
	file_j5_realm_v1_realm_j5s_proto_depIdxs = nil
}
