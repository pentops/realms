// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: j5/realm/v1/service/auth.proto

package realm_j5spb

import (
	reflect "reflect"
	sync "sync"

	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	auth_j5pb "github.com/pentops/j5/gen/j5/auth/v1/auth_j5pb"
	realm_j5pb "github.com/pentops/realms/gen/j5/realm/v1/realm_j5pb"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type WhoamiRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *WhoamiRequest) Reset() {
	*x = WhoamiRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_service_auth_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WhoamiRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WhoamiRequest) ProtoMessage() {}

func (x *WhoamiRequest) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_service_auth_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WhoamiRequest.ProtoReflect.Descriptor instead.
func (*WhoamiRequest) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_service_auth_proto_rawDescGZIP(), []int{0}
}

type WhoamiResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Actor  *auth_j5pb.Actor                    `protobuf:"bytes,1,opt,name=actor,proto3" json:"actor,omitempty"`
	Realms []*WhoamiResponse_JoinedRealmAccess `protobuf:"bytes,5,rep,name=realms,proto3" json:"realms,omitempty"`
}

func (x *WhoamiResponse) Reset() {
	*x = WhoamiResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_service_auth_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WhoamiResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WhoamiResponse) ProtoMessage() {}

func (x *WhoamiResponse) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_service_auth_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WhoamiResponse.ProtoReflect.Descriptor instead.
func (*WhoamiResponse) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_service_auth_proto_rawDescGZIP(), []int{1}
}

func (x *WhoamiResponse) GetActor() *auth_j5pb.Actor {
	if x != nil {
		return x.Actor
	}
	return nil
}

func (x *WhoamiResponse) GetRealms() []*WhoamiResponse_JoinedRealmAccess {
	if x != nil {
		return x.Realms
	}
	return nil
}

type WhoamiResponse_JoinedRealmAccess struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Realm  *realm_j5pb.RealmState  `protobuf:"bytes,1,opt,name=realm,proto3" json:"realm,omitempty"`
	Tenant *realm_j5pb.TenantState `protobuf:"bytes,2,opt,name=tenant,proto3" json:"tenant,omitempty"`
}

func (x *WhoamiResponse_JoinedRealmAccess) Reset() {
	*x = WhoamiResponse_JoinedRealmAccess{}
	if protoimpl.UnsafeEnabled {
		mi := &file_j5_realm_v1_service_auth_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WhoamiResponse_JoinedRealmAccess) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WhoamiResponse_JoinedRealmAccess) ProtoMessage() {}

func (x *WhoamiResponse_JoinedRealmAccess) ProtoReflect() protoreflect.Message {
	mi := &file_j5_realm_v1_service_auth_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WhoamiResponse_JoinedRealmAccess.ProtoReflect.Descriptor instead.
func (*WhoamiResponse_JoinedRealmAccess) Descriptor() ([]byte, []int) {
	return file_j5_realm_v1_service_auth_proto_rawDescGZIP(), []int{1, 0}
}

func (x *WhoamiResponse_JoinedRealmAccess) GetRealm() *realm_j5pb.RealmState {
	if x != nil {
		return x.Realm
	}
	return nil
}

func (x *WhoamiResponse_JoinedRealmAccess) GetTenant() *realm_j5pb.TenantState {
	if x != nil {
		return x.Tenant
	}
	return nil
}

var File_j5_realm_v1_service_auth_proto protoreflect.FileDescriptor

var file_j5_realm_v1_service_auth_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x6a, 0x35, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x13, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x1a, 0x1b, 0x62, 0x75, 0x66, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x16, 0x6a, 0x35, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x63, 0x74,
	0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x6a, 0x35, 0x2f, 0x72, 0x65, 0x61,
	0x6c, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x18, 0x6a, 0x35, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x74,
	0x65, 0x6e, 0x61, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x0f, 0x0a, 0x0d, 0x57,
	0x68, 0x6f, 0x61, 0x6d, 0x69, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x8f, 0x02, 0x0a,
	0x0e, 0x57, 0x68, 0x6f, 0x61, 0x6d, 0x69, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x27, 0x0a, 0x05, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11,
	0x2e, 0x6a, 0x35, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x74, 0x6f,
	0x72, 0x52, 0x05, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x4d, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x6c,
	0x6d, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65,
	0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x57,
	0x68, 0x6f, 0x61, 0x6d, 0x69, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x4a, 0x6f,
	0x69, 0x6e, 0x65, 0x64, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x52,
	0x06, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x73, 0x1a, 0x84, 0x01, 0x0a, 0x11, 0x4a, 0x6f, 0x69, 0x6e,
	0x65, 0x64, 0x52, 0x65, 0x61, 0x6c, 0x6d, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x35, 0x0a,
	0x05, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x6a,
	0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x61, 0x6c, 0x6d,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x42, 0x06, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0x52, 0x05, 0x72,
	0x65, 0x61, 0x6c, 0x6d, 0x12, 0x38, 0x0a, 0x06, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e,
	0x76, 0x31, 0x2e, 0x54, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65, 0x42, 0x06,
	0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0x52, 0x06, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x32, 0x7f,
	0x0a, 0x0b, 0x41, 0x75, 0x74, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x70, 0x0a,
	0x06, 0x57, 0x68, 0x6f, 0x61, 0x6d, 0x69, 0x12, 0x22, 0x2e, 0x6a, 0x35, 0x2e, 0x72, 0x65, 0x61,
	0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x57, 0x68,
	0x6f, 0x61, 0x6d, 0x69, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x6a, 0x35,
	0x2e, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x57, 0x68, 0x6f, 0x61, 0x6d, 0x69, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x1d, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x17, 0x12, 0x15, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d,
	0x2d, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x31, 0x2f, 0x77, 0x68, 0x6f, 0x61, 0x6d, 0x69, 0x42,
	0x37, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x65,
	0x6e, 0x74, 0x6f, 0x70, 0x73, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x73, 0x2f, 0x67, 0x65, 0x6e,
	0x2f, 0x6a, 0x35, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x61,
	0x6c, 0x6d, 0x5f, 0x6a, 0x35, 0x73, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_j5_realm_v1_service_auth_proto_rawDescOnce sync.Once
	file_j5_realm_v1_service_auth_proto_rawDescData = file_j5_realm_v1_service_auth_proto_rawDesc
)

func file_j5_realm_v1_service_auth_proto_rawDescGZIP() []byte {
	file_j5_realm_v1_service_auth_proto_rawDescOnce.Do(func() {
		file_j5_realm_v1_service_auth_proto_rawDescData = protoimpl.X.CompressGZIP(file_j5_realm_v1_service_auth_proto_rawDescData)
	})
	return file_j5_realm_v1_service_auth_proto_rawDescData
}

var file_j5_realm_v1_service_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_j5_realm_v1_service_auth_proto_goTypes = []any{
	(*WhoamiRequest)(nil),                    // 0: j5.realm.v1.service.WhoamiRequest
	(*WhoamiResponse)(nil),                   // 1: j5.realm.v1.service.WhoamiResponse
	(*WhoamiResponse_JoinedRealmAccess)(nil), // 2: j5.realm.v1.service.WhoamiResponse.JoinedRealmAccess
	(*auth_j5pb.Actor)(nil),                  // 3: j5.auth.v1.Actor
	(*realm_j5pb.RealmState)(nil),            // 4: j5.realm.v1.RealmState
	(*realm_j5pb.TenantState)(nil),           // 5: j5.realm.v1.TenantState
}
var file_j5_realm_v1_service_auth_proto_depIdxs = []int32{
	3, // 0: j5.realm.v1.service.WhoamiResponse.actor:type_name -> j5.auth.v1.Actor
	2, // 1: j5.realm.v1.service.WhoamiResponse.realms:type_name -> j5.realm.v1.service.WhoamiResponse.JoinedRealmAccess
	4, // 2: j5.realm.v1.service.WhoamiResponse.JoinedRealmAccess.realm:type_name -> j5.realm.v1.RealmState
	5, // 3: j5.realm.v1.service.WhoamiResponse.JoinedRealmAccess.tenant:type_name -> j5.realm.v1.TenantState
	0, // 4: j5.realm.v1.service.AuthService.Whoami:input_type -> j5.realm.v1.service.WhoamiRequest
	1, // 5: j5.realm.v1.service.AuthService.Whoami:output_type -> j5.realm.v1.service.WhoamiResponse
	5, // [5:6] is the sub-list for method output_type
	4, // [4:5] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_j5_realm_v1_service_auth_proto_init() }
func file_j5_realm_v1_service_auth_proto_init() {
	if File_j5_realm_v1_service_auth_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_j5_realm_v1_service_auth_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*WhoamiRequest); i {
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
		file_j5_realm_v1_service_auth_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*WhoamiResponse); i {
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
		file_j5_realm_v1_service_auth_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*WhoamiResponse_JoinedRealmAccess); i {
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
			RawDescriptor: file_j5_realm_v1_service_auth_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_j5_realm_v1_service_auth_proto_goTypes,
		DependencyIndexes: file_j5_realm_v1_service_auth_proto_depIdxs,
		MessageInfos:      file_j5_realm_v1_service_auth_proto_msgTypes,
	}.Build()
	File_j5_realm_v1_service_auth_proto = out.File
	file_j5_realm_v1_service_auth_proto_rawDesc = nil
	file_j5_realm_v1_service_auth_proto_goTypes = nil
	file_j5_realm_v1_service_auth_proto_depIdxs = nil
}