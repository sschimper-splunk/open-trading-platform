// Code generated by protoc-gen-go. DO NOT EDIT.
// source: order.proto

package model

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Side int32

const (
	Side_BUY  Side = 0
	Side_SELL Side = 1
)

var Side_name = map[int32]string{
	0: "BUY",
	1: "SELL",
}

var Side_value = map[string]int32{
	"BUY":  0,
	"SELL": 1,
}

func (x Side) String() string {
	return proto.EnumName(Side_name, int32(x))
}

func (Side) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_cd01338c35d87077, []int{0}
}

type OrderStatus int32

const (
	OrderStatus_NONE      OrderStatus = 0
	OrderStatus_LIVE      OrderStatus = 1
	OrderStatus_FILLED    OrderStatus = 2
	OrderStatus_CANCELLED OrderStatus = 3
)

var OrderStatus_name = map[int32]string{
	0: "NONE",
	1: "LIVE",
	2: "FILLED",
	3: "CANCELLED",
}

var OrderStatus_value = map[string]int32{
	"NONE":      0,
	"LIVE":      1,
	"FILLED":    2,
	"CANCELLED": 3,
}

func (x OrderStatus) String() string {
	return proto.EnumName(OrderStatus_name, int32(x))
}

func (OrderStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_cd01338c35d87077, []int{1}
}

type Order struct {
	Version              int32       `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Id                   string      `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Side                 Side        `protobuf:"varint,3,opt,name=side,proto3,enum=model.Side" json:"side,omitempty"`
	Quantity             *Decimal64  `protobuf:"bytes,4,opt,name=quantity,proto3" json:"quantity,omitempty"`
	Price                *Decimal64  `protobuf:"bytes,5,opt,name=price,proto3" json:"price,omitempty"`
	ListingId            int32       `protobuf:"varint,6,opt,name=listingId,proto3" json:"listingId,omitempty"`
	RemainingQuantity    *Decimal64  `protobuf:"bytes,7,opt,name=remainingQuantity,proto3" json:"remainingQuantity,omitempty"`
	TradedQuantity       *Decimal64  `protobuf:"bytes,8,opt,name=tradedQuantity,proto3" json:"tradedQuantity,omitempty"`
	AvgTradePrice        *Decimal64  `protobuf:"bytes,9,opt,name=avgTradePrice,proto3" json:"avgTradePrice,omitempty"`
	Status               OrderStatus `protobuf:"varint,10,opt,name=status,proto3,enum=model.OrderStatus" json:"status,omitempty"`
	TargetStatus         OrderStatus `protobuf:"varint,11,opt,name=targetStatus,proto3,enum=model.OrderStatus" json:"targetStatus,omitempty"`
	Created              *Timestamp  `protobuf:"bytes,12,opt,name=created,proto3" json:"created,omitempty"`
	OwnerId              string      `protobuf:"bytes,13,opt,name=ownerId,proto3" json:"ownerId,omitempty"`
	OriginatorId         string      `protobuf:"bytes,14,opt,name=originatorId,proto3" json:"originatorId,omitempty"`
	OriginatorRef        string      `protobuf:"bytes,15,opt,name=originatorRef,proto3" json:"originatorRef,omitempty"`
	LastExecQuantity     *Decimal64  `protobuf:"bytes,16,opt,name=lastExecQuantity,proto3" json:"lastExecQuantity,omitempty"`
	LastExecPrice        *Decimal64  `protobuf:"bytes,17,opt,name=lastExecPrice,proto3" json:"lastExecPrice,omitempty"`
	LastExecId           string      `protobuf:"bytes,18,opt,name=lastExecId,proto3" json:"lastExecId,omitempty"`
	LastExecSeqNo        int32       `protobuf:"varint,19,opt,name=lastExecSeqNo,proto3" json:"lastExecSeqNo,omitempty"`
	ExposedQuantity      *Decimal64  `protobuf:"bytes,20,opt,name=exposedQuantity,proto3" json:"exposedQuantity,omitempty"`
	ErrorMessage         string      `protobuf:"bytes,21,opt,name=errorMessage,proto3" json:"errorMessage,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *Order) Reset()         { *m = Order{} }
func (m *Order) String() string { return proto.CompactTextString(m) }
func (*Order) ProtoMessage()    {}
func (*Order) Descriptor() ([]byte, []int) {
	return fileDescriptor_cd01338c35d87077, []int{0}
}

func (m *Order) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Order.Unmarshal(m, b)
}
func (m *Order) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Order.Marshal(b, m, deterministic)
}
func (m *Order) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Order.Merge(m, src)
}
func (m *Order) XXX_Size() int {
	return xxx_messageInfo_Order.Size(m)
}
func (m *Order) XXX_DiscardUnknown() {
	xxx_messageInfo_Order.DiscardUnknown(m)
}

var xxx_messageInfo_Order proto.InternalMessageInfo

func (m *Order) GetVersion() int32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Order) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Order) GetSide() Side {
	if m != nil {
		return m.Side
	}
	return Side_BUY
}

func (m *Order) GetQuantity() *Decimal64 {
	if m != nil {
		return m.Quantity
	}
	return nil
}

func (m *Order) GetPrice() *Decimal64 {
	if m != nil {
		return m.Price
	}
	return nil
}

func (m *Order) GetListingId() int32 {
	if m != nil {
		return m.ListingId
	}
	return 0
}

func (m *Order) GetRemainingQuantity() *Decimal64 {
	if m != nil {
		return m.RemainingQuantity
	}
	return nil
}

func (m *Order) GetTradedQuantity() *Decimal64 {
	if m != nil {
		return m.TradedQuantity
	}
	return nil
}

func (m *Order) GetAvgTradePrice() *Decimal64 {
	if m != nil {
		return m.AvgTradePrice
	}
	return nil
}

func (m *Order) GetStatus() OrderStatus {
	if m != nil {
		return m.Status
	}
	return OrderStatus_NONE
}

func (m *Order) GetTargetStatus() OrderStatus {
	if m != nil {
		return m.TargetStatus
	}
	return OrderStatus_NONE
}

func (m *Order) GetCreated() *Timestamp {
	if m != nil {
		return m.Created
	}
	return nil
}

func (m *Order) GetOwnerId() string {
	if m != nil {
		return m.OwnerId
	}
	return ""
}

func (m *Order) GetOriginatorId() string {
	if m != nil {
		return m.OriginatorId
	}
	return ""
}

func (m *Order) GetOriginatorRef() string {
	if m != nil {
		return m.OriginatorRef
	}
	return ""
}

func (m *Order) GetLastExecQuantity() *Decimal64 {
	if m != nil {
		return m.LastExecQuantity
	}
	return nil
}

func (m *Order) GetLastExecPrice() *Decimal64 {
	if m != nil {
		return m.LastExecPrice
	}
	return nil
}

func (m *Order) GetLastExecId() string {
	if m != nil {
		return m.LastExecId
	}
	return ""
}

func (m *Order) GetLastExecSeqNo() int32 {
	if m != nil {
		return m.LastExecSeqNo
	}
	return 0
}

func (m *Order) GetExposedQuantity() *Decimal64 {
	if m != nil {
		return m.ExposedQuantity
	}
	return nil
}

func (m *Order) GetErrorMessage() string {
	if m != nil {
		return m.ErrorMessage
	}
	return ""
}

func init() {
	proto.RegisterEnum("model.Side", Side_name, Side_value)
	proto.RegisterEnum("model.OrderStatus", OrderStatus_name, OrderStatus_value)
	proto.RegisterType((*Order)(nil), "model.Order")
}

func init() { proto.RegisterFile("order.proto", fileDescriptor_cd01338c35d87077) }

var fileDescriptor_cd01338c35d87077 = []byte{
	// 503 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x93, 0x6f, 0x8b, 0xd3, 0x40,
	0x10, 0xc6, 0x4d, 0xff, 0xa5, 0x9d, 0xfe, 0xb9, 0x74, 0x54, 0x58, 0x45, 0xb4, 0x1c, 0x22, 0xa5,
	0x48, 0x5f, 0x9c, 0x52, 0x44, 0x0e, 0xc1, 0xbb, 0x8b, 0x50, 0xa8, 0x3d, 0x4d, 0x4f, 0x41, 0xdf,
	0xad, 0xd9, 0x31, 0x2c, 0x34, 0xd9, 0xde, 0x66, 0xef, 0x3c, 0xbf, 0x81, 0x1f, 0x5b, 0xb2, 0x69,
	0x7a, 0xcd, 0x1d, 0x79, 0x15, 0xe6, 0x79, 0x7e, 0xb3, 0x3b, 0x79, 0x76, 0x17, 0xba, 0x4a, 0x0b,
	0xd2, 0xd3, 0x8d, 0x56, 0x46, 0x61, 0x33, 0x56, 0x82, 0xd6, 0x4f, 0x87, 0xf6, 0x13, 0xaa, 0x38,
	0x56, 0x49, 0xee, 0x1c, 0xfe, 0x73, 0xa1, 0x79, 0x9e, 0x91, 0xc8, 0xc0, 0xbd, 0x26, 0x9d, 0x4a,
	0x95, 0x30, 0x67, 0xe4, 0x8c, 0x9b, 0x41, 0x51, 0xe2, 0x00, 0x6a, 0x52, 0xb0, 0xda, 0xc8, 0x19,
	0x77, 0x82, 0x9a, 0x14, 0xf8, 0x02, 0x1a, 0xa9, 0x14, 0xc4, 0xea, 0x23, 0x67, 0x3c, 0x38, 0xea,
	0x4e, 0xed, 0xaa, 0xd3, 0x95, 0x14, 0x14, 0x58, 0x03, 0x5f, 0x43, 0xfb, 0xf2, 0x8a, 0x27, 0x46,
	0x9a, 0xbf, 0xac, 0x31, 0x72, 0xc6, 0xdd, 0x23, 0x6f, 0x0b, 0x9d, 0x51, 0x28, 0x63, 0xbe, 0x9e,
	0xbd, 0x0d, 0x76, 0x04, 0xbe, 0x82, 0xe6, 0x46, 0xcb, 0x90, 0x58, 0xb3, 0x02, 0xcd, 0x6d, 0x7c,
	0x06, 0x9d, 0xb5, 0x4c, 0x8d, 0x4c, 0xa2, 0xb9, 0x60, 0x2d, 0x3b, 0xe2, 0xad, 0x80, 0x1f, 0x60,
	0xa8, 0x29, 0xe6, 0x32, 0x91, 0x49, 0xf4, 0xb5, 0xd8, 0xdc, 0xad, 0x58, 0xf1, 0x3e, 0x8a, 0xef,
	0x60, 0x60, 0x34, 0x17, 0x24, 0x76, 0xcd, 0xed, 0x8a, 0xe6, 0x3b, 0x1c, 0xce, 0xa0, 0xcf, 0xaf,
	0xa3, 0x8b, 0x4c, 0xfc, 0x62, 0xff, 0xa3, 0x53, 0xd1, 0x58, 0xc6, 0x70, 0x02, 0xad, 0xd4, 0x70,
	0x73, 0x95, 0x32, 0xb0, 0x41, 0xe2, 0xb6, 0xc1, 0x1e, 0xc7, 0xca, 0x3a, 0xc1, 0x96, 0xc0, 0x19,
	0xf4, 0x0c, 0xd7, 0x11, 0x99, 0x5c, 0x67, 0xdd, 0xca, 0x8e, 0x12, 0x87, 0x13, 0x70, 0x43, 0x4d,
	0xdc, 0x90, 0x60, 0xbd, 0xd2, 0x54, 0x17, 0x32, 0xa6, 0xd4, 0xf0, 0x78, 0x13, 0x14, 0x40, 0x76,
	0x01, 0xd4, 0x9f, 0x84, 0xf4, 0x5c, 0xb0, 0xbe, 0x3d, 0xeb, 0xa2, 0xc4, 0x43, 0xe8, 0x29, 0x2d,
	0x23, 0x99, 0x70, 0xa3, 0x32, 0x7b, 0x60, 0xed, 0x92, 0x86, 0x2f, 0xa1, 0x7f, 0x5b, 0x07, 0xf4,
	0x9b, 0x1d, 0x58, 0xa8, 0x2c, 0xe2, 0x31, 0x78, 0x6b, 0x9e, 0x1a, 0xff, 0x86, 0xc2, 0x5d, 0xce,
	0x5e, 0x45, 0x5c, 0xf7, 0xc8, 0x2c, 0xe9, 0x42, 0xcb, 0x93, 0x1e, 0x56, 0x25, 0x5d, 0xc2, 0xf0,
	0x39, 0x40, 0x21, 0xcc, 0x05, 0x43, 0x3b, 0xd8, 0x9e, 0x92, 0xcd, 0x5e, 0x54, 0x2b, 0xba, 0x5c,
	0x2a, 0xf6, 0xd0, 0xde, 0xae, 0xb2, 0x88, 0xef, 0xe1, 0x80, 0x6e, 0x36, 0x2a, 0xdd, 0xbb, 0x22,
	0x8f, 0x2a, 0xf6, 0xbf, 0x0b, 0x66, 0x09, 0x92, 0xd6, 0x4a, 0x7f, 0xa6, 0x34, 0xe5, 0x11, 0xb1,
	0xc7, 0x79, 0x82, 0xfb, 0xda, 0xe4, 0x09, 0x34, 0xb2, 0x37, 0x84, 0x2e, 0xd4, 0x4f, 0xbe, 0xfd,
	0xf0, 0x1e, 0x60, 0x1b, 0x1a, 0x2b, 0x7f, 0xb1, 0xf0, 0x9c, 0xc9, 0x31, 0x74, 0xf7, 0xce, 0x38,
	0x33, 0x96, 0xe7, 0x4b, 0x3f, 0x47, 0x16, 0xf3, 0xef, 0xbe, 0xe7, 0x20, 0x40, 0xeb, 0xd3, 0x7c,
	0xb1, 0xf0, 0xcf, 0xbc, 0x1a, 0xf6, 0xa1, 0x73, 0xfa, 0x71, 0x79, 0xea, 0xdb, 0xb2, 0x7e, 0xe2,
	0xfe, 0xcc, 0xdf, 0xff, 0xaf, 0x96, 0x7d, 0xf3, 0x6f, 0xfe, 0x07, 0x00, 0x00, 0xff, 0xff, 0x24,
	0xa7, 0x61, 0xd7, 0x1c, 0x04, 0x00, 0x00,
}
