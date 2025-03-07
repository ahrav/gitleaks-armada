// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.0
// source: proto/gateway.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	ScannerGatewayService_ConnectScanner_FullMethodName = "/scanner.ScannerGatewayService/ConnectScanner"
	ScannerGatewayService_GetRules_FullMethodName       = "/scanner.ScannerGatewayService/GetRules"
)

// ScannerGatewayServiceClient is the client API for ScannerGatewayService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// ScannerGatewayService provides a bidirectional streaming interface for
// external scanner instances to communicate with the central scanning system
// without direct access to the Kafka infrastructure.
type ScannerGatewayServiceClient interface {
	// ConnectScanner establishes a bidirectional stream between an external
	// scanner and the gateway. The scanner sends initialization data, followed by
	// a stream of events (results, heartbeats, etc.) The gateway sends tasks and
	// control messages back to the scanner.
	ConnectScanner(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[ScannerToGatewayMessage, GatewayToScannerMessage], error)
	// GetRules establishes a stream for the gateway to push rule definitions to
	// scanners. Despite the name suggesting scanners request rules, in our
	// architecture the controller owns the rules and pushes them to scanners via
	// this stream. The scanner connects to this stream and waits for rule
	// updates.
	//
	// This RPC should be renamed in the future to better reflect its purpose,
	// such as "ReceiveRuleUpdates" or "SubscribeToRules".
	GetRules(ctx context.Context, in *RulesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[RulesResponse], error)
}

type scannerGatewayServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewScannerGatewayServiceClient(cc grpc.ClientConnInterface) ScannerGatewayServiceClient {
	return &scannerGatewayServiceClient{cc}
}

func (c *scannerGatewayServiceClient) ConnectScanner(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[ScannerToGatewayMessage, GatewayToScannerMessage], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ScannerGatewayService_ServiceDesc.Streams[0], ScannerGatewayService_ConnectScanner_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[ScannerToGatewayMessage, GatewayToScannerMessage]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ScannerGatewayService_ConnectScannerClient = grpc.BidiStreamingClient[ScannerToGatewayMessage, GatewayToScannerMessage]

func (c *scannerGatewayServiceClient) GetRules(ctx context.Context, in *RulesRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[RulesResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ScannerGatewayService_ServiceDesc.Streams[1], ScannerGatewayService_GetRules_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[RulesRequest, RulesResponse]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ScannerGatewayService_GetRulesClient = grpc.ServerStreamingClient[RulesResponse]

// ScannerGatewayServiceServer is the server API for ScannerGatewayService service.
// All implementations must embed UnimplementedScannerGatewayServiceServer
// for forward compatibility.
//
// ScannerGatewayService provides a bidirectional streaming interface for
// external scanner instances to communicate with the central scanning system
// without direct access to the Kafka infrastructure.
type ScannerGatewayServiceServer interface {
	// ConnectScanner establishes a bidirectional stream between an external
	// scanner and the gateway. The scanner sends initialization data, followed by
	// a stream of events (results, heartbeats, etc.) The gateway sends tasks and
	// control messages back to the scanner.
	ConnectScanner(grpc.BidiStreamingServer[ScannerToGatewayMessage, GatewayToScannerMessage]) error
	// GetRules establishes a stream for the gateway to push rule definitions to
	// scanners. Despite the name suggesting scanners request rules, in our
	// architecture the controller owns the rules and pushes them to scanners via
	// this stream. The scanner connects to this stream and waits for rule
	// updates.
	//
	// This RPC should be renamed in the future to better reflect its purpose,
	// such as "ReceiveRuleUpdates" or "SubscribeToRules".
	GetRules(*RulesRequest, grpc.ServerStreamingServer[RulesResponse]) error
	mustEmbedUnimplementedScannerGatewayServiceServer()
}

// UnimplementedScannerGatewayServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedScannerGatewayServiceServer struct{}

func (UnimplementedScannerGatewayServiceServer) ConnectScanner(grpc.BidiStreamingServer[ScannerToGatewayMessage, GatewayToScannerMessage]) error {
	return status.Errorf(codes.Unimplemented, "method ConnectScanner not implemented")
}
func (UnimplementedScannerGatewayServiceServer) GetRules(*RulesRequest, grpc.ServerStreamingServer[RulesResponse]) error {
	return status.Errorf(codes.Unimplemented, "method GetRules not implemented")
}
func (UnimplementedScannerGatewayServiceServer) mustEmbedUnimplementedScannerGatewayServiceServer() {}
func (UnimplementedScannerGatewayServiceServer) testEmbeddedByValue()                               {}

// UnsafeScannerGatewayServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ScannerGatewayServiceServer will
// result in compilation errors.
type UnsafeScannerGatewayServiceServer interface {
	mustEmbedUnimplementedScannerGatewayServiceServer()
}

func RegisterScannerGatewayServiceServer(s grpc.ServiceRegistrar, srv ScannerGatewayServiceServer) {
	// If the following call pancis, it indicates UnimplementedScannerGatewayServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ScannerGatewayService_ServiceDesc, srv)
}

func _ScannerGatewayService_ConnectScanner_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ScannerGatewayServiceServer).ConnectScanner(&grpc.GenericServerStream[ScannerToGatewayMessage, GatewayToScannerMessage]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ScannerGatewayService_ConnectScannerServer = grpc.BidiStreamingServer[ScannerToGatewayMessage, GatewayToScannerMessage]

func _ScannerGatewayService_GetRules_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(RulesRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ScannerGatewayServiceServer).GetRules(m, &grpc.GenericServerStream[RulesRequest, RulesResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ScannerGatewayService_GetRulesServer = grpc.ServerStreamingServer[RulesResponse]

// ScannerGatewayService_ServiceDesc is the grpc.ServiceDesc for ScannerGatewayService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ScannerGatewayService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "scanner.ScannerGatewayService",
	HandlerType: (*ScannerGatewayServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ConnectScanner",
			Handler:       _ScannerGatewayService_ConnectScanner_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "GetRules",
			Handler:       _ScannerGatewayService_GetRules_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "proto/gateway.proto",
}
