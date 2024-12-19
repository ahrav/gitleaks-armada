// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.20.3
// source: proto/orchestration/orchestration.proto

package orchestration

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
	OrchestratorService_GetNextChunk_FullMethodName  = "/orchestration.OrchestratorService/GetNextChunk"
	OrchestratorService_CompleteChunk_FullMethodName = "/orchestration.OrchestratorService/CompleteChunk"
)

// OrchestratorServiceClient is the client API for OrchestratorService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type OrchestratorServiceClient interface {
	// Worker requests a chunk of work.
	GetNextChunk(ctx context.Context, in *GetNextChunkRequest, opts ...grpc.CallOption) (*GetNextChunkResponse, error)
	// Worker notifies orchestrator that it has completed a chunk.
	CompleteChunk(ctx context.Context, in *CompleteChunkRequest, opts ...grpc.CallOption) (*CompleteChunkResponse, error)
}

type orchestratorServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewOrchestratorServiceClient(cc grpc.ClientConnInterface) OrchestratorServiceClient {
	return &orchestratorServiceClient{cc}
}

func (c *orchestratorServiceClient) GetNextChunk(ctx context.Context, in *GetNextChunkRequest, opts ...grpc.CallOption) (*GetNextChunkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetNextChunkResponse)
	err := c.cc.Invoke(ctx, OrchestratorService_GetNextChunk_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *orchestratorServiceClient) CompleteChunk(ctx context.Context, in *CompleteChunkRequest, opts ...grpc.CallOption) (*CompleteChunkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CompleteChunkResponse)
	err := c.cc.Invoke(ctx, OrchestratorService_CompleteChunk_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OrchestratorServiceServer is the server API for OrchestratorService service.
// All implementations must embed UnimplementedOrchestratorServiceServer
// for forward compatibility.
type OrchestratorServiceServer interface {
	// Worker requests a chunk of work.
	GetNextChunk(context.Context, *GetNextChunkRequest) (*GetNextChunkResponse, error)
	// Worker notifies orchestrator that it has completed a chunk.
	CompleteChunk(context.Context, *CompleteChunkRequest) (*CompleteChunkResponse, error)
	mustEmbedUnimplementedOrchestratorServiceServer()
}

// UnimplementedOrchestratorServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedOrchestratorServiceServer struct{}

func (UnimplementedOrchestratorServiceServer) GetNextChunk(context.Context, *GetNextChunkRequest) (*GetNextChunkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNextChunk not implemented")
}
func (UnimplementedOrchestratorServiceServer) CompleteChunk(context.Context, *CompleteChunkRequest) (*CompleteChunkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CompleteChunk not implemented")
}
func (UnimplementedOrchestratorServiceServer) mustEmbedUnimplementedOrchestratorServiceServer() {}
func (UnimplementedOrchestratorServiceServer) testEmbeddedByValue()                             {}

// UnsafeOrchestratorServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to OrchestratorServiceServer will
// result in compilation errors.
type UnsafeOrchestratorServiceServer interface {
	mustEmbedUnimplementedOrchestratorServiceServer()
}

func RegisterOrchestratorServiceServer(s grpc.ServiceRegistrar, srv OrchestratorServiceServer) {
	// If the following call pancis, it indicates UnimplementedOrchestratorServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&OrchestratorService_ServiceDesc, srv)
}

func _OrchestratorService_GetNextChunk_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetNextChunkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrchestratorServiceServer).GetNextChunk(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OrchestratorService_GetNextChunk_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrchestratorServiceServer).GetNextChunk(ctx, req.(*GetNextChunkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OrchestratorService_CompleteChunk_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CompleteChunkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrchestratorServiceServer).CompleteChunk(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OrchestratorService_CompleteChunk_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrchestratorServiceServer).CompleteChunk(ctx, req.(*CompleteChunkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// OrchestratorService_ServiceDesc is the grpc.ServiceDesc for OrchestratorService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var OrchestratorService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "orchestration.OrchestratorService",
	HandlerType: (*OrchestratorServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetNextChunk",
			Handler:    _OrchestratorService_GetNextChunk_Handler,
		},
		{
			MethodName: "CompleteChunk",
			Handler:    _OrchestratorService_CompleteChunk_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/orchestration/orchestration.proto",
}