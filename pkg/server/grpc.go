// Package server provides gRPC server implementation for the orchestration service.
package server

import (
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
	orchestrationpb "github.com/ahrav/gitleaks-armada/proto/orchestration"
)

// WorkService handles gRPC requests for work distribution and management.
// It acts as an adapter between the gRPC interface and orchestration logic.
type WorkService struct {
	orchestrator *orchestration.Orchestrator
	orchestrationpb.UnimplementedOrchestratorServiceServer
}

// NewWorkService creates a WorkService that will delegate requests to the provided orchestrator.
func NewWorkService(orchestrator *orchestration.Orchestrator) *WorkService {
	return &WorkService{orchestrator: orchestrator}
}

// Server encapsulates the gRPC server setup and lifecycle management.
type Server struct {
	grpcServer  *grpc.Server
	workService *WorkService
}

// New initializes a Server with the provided orchestrator, setting up all necessary
// gRPC service registrations and configurations.
func New(orchestrator *orchestration.Orchestrator) *Server {
	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)
	workService := NewWorkService(orchestrator)
	orchestrationpb.RegisterOrchestratorServiceServer(grpcServer, workService)

	return &Server{grpcServer: grpcServer, workService: workService}
}

// Serve starts the gRPC server on the provided listener, blocking until
// the server stops or encounters an error.
func (s *Server) Serve(lis net.Listener) error { return s.grpcServer.Serve(lis) }
