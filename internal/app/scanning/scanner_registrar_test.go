package scanning

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

type registrarTestSuite struct {
	domainPublisher *mockDomainEventPublisher
	logger          *logger.Logger
	tracer          trace.Tracer
	registrar       *ScannerRegistrar
}

func newRegistrarTestSuite(t *testing.T, scannerName, groupName, hostname, version string) *registrarTestSuite {
	t.Helper()

	domainPublisher := new(mockDomainEventPublisher)
	logger := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")

	return &registrarTestSuite{
		domainPublisher: domainPublisher,
		logger:          logger,
		tracer:          tracer,
		registrar:       NewScannerRegistrar(scannerName, groupName, hostname, domainPublisher, logger, tracer, version),
	}
}

func TestScannerRegistrar_Register(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*mockDomainEventPublisher)
		scannerName string
		group       string
		host        string
		version     string
		wantErr     bool
	}{
		{
			name: "successful registration",
			setup: func(m *mockDomainEventPublisher) {
				m.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(event events.DomainEvent) bool {
						regEvent, ok := event.(scanning.ScannerRegisteredEvent)
						return ok &&
							regEvent.Name() == "scanner-test-name" &&
							regEvent.GroupName() == "test-group" &&
							regEvent.Version() == "1.0.0" &&
							regEvent.InitialStatus() == scanning.ScannerStatusOnline
					}),
					mock.Anything,
				).Return(nil)
			},
			scannerName: "scanner-test-name",
			group:       "test-group",
			host:        "test-host",
			version:     "1.0.0",
			wantErr:     false,
		},
		{
			name: "registration with empty group",
			setup: func(m *mockDomainEventPublisher) {
				m.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(event events.DomainEvent) bool {
						regEvent, ok := event.(scanning.ScannerRegisteredEvent)
						return ok &&
							regEvent.Name() == "scanner-test-name" &&
							regEvent.GroupName() == "" &&
							regEvent.Version() == "1.0.0"
					}),
					mock.Anything,
				).Return(nil)
			},
			scannerName: "scanner-test-name",
			group:       "",
			host:        "test-host",
			version:     "1.0.0",
			wantErr:     false,
		},
		{
			name: "registration with different version",
			setup: func(m *mockDomainEventPublisher) {
				m.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(event events.DomainEvent) bool {
						regEvent, ok := event.(scanning.ScannerRegisteredEvent)
						return ok &&
							regEvent.Name() == "scanner-test-name" &&
							regEvent.Version() == "2.1.3"
					}),
					mock.Anything,
				).Return(nil)
			},
			scannerName: "scanner-test-name",
			group:       "test-group",
			host:        "test-host",
			version:     "2.1.3",
			wantErr:     false,
		},
		{
			name: "publication failure",
			setup: func(m *mockDomainEventPublisher) {
				m.On("PublishDomainEvent",
					mock.Anything,
					mock.Anything,
					mock.Anything,
				).Return(errors.New("failed to publish"))
			},
			scannerName: "scanner-test-name",
			group:       "test-group",
			host:        "test-host",
			version:     "1.0.0",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newRegistrarTestSuite(t, tt.scannerName, tt.group, tt.host, tt.version)
			tt.setup(suite.domainPublisher)

			err := suite.registrar.Register(context.Background())
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			suite.domainPublisher.AssertExpectations(t)
		})
	}
}

func TestNewScannerRegistrar(t *testing.T) {
	tests := []struct {
		name        string
		scannerName string
		group       string
		host        string
		version     string
		wantName    string
		wantGroup   string
		wantHost    string
		wantCaps    []string
		wantVer     string
	}{
		{
			name:        "standard initialization",
			scannerName: "scanner-test-name",
			group:       "test-group",
			host:        "test-host",
			version:     "1.0.0",
			wantName:    "scanner-test-name",
			wantGroup:   "test-group",
			wantHost:    "test-host",
			wantCaps:    nil,
			wantVer:     "1.0.0",
		},
		{
			name:        "empty group",
			scannerName: "scanner-test-name",
			group:       "",
			host:        "test-host",
			version:     "1.0.0",
			wantName:    "scanner-test-name",
			wantGroup:   "",
			wantHost:    "test-host",
			wantCaps:    nil,
			wantVer:     "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := new(mockDomainEventPublisher)
			logger := logger.Noop()
			tracer := noop.NewTracerProvider().Tracer("test")
			registrar := NewScannerRegistrar(tt.scannerName, tt.group, tt.host, publisher, logger, tracer, tt.version)

			require.Equal(t, tt.wantName, registrar.scannerName)
			require.Equal(t, tt.wantGroup, registrar.scannerGroupName)
			require.Equal(t, tt.wantHost, registrar.hostname)
			require.Equal(t, tt.wantCaps, registrar.capabilities)
			require.Equal(t, tt.wantVer, registrar.version)
		})
	}
}
