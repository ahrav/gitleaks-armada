package progressreporter

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

type mockDomainPublisher struct{ mock.Mock }

func (m *mockDomainPublisher) PublishDomainEvent(ctx context.Context, event events.DomainEvent, opts ...events.PublishOption) error {
	args := m.Called(ctx, event, opts)
	return args.Error(0)
}

func TestDomainEventProgressReporter_ReportProgress(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() scanning.Progress
		verify  func(*testing.T, *mockDomainPublisher, scanning.Progress)
		wantErr bool
	}{
		{
			name: "successfully publishes progress event",
			setup: func() scanning.Progress {
				return scanning.NewProgress(
					uuid.New(),
					uuid.New(),
					1,
					time.Now(),
					50,
					100,
					"",
					nil,
					nil,
				)
			},
			verify: func(t *testing.T, p *mockDomainPublisher, progress scanning.Progress) {
				p.On("PublishDomainEvent",
					mock.AnythingOfType("*context.valueCtx"),
					mock.AnythingOfType("scanning.TaskProgressedEvent"),
					mock.MatchedBy(func(opts []events.PublishOption) bool {
						params := events.PublishParams{}
						for _, opt := range opts {
							opt(&params)
						}
						return params.Key == progress.TaskID().String()
					}),
				).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "handles publisher error",
			setup: func() scanning.Progress {
				return scanning.NewProgress(
					uuid.New(),
					uuid.New(),
					1,
					time.Now(),
					50,
					100,
					"",
					nil,
					nil,
				)
			},
			verify: func(t *testing.T, p *mockDomainPublisher, progress scanning.Progress) {
				p.On("PublishDomainEvent",
					mock.AnythingOfType("*context.valueCtx"),
					mock.AnythingOfType("scanning.TaskProgressedEvent"),
					mock.Anything,
				).Return(assert.AnError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := new(mockDomainPublisher)
			reporter := New(publisher, noop.NewTracerProvider().Tracer("test"))

			progress := tt.setup()
			tt.verify(t, publisher, progress)

			err := reporter.ReportProgress(context.Background(), progress)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			publisher.AssertExpectations(t)
		})
	}
}
