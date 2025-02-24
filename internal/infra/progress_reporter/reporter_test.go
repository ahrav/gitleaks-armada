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
	progress := scanning.NewProgress(uuid.New(), uuid.New(), 1, time.Now(), 50, 100, "", nil, nil)
	tests := []struct {
		name    string
		setup   func() scanning.Progress
		verify  func(*testing.T, *mockDomainPublisher, scanning.Progress)
		wantErr bool
	}{
		{
			name: "successfully publishes progress event",
			setup: func() scanning.Progress {
				return progress
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
				return progress
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
			reporter := New("test", publisher, noop.NewTracerProvider().Tracer("test"))

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

func TestDomainEventProgressReporter_ReportPausedProgress(t *testing.T) {
	progress := scanning.NewProgress(uuid.New(), uuid.New(), 1, time.Now(), 50, 100, "", nil, nil)

	tests := []struct {
		name    string
		setup   func() scanning.Progress
		verify  func(*testing.T, *mockDomainPublisher, scanning.Progress)
		wantErr bool
	}{
		{
			name: "successfully publishes paused progress events",
			setup: func() scanning.Progress {
				return progress
			},
			verify: func(t *testing.T, p *mockDomainPublisher, progress scanning.Progress) {
				p.On("PublishDomainEvent",
					mock.AnythingOfType("*context.valueCtx"),
					mock.AnythingOfType("scanning.TaskPausedEvent"),
					mock.MatchedBy(func(opts []events.PublishOption) bool {
						params := events.PublishParams{}
						for _, opt := range opts {
							opt(&params)
						}
						return params.Key == progress.TaskID().String()
					}),
				).Return(nil).Once()
				p.On("PublishDomainEvent",
					mock.AnythingOfType("*context.valueCtx"),
					mock.AnythingOfType("scanning.TaskJobMetricEvent"),
					mock.MatchedBy(func(opts []events.PublishOption) bool {
						params := events.PublishParams{}
						for _, opt := range opts {
							opt(&params)
						}
						return params.Key == progress.JobID().String()
					}),
				).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "handles error when publishing task paused event",
			setup: func() scanning.Progress {
				return progress
			},
			verify: func(t *testing.T, p *mockDomainPublisher, progress scanning.Progress) {
				p.On("PublishDomainEvent",
					mock.AnythingOfType("*context.valueCtx"),
					mock.AnythingOfType("scanning.TaskPausedEvent"),
					mock.Anything,
				).Return(assert.AnError).Once()
			},
			wantErr: true,
		},
		{
			name: "handles error when publishing task job metric event",
			setup: func() scanning.Progress {
				return progress
			},
			verify: func(t *testing.T, p *mockDomainPublisher, progress scanning.Progress) {
				p.On("PublishDomainEvent",
					mock.AnythingOfType("*context.valueCtx"),
					mock.AnythingOfType("scanning.TaskPausedEvent"),
					mock.Anything,
				).Return(nil).Once()
				p.On("PublishDomainEvent",
					mock.AnythingOfType("*context.valueCtx"),
					mock.AnythingOfType("scanning.TaskJobMetricEvent"),
					mock.Anything,
				).Return(assert.AnError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := new(mockDomainPublisher)
			reporter := New("test", publisher, noop.NewTracerProvider().Tracer("test"))
			progress := tt.setup()
			tt.verify(t, publisher, progress)
			err := reporter.ReportPausedProgress(context.Background(), progress)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			publisher.AssertExpectations(t)
		})
	}
}
