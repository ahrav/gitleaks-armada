package scanning

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

func setupJobSchedulerTestSuite() (
	*jobScheduler,
	*mockJobTaskSvc,
	*mockDomainEventPublisher,
	*mockDomainEventPublisher,
) {
	mockService := new(mockJobTaskSvc)
	mockPublisher := new(mockDomainEventPublisher)
	mockBroadcastPublisher := new(mockDomainEventPublisher)
	tracer := noop.NewTracerProvider().Tracer("test")

	scheduler := NewJobScheduler(
		"test-controller",
		mockService,
		mockPublisher,
		mockBroadcastPublisher,
		logger.Noop(),
		tracer,
	)

	return scheduler, mockService, mockPublisher, mockBroadcastPublisher
}

func TestScheduleJob(t *testing.T) {
	jobID := uuid.New()
	targets := []scanning.Target{
		scanning.NewTarget(
			"test-target-1",
			shared.SourceTypeGitHub,
			&scanning.Auth{},
			map[string]string{},
			scanning.TargetConfig{},
		),
		scanning.NewTarget(
			"test-target-2",
			shared.SourceTypeURL,
			&scanning.Auth{},
			map[string]string{},
			scanning.TargetConfig{},
		),
	}

	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher, *mockDomainEventPublisher)
		wantErr bool
	}{
		{
			name: "successful job scheduling with multiple targets",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("CreateJobFromID", mock.Anything, jobID).Return(nil)

				for _, target := range targets {
					publisher.On("PublishDomainEvent",
						mock.Anything,
						mock.MatchedBy(func(evt events.DomainEvent) bool {
							scheduledEvt, ok := evt.(scanning.JobScheduledEvent)
							if !ok {
								return false
							}
							return scheduledEvt.JobID == jobID &&
								scheduledEvt.Target.Name() == target.Name() &&
								scheduledEvt.Target.SourceType() == target.SourceType()
						}),
						mock.AnythingOfType("[]events.PublishOption"),
					).Return(nil).Once()
				}
			},
			wantErr: false,
		},
		{
			name: "job creation fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("CreateJobFromID", mock.Anything, jobID).
					Return(errors.New("any error"))
			},
			wantErr: true,
		},
		{
			name: "event publishing fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("CreateJobFromID", mock.Anything, jobID).Return(nil)
				publisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						_, ok := evt.(scanning.JobScheduledEvent)
						return ok
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(errors.New("any error"))
			},
			wantErr: true,
		},
		{
			name: "successful job scheduling with no targets",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("CreateJobFromID", mock.Anything, jobID).Return(nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler, mockService, mockPublisher, mockBroadcastPublisher := setupJobSchedulerTestSuite()
			tt.setup(mockService, mockPublisher, mockBroadcastPublisher)

			var testTargets []scanning.Target
			if tt.name != "successful job scheduling with no targets" {
				testTargets = targets
			}

			err := scheduler.Schedule(context.Background(), jobID, testTargets)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			mockService.AssertExpectations(t)
			mockPublisher.AssertExpectations(t)
			mockBroadcastPublisher.AssertExpectations(t)
		})
	}
}

func TestPauseJob(t *testing.T) {
	jobID := uuid.New()
	requestedBy := "test-user"

	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher, *mockDomainEventPublisher)
		wantErr bool
	}{
		{
			name: "successful job pause",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("UpdateJobStatus", mock.Anything, jobID, scanning.JobStatusPausing).Return(nil)

				broadcastPublisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						pausedEvt, ok := evt.(scanning.JobPausedEvent)
						if !ok {
							return false
						}
						return pausedEvt.JobID == jobID.String() &&
							pausedEvt.RequestedBy == requestedBy
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "status update fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("UpdateJobStatus", mock.Anything, jobID, scanning.JobStatusPausing).
					Return(errors.New("any error"))
			},
			wantErr: true,
		},
		{
			name: "event publishing fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("UpdateJobStatus", mock.Anything, jobID, scanning.JobStatusPausing).Return(nil)
				broadcastPublisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						_, ok := evt.(scanning.JobPausedEvent)
						return ok
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(errors.New("any error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler, mockService, mockPublisher, mockBroadcastPublisher := setupJobSchedulerTestSuite()
			tt.setup(mockService, mockPublisher, mockBroadcastPublisher)

			err := scheduler.Pause(context.Background(), jobID, requestedBy)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			mockService.AssertExpectations(t)
			mockPublisher.AssertExpectations(t)
			mockBroadcastPublisher.AssertExpectations(t)
		})
	}
}
