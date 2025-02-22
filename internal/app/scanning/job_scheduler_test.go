package scanning

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
) {
	mockService := new(mockJobTaskSvc)
	mockPublisher := new(mockDomainEventPublisher)
	tracer := noop.NewTracerProvider().Tracer("test")

	scheduler := NewJobScheduler(
		"test-controller",
		mockService,
		mockPublisher,
		logger.Noop(),
		tracer,
	)

	return scheduler, mockService, mockPublisher
}

func TestScheduleJob(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
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
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher)
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful job scheduling with multiple targets",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher) {
				job := scanning.NewJob(jobID)
				service.On("CreateJobFromID", mock.Anything, jobID).Return(job, nil)

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
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher) {
				service.On("CreateJobFromID", mock.Anything, jobID).
					Return(nil, errors.New("job creation failed"))
			},
			wantErr: true,
			errMsg:  "failed to create job",
		},
		{
			name: "event publishing fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher) {
				// Job creation succeeds.
				job := scanning.NewJob(jobID)
				service.On("CreateJobFromID", mock.Anything, jobID).Return(job, nil)

				// But event publishing fails.
				publisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						_, ok := evt.(scanning.JobScheduledEvent)
						return ok
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(errors.New("event publishing failed"))
			},
			wantErr: true,
			errMsg:  "failed to publish job scheduled event",
		},
		{
			name: "successful job scheduling with no targets",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher) {
				job := scanning.NewJob(jobID)
				service.On("CreateJobFromID", mock.Anything, jobID).Return(job, nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler, mockService, mockPublisher := setupJobSchedulerTestSuite()
			tt.setup(mockService, mockPublisher)

			var testTargets []scanning.Target
			if tt.name != "successful job scheduling with no targets" {
				testTargets = targets
			}

			err := scheduler.ScheduleJob(context.Background(), jobID, testTargets)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			mockService.AssertExpectations(t)
			mockPublisher.AssertExpectations(t)
		})
	}
}
