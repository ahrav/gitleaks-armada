package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
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
		targets []scanning.Target
		wantErr bool
	}{
		{
			name: "successful job scheduling with multiple targets",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("CreateJob", mock.Anything, mock.MatchedBy(func(cmd scanning.CreateJobCommand) bool {
					return cmd.JobID == jobID
				})).Return(nil)

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
			targets: targets,
			wantErr: false,
		},
		{
			name: "job creation fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("CreateJob", mock.Anything, mock.MatchedBy(func(cmd scanning.CreateJobCommand) bool {
					return cmd.JobID == jobID
				})).Return(errors.New("any error"))
			},
			targets: targets,
			wantErr: true,
		},
		{
			name: "event publishing fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("CreateJob", mock.Anything, mock.MatchedBy(func(cmd scanning.CreateJobCommand) bool {
					return cmd.JobID == jobID
				})).Return(nil)
				publisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						_, ok := evt.(scanning.JobScheduledEvent)
						return ok
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(errors.New("any error"))
			},
			targets: targets,
			wantErr: true,
		},
		{
			name: "job scheduling with no targets should fail",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				// No setup needed as we expect early return with error.
			},
			targets: nil, // No targets provided.
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler, mockService, mockPublisher, mockBroadcastPublisher := setupJobSchedulerTestSuite()
			tt.setup(mockService, mockPublisher, mockBroadcastPublisher)

			err := scheduler.Schedule(context.Background(), jobID, tt.targets)
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

func TestCancelJob(t *testing.T) {
	jobID := uuid.New()
	requestedBy := "test-user"

	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher, *mockDomainEventPublisher)
		wantErr bool
	}{
		{
			name: "successful job cancellation",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("UpdateJobStatus", mock.Anything, jobID, scanning.JobStatusCancelling).Return(nil)
				broadcastPublisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						cancelledEvt, ok := evt.(scanning.JobCancelledEvent)
						if !ok {
							return false
						}
						return cancelledEvt.JobID == jobID.String() && cancelledEvt.RequestedBy == requestedBy
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "job status update fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("UpdateJobStatus", mock.Anything, jobID, scanning.JobStatusCancelling).
					Return(errors.New("failed to update job status"))
			},
			wantErr: true,
		},
		{
			name: "event publishing fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("UpdateJobStatus", mock.Anything, jobID, scanning.JobStatusCancelling).Return(nil)
				broadcastPublisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						_, ok := evt.(scanning.JobCancelledEvent)
						return ok
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(errors.New("failed to publish event"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler, mockService, mockPublisher, mockBroadcastPublisher := setupJobSchedulerTestSuite()
			tt.setup(mockService, mockPublisher, mockBroadcastPublisher)

			err := scheduler.Cancel(context.Background(), jobID, requestedBy)

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

func TestResumeJob(t *testing.T) {
	jobID := uuid.New()
	requestedBy := "test-user"

	task1ID := uuid.New()
	task2ID := uuid.New()

	checkpoint1 := scanning.NewCheckpoint(task1ID, []byte("resume-token-1"), map[string]string{"position": "HEAD"})
	checkpoint2 := scanning.NewCheckpoint(task2ID, []byte("resume-token-2"), map[string]string{"position": "main"})

	mockTasks := []scanning.ResumeTaskInfo{
		scanning.NewResumeTaskInfo(task1ID, jobID, shared.SourceTypeGitHub, "https://github.com/org/repo1", 1, checkpoint1),
		scanning.NewResumeTaskInfo(task2ID, jobID, shared.SourceTypeGitHub, "https://github.com/org/repo2", 2, checkpoint2),
	}

	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher, *mockDomainEventPublisher)
		wantErr bool
	}{
		{
			name: "successful job resume with multiple tasks",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				mockConfigInfo := scanning.NewJobConfigInfo(jobID, shared.SourceTypeGitHub.String(), json.RawMessage(`{"authType":"token","token":"test-token"}`))
				service.On("GetJobConfigInfo", mock.Anything, jobID).Return(mockConfigInfo, nil)

				service.On("GetTasksToResume", mock.Anything, jobID).Return(mockTasks, nil)

				for _, task := range mockTasks {
					publisher.On("PublishDomainEvent",
						mock.Anything,
						mock.MatchedBy(func(evt events.DomainEvent) bool {
							resumeEvt, ok := evt.(*scanning.TaskResumeEvent)
							return ok &&
								resumeEvt.JobID.String() == jobID.String() &&
								resumeEvt.TaskID.String() == task.TaskID().String() &&
								resumeEvt.SourceType == task.SourceType() &&
								resumeEvt.ResourceURI == task.ResourceURI() &&
								resumeEvt.SequenceNum == int(task.SequenceNum())
						}),
						mock.AnythingOfType("[]events.PublishOption"),
					).Return(nil).Once()
				}
			},
			wantErr: false,
		},
		{
			name: "getting job config info fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				service.On("GetJobConfigInfo", mock.Anything, jobID).
					Return(nil, errors.New("failed to get job config info"))

				// Must mock GetTasksToResume as well due to concurrent execution, even though it's not used.
				service.On("GetTasksToResume", mock.Anything, jobID).
					Return(mockTasks, nil)
			},
			wantErr: true,
		},
		{
			name: "getting tasks to resume fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				mockConfigInfo := scanning.NewJobConfigInfo(jobID, shared.SourceTypeGitHub.String(), json.RawMessage(`{"authType":"token","token":"test-token"}`))
				service.On("GetJobConfigInfo", mock.Anything, jobID).Return(mockConfigInfo, nil)

				service.On("GetTasksToResume", mock.Anything, jobID).
					Return([]scanning.ResumeTaskInfo{}, errors.New("failed to get tasks to resume"))
			},
			wantErr: true,
		},
		{
			name: "publishing task resume event fails",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				mockConfigInfo := scanning.NewJobConfigInfo(jobID, shared.SourceTypeGitHub.String(), json.RawMessage(`{"authType":"token","token":"test-token"}`))
				service.On("GetJobConfigInfo", mock.Anything, jobID).Return(mockConfigInfo, nil)

				service.On("GetTasksToResume", mock.Anything, jobID).Return(mockTasks, nil)

				// First event publish succeeds.
				publisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						resumeEvt, ok := evt.(*scanning.TaskResumeEvent)
						return ok && resumeEvt.TaskID.String() == mockTasks[0].TaskID().String()
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(nil).Once()

				// Second event publish fails.
				publisher.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(evt events.DomainEvent) bool {
						resumeEvt, ok := evt.(*scanning.TaskResumeEvent)
						return ok && resumeEvt.TaskID.String() == mockTasks[1].TaskID().String()
					}),
					mock.AnythingOfType("[]events.PublishOption"),
				).Return(errors.New("failed to publish event")).Once()
			},
			wantErr: false, // Not returning error because the method continues on event publish failure.
		},
		{
			name: "successful job resume with no tasks",
			setup: func(service *mockJobTaskSvc, publisher *mockDomainEventPublisher, broadcastPublisher *mockDomainEventPublisher) {
				mockConfigInfo := scanning.NewJobConfigInfo(jobID, shared.SourceTypeGitHub.String(), json.RawMessage(`{"authType":"token","token":"test-token"}`))
				service.On("GetJobConfigInfo", mock.Anything, jobID).Return(mockConfigInfo, nil)

				service.On("GetTasksToResume", mock.Anything, jobID).Return([]scanning.ResumeTaskInfo{}, nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler, mockService, mockPublisher, mockBroadcastPublisher := setupJobSchedulerTestSuite()
			tt.setup(mockService, mockPublisher, mockBroadcastPublisher)

			err := scheduler.Resume(context.Background(), jobID, requestedBy)
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
