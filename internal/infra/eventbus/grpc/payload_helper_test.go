package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/protocol"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

func TestSetGatewayToScannerPayload(t *testing.T) {
	tests := []struct {
		name      string
		eventType events.EventType
		payload   any
		wantErr   bool
	}{
		{
			name:      "TaskCreated event",
			eventType: scanning.EventTypeTaskCreated,
			payload:   &pb.TaskCreatedEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "TaskResume event",
			eventType: scanning.EventTypeTaskResume,
			payload:   &pb.TaskResumeEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "TaskPaused event",
			eventType: scanning.EventTypeTaskPaused,
			payload:   &pb.TaskPausedEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "JobPaused event",
			eventType: scanning.EventTypeJobPaused,
			payload:   &pb.JobPausedEvent{JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "JobCancelled event",
			eventType: scanning.EventTypeJobCancelled,
			payload:   &pb.JobCancelledEvent{JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "RulesRequested event",
			eventType: rules.EventTypeRulesRequested,
			payload:   &pb.RuleRequestedEvent{},
			wantErr:   false,
		},
		{
			name:      "SystemNotification event",
			eventType: events.EventType("SystemNotification"),
			payload:   &pb.SystemNotification{Title: "Test", Message: "Test message"},
			wantErr:   false,
		},
		{
			name:      "Unhandled event type",
			eventType: events.EventType("UnknownEvent"),
			payload:   &pb.SystemNotification{},
			wantErr:   true,
		},
		{
			name:      "Invalid payload type",
			eventType: scanning.EventTypeTaskCreated,
			payload:   &pb.JobPausedEvent{}, // Wrong payload type for TaskCreated
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &pb.GatewayToScannerMessage{
				MessageId: "test-message-id",
				Timestamp: time.Now().UnixNano(),
			}

			err := SetGatewayToScannerPayload(msg, tt.eventType, tt.payload)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, msg.Payload, "Payload should be set")
			}
		})
	}
}

func TestSetScannerToGatewayPayload(t *testing.T) {
	tests := []struct {
		name      string
		eventType events.EventType
		payload   any
		wantErr   bool
	}{
		{
			name:      "ScannerRegistered event",
			eventType: scanning.EventTypeScannerRegistered,
			payload:   &pb.ScannerRegisteredEvent{ScannerName: "scanner-1"},
			wantErr:   false,
		},
		{
			name:      "ScannerHeartbeat event",
			eventType: scanning.EventTypeScannerHeartbeat,
			payload:   &pb.ScannerHeartbeatEvent{ScannerName: "scanner-1"},
			wantErr:   false,
		},
		{
			name:      "ScannerStatusChanged event",
			eventType: scanning.EventTypeScannerStatusChanged,
			payload:   &pb.ScannerStatusChangedEvent{ScannerName: "scanner-1"},
			wantErr:   false,
		},
		{
			name:      "ScannerDeregistered event",
			eventType: scanning.EventTypeScannerDeregistered,
			payload:   &pb.ScannerDeregisteredEvent{ScannerName: "scanner-1"},
			wantErr:   false,
		},
		{
			name:      "TaskStarted event",
			eventType: scanning.EventTypeTaskStarted,
			payload:   &pb.TaskStartedEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "TaskProgressed event",
			eventType: scanning.EventTypeTaskProgressed,
			payload:   &pb.TaskProgressedEvent{TaskId: "task-123"},
			wantErr:   false,
		},
		{
			name:      "TaskCompleted event",
			eventType: scanning.EventTypeTaskCompleted,
			payload:   &pb.TaskCompletedEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "TaskFailed event",
			eventType: scanning.EventTypeTaskFailed,
			payload:   &pb.TaskFailedEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "TaskPaused event",
			eventType: scanning.EventTypeTaskPaused,
			payload:   &pb.TaskPausedEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "TaskCancelled event",
			eventType: scanning.EventTypeTaskCancelled,
			payload:   &pb.TaskCancelledEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "TaskHeartbeat event",
			eventType: scanning.EventTypeTaskHeartbeat,
			payload:   &pb.TaskHeartbeatEvent{TaskId: "task-123"},
			wantErr:   false,
		},
		{
			name:      "TaskJobMetric event",
			eventType: scanning.EventTypeTaskJobMetric,
			payload:   &pb.TaskJobMetricEvent{TaskId: "task-123", JobId: "job-123"},
			wantErr:   false,
		},
		{
			name:      "RulesUpdated event",
			eventType: rules.EventTypeRulesUpdated,
			payload:   &pb.RuleMessage{},
			wantErr:   false,
		},
		{
			name:      "RulesPublished event",
			eventType: rules.EventTypeRulesPublished,
			payload:   &pb.RuleMessage{},
			wantErr:   false,
		},
		{
			name:      "MessageAcknowledgment event",
			eventType: events.EventType("MessageAcknowledgment"),
			payload:   &pb.MessageAcknowledgment{OriginalMessageId: "msg-123"},
			wantErr:   false,
		},
		{
			name:      "Unhandled event type",
			eventType: events.EventType("UnknownEvent"),
			payload:   &pb.SystemNotification{},
			wantErr:   true,
		},
		{
			name:      "Invalid payload type",
			eventType: scanning.EventTypeTaskStarted,
			payload:   &pb.ScannerHeartbeatEvent{}, // Wrong payload type for TaskStarted
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &pb.ScannerToGatewayMessage{
				MessageId: "test-message-id",
				Timestamp: time.Now().UnixNano(),
			}

			err := SetScannerToGatewayPayload(msg, tt.eventType, tt.payload)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, msg.Payload, "Payload should be set")
			}
		})
	}
}

func TestMapMessageTypeToEventType(t *testing.T) {
	tests := []struct {
		name        string
		messageType protocol.MessageType
		want        events.EventType
	}{
		{
			name:        "Scanner Heartbeat",
			messageType: protocol.MessageTypeScannerHeartbeat,
			want:        scanning.EventTypeScannerHeartbeat,
		},
		{
			name:        "Scanner Registered",
			messageType: protocol.MessageTypeScannerRegistered,
			want:        scanning.EventTypeScannerRegistered,
		},
		{
			name:        "Scanner Status Changed",
			messageType: protocol.MessageTypeScannerStatusChanged,
			want:        scanning.EventTypeScannerStatusChanged,
		},
		{
			name:        "Scanner Deregistered",
			messageType: protocol.MessageTypeScannerDeregistered,
			want:        scanning.EventTypeScannerDeregistered,
		},
		{
			name:        "Task Started",
			messageType: protocol.MessageTypeScanTaskStarted,
			want:        scanning.EventTypeTaskStarted,
		},
		{
			name:        "Task Progressed",
			messageType: protocol.MessageTypeScanTaskProgressed,
			want:        scanning.EventTypeTaskProgressed,
		},
		{
			name:        "Task Completed",
			messageType: protocol.MessageTypeScanTaskCompleted,
			want:        scanning.EventTypeTaskCompleted,
		},
		{
			name:        "Task Failed",
			messageType: protocol.MessageTypeScanTaskFailed,
			want:        scanning.EventTypeTaskFailed,
		},
		{
			name:        "Task Paused",
			messageType: protocol.MessageTypeScanTaskPaused,
			want:        scanning.EventTypeTaskPaused,
		},
		{
			name:        "Task Cancelled",
			messageType: protocol.MessageTypeScanTaskCancelled,
			want:        scanning.EventTypeTaskCancelled,
		},
		{
			name:        "Task Resume",
			messageType: protocol.MessageTypeScanTaskResume,
			want:        scanning.EventTypeTaskResume,
		},
		{
			name:        "Task Heartbeat",
			messageType: protocol.MessageTypeScanTaskHeartbeat,
			want:        scanning.EventTypeTaskHeartbeat,
		},
		{
			name:        "Task Job Metric",
			messageType: protocol.MessageTypeScanTaskJobMetric,
			want:        scanning.EventTypeTaskJobMetric,
		},
		{
			name:        "Job Paused",
			messageType: protocol.MessageTypeScanJobPaused,
			want:        scanning.EventTypeJobPaused,
		},
		{
			name:        "Job Cancelled",
			messageType: protocol.MessageTypeScanJobCancelled,
			want:        scanning.EventTypeJobCancelled,
		},
		{
			name:        "Rules Requested",
			messageType: protocol.MessageTypeRulesRequested,
			want:        rules.EventTypeRulesRequested,
		},
		{
			name:        "Rules Published",
			messageType: protocol.MessageTypeRulesPublished,
			want:        rules.EventTypeRulesPublished,
		},
		{
			name:        "Rules Updated",
			messageType: protocol.MessageTypeRulesUpdated,
			want:        rules.EventTypeRulesUpdated,
		},
		{
			name:        "System Notification",
			messageType: protocol.MessageTypeSystemNotification,
			want:        events.EventType("SystemNotification"),
		},
		{
			name:        "Unknown Type",
			messageType: protocol.MessageType("unknown_type"),
			want:        events.EventType(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapMessageTypeToEventType(tt.messageType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractScannerMessageInfo(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		setupMessage  func() *pb.ScannerToGatewayMessage
		expectedType  events.EventType
		validateEvent func(t *testing.T, event any)
		expectError   bool
	}{
		{
			name: "scanner heartbeat message",
			setupMessage: func() *pb.ScannerToGatewayMessage {
				return &pb.ScannerToGatewayMessage{
					MessageId:  "msg-1",
					Timestamp:  time.Now().UnixNano(),
					AuthToken:  "test-token",
					ScannerId:  "scanner-123",
					RoutingKey: "scanner.heartbeat",
					Payload: &pb.ScannerToGatewayMessage_Heartbeat{
						Heartbeat: &pb.ScannerHeartbeatEvent{
							ScannerName: "scanner-123",
							Status:      pb.ScannerStatus_SCANNER_STATUS_ONLINE,
							Timestamp:   time.Now().UnixNano(),
							Metrics: map[string]float64{
								"cpu_usage": 42.5,
								"memory":    1024.0,
							},
						},
					},
				}
			},
			expectedType: scanning.EventTypeScannerHeartbeat,
			validateEvent: func(t *testing.T, event any) {
				heartbeat, ok := event.(scanning.ScannerHeartbeatEvent)
				require.True(t, ok, "event should be a ScannerHeartbeatEvent")
				assert.Equal(t, "scanner-123", heartbeat.ScannerName())
				assert.Equal(t, scanning.ScannerStatusOnline, heartbeat.Status())
				assert.Contains(t, heartbeat.Metrics(), "cpu_usage")
				assert.Equal(t, 42.5, heartbeat.Metrics()["cpu_usage"])
			},
			expectError: false,
		},
		{
			name: "task started message",
			setupMessage: func() *pb.ScannerToGatewayMessage {
				taskID := uuid.New()
				jobID := uuid.New()
				return &pb.ScannerToGatewayMessage{
					MessageId:  "task-started-1",
					Timestamp:  time.Now().UnixNano(),
					ScannerId:  "scanner-123",
					RoutingKey: "task.started",
					Payload: &pb.ScannerToGatewayMessage_TaskStarted{
						TaskStarted: &pb.TaskStartedEvent{
							JobId:       jobID.String(),
							TaskId:      taskID.String(),
							ResourceUri: "git://github.com/org/repo.git",
							Timestamp:   time.Now().UnixNano(),
						},
					},
				}
			},
			expectedType: scanning.EventTypeTaskStarted,
			validateEvent: func(t *testing.T, event any) {
				taskStarted, ok := event.(scanning.TaskStartedEvent)
				require.True(t, ok, "event should be a TaskStartedEvent")
				assert.NotEmpty(t, taskStarted.JobID)
				assert.NotEmpty(t, taskStarted.TaskID)
				assert.Equal(t, "git://github.com/org/repo.git", taskStarted.ResourceURI)
			},
			expectError: false,
		},
		{
			name: "task progressed message",
			setupMessage: func() *pb.ScannerToGatewayMessage {
				taskID := uuid.New()
				jobID := uuid.New()
				return &pb.ScannerToGatewayMessage{
					MessageId:  "task-progress-1",
					Timestamp:  time.Now().UnixNano(),
					ScannerId:  "scanner-123",
					RoutingKey: "task.progressed",
					Payload: &pb.ScannerToGatewayMessage_TaskProgressed{
						TaskProgressed: &pb.TaskProgressedEvent{
							TaskId:         taskID.String(),
							JobId:          jobID.String(),
							SequenceNum:    42,
							Timestamp:      time.Now().UnixNano(),
							ItemsProcessed: 100,
							ErrorCount:     2,
							Message:        "Processing commits",
						},
					},
				}
			},
			expectedType: scanning.EventTypeTaskProgressed,
			validateEvent: func(t *testing.T, event any) {
				progress, ok := event.(scanning.TaskProgressedEvent)
				require.True(t, ok, "event should be a TaskProgressedEvent")
				assert.NotEmpty(t, progress.Progress.TaskID)
				assert.NotEmpty(t, progress.Progress.JobID)
				assert.Equal(t, int64(42), progress.Progress.SequenceNum())
				assert.Equal(t, int64(100), progress.Progress.ItemsProcessed())
				assert.Equal(t, int32(2), progress.Progress.ErrorCount())
				assert.Equal(t, "Processing commits", progress.Progress.Message())
			},
			expectError: false,
		},
		{
			name: "task completed message",
			setupMessage: func() *pb.ScannerToGatewayMessage {
				taskID := uuid.New()
				jobID := uuid.New()
				return &pb.ScannerToGatewayMessage{
					MessageId:  "task-completed-1",
					Timestamp:  time.Now().UnixNano(),
					ScannerId:  "scanner-123",
					RoutingKey: "task.completed",
					Payload: &pb.ScannerToGatewayMessage_TaskCompleted{
						TaskCompleted: &pb.TaskCompletedEvent{
							JobId:     jobID.String(),
							TaskId:    taskID.String(),
							Timestamp: time.Now().UnixNano(),
						},
					},
				}
			},
			expectedType: scanning.EventTypeTaskCompleted,
			validateEvent: func(t *testing.T, event any) {
				taskCompleted, ok := event.(scanning.TaskCompletedEvent)
				require.True(t, ok, "event should be a TaskCompletedEvent")
				assert.NotEmpty(t, taskCompleted.JobID)
				assert.NotEmpty(t, taskCompleted.TaskID)
			},
			expectError: false,
		},
		{
			name: "task failed message",
			setupMessage: func() *pb.ScannerToGatewayMessage {
				taskID := uuid.New()
				jobID := uuid.New()
				return &pb.ScannerToGatewayMessage{
					MessageId:  "task-failed-1",
					Timestamp:  time.Now().UnixNano(),
					ScannerId:  "scanner-123",
					RoutingKey: "task.failed",
					Payload: &pb.ScannerToGatewayMessage_TaskFailed{
						TaskFailed: &pb.TaskFailedEvent{
							JobId:     jobID.String(),
							TaskId:    taskID.String(),
							Timestamp: time.Now().UnixNano(),
							Reason:    "Repository not accessible",
						},
					},
				}
			},
			expectedType: scanning.EventTypeTaskFailed,
			validateEvent: func(t *testing.T, event any) {
				taskFailed, ok := event.(scanning.TaskFailedEvent)
				require.True(t, ok, "event should be a TaskFailedEvent")
				assert.NotEmpty(t, taskFailed.JobID)
				assert.NotEmpty(t, taskFailed.TaskID)
				assert.Equal(t, "Repository not accessible", taskFailed.Reason)
			},
			expectError: false,
		},
		{
			name: "acknowledgment message",
			setupMessage: func() *pb.ScannerToGatewayMessage {
				return &pb.ScannerToGatewayMessage{
					MessageId:  "ack-1",
					Timestamp:  time.Now().UnixNano(),
					ScannerId:  "scanner-123",
					RoutingKey: "ack",
					Payload: &pb.ScannerToGatewayMessage_Ack{
						Ack: &pb.MessageAcknowledgment{
							OriginalMessageId: "task-123",
							Success:           true,
							ScannerId:         "scanner-123",
							Metadata: map[string]string{
								"type": "task_ack",
							},
						},
					},
				}
			},
			expectedType: protocol.EventTypeMessageAck,
			validateEvent: func(t *testing.T, event any) {
				// The ack message is passed through directly
				ack, ok := event.(*pb.MessageAcknowledgment)
				require.True(t, ok, "event should be a MessageAcknowledgment")
				assert.Equal(t, "task-123", ack.OriginalMessageId)
				assert.True(t, ack.Success)
				assert.Equal(t, "scanner-123", ack.ScannerId)
				assert.Equal(t, "task_ack", ack.Metadata["type"])
			},
			expectError: false,
		},
		{
			name: "empty message - error case",
			setupMessage: func() *pb.ScannerToGatewayMessage {
				return &pb.ScannerToGatewayMessage{
					MessageId:  "empty-1",
					Timestamp:  time.Now().UnixNano(),
					ScannerId:  "scanner-123",
					RoutingKey: "unknown",
					// No payload set
				}
			},
			expectedType:  "",
			validateEvent: nil,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventType, event, err := ExtractScannerMessageInfo(ctx, tt.setupMessage())

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, eventType)

			if tt.validateEvent != nil {
				tt.validateEvent(t, event)
			}
		})
	}
}

func TestIsRegistrationAck(t *testing.T) {
	tests := []struct {
		name string
		ack  *pb.MessageAcknowledgment
		want bool
	}{
		{
			name: "Registration acknowledgment - contains register",
			ack: &pb.MessageAcknowledgment{
				OriginalMessageId: "register-scanner-123",
			},
			want: true,
		},
		{
			name: "Registration acknowledgment - contains registration",
			ack: &pb.MessageAcknowledgment{
				OriginalMessageId: "scanner-registration-123",
			},
			want: true,
		},
		{
			name: "Regular acknowledgment",
			ack: &pb.MessageAcknowledgment{
				OriginalMessageId: "task-123",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRegistrationAck(tt.ack)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetScannerToGatewayMessageType(t *testing.T) {
	tests := []struct {
		name            string
		message         *pb.ScannerToGatewayMessage
		expectedType    protocol.MessageType
		expectedPayload any
		expectError     bool
	}{
		{
			name: "scanner heartbeat message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_Heartbeat{
					Heartbeat: &pb.ScannerHeartbeatEvent{
						ScannerName: "test-scanner",
					},
				},
			},
			expectedType:    protocol.MessageTypeScannerHeartbeat,
			expectedPayload: &pb.ScannerHeartbeatEvent{ScannerName: "test-scanner"},
			expectError:     false,
		},
		{
			name: "scanner registration message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_Registration{
					Registration: &pb.ScannerRegistrationRequest{
						ScannerName: "test-scanner",
						Version:     "1.0.0",
					},
				},
			},
			expectedType:    protocol.MessageTypeScannerRegistered,
			expectedPayload: &pb.ScannerRegistrationRequest{ScannerName: "test-scanner", Version: "1.0.0"},
			expectError:     false,
		},
		{
			name: "scanner status changed message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_StatusChanged{
					StatusChanged: &pb.ScannerStatusChangedEvent{
						ScannerName: "test-scanner",
						NewStatus:   pb.ScannerStatus_SCANNER_STATUS_ONLINE,
					},
				},
			},
			expectedType:    protocol.MessageTypeScannerStatusChanged,
			expectedPayload: &pb.ScannerStatusChangedEvent{ScannerName: "test-scanner", NewStatus: pb.ScannerStatus_SCANNER_STATUS_ONLINE},
			expectError:     false,
		},
		{
			name: "scanner deregistered message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_Deregistered{
					Deregistered: &pb.ScannerDeregisteredEvent{
						ScannerName: "test-scanner",
					},
				},
			},
			expectedType:    protocol.MessageTypeScannerDeregistered,
			expectedPayload: &pb.ScannerDeregisteredEvent{ScannerName: "test-scanner"},
			expectError:     false,
		},
		{
			name: "task started message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskStarted{
					TaskStarted: &pb.TaskStartedEvent{
						TaskId: "task-123",
						JobId:  "job-456",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskStarted,
			expectedPayload: &pb.TaskStartedEvent{TaskId: "task-123", JobId: "job-456"},
			expectError:     false,
		},
		{
			name: "task progressed message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskProgressed{
					TaskProgressed: &pb.TaskProgressedEvent{
						TaskId: "task-123",
						JobId:  "job-456",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskProgressed,
			expectedPayload: &pb.TaskProgressedEvent{TaskId: "task-123", JobId: "job-456"},
			expectError:     false,
		},
		{
			name: "task completed message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskCompleted{
					TaskCompleted: &pb.TaskCompletedEvent{
						TaskId: "task-123",
						JobId:  "job-456",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskCompleted,
			expectedPayload: &pb.TaskCompletedEvent{TaskId: "task-123", JobId: "job-456"},
			expectError:     false,
		},
		{
			name: "task failed message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskFailed{
					TaskFailed: &pb.TaskFailedEvent{
						TaskId: "task-123",
						JobId:  "job-456",
						Reason: "Something went wrong",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskFailed,
			expectedPayload: &pb.TaskFailedEvent{TaskId: "task-123", JobId: "job-456", Reason: "Something went wrong"},
			expectError:     false,
		},
		{
			name: "task paused message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskPaused{
					TaskPaused: &pb.TaskPausedEvent{
						TaskId: "task-123",
						JobId:  "job-456",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskPaused,
			expectedPayload: &pb.TaskPausedEvent{TaskId: "task-123", JobId: "job-456"},
			expectError:     false,
		},
		{
			name: "task cancelled message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskCancelled{
					TaskCancelled: &pb.TaskCancelledEvent{
						TaskId: "task-123",
						JobId:  "job-456",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskCancelled,
			expectedPayload: &pb.TaskCancelledEvent{TaskId: "task-123", JobId: "job-456"},
			expectError:     false,
		},
		{
			name: "task job metric message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskJobMetric{
					TaskJobMetric: &pb.TaskJobMetricEvent{
						TaskId: "task-123",
						JobId:  "job-456",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskJobMetric,
			expectedPayload: &pb.TaskJobMetricEvent{TaskId: "task-123", JobId: "job-456"},
			expectError:     false,
		},
		{
			name: "task heartbeat message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_TaskHeartbeat{
					TaskHeartbeat: &pb.TaskHeartbeatEvent{
						TaskId: "task-123",
					},
				},
			},
			expectedType:    protocol.MessageTypeScanTaskHeartbeat,
			expectedPayload: &pb.TaskHeartbeatEvent{TaskId: "task-123"},
			expectError:     false,
		},
		{
			name: "acknowledgment message",
			message: &pb.ScannerToGatewayMessage{
				Payload: &pb.ScannerToGatewayMessage_Ack{
					Ack: &pb.MessageAcknowledgment{
						OriginalMessageId: "msg-123",
						Success:           true,
					},
				},
			},
			expectedType:    protocol.MessageTypeAck,
			expectedPayload: &pb.MessageAcknowledgment{OriginalMessageId: "msg-123", Success: true},
			expectError:     false,
		},
		{
			name:            "empty message",
			message:         &pb.ScannerToGatewayMessage{},
			expectedType:    "",
			expectedPayload: nil,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageType, payload, err := getScannerToGatewayMessageType(tt.message)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedType, messageType)

				// lol...
				switch expectedPayload := tt.expectedPayload.(type) {
				case *pb.ScannerHeartbeatEvent:
					actualPayload, ok := payload.(*pb.ScannerHeartbeatEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.ScannerName, actualPayload.ScannerName)
				case *pb.ScannerRegistrationRequest:
					actualPayload, ok := payload.(*pb.ScannerRegistrationRequest)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.ScannerName, actualPayload.ScannerName)
					assert.Equal(t, expectedPayload.Version, actualPayload.Version)
				case *pb.ScannerStatusChangedEvent:
					actualPayload, ok := payload.(*pb.ScannerStatusChangedEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.ScannerName, actualPayload.ScannerName)
					assert.Equal(t, expectedPayload.NewStatus, actualPayload.NewStatus)
				case *pb.ScannerDeregisteredEvent:
					actualPayload, ok := payload.(*pb.ScannerDeregisteredEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.ScannerName, actualPayload.ScannerName)
				case *pb.TaskStartedEvent:
					actualPayload, ok := payload.(*pb.TaskStartedEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
					assert.Equal(t, expectedPayload.JobId, actualPayload.JobId)
				case *pb.TaskProgressedEvent:
					actualPayload, ok := payload.(*pb.TaskProgressedEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
					assert.Equal(t, expectedPayload.JobId, actualPayload.JobId)
				case *pb.TaskCompletedEvent:
					actualPayload, ok := payload.(*pb.TaskCompletedEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
					assert.Equal(t, expectedPayload.JobId, actualPayload.JobId)
				case *pb.TaskFailedEvent:
					actualPayload, ok := payload.(*pb.TaskFailedEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
					assert.Equal(t, expectedPayload.JobId, actualPayload.JobId)
					assert.Equal(t, expectedPayload.Reason, actualPayload.Reason)
				case *pb.TaskPausedEvent:
					actualPayload, ok := payload.(*pb.TaskPausedEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
					assert.Equal(t, expectedPayload.JobId, actualPayload.JobId)
				case *pb.TaskCancelledEvent:
					actualPayload, ok := payload.(*pb.TaskCancelledEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
					assert.Equal(t, expectedPayload.JobId, actualPayload.JobId)
				case *pb.TaskJobMetricEvent:
					actualPayload, ok := payload.(*pb.TaskJobMetricEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
					assert.Equal(t, expectedPayload.JobId, actualPayload.JobId)
				case *pb.TaskHeartbeatEvent:
					actualPayload, ok := payload.(*pb.TaskHeartbeatEvent)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.TaskId, actualPayload.TaskId)
				case *pb.MessageAcknowledgment:
					actualPayload, ok := payload.(*pb.MessageAcknowledgment)
					require.True(t, ok)
					assert.Equal(t, expectedPayload.OriginalMessageId, actualPayload.OriginalMessageId)
					assert.Equal(t, expectedPayload.Success, actualPayload.Success)
				default:
					t.Fatalf("Unexpected payload type: %T", expectedPayload)
				}
			}
		})
	}
}

func TestExtractGatewayMessageInfo(t *testing.T) {
	tests := []struct {
		name          string
		msg           *pb.GatewayToScannerMessage
		wantEventType events.EventType
		wantErr       bool
	}{
		{
			name: "Registration acknowledgment",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_Ack{
					Ack: &pb.MessageAcknowledgment{
						OriginalMessageId: "register-scanner-123",
						ScannerId:         "scanner-1",
					},
				},
			},
			wantEventType: protocol.EventTypeScannerRegistrationAck,
			wantErr:       false,
		},
		{
			name: "Regular acknowledgment",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_Ack{
					Ack: &pb.MessageAcknowledgment{
						OriginalMessageId: "task-123",
					},
				},
			},
			wantEventType: protocol.EventTypeMessageAck,
			wantErr:       false,
		},
		{
			name: "Task created message",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_TaskCreated{
					TaskCreated: &pb.TaskCreatedEvent{
						TaskId: "task-123",
						JobId:  "job-123",
					},
				},
			},
			wantEventType: scanning.EventTypeTaskCreated,
			wantErr:       false,
		},
		{
			name: "Task resume message",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_TaskResume{
					TaskResume: &pb.TaskResumeEvent{
						TaskId: "task-123",
						JobId:  "job-123",
					},
				},
			},
			wantEventType: scanning.EventTypeTaskResume,
			wantErr:       false,
		},
		{
			name: "Task paused message",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_TaskPaused{
					TaskPaused: &pb.TaskPausedEvent{
						TaskId: "task-123",
						JobId:  "job-123",
					},
				},
			},
			wantEventType: scanning.EventTypeTaskPaused,
			wantErr:       false,
		},
		{
			name: "Job paused message",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_JobPaused{
					JobPaused: &pb.JobPausedEvent{
						JobId: "job-123",
					},
				},
			},
			wantEventType: scanning.EventTypeJobPaused,
			wantErr:       false,
		},
		{
			name: "Job cancelled message",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_JobCancelled{
					JobCancelled: &pb.JobCancelledEvent{
						JobId: "job-123",
					},
				},
			},
			wantEventType: scanning.EventTypeJobCancelled,
			wantErr:       false,
		},
		{
			name: "Rule requested message",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_RuleRequested{
					RuleRequested: &pb.RuleRequestedEvent{},
				},
			},
			wantEventType: rules.EventTypeRulesRequested,
			wantErr:       false,
		},
		{
			name: "System notification message",
			msg: &pb.GatewayToScannerMessage{
				MessageId: "msg-123",
				Payload: &pb.GatewayToScannerMessage_Notification{
					Notification: &pb.SystemNotification{
						Title:   "Test",
						Message: "Test message",
					},
				},
			},
			wantEventType: events.EventType("system_notification"),
			wantErr:       false,
		},
		{
			name:          "Empty message",
			msg:           &pb.GatewayToScannerMessage{},
			wantEventType: "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventType, payload, err := extractGatewayMessageInfo(context.Background(), tt.msg)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantEventType, eventType)
			assert.NotNil(t, payload)
		})
	}
}
