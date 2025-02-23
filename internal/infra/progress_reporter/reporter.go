// Package progressreporter provides infrastructure for tracking and reporting progress
// of long-running scan operations through domain events. It implements the scanning.ProgressReporter
// interface to enable asynchronous monitoring of scan tasks across system boundaries.
//
// The package uses OpenTelemetry for tracing and observability, allowing detailed
// tracking of progress reporting operations. It serves as a bridge between the scanning
// domain and the event publishing infrastructure.
package progressreporter

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	scanSvc "github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

var _ scanSvc.ProgressReporter = (*DomainEventProgressReporter)(nil)

// DomainEventProgressReporter publishes domain events for scan progress updates.
// This enables asynchronous progress tracking and monitoring of long-running scan
// operations across system boundaries.
// TODO: Add logging and update tracing.
type DomainEventProgressReporter struct {
	scannerID string

	domainPublisher events.DomainEventPublisher
	tracer          trace.Tracer
}

// New creates a new DomainEventProgressReporter.
func New(scannerID string, domainPublisher events.DomainEventPublisher, tracer trace.Tracer) *DomainEventProgressReporter {
	return &DomainEventProgressReporter{scannerID: scannerID, domainPublisher: domainPublisher, tracer: tracer}
}

// ReportProgress publishes a TaskProgressedEvent containing the current scan progress.
// This allows other components to track scan status and detect stalled operations.
// It returns an error if event publishing fails.
func (r *DomainEventProgressReporter) ReportProgress(ctx context.Context, p scanning.Progress) error {
	ctx, span := r.tracer.Start(
		ctx,
		"progress_reporter.report_progress",
		trace.WithAttributes(
			attribute.String("scanner_id", r.scannerID),
			attribute.String("task_id", p.TaskID().String()),
			attribute.Int("seq_num", int(p.SequenceNum())),
		),
	)
	defer span.End()

	evt := scanning.NewTaskProgressedEvent(p)
	if err := r.domainPublisher.PublishDomainEvent(ctx, evt, events.WithKey(p.TaskID().String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task progressed event")
		return fmt.Errorf("failed to publish task progressed event: %w", err)
	}
	span.SetStatus(codes.Ok, "task progressed event published")
	span.AddEvent("task_progressed_event_published")

	return nil
}

// ReportPausedProgress publishes a TaskPausedEvent and a TaskJobMetricEvent.
// It returns an error if event publishing fails.
func (r *DomainEventProgressReporter) ReportPausedProgress(ctx context.Context, p scanning.Progress) error {
	ctx, span := r.tracer.Start(
		ctx,
		"progress_reporter.report_paused_progress",
		trace.WithAttributes(
			attribute.String("scanner_id", r.scannerID),
			attribute.String("task_id", p.TaskID().String()),
		),
	)
	defer span.End()

	evt := scanning.NewTaskPausedEvent(p.JobID(), p.TaskID(), p, "system")
	if err := r.domainPublisher.PublishDomainEvent(ctx, evt, events.WithKey(p.TaskID().String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task paused event")
		return fmt.Errorf("failed to publish task paused event: %w", err)
	}
	span.AddEvent("task_paused_event_published")

	if err := r.domainPublisher.PublishDomainEvent(
		ctx,
		scanning.NewTaskJobMetricEvent(p.JobID(), p.TaskID(), scanning.TaskStatusPaused),
		events.WithKey(p.JobID().String()),
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task job metric event")
		return fmt.Errorf("failed to publish task job metric task paused event: %w", err)
	}
	span.AddEvent("task_job_metric_event_published")

	span.SetStatus(codes.Ok, "task paused and job metric published")
	span.AddEvent("task_paused_and_job_metric_published")

	return nil
}
