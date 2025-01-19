package progressreporter

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

type DomainEventProgressReporter struct {
	domainPublisher events.DomainEventPublisher

	tracer trace.Tracer
}

func (r *DomainEventProgressReporter) ReportProgress(ctx context.Context, p scanning.Progress) {
	ctx, span := r.tracer.Start(
		ctx,
		"progress_reporter.report_progress",
		trace.WithAttributes(
			attribute.String("task_id", p.TaskID().String()),
			attribute.String("status", string(p.Status())),
			attribute.Int("seq_num", int(p.SequenceNum())),
		),
	)
	defer span.End()

	evt := scanning.NewTaskProgressedEvent(p)
	_ = r.domainPublisher.PublishDomainEvent(ctx, evt)
}
