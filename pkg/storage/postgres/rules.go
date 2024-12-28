package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// Compile-time check that RulesStorage implements storage.RulesStorage.
var _ storage.RulesStorage = (*RulesStorage)(nil)

// RulesStorage provides persistent storage for Gitleaks rules and allowlists in PostgreSQL.
// It handles atomic updates of rule sets and their associated allowlist components to maintain
// data consistency.
type RulesStorage struct {
	q      *db.Queries
	conn   *pgxpool.Pool
	tracer trace.Tracer
}

// NewRulesStorage creates a new PostgreSQL-backed rules storage using the provided database connection.
func NewRulesStorage(conn *pgxpool.Pool, tracer trace.Tracer) *RulesStorage {
	return &RulesStorage{
		q:      db.New(conn),
		conn:   conn,
		tracer: tracer,
	}
}

// SaveRuleset persists a complete Gitleaks ruleset and its allowlists to PostgreSQL.
// It executes all operations within a transaction to ensure atomic updates.
func (s *RulesStorage) SaveRuleset(ctx context.Context, ruleset messaging.GitleaksRuleSet) error {
	ctx, span := s.tracer.Start(ctx, "postgres.save_ruleset",
		trace.WithAttributes(
			attribute.Int("rule_count", len(ruleset.Rules)),
		))
	defer span.End()

	// Set a context timeout to prevent transaction deadlocks and resource exhaustion.
	// We use a serializable isolation level and a relatively short timeout since
	// rule updates should be quick and we want to fail fast if there are issues.
	const txTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, txTimeout)
	defer cancel()

	return pgx.BeginTxFunc(ctx, s.conn, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)

		for _, rule := range ruleset.Rules {
			ruleCtx, ruleSpan := s.tracer.Start(ctx, "postgres.upsert_rule",
				trace.WithAttributes(
					attribute.String("rule_id", rule.RuleID),
					attribute.Int("allowlist_count", len(rule.Allowlists)),
				))

			ruleID, err := qtx.UpsertRule(ruleCtx, db.UpsertRuleParams{
				RuleID:      rule.RuleID,
				Description: pgtype.Text{String: rule.Description, Valid: true},
				Entropy:     pgtype.Float8{Float64: rule.Entropy, Valid: rule.Entropy > 0},
				SecretGroup: pgtype.Int4{Int32: int32(rule.SecretGroup), Valid: rule.SecretGroup > 0},
				Regex:       rule.Regex,
				Path:        pgtype.Text{String: rule.Path, Valid: rule.Path != ""},
				Tags:        rule.Tags,
				Keywords:    rule.Keywords,
			})
			if err != nil {
				ruleSpan.RecordError(err)
				ruleSpan.End()
				return fmt.Errorf("failed to upsert rule: %w", err)
			}
			ruleSpan.End()

			for _, al := range rule.Allowlists {
				alCtx, alSpan := s.tracer.Start(ctx, "postgres.create_allowlist",
					trace.WithAttributes(
						attribute.String("rule_id", rule.RuleID),
						attribute.Int("commit_count", len(al.Commits)),
						attribute.Int("path_count", len(al.PathRegexes)),
						attribute.Int("regex_count", len(al.Regexes)),
						attribute.Int("stopword_count", len(al.StopWords)),
					))

				allowlistID, err := qtx.CreateAllowlist(alCtx, db.CreateAllowlistParams{
					RuleID:         ruleID,
					Description:    pgtype.Text{String: al.Description, Valid: true},
					MatchCondition: string(al.MatchCondition),
					RegexTarget:    pgtype.Text{String: al.RegexTarget, Valid: al.RegexTarget != ""},
				})
				if err != nil {
					alSpan.RecordError(err)
					alSpan.End()
					return fmt.Errorf("failed to create allowlist: %w", err)
				}
				alSpan.End()

				if err := s.bulkInsertAllowlistComponents(ctx, qtx, allowlistID, al); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// bulkInsertAllowlistComponents handles the insertion of all allowlist components
// (commits, paths, regexes, stopwords) for a given allowlist ID.
func (s *RulesStorage) bulkInsertAllowlistComponents(
	ctx context.Context,
	qtx *db.Queries,
	allowlistID int64,
	al messaging.GitleaksAllowlist,
) error {
	ctx, span := s.tracer.Start(ctx, "postgres.bulk_insert_components",
		trace.WithAttributes(
			attribute.Int64("allowlist_id", allowlistID),
		))
	defer span.End()

	if err := s.bulkInsertCommits(ctx, qtx, allowlistID, al.Commits); err != nil {
		span.RecordError(err)
		return err
	}

	if err := s.bulkInsertPaths(ctx, qtx, allowlistID, al.PathRegexes); err != nil {
		span.RecordError(err)
		return err
	}

	if err := s.bulkInsertRegexes(ctx, qtx, allowlistID, al.Regexes); err != nil {
		span.RecordError(err)
		return err
	}

	if err := s.bulkInsertStopwords(ctx, qtx, allowlistID, al.StopWords); err != nil {
		span.RecordError(err)
		return err
	}

	return nil
}

// bulkInsertCommits efficiently inserts multiple commit allowlist entries in a single operation.
// It validates that all expected rows were inserted.
func (s *RulesStorage) bulkInsertCommits(
	ctx context.Context,
	qtx *db.Queries,
	allowlistID int64,
	commits []string,
) error {
	if len(commits) == 0 {
		return nil
	}

	ctx, span := s.tracer.Start(ctx, "postgres.bulk_insert_commits",
		trace.WithAttributes(
			attribute.Int64("allowlist_id", allowlistID),
			attribute.Int("commit_count", len(commits)),
		))
	defer span.End()

	commitParams := make([]db.BulkInsertAllowlistCommitsParams, len(commits))
	for i, commit := range commits {
		commitParams[i] = db.BulkInsertAllowlistCommitsParams{
			AllowlistID: allowlistID,
			Commit:      commit,
		}
	}

	rows, err := qtx.BulkInsertAllowlistCommits(ctx, commitParams)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to bulk insert commits: %w", err)
	}
	if rows != int64(len(commits)) {
		err := fmt.Errorf("expected to insert %d commits, but inserted %d", len(commits), rows)
		span.RecordError(err)
		return err
	}
	return nil
}

// bulkInsertPaths efficiently inserts multiple path allowlist entries in a single operation.
// It validates that all expected rows were inserted.
func (s *RulesStorage) bulkInsertPaths(
	ctx context.Context,
	qtx *db.Queries,
	allowlistID int64,
	paths []string,
) error {
	if len(paths) == 0 {
		return nil
	}

	ctx, span := s.tracer.Start(ctx, "postgres.bulk_insert_paths",
		trace.WithAttributes(
			attribute.Int64("allowlist_id", allowlistID),
			attribute.Int("path_count", len(paths)),
		))
	defer span.End()

	pathParams := make([]db.BulkInsertAllowlistPathsParams, len(paths))
	for i, path := range paths {
		pathParams[i] = db.BulkInsertAllowlistPathsParams{
			AllowlistID: allowlistID,
			Path:        path,
		}
	}

	rows, err := qtx.BulkInsertAllowlistPaths(ctx, pathParams)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to bulk insert paths: %w", err)
	}
	if rows != int64(len(paths)) {
		err := fmt.Errorf("expected to insert %d paths, but inserted %d", len(paths), rows)
		span.RecordError(err)
		return err
	}
	return nil
}

// bulkInsertRegexes efficiently inserts multiple regex allowlist entries in a single operation.
// It validates that all expected rows were inserted.
func (s *RulesStorage) bulkInsertRegexes(
	ctx context.Context,
	qtx *db.Queries,
	allowlistID int64,
	regexes []string,
) error {
	if len(regexes) == 0 {
		return nil
	}

	ctx, span := s.tracer.Start(ctx, "postgres.bulk_insert_regexes",
		trace.WithAttributes(
			attribute.Int64("allowlist_id", allowlistID),
			attribute.Int("regex_count", len(regexes)),
		))
	defer span.End()

	regexParams := make([]db.BulkInsertAllowlistRegexesParams, len(regexes))
	for i, regex := range regexes {
		regexParams[i] = db.BulkInsertAllowlistRegexesParams{
			AllowlistID: allowlistID,
			Regex:       regex,
		}
	}

	rows, err := qtx.BulkInsertAllowlistRegexes(ctx, regexParams)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to bulk insert regexes: %w", err)
	}
	if rows != int64(len(regexes)) {
		err := fmt.Errorf("expected to insert %d regexes, but inserted %d", len(regexes), rows)
		span.RecordError(err)
		return err
	}
	return nil
}

// bulkInsertStopwords efficiently inserts multiple stopword allowlist entries in a single operation.
// It validates that all expected rows were inserted.
func (s *RulesStorage) bulkInsertStopwords(
	ctx context.Context,
	qtx *db.Queries,
	allowlistID int64,
	stopwords []string,
) error {
	if len(stopwords) == 0 {
		return nil
	}

	ctx, span := s.tracer.Start(ctx, "postgres.bulk_insert_stopwords",
		trace.WithAttributes(
			attribute.Int64("allowlist_id", allowlistID),
			attribute.Int("stopword_count", len(stopwords)),
		))
	defer span.End()

	stopwordParams := make([]db.BulkInsertAllowlistStopwordsParams, len(stopwords))
	for i, stopword := range stopwords {
		stopwordParams[i] = db.BulkInsertAllowlistStopwordsParams{
			AllowlistID: allowlistID,
			Stopword:    stopword,
		}
	}

	rows, err := qtx.BulkInsertAllowlistStopwords(ctx, stopwordParams)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to bulk insert stopwords: %w", err)
	}
	if rows != int64(len(stopwords)) {
		err := fmt.Errorf("expected to insert %d stopwords, but inserted %d", len(stopwords), rows)
		span.RecordError(err)
		return err
	}
	return nil
}
