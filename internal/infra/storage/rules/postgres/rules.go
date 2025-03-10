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
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

// RulesMetrics defines the interface for tracking metrics related to rule operations.
type RulesMetrics interface {
	// IncRulesSaved increments the counter for successfully saved rules
	IncRulesSaved(ctx context.Context)

	// IncRuleSaveErrors increments the counter for rule save failures.
	IncRuleSaveErrors(ctx context.Context)
}

// Compile-time check that RulesStorage implements rules.RulesStorage.
var _ rules.Repository = (*ruleStore)(nil)

// ruleStore provides persistent storage for Gitleaks rules and allowlists in PostgreSQL.
// It handles atomic updates of rule sets and their associated allowlist components to maintain
// data consistency.
type ruleStore struct {
	q       *db.Queries
	conn    *pgxpool.Pool
	tracer  trace.Tracer
	metrics RulesMetrics
}

// NewStore creates a new PostgreSQL-backed rules storage.
// It initializes the underlying database queries and tracing components
// needed for rule persistence and monitoring.
func NewStore(conn *pgxpool.Pool, tracer trace.Tracer, metrics RulesMetrics) *ruleStore {
	return &ruleStore{
		q:       db.New(conn),
		conn:    conn,
		tracer:  tracer,
		metrics: metrics,
	}
}

// bulkInsertParams constrains the generic type parameter to valid bulk insert parameter types.
// This enables code reuse across different allowlist component inserts while maintaining type safety.
type bulkInsertParams interface {
	db.BulkInsertAllowlistCommitsParams |
		db.BulkInsertAllowlistPathsParams |
		db.BulkInsertAllowlistRegexesParams |
		db.BulkInsertAllowlistStopwordsParams
}

// bulkInsertOperation represents a database operation that can bulk insert records of type T.
type bulkInsertOperation[T bulkInsertParams] func(context.Context, []T) (int64, error)

// bulkInsert provides a generic implementation for bulk inserting allowlist components.
// It handles common tasks like parameter preparation, execution tracing, and result validation
// to avoid code duplication across different component types.
func bulkInsert[T bulkInsertParams](
	ctx context.Context,
	tracer trace.Tracer,
	spanName string,
	allowlistID int64,
	items []string,
	itemType string,
	newParams func(allowlistID int64, item string) T,
	operation bulkInsertOperation[T],
) error {
	if len(items) == 0 {
		return nil
	}

	return storage.ExecuteAndTrace(ctx, tracer, spanName, []attribute.KeyValue{
		attribute.Int64("allowlist_id", allowlistID),
		attribute.Int(fmt.Sprintf("%s_count", itemType), len(items)),
	}, func(ctx context.Context) error {
		params := make([]T, len(items))
		for i, item := range items {
			params[i] = newParams(allowlistID, item)
		}

		rows, err := operation(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to bulk insert %s: %w", itemType, err)
		}
		if rows != int64(len(items)) {
			return fmt.Errorf("expected to insert %d %s, but inserted %d", len(items), itemType, rows)
		}
		return nil
	})
}

// SaveRule persists a single rule and its allowlists to PostgreSQL.
// It ensures atomic updates by executing all operations within a transaction,
// preventing partial or inconsistent updates that could affect scanning accuracy.
func (s *ruleStore) SaveRule(ctx context.Context, rule rules.GitleaksRule) error {
	// Set a context timeout to prevent transaction deadlocks and resource exhaustion.
	// We use a serializable isolation level and a relatively short timeout since
	// rule updates should be quick and we want to fail fast if there are issues.
	// TODO: Figure out if this is the best timeout value.
	const txTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, txTimeout)
	defer cancel()

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.save_ruleset", []attribute.KeyValue{
		attribute.Int("rule_count", 1),
	}, func(ctx context.Context) error {
		err := pgx.BeginTxFunc(ctx, s.conn, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
			qtx := s.q.WithTx(tx)

			err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.upsert_rule", []attribute.KeyValue{
				attribute.String("rule_id", rule.RuleID),
				attribute.Int("allowlist_count", len(rule.Allowlists)),
			}, func(ctx context.Context) error {
				ruleID, err := qtx.UpsertRule(ctx, db.UpsertRuleParams{
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
					return fmt.Errorf("failed to upsert rule: %w", err)
				}

				for _, al := range rule.Allowlists {
					err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.create_allowlist", []attribute.KeyValue{
						attribute.String("rule_id", rule.RuleID),
						attribute.Int("commit_count", len(al.Commits)),
						attribute.Int("path_count", len(al.PathRegexes)),
						attribute.Int("regex_count", len(al.Regexes)),
						attribute.Int("stopword_count", len(al.StopWords)),
					}, func(ctx context.Context) error {
						allowlistID, err := qtx.UpsertAllowlist(ctx, db.UpsertAllowlistParams{
							RuleID:         ruleID,
							Description:    pgtype.Text{String: al.Description, Valid: true},
							MatchCondition: string(al.MatchCondition),
							RegexTarget:    pgtype.Text{String: al.RegexTarget, Valid: al.RegexTarget != ""},
						})
						if err != nil {
							return fmt.Errorf("failed to create allowlist: %w", err)
						}

						return s.bulkInsertAllowlistComponents(ctx, qtx, allowlistID, al)
					})
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			return nil
		})

		if err != nil {
			s.metrics.IncRuleSaveErrors(ctx)
			return err
		}

		s.metrics.IncRulesSaved(ctx)
		return nil
	})
}

// bulkInsertAllowlistComponents handles the insertion of all allowlist components for a given allowlist.
// It coordinates the insertion of commits, paths, regexes, and stopwords while maintaining proper error
// handling and tracing.
func (s *ruleStore) bulkInsertAllowlistComponents(
	ctx context.Context,
	qtx *db.Queries,
	allowlistID int64,
	al rules.GitleaksAllowlist,
) error {
	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.bulk_insert_components", []attribute.KeyValue{
		attribute.Int64("allowlist_id", allowlistID),
	}, func(ctx context.Context) error {
		if err := s.bulkInsertCommits(ctx, qtx, allowlistID, al.Commits); err != nil {
			return err
		}

		if err := s.bulkInsertPaths(ctx, qtx, allowlistID, al.PathRegexes); err != nil {
			return err
		}

		if err := s.bulkInsertRegexes(ctx, qtx, allowlistID, al.Regexes); err != nil {
			return err
		}

		if err := s.bulkInsertStopwords(ctx, qtx, allowlistID, al.StopWords); err != nil {
			return err
		}

		return nil
	})
}

func (s *ruleStore) bulkInsertCommits(ctx context.Context, qtx *db.Queries, allowlistID int64, commits []string) error {
	if err := qtx.DeleteAllowlistCommits(ctx, allowlistID); err != nil {
		return fmt.Errorf("failed to delete existing commits: %w", err)
	}

	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_commits",
		allowlistID,
		commits,
		"commits",
		func(allowlistID int64, commit string) db.BulkInsertAllowlistCommitsParams {
			return db.BulkInsertAllowlistCommitsParams{
				AllowlistID: allowlistID,
				Commit:      commit,
			}
		},
		qtx.BulkInsertAllowlistCommits,
	)
}

func (s *ruleStore) bulkInsertPaths(ctx context.Context, qtx *db.Queries, allowlistID int64, paths []string) error {
	if err := qtx.DeleteAllowlistPaths(ctx, allowlistID); err != nil {
		return fmt.Errorf("failed to delete existing paths: %w", err)
	}

	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_paths",
		allowlistID,
		paths,
		"paths",
		func(allowlistID int64, path string) db.BulkInsertAllowlistPathsParams {
			return db.BulkInsertAllowlistPathsParams{
				AllowlistID: allowlistID,
				Path:        path,
			}
		},
		qtx.BulkInsertAllowlistPaths,
	)
}

func (s *ruleStore) bulkInsertRegexes(ctx context.Context, qtx *db.Queries, allowlistID int64, regexes []string) error {
	if err := qtx.DeleteAllowlistRegexes(ctx, allowlistID); err != nil {
		return fmt.Errorf("failed to delete existing regexes: %w", err)
	}

	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_regexes",
		allowlistID,
		regexes,
		"regexes",
		func(allowlistID int64, regex string) db.BulkInsertAllowlistRegexesParams {
			return db.BulkInsertAllowlistRegexesParams{
				AllowlistID: allowlistID,
				Regex:       regex,
			}
		},
		qtx.BulkInsertAllowlistRegexes,
	)
}

func (s *ruleStore) bulkInsertStopwords(ctx context.Context, qtx *db.Queries, allowlistID int64, stopwords []string) error {
	if err := qtx.DeleteAllowlistStopwords(ctx, allowlistID); err != nil {
		return fmt.Errorf("failed to delete existing stopwords: %w", err)
	}

	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_stopwords",
		allowlistID,
		stopwords,
		"stopwords",
		func(allowlistID int64, stopword string) db.BulkInsertAllowlistStopwordsParams {
			return db.BulkInsertAllowlistStopwordsParams{
				AllowlistID: allowlistID,
				Stopword:    stopword,
			}
		},
		qtx.BulkInsertAllowlistStopwords,
	)
}
