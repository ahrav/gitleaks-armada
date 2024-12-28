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

// NewRulesStorage creates a new PostgreSQL-backed rules storage. It initializes the underlying
// database queries and tracing components needed for rule persistence and monitoring.
func NewRulesStorage(conn *pgxpool.Pool, tracer trace.Tracer) *RulesStorage {
	return &RulesStorage{
		q:      db.New(conn),
		conn:   conn,
		tracer: tracer,
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

	return executeAndTrace(ctx, tracer, spanName, []attribute.KeyValue{
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

// SaveRuleset persists a complete Gitleaks ruleset to PostgreSQL. It ensures atomic updates
// by executing all operations within a transaction, preventing partial or inconsistent updates
// that could affect scanning accuracy.
func (s *RulesStorage) SaveRuleset(ctx context.Context, ruleset messaging.GitleaksRuleSet) error {
	// Set a context timeout to prevent transaction deadlocks and resource exhaustion.
	// We use a serializable isolation level and a relatively short timeout since
	// rule updates should be quick and we want to fail fast if there are issues.
	// TODO: Figure out if this is the best timeout value.
	const txTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, txTimeout)
	defer cancel()

	return executeAndTrace(ctx, s.tracer, "postgres.save_ruleset", []attribute.KeyValue{
		attribute.Int("rule_count", len(ruleset.Rules)),
	}, func(ctx context.Context) error {
		return pgx.BeginTxFunc(ctx, s.conn, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
			qtx := s.q.WithTx(tx)

			for _, rule := range ruleset.Rules {
				err := executeAndTrace(ctx, s.tracer, "postgres.upsert_rule", []attribute.KeyValue{
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
						err := executeAndTrace(ctx, s.tracer, "postgres.create_allowlist", []attribute.KeyValue{
							attribute.String("rule_id", rule.RuleID),
							attribute.Int("commit_count", len(al.Commits)),
							attribute.Int("path_count", len(al.PathRegexes)),
							attribute.Int("regex_count", len(al.Regexes)),
							attribute.Int("stopword_count", len(al.StopWords)),
						}, func(ctx context.Context) error {
							allowlistID, err := qtx.CreateAllowlist(ctx, db.CreateAllowlistParams{
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
			}
			return nil
		})
	})
}

// bulkInsertAllowlistComponents handles the insertion of all allowlist components for a given allowlist.
// It coordinates the insertion of commits, paths, regexes, and stopwords while maintaining proper error
// handling and tracing.
func (s *RulesStorage) bulkInsertAllowlistComponents(
	ctx context.Context,
	qtx *db.Queries,
	allowlistID int64,
	al messaging.GitleaksAllowlist,
) error {
	return executeAndTrace(ctx, s.tracer, "postgres.bulk_insert_components", []attribute.KeyValue{
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

func (s *RulesStorage) bulkInsertCommits(ctx context.Context, qtx *db.Queries, allowlistID int64, commits []string) error {
	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_commits",
		allowlistID,
		commits,
		"commit",
		func(id int64, commit string) db.BulkInsertAllowlistCommitsParams {
			return db.BulkInsertAllowlistCommitsParams{AllowlistID: id, Commit: commit}
		},
		qtx.BulkInsertAllowlistCommits,
	)
}

func (s *RulesStorage) bulkInsertPaths(ctx context.Context, qtx *db.Queries, allowlistID int64, paths []string) error {
	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_paths",
		allowlistID,
		paths,
		"path",
		func(id int64, path string) db.BulkInsertAllowlistPathsParams {
			return db.BulkInsertAllowlistPathsParams{AllowlistID: id, Path: path}
		},
		qtx.BulkInsertAllowlistPaths,
	)
}

func (s *RulesStorage) bulkInsertRegexes(ctx context.Context, qtx *db.Queries, allowlistID int64, regexes []string) error {
	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_regexes",
		allowlistID,
		regexes,
		"regex",
		func(id int64, regex string) db.BulkInsertAllowlistRegexesParams {
			return db.BulkInsertAllowlistRegexesParams{AllowlistID: id, Regex: regex}
		},
		qtx.BulkInsertAllowlistRegexes,
	)
}

func (s *RulesStorage) bulkInsertStopwords(ctx context.Context, qtx *db.Queries, allowlistID int64, stopwords []string) error {
	return bulkInsert(
		ctx,
		s.tracer,
		"postgres.bulk_insert_stopwords",
		allowlistID,
		stopwords,
		"stopword",
		func(id int64, stopword string) db.BulkInsertAllowlistStopwordsParams {
			return db.BulkInsertAllowlistStopwordsParams{AllowlistID: id, Stopword: stopword}
		},
		qtx.BulkInsertAllowlistStopwords,
	)
}
