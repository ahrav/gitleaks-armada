// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: copyfrom.go

package db

import (
	"context"
)

// iteratorForBulkInsertAllowlistCommits implements pgx.CopyFromSource.
type iteratorForBulkInsertAllowlistCommits struct {
	rows                 []BulkInsertAllowlistCommitsParams
	skippedFirstNextCall bool
}

func (r *iteratorForBulkInsertAllowlistCommits) Next() bool {
	if len(r.rows) == 0 {
		return false
	}
	if !r.skippedFirstNextCall {
		r.skippedFirstNextCall = true
		return true
	}
	r.rows = r.rows[1:]
	return len(r.rows) > 0
}

func (r iteratorForBulkInsertAllowlistCommits) Values() ([]interface{}, error) {
	return []interface{}{
		r.rows[0].AllowlistID,
		r.rows[0].Commit,
	}, nil
}

func (r iteratorForBulkInsertAllowlistCommits) Err() error {
	return nil
}

func (q *Queries) BulkInsertAllowlistCommits(ctx context.Context, arg []BulkInsertAllowlistCommitsParams) (int64, error) {
	return q.db.CopyFrom(ctx, []string{"allowlist_commits"}, []string{"allowlist_id", "commit"}, &iteratorForBulkInsertAllowlistCommits{rows: arg})
}

// iteratorForBulkInsertAllowlistPaths implements pgx.CopyFromSource.
type iteratorForBulkInsertAllowlistPaths struct {
	rows                 []BulkInsertAllowlistPathsParams
	skippedFirstNextCall bool
}

func (r *iteratorForBulkInsertAllowlistPaths) Next() bool {
	if len(r.rows) == 0 {
		return false
	}
	if !r.skippedFirstNextCall {
		r.skippedFirstNextCall = true
		return true
	}
	r.rows = r.rows[1:]
	return len(r.rows) > 0
}

func (r iteratorForBulkInsertAllowlistPaths) Values() ([]interface{}, error) {
	return []interface{}{
		r.rows[0].AllowlistID,
		r.rows[0].Path,
	}, nil
}

func (r iteratorForBulkInsertAllowlistPaths) Err() error {
	return nil
}

func (q *Queries) BulkInsertAllowlistPaths(ctx context.Context, arg []BulkInsertAllowlistPathsParams) (int64, error) {
	return q.db.CopyFrom(ctx, []string{"allowlist_paths"}, []string{"allowlist_id", "path"}, &iteratorForBulkInsertAllowlistPaths{rows: arg})
}

// iteratorForBulkInsertAllowlistRegexes implements pgx.CopyFromSource.
type iteratorForBulkInsertAllowlistRegexes struct {
	rows                 []BulkInsertAllowlistRegexesParams
	skippedFirstNextCall bool
}

func (r *iteratorForBulkInsertAllowlistRegexes) Next() bool {
	if len(r.rows) == 0 {
		return false
	}
	if !r.skippedFirstNextCall {
		r.skippedFirstNextCall = true
		return true
	}
	r.rows = r.rows[1:]
	return len(r.rows) > 0
}

func (r iteratorForBulkInsertAllowlistRegexes) Values() ([]interface{}, error) {
	return []interface{}{
		r.rows[0].AllowlistID,
		r.rows[0].Regex,
	}, nil
}

func (r iteratorForBulkInsertAllowlistRegexes) Err() error {
	return nil
}

func (q *Queries) BulkInsertAllowlistRegexes(ctx context.Context, arg []BulkInsertAllowlistRegexesParams) (int64, error) {
	return q.db.CopyFrom(ctx, []string{"allowlist_regexes"}, []string{"allowlist_id", "regex"}, &iteratorForBulkInsertAllowlistRegexes{rows: arg})
}

// iteratorForBulkInsertAllowlistStopwords implements pgx.CopyFromSource.
type iteratorForBulkInsertAllowlistStopwords struct {
	rows                 []BulkInsertAllowlistStopwordsParams
	skippedFirstNextCall bool
}

func (r *iteratorForBulkInsertAllowlistStopwords) Next() bool {
	if len(r.rows) == 0 {
		return false
	}
	if !r.skippedFirstNextCall {
		r.skippedFirstNextCall = true
		return true
	}
	r.rows = r.rows[1:]
	return len(r.rows) > 0
}

func (r iteratorForBulkInsertAllowlistStopwords) Values() ([]interface{}, error) {
	return []interface{}{
		r.rows[0].AllowlistID,
		r.rows[0].Stopword,
	}, nil
}

func (r iteratorForBulkInsertAllowlistStopwords) Err() error {
	return nil
}

func (q *Queries) BulkInsertAllowlistStopwords(ctx context.Context, arg []BulkInsertAllowlistStopwordsParams) (int64, error) {
	return q.db.CopyFrom(ctx, []string{"allowlist_stopwords"}, []string{"allowlist_id", "stopword"}, &iteratorForBulkInsertAllowlistStopwords{rows: arg})
}

// iteratorForBulkInsertAllowlists implements pgx.CopyFromSource.
type iteratorForBulkInsertAllowlists struct {
	rows                 []BulkInsertAllowlistsParams
	skippedFirstNextCall bool
}

func (r *iteratorForBulkInsertAllowlists) Next() bool {
	if len(r.rows) == 0 {
		return false
	}
	if !r.skippedFirstNextCall {
		r.skippedFirstNextCall = true
		return true
	}
	r.rows = r.rows[1:]
	return len(r.rows) > 0
}

func (r iteratorForBulkInsertAllowlists) Values() ([]interface{}, error) {
	return []interface{}{
		r.rows[0].RuleID,
		r.rows[0].Description,
		r.rows[0].MatchCondition,
		r.rows[0].RegexTarget,
	}, nil
}

func (r iteratorForBulkInsertAllowlists) Err() error {
	return nil
}

func (q *Queries) BulkInsertAllowlists(ctx context.Context, arg []BulkInsertAllowlistsParams) (int64, error) {
	return q.db.CopyFrom(ctx, []string{"allowlists"}, []string{"rule_id", "description", "match_condition", "regex_target"}, &iteratorForBulkInsertAllowlists{rows: arg})
}

// iteratorForBulkInsertRules implements pgx.CopyFromSource.
type iteratorForBulkInsertRules struct {
	rows                 []BulkInsertRulesParams
	skippedFirstNextCall bool
}

func (r *iteratorForBulkInsertRules) Next() bool {
	if len(r.rows) == 0 {
		return false
	}
	if !r.skippedFirstNextCall {
		r.skippedFirstNextCall = true
		return true
	}
	r.rows = r.rows[1:]
	return len(r.rows) > 0
}

func (r iteratorForBulkInsertRules) Values() ([]interface{}, error) {
	return []interface{}{
		r.rows[0].RuleID,
		r.rows[0].Description,
		r.rows[0].Entropy,
		r.rows[0].SecretGroup,
		r.rows[0].Regex,
		r.rows[0].Path,
		r.rows[0].Tags,
		r.rows[0].Keywords,
	}, nil
}

func (r iteratorForBulkInsertRules) Err() error {
	return nil
}

func (q *Queries) BulkInsertRules(ctx context.Context, arg []BulkInsertRulesParams) (int64, error) {
	return q.db.CopyFrom(ctx, []string{"rules"}, []string{"rule_id", "description", "entropy", "secret_group", "regex", "path", "tags", "keywords"}, &iteratorForBulkInsertRules{rows: arg})
}