package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// setupScannerTest prepares the test environment for scanner tests.
// It connects to a test database container with migrations already applied.
func setupScannerTest(t *testing.T) (context.Context, *pgxpool.Pool, *scannerStore, func()) {
	t.Helper()

	ctx := context.Background()

	// Use the test container helper from storage package.
	// This already applies migrations including our schema.
	pool, containerCleanup := storage.SetupTestContainer(t)

	repo := NewScannerStore(pool, storage.NoOpTracer())

	// Define cleanup function that extends the container cleanup.
	cleanup := func() {
		// First clean up the test data.
		_, err := pool.Exec(ctx, "DELETE FROM scanners")
		if err != nil {
			t.Logf("Failed to clean up scanners table: %v", err)
		}

		_, err = pool.Exec(ctx, "DELETE FROM scanner_groups")
		if err != nil {
			t.Logf("Failed to clean up scanner_groups table: %v", err)
		}

		containerCleanup()
	}

	return ctx, pool, repo, cleanup
}

// createTestScannerGroup creates a scanner group for testing.
func createTestScannerGroup(t *testing.T) *scanning.ScannerGroup {
	t.Helper()
	group, err := scanning.NewScannerGroup(uuid.New(), "Test Scanner Group", "Description for test scanner group")
	require.NoError(t, err, "Failed to create scanner group")
	return group
}

// createTestScanner creates a scanner for testing.
func createTestScanner(t *testing.T, groupID uuid.UUID) *scanning.Scanner {
	t.Helper()
	scanner, err := scanning.NewScanner(uuid.New(), groupID, "Test Scanner", "1.0.0")
	require.NoError(t, err, "Failed to create scanner")
	return scanner
}

func TestScannerStore_CreateScannerGroup(t *testing.T) {
	t.Parallel()
	ctx, _, repo, cleanup := setupScannerTest(t)
	defer cleanup()

	group := createTestScannerGroup(t)

	err := repo.CreateScannerGroup(ctx, group)
	require.NoError(t, err, "Failed to create scanner group")

	// Verify the group was created by querying directly.
	var count int
	err = repo.db.QueryRow(ctx, "SELECT COUNT(*) FROM scanner_groups WHERE id = $1", group.ID()).Scan(&count)
	require.NoError(t, err, "Failed to query scanner group")
	assert.Equal(t, 1, count, "Scanner group should exist in database")
}

func TestScannerStore_CreateDuplicateScannerGroup(t *testing.T) {
	t.Parallel()
	ctx, _, repo, cleanup := setupScannerTest(t)
	defer cleanup()

	group := createTestScannerGroup(t)

	err := repo.CreateScannerGroup(ctx, group)
	require.NoError(t, err, "Failed to create scanner group")

	// Creating another group with the same ID should fail.
	duplicateGroup, err := scanning.NewScannerGroup(
		group.ID(), // Same ID
		"Different Name",
		"Different description",
	)
	require.NoError(t, err, "Failed to create duplicate scanner group")

	err = repo.CreateScannerGroup(ctx, duplicateGroup)
	assert.ErrorIs(t, err, scanning.ErrScannerGroupAlreadyExists, "Should return ErrGroupAlreadyExists for duplicate ID")

	// Creating another group with the same name should fail.
	duplicateNameGroup, err := scanning.NewScannerGroup(
		uuid.New(),   // Different ID
		group.Name(), // Same name
		"Different description",
	)
	require.NoError(t, err, "Failed to create duplicate scanner group")

	err = repo.CreateScannerGroup(ctx, duplicateNameGroup)
	assert.ErrorIs(t, err, scanning.ErrScannerGroupAlreadyExists, "Should return ErrGroupAlreadyExists for duplicate name")
}

func TestScannerStore_CreateScanner(t *testing.T) {
	t.Parallel()
	ctx, _, repo, cleanup := setupScannerTest(t)
	defer cleanup()

	group := createTestScannerGroup(t)
	err := repo.CreateScannerGroup(ctx, group)
	require.NoError(t, err, "Failed to create scanner group")

	scanner := createTestScanner(t, group.ID())

	err = repo.CreateScanner(ctx, scanner)
	require.NoError(t, err, "Failed to create scanner")

	var count int
	err = repo.db.QueryRow(ctx, "SELECT COUNT(*) FROM scanners WHERE id = $1", scanner.ID()).Scan(&count)
	require.NoError(t, err, "Failed to query scanner")
	assert.Equal(t, 1, count, "Scanner should exist in database")
}

func TestScannerStore_CreateScannerInvalidGroup(t *testing.T) {
	t.Parallel()
	ctx, _, repo, cleanup := setupScannerTest(t)
	defer cleanup()

	nonExistentGroupID := uuid.New() // This ID doesn't exist in the database
	scanner := createTestScanner(t, nonExistentGroupID)

	err := repo.CreateScanner(ctx, scanner)
	assert.Error(t, err, "Creating a scanner with non-existent group ID should fail")
}

func TestScannerStore_GetScannerGroupIDByScannerGroupName(t *testing.T) {
	t.Parallel()
	ctx, _, repo, cleanup := setupScannerTest(t)
	defer cleanup()

	group := createTestScannerGroup(t)
	err := repo.CreateScannerGroup(ctx, group)
	require.NoError(t, err, "Failed to create scanner group")

	retrievedID, err := repo.GetScannerGroupIDByScannerGroupName(ctx, group.Name())
	require.NoError(t, err, "Failed to get scanner group ID by name")
	assert.Equal(t, group.ID(), retrievedID, "Retrieved ID should match the original group ID")

	// Test with non-existent name.
	_, err = repo.GetScannerGroupIDByScannerGroupName(ctx, "NonExistentGroup")
	assert.ErrorIs(t, err, scanning.ErrScannerGroupNotFound, "Should return ErrScannerGroupNotFound for non-existent group")
}
