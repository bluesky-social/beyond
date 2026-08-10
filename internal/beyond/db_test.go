package beyond

import (
	"database/sql"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	dbSetupOnce sync.Once
	dbSetupErr  error
)

// ensureDB returns a database connection with the beyond schema already
// migrated. The migration (including DROP + recreate) runs once per test
// binary execution via sync.Once, so all DB tests can run in parallel using
// unique data for isolation.
func ensureDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("BEYOND_DB_URL")
	if dbURL == "" {
		t.Skip("BEYOND_DB_URL not set")
	}
	db, err := OpenDB(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	dbSetupOnce.Do(func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS access_logs, goose_db_version`)
		dbSetupErr = RunBeyondMigrations(db)
	})
	require.NoError(t, dbSetupErr, "migration must succeed")
	return db
}

func TestRunBeyondMigrations(t *testing.T) {
	t.Parallel()
	db := ensureDB(t)

	// Verify the access_logs table exists.
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'access_logs'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "access_logs table should exist after migration")

	// Verify idempotency: running again should not error.
	assert.NoError(t, RunBeyondMigrations(db), "re-running migrations should be idempotent")
}
