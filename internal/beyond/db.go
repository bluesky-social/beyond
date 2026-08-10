package beyond

import (
	"database/sql"
	"embed"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// OpenDB opens a PostgreSQL connection using the given URL.
func OpenDB(dbURL string) (*sql.DB, error) {
	return sql.Open("postgres", dbURL)
}

// RunBeyondMigrations applies all pending goose migrations for the beyond package.
func RunBeyondMigrations(db *sql.DB) error {
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}
