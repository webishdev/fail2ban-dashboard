package track

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v3/log"
	"github.com/webishdev/fail2ban-dashboard/internal/models"
	"github.com/webishdev/fail2ban-dashboard/internal/store"

	// pure Go SQLite driver, registered as "sqlite"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS bans (
	jail      TEXT    NOT NULL,
	address   TEXT    NOT NULL,
	banned_at INTEGER NOT NULL,
	PRIMARY KEY (jail, address, banned_at)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_bans_banned_at ON bans(banned_at);
`

// Tracker stores bans seen in fail2ban in a SQLite database and keeps them for one year.
type Tracker struct {
	db  *sql.DB
	now func() time.Time
}

// dataSource defines the minimal interface needed to record bans after each data refresh
type dataSource interface {
	RegisterUpdateHandler(handler store.UpdateHandler)
	GetJails() []models.Jail
}

// Open opens or creates the SQLite database at the given path.
func Open(path string) (*Tracker, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// update handlers run concurrently, a single connection serializes all access
	db.SetMaxOpenConns(1)

	tracker := &Tracker{
		db:  db,
		now: time.Now,
	}

	if err := tracker.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}

	if _, err := tracker.Prune(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return tracker, nil
}

func (tracker *Tracker) migrate() error {
	if _, err := tracker.db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
		return fmt.Errorf("configure database: %w", err)
	}
	if _, err := tracker.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}

// Close closes the database.
func (tracker *Tracker) Close() error {
	return tracker.db.Close()
}

// Register records the bans of the data source after each refresh.
func (tracker *Tracker) Register(source dataSource) {
	source.RegisterUpdateHandler(func() {
		log.Debug("Recording bans")
		if err := tracker.Record(source.GetJails()); err != nil {
			log.Errorf("Could not record bans: %s", err)
		}
	})
}

// Record stores the banned entries of the given jails, already known bans are ignored.
func (tracker *Tracker) Record(jails []models.Jail) error {
	cutoff := tracker.cutoff()

	tx, err := tracker.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	statement, err := tx.Prepare("INSERT OR IGNORE INTO bans (jail, address, banned_at) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() {
		_ = statement.Close()
	}()

	for _, jail := range jails {
		for _, entry := range jail.BannedEntries {
			if entry.BannedAt.IsZero() || entry.BannedAt.Before(cutoff) {
				continue
			}
			if _, err := statement.Exec(jail.Name, entry.Address, entry.BannedAt.Unix()); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	_, err = tracker.Prune()
	return err
}

// Prune removes bans older than one year and returns the number of removed bans.
func (tracker *Tracker) Prune() (int64, error) {
	result, err := tracker.db.Exec("DELETE FROM bans WHERE banned_at < ?", tracker.cutoff().Unix())
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if removed > 0 {
		log.Debugf("Removed %d bans older than one year", removed)
	}
	return removed, nil
}

func (tracker *Tracker) cutoff() time.Time {
	return tracker.now().AddDate(-1, 0, 0)
}
