// Package store is the SQLite persistence layer. It records scans, findings,
// and full serialized results so the reporting engine can render them and the
// monitoring engine can diff consecutive scans of the same target.
//
// It uses the pure-Go modernc.org/sqlite driver, so ThreatPrism builds and runs
// on Linux, Windows, and macOS with no cgo toolchain.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/threatprism/threatprism/pkg/models"
)

// Store wraps a SQLite database connection.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and applies
// the schema migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite writer; keep it simple and safe
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace  TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    mode       TEXT    NOT NULL,
    modules    TEXT    NOT NULL DEFAULT '[]',
    status     TEXT    NOT NULL,
    started_at DATETIME NOT NULL,
    ended_at   DATETIME,
    error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module      TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    description TEXT,
    severity    TEXT    NOT NULL,
    confidence  INTEGER NOT NULL DEFAULT 0,
    url         TEXT,
    evidence    TEXT,
    tags        TEXT    NOT NULL DEFAULT '[]',
    metadata    TEXT    NOT NULL DEFAULT '{}',
    found_at    DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS results (
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    json    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT    NOT NULL,
    asset_url  TEXT    NOT NULL,
    text       TEXT    NOT NULL,
    tags       TEXT    NOT NULL DEFAULT '[]',
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// CreateScan inserts a new scan row and returns its assigned ID.
func (s *Store) CreateScan(sc *models.Scan) (int64, error) {
	mods, _ := json.Marshal(sc.Modules)
	res, err := s.db.Exec(
		`INSERT INTO scans (workspace, target, mode, modules, status, started_at) VALUES (?,?,?,?,?,?)`,
		sc.Workspace, sc.Target, string(sc.Mode), string(mods), string(sc.Status), sc.StartedAt,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	sc.ID = id
	return id, nil
}

// FinishScan updates a scan's terminal status, end time, and error.
func (s *Store) FinishScan(id int64, status models.ScanStatus, endedAt time.Time, scanErr string) error {
	_, err := s.db.Exec(
		`UPDATE scans SET status=?, ended_at=?, error=? WHERE id=?`,
		string(status), endedAt, scanErr, id,
	)
	return err
}

// SaveFindings bulk-inserts findings for a scan.
func (s *Store) SaveFindings(scanID int64, findings []models.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO findings (scan_id, module, type, title, description, severity, confidence, url, evidence, tags, metadata, found_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, f := range findings {
		tags, _ := json.Marshal(f.Tags)
		meta, _ := json.Marshal(f.Metadata)
		if _, err := stmt.Exec(scanID, f.Module, f.Type, f.Title, f.Description,
			string(f.Severity), f.Confidence, f.URL, f.Evidence, string(tags), string(meta), f.FoundAt); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// SaveResult stores the full serialized result for a scan (upsert).
func (s *Store) SaveResult(scanID int64, r *models.Result) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO results (scan_id, json) VALUES (?, ?)
		 ON CONFLICT(scan_id) DO UPDATE SET json=excluded.json`,
		scanID, string(data),
	)
	return err
}

// ListScans returns scans for a target, newest first.
func (s *Store) ListScans(target string) ([]models.Scan, error) {
	rows, err := s.db.Query(
		`SELECT id, workspace, target, mode, modules, status, started_at, ended_at, error
		 FROM scans WHERE target=? ORDER BY started_at DESC`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// AllScans returns every recorded scan, newest first.
func (s *Store) AllScans() ([]models.Scan, error) {
	rows, err := s.db.Query(
		`SELECT id, workspace, target, mode, modules, status, started_at, ended_at, error
		 FROM scans ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// Result returns the stored result for a scan ID.
func (s *Store) Result(scanID int64) (*models.Result, error) {
	var data string
	err := s.db.QueryRow(`SELECT json FROM results WHERE scan_id=?`, scanID).Scan(&data)
	if err != nil {
		return nil, err
	}
	var r models.Result
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// PreviousResult returns the most recent completed result for a target strictly
// before the given scan ID — the baseline the monitoring engine diffs against.
// It returns (nil, nil) when there is no prior scan.
func (s *Store) PreviousResult(target string, beforeScanID int64) (*models.Result, error) {
	var data string
	err := s.db.QueryRow(
		`SELECT r.json FROM results r
		 JOIN scans s ON s.id = r.scan_id
		 WHERE s.target = ? AND s.id < ? AND s.status = ?
		 ORDER BY s.id DESC LIMIT 1`,
		target, beforeScanID, string(models.ScanCompleted)).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r models.Result
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func scanRows(rows *sql.Rows) ([]models.Scan, error) {
	var out []models.Scan
	for rows.Next() {
		var (
			sc      models.Scan
			mode    string
			status  string
			mods    string
			ended   sql.NullTime
			errText sql.NullString
		)
		if err := rows.Scan(&sc.ID, &sc.Workspace, &sc.Target, &mode, &mods, &status,
			&sc.StartedAt, &ended, &errText); err != nil {
			return nil, err
		}
		sc.Mode = models.Mode(mode)
		sc.Status = models.ScanStatus(status)
		_ = json.Unmarshal([]byte(mods), &sc.Modules)
		if errText.Valid {
			sc.Error = errText.String
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// SaveNote persists an investigation notebook entry.
func (s *Store) SaveNote(n *models.Note) error {
	tagsJSON, _ := json.Marshal(n.Tags)
	_, err := s.db.Exec(
		`INSERT INTO notes (target, asset_url, text, tags, created_at) VALUES (?, ?, ?, ?, ?)`,
		n.Target, n.AssetURL, n.Text, string(tagsJSON), time.Now())
	return err
}

// GetNotes retrieves all investigation notebook entries for a target.
func (s *Store) GetNotes(target string) ([]models.Note, error) {
	rows, err := s.db.Query(`SELECT id, target, asset_url, text, tags, created_at FROM notes WHERE target = ? ORDER BY id DESC`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Note
	for rows.Next() {
		var n models.Note
		var tagsJSON string
		if err := rows.Scan(&n.ID, &n.Target, &n.AssetURL, &n.Text, &tagsJSON, &n.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsJSON), &n.Tags)
		out = append(out, n)
	}
	return out, nil
}

