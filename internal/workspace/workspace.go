// Package workspace manages per-target working directories. Every scan target
// gets its own workspace containing a fixed, numbered directory layout plus the
// SQLite database, logs, screenshots, and generated reports.
package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Canonical numbered sub-directories, matching the documented output layout.
const (
	DirOverview       = "01_overview"
	DirSubdomains     = "02_subdomains"
	DirAlive          = "03_alive"
	DirDNS            = "04_dns"
	DirURLs           = "05_urls"
	DirJS             = "06_js"
	DirAPI            = "07_api"
	DirLogin          = "08_login"
	DirAdmin          = "09_admin"
	DirTechnology     = "10_technology"
	DirHeaders        = "11_headers"
	DirParameters     = "12_parameters"
	DirSensitiveFiles = "13_sensitive_files"
	DirGraphQL        = "14_graphql"
	DirSwagger        = "15_swagger"
	DirScreenshots    = "16_screenshots"
	DirAI             = "17_ai"
	DirReports        = "18_reports"
)

// layout is the full ordered set of sub-directories created for every
// workspace.
var layout = []string{
	DirOverview, DirSubdomains, DirAlive, DirDNS, DirURLs, DirJS, DirAPI,
	DirLogin, DirAdmin, DirTechnology, DirHeaders, DirParameters,
	DirSensitiveFiles, DirGraphQL, DirSwagger, DirScreenshots, DirAI, DirReports,
}

const (
	dbFileName  = "threatprism.db"
	logFileName = "threatprism.log"
	metaFile    = "workspace.json"
)

// Manager creates and enumerates workspaces under a shared root directory.
type Manager struct {
	root string
}

// NewManager returns a Manager rooted at dir, creating dir if necessary.
func NewManager(dir string) (*Manager, error) {
	if dir == "" {
		return nil, fmt.Errorf("workspace: empty root dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Manager{root: dir}, nil
}

// Root returns the workspace root directory.
func (m *Manager) Root() string { return m.root }

// Workspace represents a single target's workspace on disk.
type Workspace struct {
	Name      string    `json:"name"`
	Target    string    `json:"target"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Open returns an existing workspace by name, or creates it if missing. The
// full numbered directory layout is materialized on first open.
func (m *Manager) Open(name, target string) (*Workspace, error) {
	name = Slugify(name)
	if name == "" {
		return nil, fmt.Errorf("workspace: invalid name")
	}
	path := filepath.Join(m.root, name)

	created := time.Now()
	if info, err := os.Stat(filepath.Join(path, metaFile)); err == nil {
		created = info.ModTime()
	}

	for _, sub := range layout {
		if err := os.MkdirAll(filepath.Join(path, sub), 0o755); err != nil {
			return nil, err
		}
	}

	ws := &Workspace{
		Name:      name,
		Target:    target,
		Path:      path,
		CreatedAt: created,
		UpdatedAt: time.Now(),
	}
	if err := ws.writeMeta(); err != nil {
		return nil, err
	}
	return ws, nil
}

// List returns all workspaces known under the root, newest first.
func (m *Manager) List() ([]*Workspace, error) {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return nil, err
	}
	var out []*Workspace
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		metaPath := filepath.Join(m.root, e.Name(), metaFile)
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var ws Workspace
		if json.Unmarshal(data, &ws) == nil {
			out = append(out, &ws)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

// Delete removes a workspace and all of its contents.
func (m *Manager) Delete(name string) error {
	name = Slugify(name)
	if name == "" {
		return fmt.Errorf("workspace: invalid name")
	}
	return os.RemoveAll(filepath.Join(m.root, name))
}

// Dir returns the absolute path of a canonical sub-directory.
func (w *Workspace) Dir(sub string) string { return filepath.Join(w.Path, sub) }

// DBPath returns the SQLite database path for this workspace.
func (w *Workspace) DBPath() string { return filepath.Join(w.Path, dbFileName) }

// LogPath returns the log file path for this workspace.
func (w *Workspace) LogPath() string { return filepath.Join(w.Path, logFileName) }

// ScreenshotsDir returns the screenshots directory.
func (w *Workspace) ScreenshotsDir() string { return w.Dir(DirScreenshots) }

// ReportsDir returns the reports directory.
func (w *Workspace) ReportsDir() string { return w.Dir(DirReports) }

// WriteFile writes raw bytes to sub/name within the workspace.
func (w *Workspace) WriteFile(sub, name string, data []byte) (string, error) {
	dir := w.Dir(sub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// WriteJSON marshals v as indented JSON into sub/name.
func (w *Workspace) WriteJSON(sub, name string, v any) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return w.WriteFile(sub, name, data)
}

func (w *Workspace) writeMeta() error {
	w.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(w.Path, metaFile), data, 0o644)
}

var slugRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// Slugify converts an arbitrary target/name into a filesystem-safe workspace
// name (e.g. "https://Google.com/" -> "google.com").
func Slugify(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = slugRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_.-")
	return s
}
