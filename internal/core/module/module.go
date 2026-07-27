// Package module defines the contract that every ThreatPrism capability
// implements, plus the registry and shared execution context that let modules
// run independently or together during a Full Recon scan.
//
// The design goal is extensibility: adding a new capability means writing a
// type that satisfies Module and registering it. The engine discovers
// dependencies via Requires() and orders execution automatically, so new
// modules slot in without touching the core.
package module

import (
	"context"
	"sort"
	"sync"

	"github.com/threatprism/threatprism/internal/config"
	"github.com/threatprism/threatprism/internal/core/httpclient"
	"github.com/threatprism/threatprism/internal/logging"
	"github.com/threatprism/threatprism/internal/store"
	"github.com/threatprism/threatprism/internal/workspace"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module is the interface every ThreatPrism capability implements.
type Module interface {
	// Slug is the stable machine identifier (also the output sub-directory key).
	Slug() string
	// Name is the human-readable module name.
	Name() string
	// Description is a one-line summary shown in menus and help.
	Description() string
	// Category groups related modules (discovery, intelligence, analysis, ...).
	Category() string
	// Modes returns the recon modes that include this module by default.
	Modes() []models.Mode
	// Requires lists slugs of modules whose output this module consumes.
	Requires() []string
	// Run executes the module against the shared context.
	Run(rc *RunContext) error
}

// RunContext carries everything a module needs to execute. Fields that are not
// applicable to standalone runs (Store, Workspace) may be nil; modules must
// tolerate that so they remain usable in isolation and in tests.
type RunContext struct {
	Ctx       context.Context
	Target    models.Target
	Mode      models.Mode
	Config    *config.Config
	HTTP      *httpclient.Client
	Store     *store.Store
	Workspace *workspace.Workspace
	Log       logging.Logger
	Progress  Progress

	mu     sync.Mutex
	result *models.Result
}

// NewRunContext builds a RunContext around a shared result.
func NewRunContext(ctx context.Context, res *models.Result) *RunContext {
	if res == nil {
		res = &models.Result{}
	}
	return &RunContext{Ctx: ctx, result: res, Progress: NopProgress{}}
}

// Update mutates the shared result under lock. All writes to the aggregated
// result MUST go through Update so concurrent modules stay race-free.
func (rc *RunContext) Update(fn func(*models.Result)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	fn(rc.result)
}

// Result returns the underlying shared result pointer. Callers must only read
// it after all modules have finished, or via Update for writes.
func (rc *RunContext) Result() *models.Result { return rc.result }

// AddFinding is a convenience for the common case of emitting a single finding.
func (rc *RunContext) AddFinding(f models.Finding) {
	rc.Update(func(r *models.Result) { r.Findings = append(r.Findings, f) })
}

// Progress receives coarse progress updates from a running module. The TUI and
// CLI provide concrete implementations; tests and library use get NopProgress.
type Progress interface {
	// Stage announces a new module beginning execution.
	Stage(slug, name string)
	// Stepf logs a human-readable progress line for the current module.
	Stepf(format string, args ...any)
	// Done marks the current module finished with a findings count.
	Done(slug string, findings int)
}

// NopProgress is a Progress that discards everything.
type NopProgress struct{}

func (NopProgress) Stage(string, string)     {}
func (NopProgress) Stepf(string, ...any)      {}
func (NopProgress) Done(string, int)          {}

// Registry holds all known modules.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{modules: make(map[string]Module)}
}

// Register adds a module. It panics on a duplicate slug, which can only be a
// programming error at startup.
func (r *Registry) Register(m Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.modules[m.Slug()]; exists {
		panic("module: duplicate slug " + m.Slug())
	}
	r.modules[m.Slug()] = m
}

// Get returns a module by slug.
func (r *Registry) Get(slug string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[slug]
	return m, ok
}

// All returns every registered module sorted by slug.
func (r *Registry) All() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug() < out[j].Slug() })
	return out
}

// ForMode returns the modules that participate in a given recon mode. For
// ModeCustom the caller supplies the explicit slug list.
func (r *Registry) ForMode(mode models.Mode, custom []string) []Module {
	if mode == models.ModeCustom {
		return r.Select(custom)
	}
	var out []Module
	for _, m := range r.All() {
		for _, mm := range m.Modes() {
			if mm == mode {
				out = append(out, m)
				break
			}
		}
	}
	return out
}

// Select returns the modules matching the provided slugs, preserving registry
// order and silently skipping unknown slugs.
func (r *Registry) Select(slugs []string) []Module {
	want := make(map[string]bool, len(slugs))
	for _, s := range slugs {
		want[s] = true
	}
	var out []Module
	for _, m := range r.All() {
		if want[m.Slug()] {
			out = append(out, m)
		}
	}
	return out
}

// Resolve topologically sorts the requested modules so that every module runs
// after the modules it Requires(). Dependencies already in the registry but not
// requested are pulled in automatically. A cycle returns an error.
func (r *Registry) Resolve(requested []Module) ([]Module, error) {
	selected := make(map[string]Module)
	var addDeps func(m Module) error
	addDeps = func(m Module) error {
		if _, ok := selected[m.Slug()]; ok {
			return nil
		}
		selected[m.Slug()] = m
		for _, dep := range m.Requires() {
			if dm, ok := r.Get(dep); ok {
				if err := addDeps(dm); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, m := range requested {
		if err := addDeps(m); err != nil {
			return nil, err
		}
	}
	return topoSort(selected)
}
