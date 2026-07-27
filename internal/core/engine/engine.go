// Package engine orchestrates a reconnaissance scan: it selects the modules for
// a mode, resolves their dependency order, executes them against a shared
// result, persists findings, computes the aggregate risk score, and reports
// progress. It is the piece that lets every module run independently yet compose
// into a single Full Recon run.
package engine

import (
	"context"
	"errors"
	"time"

	"github.com/threatprism/threatprism/internal/config"
	"github.com/threatprism/threatprism/internal/core/httpclient"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/internal/logging"
	"github.com/threatprism/threatprism/internal/store"
	"github.com/threatprism/threatprism/internal/workspace"
	"github.com/threatprism/threatprism/pkg/models"
)

// Engine executes scans.
type Engine struct {
	registry *module.Registry
	cfg      *config.Config
	http     *httpclient.Client
	log      logging.Logger
	wsm      *workspace.Manager
}

// New builds an Engine. http may be created here from cfg if nil is passed.
func New(reg *module.Registry, cfg *config.Config, log logging.Logger, wsm *workspace.Manager) (*Engine, error) {
	hc, err := httpclient.New(cfg.HTTP)
	if err != nil {
		return nil, err
	}
	return &Engine{registry: reg, cfg: cfg, http: hc, log: log, wsm: wsm}, nil
}

// Registry exposes the module registry (used by CLI/TUI listings).
func (e *Engine) Registry() *module.Registry { return e.registry }

// Options tunes a single Run.
type Options struct {
	Mode          models.Mode
	CustomModules []string          // used when Mode == ModeCustom
	Progress      module.Progress   // optional progress sink
}

// Run executes a scan against target and returns the aggregated result. It
// creates/updates the workspace and persists everything to the workspace DB.
func (e *Engine) Run(ctx context.Context, target models.Target, opts Options) (*models.Result, error) {
	if !opts.Mode.Valid() {
		opts.Mode = models.Mode(e.cfg.Recon.DefaultMode)
	}
	prog := opts.Progress
	if prog == nil {
		prog = module.NopProgress{}
	}

	// Resolve the module set and dependency order.
	requested := e.registry.ForMode(opts.Mode, opts.CustomModules)
	if len(requested) == 0 {
		return nil, errors.New("engine: no modules selected for this mode")
	}
	ordered, err := e.registry.Resolve(requested)
	if err != nil {
		return nil, err
	}

	// Prepare workspace + store.
	ws, err := e.wsm.Open(target.Host, target.URL)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ws.DBPath())
	if err != nil {
		return nil, err
	}
	defer st.Close()

	result := &models.Result{
		Target:    target,
		Mode:      opts.Mode,
		StartedAt: time.Now(),
	}

	slugs := make([]string, len(ordered))
	for i, m := range ordered {
		slugs[i] = m.Slug()
	}
	scan := &models.Scan{
		Workspace: ws.Name,
		Target:    target.URL,
		Mode:      opts.Mode,
		Modules:   slugs,
		Status:    models.ScanRunning,
		StartedAt: result.StartedAt,
	}
	scanID, err := st.CreateScan(scan)
	if err != nil {
		return nil, err
	}

	rc := module.NewRunContext(ctx, result)
	rc.Target = target
	rc.Mode = opts.Mode
	rc.Config = e.cfg
	rc.HTTP = e.http
	rc.Store = st
	rc.Workspace = ws
	rc.Log = e.log
	rc.Progress = prog

	// Execute modules in dependency order.
	for _, m := range ordered {
		if err := ctx.Err(); err != nil {
			_ = st.FinishScan(scanID, models.ScanCanceled, time.Now(), err.Error())
			result.EndedAt = time.Now()
			return result, err
		}
		prog.Stage(m.Slug(), m.Name())
		before := len(result.Findings)
		start := time.Now()

		runErr := safeRun(m, rc)

		stat := models.ModuleStat{
			Module:   m.Slug(),
			Status:   "ok",
			Findings: len(result.Findings) - before,
			Duration: time.Since(start),
		}
		if runErr != nil {
			stat.Status = "error"
			stat.Error = runErr.Error()
			e.log.Warn("module failed", "module", m.Slug(), "err", runErr)
		}
		rc.Update(func(r *models.Result) { r.ModuleStats = append(r.ModuleStats, stat) })
		prog.Done(m.Slug(), stat.Findings)
	}

	result.EndedAt = time.Now()
	result.RiskScore = ComputeRisk(result)

	// Persist findings + full result.
	if err := st.SaveFindings(scanID, result.Findings); err != nil {
		e.log.Warn("save findings", "err", err)
	}
	if err := st.SaveResult(scanID, result); err != nil {
		e.log.Warn("save result", "err", err)
	}
	if err := st.FinishScan(scanID, models.ScanCompleted, result.EndedAt, ""); err != nil {
		e.log.Warn("finish scan", "err", err)
	}

	// Write an overview snapshot to the workspace.
	if _, err := ws.WriteJSON(workspace.DirOverview, "result.json", result); err != nil {
		e.log.Warn("write overview", "err", err)
	}

	return result, nil
}

// safeRun runs a module, converting panics into errors so one misbehaving
// module can never crash an entire scan.
func safeRun(m module.Module, rc *module.RunContext) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errorf("module %s panicked: %v", m.Slug(), r)
		}
	}()
	return m.Run(rc)
}
