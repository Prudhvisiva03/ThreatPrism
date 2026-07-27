// Package cli wires ThreatPrism's Cobra command tree: the root command, the
// recon command, per-module commands, and the workspace/report/monitor/plugin/
// config/menu subcommands. It is the thin imperative shell around the engine.
package cli

import (
	"fmt"
	"os"

	"github.com/threatprism/threatprism/internal/config"
	"github.com/threatprism/threatprism/internal/core/engine"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/internal/logging"
	"github.com/threatprism/threatprism/internal/modules"
	"github.com/threatprism/threatprism/internal/workspace"
)

// appCtx holds the process-wide dependencies constructed once in the root
// command's PersistentPreRunE and shared by every subcommand.
type appCtx struct {
	cfg      *config.Config
	log      logging.Logger
	registry *module.Registry
	wsm      *workspace.Manager
	engine   *engine.Engine
}

// build constructs the shared application context from the resolved config.
func build(cfg *config.Config) (*appCtx, error) {
	log := logging.New(logging.Options{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Output: os.Stderr,
	})

	wsm, err := workspace.NewManager(cfg.WorkspaceDir)
	if err != nil {
		return nil, fmt.Errorf("workspace manager: %w", err)
	}

	reg := modules.Default()

	eng, err := engine.New(reg, cfg, log, wsm)
	if err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}

	return &appCtx{cfg: cfg, log: log, registry: reg, wsm: wsm, engine: eng}, nil
}
