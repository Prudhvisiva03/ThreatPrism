// Package modules wires all built-in modules into a registry. Adding a new
// capability to ThreatPrism is as simple as implementing module.Module and
// adding one line here.
package modules

import (
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/internal/modules/apiintel"
	"github.com/threatprism/threatprism/internal/modules/aiintel"
	"github.com/threatprism/threatprism/internal/modules/crawler"
	"github.com/threatprism/threatprism/internal/modules/dirdisco"
	"github.com/threatprism/threatprism/internal/modules/discovery"
	"github.com/threatprism/threatprism/internal/modules/jsintel"
	"github.com/threatprism/threatprism/internal/modules/loginintel"
	"github.com/threatprism/threatprism/internal/modules/monitoring"
	"github.com/threatprism/threatprism/internal/modules/params"
	"github.com/threatprism/threatprism/internal/modules/screenshot"
	"github.com/threatprism/threatprism/internal/modules/security"
	"github.com/threatprism/threatprism/internal/modules/sensitive"
	"github.com/threatprism/threatprism/internal/modules/techfp"
)

// Register adds every built-in module to reg.
func Register(reg *module.Registry) {
	reg.Register(discovery.New())
	reg.Register(crawler.New())
	reg.Register(jsintel.New())
	reg.Register(apiintel.New())
	reg.Register(loginintel.New())
	reg.Register(techfp.New())
	reg.Register(dirdisco.New())
	reg.Register(sensitive.New())
	reg.Register(params.New())
	reg.Register(security.New())
	reg.Register(screenshot.New())
	reg.Register(aiintel.New())
	reg.Register(monitoring.New())
}

// Default returns a registry pre-loaded with all built-in modules.
func Default() *module.Registry {
	reg := module.NewRegistry()
	Register(reg)
	return reg
}
