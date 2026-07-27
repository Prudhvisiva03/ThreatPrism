package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/core/engine"
	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/internal/modules"
	"github.com/threatprism/threatprism/pkg/models"
)

// newModuleCmds builds one subcommand per registered module, letting users run
// any single module in isolation, e.g. `threatprism jsintel https://x.com`.
func newModuleCmds() []*cobra.Command {
	reg := modules.Default() // metadata only; the real run uses app.engine
	var cmds []*cobra.Command
	for _, m := range reg.All() {
		m := m
		var quiet bool
		cmd := &cobra.Command{
			Use:   m.Slug() + " <target>",
			Short: m.Description(),
			Args:  cobra.ExactArgs(1),
			GroupID: "modules",
			RunE: func(cmd *cobra.Command, args []string) error {
				t, err := target.Parse(args[0])
				if err != nil {
					return err
				}
				fmt.Println(headerStyle.Render(m.Name()) + mutedStyle.Render("  "+t.Host))
				res, err := app.engine.Run(context.Background(), t, engine.Options{
					Mode:          models.ModeCustom,
					CustomModules: []string{m.Slug()},
					Progress:      cliProgress{quiet: quiet},
				})
				if err != nil {
					return err
				}
				printResult(res)
				return nil
			},
		}
		cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress per-module progress output")
		cmds = append(cmds, cmd)
	}
	return cmds
}
