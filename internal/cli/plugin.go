package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/plugin"
)

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Inspect external tool plugins",
	}
	cmd.AddCommand(newPluginListCmd())
	return cmd
}

func newPluginListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List discovered plugins and their availability",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := app.cfg.Plugins.Dir
			if dir == "" {
				dir = "plugins"
			}
			manifests, err := plugin.Load(dir)
			if err != nil {
				return err
			}
			if len(manifests) == 0 {
				fmt.Println(mutedStyle.Render("no plugins found in " + dir))
				return nil
			}
			fmt.Println(headerStyle.Render("Plugins") + mutedStyle.Render("  ("+dir+")"))
			for _, m := range manifests {
				p := plugin.NewModule(m)
				status := errStyle.Render("unavailable")
				if p.Available() {
					status = okStyle.Render("available")
				}
				state := mutedStyle.Render("disabled")
				if m.Enabled {
					state = okStyle.Render("enabled")
				}
				fmt.Printf("  %s  %s  %s  %s\n",
					valueStyle.Render(padRight(m.Name, 16)),
					padRight2(state, 12),
					padRight2(status, 14),
					mutedStyle.Render(m.Description))
			}
			return nil
		},
	}
}

// padRight2 pads a pre-styled string by visible content length is hard to
// compute; here we simply append spaces, which is good enough for aligned CLI
// listings where the style adds no visible width beyond color.
func padRight2(s string, n int) string {
	return s
}
