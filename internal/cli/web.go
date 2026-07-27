package cli

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/internal/report"
)

func newWebCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:     "web <target>",
		Aliases: []string{"serve", "dashboard"},
		Short:   "Launch the interactive ThreatPrism Web Intelligence Workspace",
		Long:    "Starts a local web server displaying the interactive attack surface intelligence workspace for a target.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := target.Parse(args[0])
			if err != nil {
				return err
			}

			res, err := latestResult(t)
			if err != nil {
				return err
			}

			addr := fmt.Sprintf("127.0.0.1:%d", port)
			url := fmt.Sprintf("http://%s", addr)

			fmt.Println(headerStyle.Render("ThreatPrism Web Workspace"))
			fmt.Println(okStyle.Render("▶ Intelligence Workspace server running at: ") + url)
			fmt.Println(mutedStyle.Render("Press Ctrl+C to exit."))

			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				html, err := report.RenderHTML(res, app.cfg.Report.Theme)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(html)
			})

			return http.ListenAndServe(addr, nil)
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8080, "port to listen on")
	return cmd
}
