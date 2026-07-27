package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/ai"
	"github.com/threatprism/threatprism/internal/core/target"
)

func newAICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai <target>",
		Short: "Ask AI assistant to triage findings for a target",
		Long:  "Loads the latest scan results for a target and uses the configured AI provider to analyze and summarize findings.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := target.Parse(args[0])
			if err != nil {
				return err
			}

			res, err := latestResult(t)
			if err != nil {
				return err
			}

			provider, err := ai.NewProvider(app.cfg.AI)
			if err != nil {
				return err
			}

			fmt.Println(headerStyle.Render("AI Assistant Triage") + mutedStyle.Render(fmt.Sprintf("  %s (%s)", t.Host, provider.Name())))

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Target: %s\n", res.Target.Host))
			sb.WriteString(fmt.Sprintf("Risk Score: %d\n", res.RiskScore))
			sb.WriteString(fmt.Sprintf("Findings Count: %d\n\n", len(res.Findings)))

			sb.WriteString("Top Findings:\n")
			for i, f := range res.Findings {
				if i >= 10 {
					break
				}
				sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", f.Severity, f.Title, f.Description))
			}

			prompt := "Analyze these reconnaissance findings for " + res.Target.Host + ":\n\n" + sb.String()

			resp, err := provider.Complete(context.Background(), prompt)
			if err != nil {
				return err
			}

			fmt.Println("\n" + resp)
			return nil
		},
	}
	return cmd
}
