package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "View and manage ThreatPrism configuration",
		Annotations: map[string]string{"skipInit": "true"},
	}
	cmd.AddCommand(newConfigShowCmd(), newConfigInitCmd(), newConfigPathCmd())
	return cmd
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:         "show",
		Short:       "Print the active configuration as YAML",
		Annotations: map[string]string{"skipInit": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			// Redact the AI key before printing.
			if cfg.AI.APIKey != "" {
				cfg.AI.APIKey = "<redacted>"
			}
			out, err := yaml.Marshal(cfg)
			if err != nil {
				return err
			}
			fmt.Print(string(out))
			return nil
		},
	}
}

func newConfigInitCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:         "init",
		Short:       "Write a default config file",
		Annotations: map[string]string{"skipInit": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				dir, err := os.UserConfigDir()
				if err != nil {
					dir = "."
				}
				path = filepath.Join(dir, "threatprism", "config.yaml")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("config already exists at %s (use --path to override)", path)
			}
			from, err := loadConfig()
			if err != nil {
				return err
			}
			if err := from.Save(path); err != nil {
				return err
			}
			fmt.Println(okStyle.Render("config written to " + path))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "destination path (default: OS config dir)")
	return cmd
}

func newConfigPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:         "path",
		Short:       "Print the path where config would be loaded from",
		Annotations: map[string]string{"skipInit": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if flagConfig != "" {
				fmt.Println(flagConfig)
				return nil
			}
			candidates := []string{}
			if wd, err := os.Getwd(); err == nil {
				candidates = append(candidates, filepath.Join(wd, "config.yaml"))
			}
			if home, err := os.UserConfigDir(); err == nil {
				candidates = append(candidates, filepath.Join(home, "threatprism", "config.yaml"))
			}
			for _, p := range candidates {
				if _, err := os.Stat(p); err == nil {
					fmt.Println(p)
					return nil
				}
			}
			fmt.Println(mutedStyle.Render("no config file found; using defaults"))
			return nil
		},
	}
}
