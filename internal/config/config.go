// Package config loads, validates, and persists ThreatPrism's YAML
// configuration. It provides sensible defaults so the tool runs with zero
// configuration, while allowing power users to tune every subsystem.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration object.
type Config struct {
	// WorkspaceDir is the root directory under which per-target workspaces live.
	WorkspaceDir string `yaml:"workspace_dir"`

	Log      LogConfig      `yaml:"log"`
	HTTP     HTTPConfig     `yaml:"http"`
	Recon    ReconConfig    `yaml:"recon"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Crawler  CrawlerConfig  `yaml:"crawler"`
	Dirs     DirsConfig     `yaml:"directory_discovery"`
	AI       AIConfig       `yaml:"ai"`
	Report   ReportConfig   `yaml:"report"`
	Plugins  PluginsConfig  `yaml:"plugins"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text, json
	File   bool   `yaml:"file"`   // also write a log file into the workspace
}

// HTTPConfig controls the shared HTTP client used by every module.
type HTTPConfig struct {
	Timeout         time.Duration `yaml:"timeout"`
	Concurrency     int           `yaml:"concurrency"`
	RateLimitPerSec int           `yaml:"rate_limit_per_sec"` // 0 = unlimited
	Retries         int           `yaml:"retries"`
	UserAgent       string        `yaml:"user_agent"`
	FollowRedirects bool          `yaml:"follow_redirects"`
	InsecureTLS     bool          `yaml:"insecure_tls"`
	ProxyURL        string        `yaml:"proxy_url"`
}

// ReconConfig controls default scan behavior.
type ReconConfig struct {
	DefaultMode   string   `yaml:"default_mode"`
	CustomModules []string `yaml:"custom_modules"`
}

// DiscoveryConfig controls passive/active asset discovery.
type DiscoveryConfig struct {
	PassiveSources []string `yaml:"passive_sources"`
	ResolveDNS     bool     `yaml:"resolve_dns"`
	ProbeAlive     bool     `yaml:"probe_alive"`
	Wayback        bool     `yaml:"wayback"`
	MaxSubdomains  int      `yaml:"max_subdomains"`
}

// CrawlerConfig controls the active crawling engine.
type CrawlerConfig struct {
	MaxDepth     int  `yaml:"max_depth"`
	MaxPages     int  `yaml:"max_pages"`
	ParseRobots  bool `yaml:"parse_robots"`
	ParseSitemap bool `yaml:"parse_sitemap"`
	CrawlJS      bool `yaml:"crawl_js"`
}

// DirsConfig controls directory/content discovery.
type DirsConfig struct {
	Wordlist    string `yaml:"wordlist"`
	Extensions  []string `yaml:"extensions"`
	Concurrency int    `yaml:"concurrency"`
}

// AIConfig controls the AI assistant.
type AIConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"` // openai, gemini, openrouter, ollama
	Model    string `yaml:"model"`
	Mode     string `yaml:"mode"` // beginner, professional
	BaseURL  string `yaml:"base_url"`
	// APIKey may be set here but is preferably supplied via environment
	// variable (THREATPRISM_AI_API_KEY) to avoid storing secrets on disk.
	APIKey string `yaml:"api_key"`
}

// ReportConfig controls the reporting engine.
type ReportConfig struct {
	Formats    []string `yaml:"formats"` // html, pdf, markdown, json, csv
	Theme      string   `yaml:"theme"`   // dark, light
	OpenAfter  bool     `yaml:"open_after"`
}

// PluginsConfig controls the external plugin system.
type PluginsConfig struct {
	Dir     string   `yaml:"dir"`
	Enabled []string `yaml:"enabled"`
}

// Default returns a fully-populated Config with production-sane defaults.
func Default() *Config {
	return &Config{
		WorkspaceDir: defaultWorkspaceDir(),
		Log: LogConfig{
			Level:  "info",
			Format: "text",
			File:   true,
		},
		HTTP: HTTPConfig{
			Timeout:         15 * time.Second,
			Concurrency:     40,
			RateLimitPerSec: 0,
			Retries:         2,
			UserAgent:       "ThreatPrism/1.0 (+https://github.com/threatprism/threatprism)",
			FollowRedirects: true,
			InsecureTLS:     true,
			ProxyURL:        "",
		},
		Recon: ReconConfig{
			DefaultMode:   "standard",
			CustomModules: []string{},
		},
		Discovery: DiscoveryConfig{
			PassiveSources: []string{"crtsh", "hackertarget", "rapiddns", "wayback"},
			ResolveDNS:     true,
			ProbeAlive:     true,
			Wayback:        true,
			MaxSubdomains:  5000,
		},
		Crawler: CrawlerConfig{
			MaxDepth:     3,
			MaxPages:     500,
			ParseRobots:  true,
			ParseSitemap: true,
			CrawlJS:      true,
		},
		Dirs: DirsConfig{
			Wordlist:    "",
			Extensions:  []string{"", "php", "json", "bak", "old", "zip"},
			Concurrency: 40,
		},
		AI: AIConfig{
			Enabled:  false,
			Provider: "ollama",
			Model:    "llama3.1",
			Mode:     "professional",
			BaseURL:  "",
			APIKey:   "",
		},
		Report: ReportConfig{
			Formats:   []string{"html", "json", "markdown"},
			Theme:     "dark",
			OpenAfter: false,
		},
		Plugins: PluginsConfig{
			Dir:     "plugins",
			Enabled: []string{},
		},
	}
}

// Load reads configuration from path, filling any unset fields with defaults.
// If path is empty it looks in the standard locations. A missing file is not an
// error — defaults are returned.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		path = discover()
	}
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	// Environment override for the AI key keeps secrets out of the file.
	if v := os.Getenv("THREATPRISM_AI_API_KEY"); v != "" {
		cfg.AI.APIKey = v
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config as YAML to path, creating parent directories.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Validate checks for obviously invalid configuration.
func (c *Config) Validate() error {
	if c.HTTP.Concurrency <= 0 {
		c.HTTP.Concurrency = 1
	}
	if c.HTTP.Timeout <= 0 {
		c.HTTP.Timeout = 15 * time.Second
	}
	switch c.Recon.DefaultMode {
	case "quick", "standard", "deep", "custom":
	default:
		return fmt.Errorf("invalid recon.default_mode %q", c.Recon.DefaultMode)
	}
	return nil
}

// discover returns the first config path that exists among the standard
// locations, or "" if none do.
func discover() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "config.yaml"))
	}
	if home, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "threatprism", "config.yaml"))
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// defaultWorkspaceDir returns the default root for workspaces.
func defaultWorkspaceDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".threatprism", "workspaces")
	}
	return "workspaces"
}
