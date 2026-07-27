// Package logging provides a small structured-logging facade built on the
// standard library's log/slog. It supports text and JSON handlers, level
// control, and an optional per-workspace log file.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Logger is the application logging interface. It is intentionally a thin
// wrapper over *slog.Logger so callers can use structured key/value logging.
type Logger = *slog.Logger

// Options configures logger construction.
type Options struct {
	Level  string    // debug, info, warn, error
	Format string    // text, json
	Output io.Writer // defaults to os.Stderr
	// AddSource includes source file:line in records (useful for debug).
	AddSource bool
}

// New builds a Logger from Options.
func New(opts Options) Logger {
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}
	handlerOpts := &slog.HandlerOptions{
		Level:     parseLevel(opts.Level),
		AddSource: opts.AddSource,
	}
	var h slog.Handler
	if strings.EqualFold(opts.Format, "json") {
		h = slog.NewJSONHandler(out, handlerOpts)
	} else {
		h = slog.NewTextHandler(out, handlerOpts)
	}
	return slog.New(h)
}

// NewMulti builds a Logger that writes to several destinations at once (for
// example both the console and a workspace log file). Level and format apply to
// all destinations.
func NewMulti(opts Options, extra ...io.Writer) Logger {
	writers := []io.Writer{}
	if opts.Output != nil {
		writers = append(writers, opts.Output)
	} else {
		writers = append(writers, os.Stderr)
	}
	writers = append(writers, extra...)
	opts.Output = io.MultiWriter(writers...)
	return New(opts)
}

// Discard returns a logger that drops all output — handy in tests.
func Discard() Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
