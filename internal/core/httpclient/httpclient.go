// Package httpclient provides the single shared HTTP client used by every
// ThreatPrism module. Centralizing HTTP here gives the whole platform uniform
// timeouts, a configurable User-Agent, optional proxying, TLS behavior,
// automatic retries, global concurrency limiting, and rate limiting — which is
// what lets modules run together safely during a Full Recon scan without
// hammering a target or duplicating requests.
package httpclient

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/threatprism/threatprism/internal/config"
)

// Response is a lightweight, already-drained HTTP response. The body is read
// fully (bounded) so callers never have to remember to Close it.
type Response struct {
	URL        string
	StatusCode int
	Status     string
	Header     http.Header
	Body       []byte
	FinalURL   string // after redirects
	Elapsed    time.Duration
}

// ContentType returns the response Content-Type without parameters.
func (r *Response) ContentType() string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}

// Client is the shared HTTP client.
type Client struct {
	http     *http.Client
	ua       string
	retries  int
	sem      chan struct{}
	limiter  *rateLimiter
	maxBody  int64
}

// New constructs a Client from HTTP configuration.
func New(cfg config.HTTPConfig) (*Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.InsecureTLS}, //nolint:gosec // recon targets frequently have invalid certs; opt-out via config
	}

	if cfg.ProxyURL != "" {
		pu, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(pu)
	}

	hc := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}
	if !cfg.FollowRedirects {
		hc.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 1
	}

	c := &Client{
		http:    hc,
		ua:      cfg.UserAgent,
		retries: cfg.Retries,
		sem:     make(chan struct{}, conc),
		maxBody: 10 << 20, // 10 MiB cap to protect memory
	}
	if cfg.RateLimitPerSec > 0 {
		c.limiter = newRateLimiter(cfg.RateLimitPerSec)
	}
	return c, nil
}

// Get performs a GET request with the shared policies applied.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, rawURL, nil, nil)
}

// Do performs an arbitrary request honoring concurrency, rate limiting, and
// retry policy. header may be nil.
func (c *Client) Do(ctx context.Context, method, rawURL string, body io.Reader, header http.Header) (*Response, error) {
	// Acquire a concurrency slot.
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var lastErr error
	attempts := c.retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if c.limiter != nil {
			if err := c.limiter.wait(ctx); err != nil {
				return nil, err
			}
		}
		resp, err := c.once(ctx, method, rawURL, body, header)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		// Only retry idempotent GETs; back off briefly.
		if body != nil || method != http.MethodGet {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 300 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func (c *Client) once(ctx context.Context, method, rawURL string, body io.Reader, header http.Header) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	if c.ua != "" {
		req.Header.Set("User-Agent", c.ua)
	}
	req.Header.Set("Accept", "*/*")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody))
	if err != nil {
		return nil, err
	}

	return &Response{
		URL:        rawURL,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     resp.Header,
		Body:       data,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}, nil
}

// rateLimiter is a minimal token-bucket limiter (dependency-free).
type rateLimiter struct {
	tokens chan struct{}
	ticker *time.Ticker
}

func newRateLimiter(perSec int) *rateLimiter {
	rl := &rateLimiter{
		tokens: make(chan struct{}, perSec),
		ticker: time.NewTicker(time.Second / time.Duration(perSec)),
	}
	for i := 0; i < perSec; i++ {
		rl.tokens <- struct{}{}
	}
	go func() {
		for range rl.ticker.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
	}()
	return rl
}

func (rl *rateLimiter) wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
