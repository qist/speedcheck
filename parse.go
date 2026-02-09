package speedcheck

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
)

type ipPreference int

const (
	ipPrefNone ipPreference = iota
	ipPrefV4First
	ipPrefV6First
)

type httpAliveClass uint8

const (
	httpAlive2xx httpAliveClass = 2
	httpAlive3xx httpAliveClass = 3
	httpAlive4xx httpAliveClass = 4
	httpAlive5xx httpAliveClass = 5
)

type checkKind uint8

const (
	checkPing checkKind = iota + 1
	checkTCP
	checkHTTP
)

type checkSpec struct {
	kind checkKind
	port uint16
}

type config struct {
	enabled          bool
	checks           []checkSpec
	ipPref           ipPreference
	timeout          time.Duration
	httpSend         []byte
	httpAliveClasses map[httpAliveClass]struct{}
}

func parse(c *caddy.Controller) (*SpeedCheck, error) {
	var seen bool
	var cfg config
	cfg.timeout = 2 * time.Second
	cfg.ipPref = ipPrefV6First

	for c.Next() {
		if seen {
			return nil, plugin.ErrOnce
		}
		seen = true

		for c.NextBlock() {
			switch strings.ToLower(c.Val()) {
			case "speed-check-mode":
				modes := c.RemainingArgs()
				if len(modes) == 0 {
					return nil, c.ArgErr()
				}
				checks, enabled, err := parseSpeedCheckMode(modes)
				if err != nil {
					return nil, err
				}
				cfg.enabled = enabled
				cfg.checks = checks
			case "speed-ip-mode":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				if err := parseSpeedIPMode(&cfg, args); err != nil {
					return nil, err
				}
			case "speed-timeout-mode":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				if err := parseSpeedTimeoutMode(&cfg, args); err != nil {
					return nil, err
				}
			case "check_http_send":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				cfg.httpSend = []byte(args[0])
			case "check_http_expect_alive":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				if err := parseHTTPExpectAlive(&cfg, args); err != nil {
					return nil, err
				}
			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	return &SpeedCheck{
		cfg:    cfg,
		prober: newDefaultProber(cfg.timeout, cfg.httpSend, cfg.httpAliveClasses),
	}, nil
}

func parseSpeedCheckMode(args []string) ([]checkSpec, bool, error) {
	var items []string
	for _, a := range args {
		for _, part := range strings.Split(a, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			items = append(items, p)
		}
	}
	if len(items) == 0 {
		return nil, false, fmt.Errorf("speed-check-mode is empty")
	}
	if len(items) == 1 && strings.EqualFold(items[0], "none") {
		return nil, false, nil
	}

	checks := make([]checkSpec, 0, len(items))
	for _, it := range items {
		lit := strings.ToLower(it)
		if lit == "ping" {
			checks = append(checks, checkSpec{kind: checkPing})
			continue
		}
		if strings.HasPrefix(lit, "tcp:") {
			port, err := parsePort(strings.TrimPrefix(lit, "tcp:"))
			if err != nil {
				return nil, false, err
			}
			checks = append(checks, checkSpec{kind: checkTCP, port: port})
			continue
		}
		if strings.HasPrefix(lit, "http:") {
			port, err := parsePort(strings.TrimPrefix(lit, "http:"))
			if err != nil {
				return nil, false, err
			}
			checks = append(checks, checkSpec{kind: checkHTTP, port: port})
			continue
		}
		return nil, false, fmt.Errorf("unknown speed-check-mode %q", it)
	}
	return checks, true, nil
}

func parseSpeedTimeoutMode(cfg *config, args []string) error {
	if len(args) == 2 && strings.EqualFold(args[0], "timeout") {
		args = args[1:]
	}
	if len(args) != 1 {
		return fmt.Errorf("invalid speed-timeout-mode %q", strings.Join(args, " "))
	}
	d, err := time.ParseDuration(args[0])
	if err != nil {
		return fmt.Errorf("invalid speed-timeout-mode %q: %w", args[0], err)
	}
	if d <= 0 {
		return fmt.Errorf("speed-timeout-mode must be > 0")
	}
	cfg.timeout = d
	return nil
}

func parseSpeedIPMode(cfg *config, args []string) error {
	var tokens []string
	for _, a := range args {
		for _, part := range strings.Split(a, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			tokens = append(tokens, p)
		}
	}
	if len(tokens) == 0 {
		return fmt.Errorf("invalid speed-ip-mode %q", strings.Join(args, " "))
	}

	var (
		seenV4      bool
		seenV6      bool
		firstFamily string
		anySet      bool
	)

	for i := 0; i < len(tokens); {
		t := strings.ToLower(strings.TrimSpace(tokens[i]))
		switch t {
		case "timeout":
			if i+1 >= len(tokens) {
				return fmt.Errorf("invalid speed-ip-mode %q", strings.Join(args, " "))
			}
			d, err := time.ParseDuration(tokens[i+1])
			if err != nil {
				return fmt.Errorf("invalid speed-ip-mode timeout %q: %w", tokens[i+1], err)
			}
			if d <= 0 {
				return fmt.Errorf("speed-ip-mode timeout must be > 0")
			}
			cfg.timeout = d
			anySet = true
			i += 2
			continue
		case "ipv4", "v4":
			seenV4 = true
			if firstFamily == "" {
				firstFamily = t
			}
			anySet = true
			i++
			continue
		case "ipv6", "v6":
			seenV6 = true
			if firstFamily == "" {
				firstFamily = t
			}
			anySet = true
			i++
			continue
		default:
			return fmt.Errorf("invalid speed-ip-mode %q", strings.Join(args, " "))
		}
	}

	if seenV4 && seenV6 {
		if firstFamily == "ipv4" || firstFamily == "v4" {
			cfg.ipPref = ipPrefV4First
			return nil
		}
		cfg.ipPref = ipPrefV6First
		return nil
	}
	if seenV4 {
		cfg.ipPref = ipPrefV4First
		return nil
	}
	if seenV6 {
		cfg.ipPref = ipPrefV6First
		return nil
	}
	if anySet {
		return nil
	}
	return fmt.Errorf("invalid speed-ip-mode %q", strings.Join(args, " "))
}

func parseHTTPExpectAlive(cfg *config, args []string) error {
	if len(args) == 1 && strings.EqualFold(args[0], "http_all") {
		cfg.httpAliveClasses = nil
		return nil
	}

	if cfg.httpAliveClasses == nil {
		cfg.httpAliveClasses = make(map[httpAliveClass]struct{}, 3)
	}
	for _, a := range args {
		switch strings.ToLower(a) {
		case "http_2xx":
			cfg.httpAliveClasses[httpAlive2xx] = struct{}{}
		case "http_3xx":
			cfg.httpAliveClasses[httpAlive3xx] = struct{}{}
		case "http_4xx":
			cfg.httpAliveClasses[httpAlive4xx] = struct{}{}
		case "http_5xx":
			cfg.httpAliveClasses[httpAlive5xx] = struct{}{}
		case "http_all":
			cfg.httpAliveClasses = nil
			return nil
		default:
			return fmt.Errorf("unknown check_http_expect_alive value %q", a)
		}
	}
	return nil
}

func parsePort(s string) (uint16, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(p), nil
}
