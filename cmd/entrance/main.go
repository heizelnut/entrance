// Command entrance is the bastion: one HTTPS port that agents dial out to,
// with WebAuthn (passkey) admin auth and a browser terminal that drives PTYs
// on the connected agents.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"entrance/internal/bastion"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "entrance:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		listen   string
		dataDir  string
		dev      bool
		hostname string
		rpID     string
		origin   string
		token    string
		shell    string
		loglevel string
	)
	cmd := &cobra.Command{
		Use:   "entrance",
		Short: "Entrance bastion (HTTPS + WebAuthn + remote shell)",
		RunE: func(cmd *cobra.Command, args []string) error {
			level := slog.LevelInfo
			if loglevel == "debug" {
				level = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
			slog.SetDefault(log)

			tok := envOr("ENTRANCE_TOKEN", token)
			if tok == "" {
				return errors.New("--token (or ENTRANCE_TOKEN) is required: it authenticates agents and bootstraps the first passkey")
			}
			dd := expandHome(dataDir)
			if hostname == "" {
				if dev {
					hostname = "localhost"
				} else {
					h, _ := os.Hostname()
					hostname = h
				}
			}
			if rpID == "" {
				rpID = hostOnly(hostname)
			}
			if origin == "" {
				origin = deriveOrigin(dev, hostname, listen)
			}
			cfg := bastion.Config{
				ListenAddr: listen,
				DataDir:    dd,
				Dev:        dev,
				Hostname:   hostname,
				RPID:       rpID,
				Origin:     origin,
				Token:      tok,
				Shell:      shell,
			}
			b, err := bastion.New(cfg, log)
			if err != nil {
				return err
			}
			defer b.Close()

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return b.Run(ctx)
		},
	}
	f := cmd.Flags()
	f.StringVar(&listen, "listen", "127.0.0.1:8443", "HTTPS bind address (prod: 0.0.0.0:443)")
	f.StringVar(&dataDir, "data-dir", "~/.entrance", "state directory (SQLite, TLS cache)")
	f.BoolVar(&dev, "dev", true, "dev mode: plain HTTP on localhost, no ACME")
	f.StringVar(&hostname, "hostname", "", "public hostname (dev default: localhost)")
	f.StringVar(&rpID, "rp-id", "", "WebAuthn RP ID (default: hostname without port)")
	f.StringVar(&origin, "origin", "", "WebAuthn origin (default derived from hostname/port)")
	f.StringVar(&token, "token", "", "single token: agent auth + first-passkey bootstrap (env ENTRANCE_TOKEN)")
	f.StringVar(&shell, "shell", "", "shell advertised to agents (default: agent $SHELL or /bin/sh)")
	f.StringVar(&loglevel, "log-level", "info", "info or debug")
	return cmd
}

func deriveOrigin(dev bool, hostname, listen string) string {
	scheme := "https://"
	if dev {
		scheme = "http://"
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" || port == "443" || (dev && port == "80") {
		return scheme + hostname
	}
	return scheme + hostname + ":" + port
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func expandHome(p string) string {
	if len(p) >= 2 && p[0] == '~' && p[1] == '/' {
		if h, err := os.UserHomeDir(); err == nil {
			return h + p[1:]
		}
	}
	return p
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
