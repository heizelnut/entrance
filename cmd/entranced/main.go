// Command entranced is the outbound-only agent: it dials the bastion over
// HTTPS, authenticates with a single token, and serves remote PTY shells when
// the authenticated bastion asks. It opens no inbound ports.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"entrance/internal/agent"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "entranced:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		server   string
		token    string
		hostname string
		shell    string
		caFile   string
		auditLog string
		loglevel string
	)
	cmd := &cobra.Command{
		Use:   "entranced",
		Short: "Entrance outbound-only agent (remote shell over HTTPS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			level := slog.LevelInfo
			if loglevel == "debug" {
				level = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
			slog.SetDefault(log)

			if server == "" {
				return errors.New("--server is required (e.g. https://bastion.example.com)")
			}
			tok := envOr("ENTRANCED_TOKEN", envOr("ENTRANCE_TOKEN", token))
			if tok == "" {
				return errors.New("--token (or ENTRANCED_TOKEN) is required")
			}
			if hostname == "" {
				hostname, _ = os.Hostname()
			}
			cfg := agent.Config{
				ServerURL: server,
				Token:     tok,
				Hostname:  hostname,
				Shell:     shell,
				CAFile:    caFile,
				AuditLog:  auditLog,
			}
			a := agent.New(cfg, log)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			log.Info("entranced starting", "server", server, "hostname", hostname)
			return a.Run(ctx)
		},
	}
	f := cmd.Flags()
	f.StringVar(&server, "server", envOr("ENTRANCED_SERVER", ""), "bastion base URL (https://...)")
	f.StringVar(&token, "token", "", "shared token (env ENTRANCED_TOKEN / ENTRANCE_TOKEN)")
	f.StringVar(&hostname, "hostname", "", "reported hostname (default: os.Hostname)")
	f.StringVar(&shell, "shell", "", "shell to run for bastion sessions (default: $SHELL or /bin/sh)")
	f.StringVar(&caFile, "ca-file", "", "pin the bastion CA certificate (PEM)")
	f.StringVar(&auditLog, "audit-log", "", "append shell session audit lines to this file")
	f.StringVar(&loglevel, "log-level", "info", "info or debug")
	return cmd
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
