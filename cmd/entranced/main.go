// Command entranced is the outbound-only agent (spoke): no inbound ports.
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

	"entrance/internal/config"
	"entrance/internal/daemon"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "entranced:", err)
		var revoked *daemon.RevokedError
		if errors.As(err, &revoked) {
			os.Exit(daemon.ExitRevoked)
		}
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		serverURL string
		dataDir   string
		allow     string
		bindMode  string
		remapStr  string
		caFile    string
		secret    string
		hostname  string
		wgPort    uint16
		heartbeat int
		loglevel  string
	)
	cmd := &cobra.Command{
		Use:   "entranced",
		Short: "Outbound-only bastion agent (spoke)",
		RunE: func(cmd *cobra.Command, args []string) error {
			level := slog.LevelInfo
			if loglevel == "debug" {
				level = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(os.Stderr,
				&slog.HandlerOptions{Level: level}))
			slog.SetDefault(log)

			ports, err := config.ParsePortList(allow)
			if err != nil {
				return err
			}
			remap, err := config.ParseRemap(remapStr)
			if err != nil {
				return err
			}
			if serverURL == "" {
				return errors.New("--server is required (e.g. https://127.0.0.1:8443)")
			}
			cfg := config.DefaultDaemon()
			cfg.ServerURL = serverURL
			cfg.DataDir = expandHome(dataDir)
			cfg.EnrollSecret = secret
			cfg.CAFile = caFile
			cfg.AllowedPorts = ports
			cfg.Remap = remap
			cfg.NetMode = bindMode
			cfg.WGPort = wgPort
			cfg.Hostname = hostname
			if heartbeat > 0 {
				cfg.HeartbeatIntervalSec = heartbeat
			}
			if cfg.Hostname == "" {
				h, _ := os.Hostname()
				cfg.Hostname = h
			}

			agent, err := daemon.New(cfg, log)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			log.Info("entranced starting", "server", serverURL, "mode", bindMode,
				"allow", allow, "wg_port", wgPort)
			if err := agent.Run(ctx); err != nil {
				return err
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&serverURL, "server", envOr("ENTRANCED_SERVER", ""), "control plane base URL")
	f.StringVar(&dataDir, "data-dir", envOr("ENTRANCED_DATA_DIR", "~/.entrance-agent"), "agent state directory (0600)")
	f.StringVar(&allow, "allow", "", "comma-separated allowed target ports, e.g. 22,3389,5432")
	f.StringVar(&bindMode, "net-mode", envOr("ENTRANCED_NET_MODE", "loopback"), "loopback (rootless) or tun (kernel TUN, root)")
	f.StringVar(&remapStr, "remap", "", "exposed-port remap, e.g. 22=2222")
	f.StringVar(&caFile, "ca-file", "", "pin control plane CA cert (dev fingerprint / corporate CA)")
	f.StringVar(&secret, "secret", envOr("ENTRANCED_ENROLL_SECRET", ""), "one-time enrollment secret (first run only)")
	f.StringVar(&hostname, "hostname", "", "reported hostname (default: os.Hostname)")
	f.Uint16Var(&wgPort, "wg-port", 51821, "loopback WG anchor port")
	f.IntVar(&heartbeat, "heartbeat", 30, "heartbeat interval seconds")
	f.StringVar(&loglevel, "log-level", "info", "info or debug")
	return cmd
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
