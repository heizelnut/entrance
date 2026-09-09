// Command entrance is the self-hosted bastion control plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"entrance/internal/api"
	"entrance/internal/auth"
	"entrance/internal/config"
	"entrance/internal/db"
	"entrance/internal/relay"
	"entrance/internal/tlssetup"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "entrance:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var dataDir string
	var dev bool
	var adminPassword string
	var relayMode string

	root := &cobra.Command{
		Use:   "entrance",
		Short: "Self-hosted bastion access control plane (HTTPS-only, single port)",
	}
	pf := root.PersistentFlags()
	pf.StringVar(&dataDir, "data-dir", envOr("ENTRANCE_DATA_DIR", "~/.entrance"),
		"control plane data directory (SQLite, keys, certs)")
	pf.StringVar(&adminPassword, "admin-password", envOr("ENTRANCE_ADMIN_PASSWORD", ""),
		"initial admin password (first run only)")
	pf.BoolVar(&dev, "dev", envBool("ENTRANCE_DEV", true),
		"dev mode: self-signed loopback cert on 127.0.0.1:8443")
	pf.StringVar(&relayMode, "relay-mode", envOr("ENTRANCE_RELAY_MODE", "loopback"),
		"relay dial mode: wg (tunnel IP, needs TUN) or loopback (rootless dev)")

	root.AddCommand(serveCmd(&serveOpts{dataDir: &dataDir, dev: &dev,
		adminPassword: &adminPassword, relayMode: &relayMode}))
	root.AddCommand(addHostCmd(&addHostOpts{dataDir: &dataDir}))
	root.AddCommand(daemonsCmd(&daemonsOpts{dataDir: &dataDir}))
	return root
}

type serveOpts struct {
	dataDir       *string
	dev           *bool
	adminPassword *string
	relayMode     *string
}

func serveCmd(o *serveOpts) *cobra.Command {
	var listen, hostname, network string
	var wgPort uint16
	var trustedProxy string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the control plane HTTPS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			level := slog.LevelInfo
			if envOr("ENTRANCE_LOG_LEVEL", "") == "debug" {
				level = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
			slog.SetDefault(log)
			dir := expandHome(*o.dataDir)
			cfg := config.DefaultServer()
			cfg.DataDir = dir
			cfg.Dev = *o.dev
			cfg.AdminPassword = *o.adminPassword
			cfg.RelayDialMode = *o.relayMode
			if listen != "" {
				cfg.ListenAddr = listen
			}
			if hostname != "" {
				cfg.Hostname = hostname
			}
			if network != "" {
				cfg.NetworkCIDR = network
			}
			if wgPort != 0 {
				cfg.WGPort = wgPort
			}
			if trustedProxy != "" {
				cfg.TrustedProxies = splitList(trustedProxy)
			}

			if cfg.RelayDialMode == relay.DialLoopback && !cfg.Dev {
				return errors.New("--relay-mode loopback is dev/e2e only: relay targets are the bastion's own " +
					"127.0.0.1, which would proxy the bastion host directly to users; " +
					"use --relay-mode wg (or --dev for local testing)")
			}

			store, err := db.Open(dir)
			if err != nil {
				return err
			}
			defer store.Close()

			server, err := api.NewServer(cfg, store, log)
			if err != nil {
				return err
			}

			tlsCfg, devCert, err := tlssetup.TLSConfig(tlssetup.Config{
				Dev: cfg.Dev, Hostname: cfg.Hostname, DataDir: dir,
			})
			if err != nil {
				return err
			}
			if devCert != nil && devCert.Fingerprint != "" {
				log.Info("dev certificate fingerprint (pin with --ca-file)",
					"fingerprint", devCert.Fingerprint)
			}

			hs := &http.Server{
				Addr:              cfg.ListenAddr,
				Handler:           server.Routes(),
				TLSConfig:         tlsCfg,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       60 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 1)
			go func() {
				log.Info("entrance listening", "addr", cfg.ListenAddr, "dev", cfg.Dev,
					"relay_mode", cfg.RelayDialMode, "network", cfg.NetworkCIDR)
				errCh <- hs.ListenAndServeTLS("", "")
			}()
			select {
			case err := <-errCh:
				if !errors.Is(err, http.ErrServerClosed) {
					return err
				}
			case <-ctx.Done():
				log.Info("shutting down")
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = hs.Shutdown(shutdownCtx)
			server.Close()
			return err
		},
	}
	cmd.Flags().StringVarP(&listen, "listen", "l", "",
		"HTTPS listen address (default 127.0.0.1:8443 dev / 0.0.0.0:443 prod)")
	cmd.Flags().StringVarP(&hostname, "hostname", "H", "", "public hostname for ACME (prod)")
	cmd.Flags().StringVarP(&network, "network", "n", "", "wg network cidr (default 10.99.0.0/24)")
	cmd.Flags().Uint16Var(&wgPort, "wg-port", 0, "loopback WG anchor port (default 51820)")
	cmd.Flags().StringVar(&trustedProxy, "trusted-proxy", "",
		"comma-separated proxy CIDRs whose X-Forwarded-For is trusted")
	return cmd
}

type addHostOpts struct {
	dataDir *string
}

func addHostCmd(o *addHostOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "add-host <label>",
		Short: "Create a one-time enrollment secret for a new host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := expandHome(*o.dataDir)
			store, err := db.Open(dir)
			if err != nil {
				return err
			}
			defer store.Close()
			secret, err := auth.GenerateToken()
			if err != nil {
				return err
			}
			hash, err := auth.HashPassword(secret) // argon2id (D3)
			if err != nil {
				return err
			}
			sec, err := store.CreateEnrollSecret(hash, auth.HashToken(secret), args[0], 24*time.Hour)
			if err != nil {
				return err
			}
			fmt.Printf("host %q enrolled; single-use secret (24h):\n  %s\n", args[0], secret)
			_ = sec
			return nil
		},
	}
}

type daemonsOpts struct {
	dataDir *string
}

func daemonsCmd(o *daemonsOpts) *cobra.Command {
	var revokeID int64
	cmd := &cobra.Command{
		Use:   "daemons",
		Short: "List or revoke registered daemons",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := db.Open(expandHome(*o.dataDir))
			if err != nil {
				return err
			}
			defer store.Close()
			if revokeID != 0 {
				if err := store.DeactivateDaemon(revokeID); err != nil {
					return err
				}
				fmt.Printf("revoked daemon %d in the database.\n", revokeID)
				fmt.Println("NOTE: live hub peers and relay sessions are cut by the running server;",
					"use DELETE /api/v1/daemons/{id} (or `entrui`) for live revocation,",
					"or restart `entrance serve` to re-issue the peer set.")
				return nil
			}
			daemons, err := store.ListDaemons()
			if err != nil {
				return err
			}
			for _, dm := range daemons {
				status := "online"
				if dm.LastSeenAt.IsZero() {
					status = "pending"
				}
				fmt.Printf("%-4d %-20s %-12s %-6s relays=%d\n",
					dm.ID, dm.Hostname, dm.WGIP, status, dm.ActiveRelays)
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&revokeID, "revoke", 0, "revoke a daemon by id (token invalidated)")
	return cmd
}

// --- helpers ---

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

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "1" || v == "true"
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
