// Command entrui is the user-facing control plane client: an interactive TUI
// plus non-interactive login / hosts / connect subcommands.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"entrance/internal/client"
	"entrance/internal/config"
	"entrance/internal/tui"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func expandHome(p string) string {
	if len(p) >= 2 && p[0] == '~' && p[1] == '/' {
		if h, err := os.UserHomeDir(); err == nil {
			return h + p[1:]
		}
	}
	return p
}

func prompt(label string) string {
	fmt.Print(label)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return ""
	}
	return sc.Text()
}

func promptSecret(label string) string {
	// phase 1: plain echo prompt; terminals with stty -echo can script this
	fmt.Print(label)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return ""
	}
	return sc.Text()
}

func main() {
	var configPath string
	root := &cobra.Command{
		Use:   "entrui",
		Short: "Bastion access from the terminal",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// first arg can be the control plane URL for login-less UX
			return nil
		},
	}
	root.PersistentFlags().StringVar(&configPath, "config", envOr("ENTRUI_CONFIG", "~/.config/entrui/creds.json"),
		"session/credentials file")
	configPath = expandHome(configPath)

	root.AddCommand(loginCmd(configPath))
	root.AddCommand(hostsCmd(configPath))
	root.AddCommand(connectCmd(configPath))
	root.AddCommand(interactiveCmd(configPath))
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "entrui:", err)
		os.Exit(1)
	}
}

func loginCmd(cfgPath string) *cobra.Command {
	var url, caFile string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store credentials for the control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := tui.LoadSession(cfgPath)
			if err != nil && s == nil {
				// no URL yet; create a blank session
				s = &tui.Session{}
			}
			if url != "" {
				s.URL = url
			}
			if s.URL == "" {
				return errors.New("--url required on first login")
			}
			s.CAFile = caFile
			c, err := client.New(client.Options{BaseURL: s.URL, CAFile: s.CAFile})
			if err != nil {
				return err
			}
			username := prompt("username: ")
			password := promptSecret("password: ")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			resp, err := c.Login(ctx, username, password)
			if err != nil {
				return err
			}
			s.Username = username
			s.Token = resp.SessionToken
			s.TokenExp = resp.ExpiresAt.Unix()
			s.Client = c
			s.Path = cfgPath
			if err := s.Close(); err != nil {
				return err
			}
			fmt.Printf("logged in; session valid until %s\n", resp.ExpiresAt.Local().Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "control plane base URL")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "pin CA cert (dev fingerprint)")
	return cmd
}

func hostsCmd(cfgPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "hosts",
		Short: "List hosts (daemons)",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := tui.LoadSession(cfgPath)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			hosts, err := s.Client.ListDaemons(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("%-4s %-24s %-14s %-8s %s\n", "ID", "HOST", "WG IP", "STATUS", "PORTS")
			for _, h := range hosts {
				fmt.Printf("%-4d %-24s %-14s %-8s %v\n", h.ID, h.Hostname, h.WGIP, h.Status, h.AllowedPorts)
			}
			return nil
		},
	}
}

func connectCmd(cfgPath string) *cobra.Command {
	var port int
	var sshUser string
	var noSSH bool
	cmd := &cobra.Command{
		Use:   "connect <host-id|hostname>",
		Short: "Tunnel to a host port (optionally launching ssh)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := tui.LoadSession(cfgPath)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			hosts, err := s.Client.ListDaemons(ctx)
			if err != nil {
				return err
			}
			var found *int64
			if id, err := strconv.ParseInt(args[0], 10, 64); err == nil {
				for i := range hosts {
					if hosts[i].ID == id {
						found = &hosts[i].ID
						break
					}
				}
			} else {
				for i := range hosts {
					if hosts[i].Hostname == args[0] {
						found = &hosts[i].ID
						break
					}
				}
			}
			if found == nil {
				return fmt.Errorf("host %q not found (see `entrui hosts`)", args[0])
			}
			if port == 0 {
				var host *daemonRow
				for i := range hosts {
					if hosts[i].ID == *found {
						host = &daemonRow{ID: hosts[i].ID, Ports: hosts[i].AllowedPorts}
						break
					}
				}
				if host == nil || len(host.Ports) == 0 {
					return errors.New("host exposes no ports; check `--allow` on entranced")
				}
				port = host.Ports[0]
			}

			tunnel, err := s.Client.Tunnel(context.WithoutCancel(ctx), *found, port)
			if err != nil {
				return err
			}
			defer tunnel.Close()
			s.AppendLog(fmt.Sprintf("tunnel ready: 127.0.0.1:%s -> host %d port %d", localPort(tunnel.LocalAddr), *found, port))
			fmt.Fprintf(os.Stderr, "tunnel ready: %s (host %d port %d)\n", tunnel.LocalAddr, *found, port)

			if noSSH {
				fmt.Println("holding tunnel open (Ctrl-C to close)")
				sig := make(chan os.Signal, 1)
				signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
				<-sig
				return nil
			}

			user := sshUser
			args2 := []string{"-p", localPort(tunnel.LocalAddr)}
			if user != "" {
				args2 = append(args2, "-l", user)
			}
			args2 = append(args2, "127.0.0.1")
			scmd := exec.Command("ssh", args2...)
			scmd.Stdin = os.Stdin
			scmd.Stdout = os.Stdout
			scmd.Stderr = os.Stderr
			s.AppendLog("launching ssh " + stringsJoin(args2, " "))
			if err := scmd.Run(); err != nil {
				s.AppendLog(fmt.Sprintf("ssh exited: %v", err))
				return err
			}
			s.AppendLog("ssh session ended")
			return nil
		},
	}
	cmd.Flags().IntVarP(&port, "port", "p", 0, "target port on the host (default: first allowlisted)")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "", "ssh username (-l)")
	cmd.Flags().BoolVar(&noSSH, "no-ssh", false, "hold the tunnel open without launching ssh")
	return cmd
}

func interactiveCmd(cfgPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "ui",
		Short: "Interactive dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := tui.LoadSession(cfgPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "entrui:", err)
				fmt.Fprintln(os.Stderr, "hint: run `entrui login --url https://…` first")
				return err
			}
			p := tea.NewProgram(tui.NewApp(s), tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return err
			}
			if s.ConnectRequest != nil {
				fmt.Println()
				req := s.ConnectRequest
				port := req.Port
				if port == 0 {
					port = firstPort(s)
				}
				if port == 0 {
					return errors.New("host exposes no ports")
				}
				return runConnectStdio(s, req.DaemonID, port)
			}
			_ = s.Close()
			return nil
		},
	}
}

func runConnectStdio(s *tui.Session, daemonID int64, port int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Setup calls use the deadline above, but the tunnel itself must NOT
	// inherit it: the bridges derive from this context and a 20s deadline
	// would kill every connected session. WithoutCancel keeps it alive for
	// the whole ssh run; Tunnel.Close still cancels it.
	tunnel, err := s.Client.Tunnel(context.WithoutCancel(ctx), daemonID, port)
	if err != nil {
		return err
	}
	defer tunnel.Close()
	s.AppendLog(fmt.Sprintf("tunnel ready at %s", tunnel.LocalAddr))
	args := []string{"-p", localPort(tunnel.LocalAddr), "127.0.0.1"}
	scmd := exec.Command("ssh", args...)
	scmd.Stdin = os.Stdin
	scmd.Stdout = os.Stdout
	scmd.Stderr = os.Stderr
	return scmd.Run()
}

type daemonRow struct {
	ID    int64
	Ports []int
}

func firstPort(s *tui.Session) int {
	if s.Hosts != nil {
		for _, h := range s.Hosts {
			if len(h.AllowedPorts) > 0 {
				return h.AllowedPorts[0]
			}
		}
	}
	return 0
}

func localPort(addr string) string {
	_, port, err := splitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

func splitHostPort(addr string) (string, string, error) {
	return net.SplitHostPort(addr)
}

var _ = config.DefaultDaemon
var _ = filepath.Separator

func stringsJoin(a []string, sep string) string { return strings.Join(a, sep) }
