//go:build linux

package wg

import (
	"fmt"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

// OpenTun creates a userspace TUN device. Requires root.
func OpenTun(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

// ConfigureInterface configures the tunnel address and the route to the peer
// on Linux. Requires root. Errors are returned so callers can log them.
func ConfigureInterface(ifname, addr, peerAddr, network string) error {
	cmds := [][]string{
		{"ip", "link", "set", "dev", ifname, "mtu", "1420"},
		{"ip", "address", "change", "dev", ifname, "local", addr, "peer", peerAddr},
		{"ip", "link", "set", "dev", ifname, "up"},
		{"ip", "route", "add", network, "dev", ifname},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// The route may already exist; treat add-failures as non-fatal but
			// return a descriptive error so callers can decide.
			return fmt.Errorf("%v: %w (%s)", args, err, string(out))
		}
	}
	return nil
}
