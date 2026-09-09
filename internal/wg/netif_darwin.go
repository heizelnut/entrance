//go:build darwin

package wg

import (
	"fmt"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

// OpenTun creates a userspace utun device. Requires root.
func OpenTun(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

// ConfigureInterface configures the tunnel address and the route to the peer
// on macOS. Requires root. Errors are returned so callers can log them.
func ConfigureInterface(ifname, addr, peerAddr, network string) error {
	cmds := [][]string{
		{"ifconfig", ifname, "up"},
		{"ifconfig", ifname, "inet", addr + "/24", "up"},
		{"route", "-n", "add", "-net", network, "-interface", ifname},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %w (%s)", args, err, string(out))
		}
	}
	_ = peerAddr // peer is implicit on point-to-point setup (10.99.0.0/24 route)
	return nil
}
