package wg

import (
	"fmt"
	"net/netip"
)

// IPAM allocates /32 addresses out of the hub-and-spoke WireGuard network
// (D2). The bastion owns .1 and daemons are allocated sequentially from .2.
type IPAM struct {
	network   netip.Prefix
	bastionIP netip.Addr
}

// ParseNetwork builds an IPAM for a /24-style network like "10.99.0.0/24".
// The bastion address is the first usable address in the network.
func ParseNetwork(cidr string) (*IPAM, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid network cidr %q: %w", cidr, err)
	}
	if p.Addr().BitLen() != 32 {
		return nil, fmt.Errorf("network cidr %q must be IPv4", cidr)
	}
	masked := p.Masked()
	return &IPAM{network: masked, bastionIP: masked.Addr().Next()}, nil
}

// Network returns the cidr string (e.g. "10.99.0.0/24").
func (a *IPAM) Network() string { return a.network.String() }

// BastionIP returns the address of the bastion (e.g. 10.99.0.1).
func (a *IPAM) BastionIP() netip.Addr { return a.bastionIP }

// Contains reports whether ip is inside the network.
func (a *IPAM) Contains(ip netip.Addr) bool { return a.network.Contains(ip) }

// AddressForN returns the address of the nth daemon (n=0 → the first daemon
// address, bastionIP+1), or an error when the network is exhausted.
func (a *IPAM) AddressForN(n uint64) (netip.Addr, error) {
	ip := a.bastionIP
	for range n + 1 {
		ip = ip.Next()
		if !a.Contains(ip) || ip.IsUnspecified() {
			return netip.Addr{}, fmt.Errorf("network %s exhausted allocating daemon #%d", a.network, n)
		}
	}
	return ip, nil
}

// NextAfter returns the next address after ip within the network, or an error
// when the network would be exhausted.
func (a *IPAM) NextAfter(ip netip.Addr) (netip.Addr, error) {
	next := ip.Next()
	if !a.Contains(next) {
		return netip.Addr{}, fmt.Errorf("network %s exhausted at %s", a.network, ip)
	}
	return next, nil
}

// AddressForAllocation picks the address that follows the highest allocated
// one; empty ip means the first daemon address. Callers pass the current max
// allocated wg_ip (or zero).
func (a *IPAM) AddressForAllocation(maxAllocated netip.Addr, count int64) (netip.Addr, error) {
	if count <= 0 {
		count = 0
	}
	if maxAllocated.IsValid() && !maxAllocated.IsUnspecified() {
		ip, err := a.NextAfter(maxAllocated)
		if err != nil {
			return netip.Addr{}, err
		}
		// skip if it's somehow the bastion
		if ip.Compare(a.bastionIP) == 0 {
			return a.NextAfter(ip)
		}
		return ip, nil
	}
	return a.AddressForN(uint64(count))
}
