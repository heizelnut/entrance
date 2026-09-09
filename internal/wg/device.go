package wg

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// TUN is the wireguard-go tun.Device interface re-exported so callers do not
// need to import the wireguard module.
type TUN = tun.Device

// DatagramWriter sends one WireGuard datagram as a binary WebSocket frame;
// implemented by internal/wsproto.Conn.
type DatagramWriter interface {
	WriteDatagram(data []byte) error
}

// PeerConfig is the single-peer configuration our hub/spoke topology needs.
type PeerConfig struct {
	PublicKey           string   // hex
	AllowedIPs          []string // e.g. ["10.99.0.2/32"]
	Endpoint            string   // e.g. "127.0.0.1:51821" (loopback anchor)
	PersistentKeepalive int      // seconds; 0 disables
	PreSharedKey        string   // optional hex (phase 2)
}

// Config is the full UAPI-style configuration for the device.
type Config struct {
	PrivateKey string // hex
	ListenPort uint16 // 51820 (bastion) / 51821 (daemon) loopback anchor
	Replace    bool   // replace_peers=true before re-adding all peers
	Peers      []PeerConfig
}

// String renders the config in wireguard-go uapi line format.
func (c Config) String() string {
	var sb strings.Builder
	if c.PrivateKey != "" {
		sb.WriteString("private_key=" + c.PrivateKey + "\n")
	}
	if c.ListenPort != 0 {
		sb.WriteString("listen_port=" + strconv.Itoa(int(c.ListenPort)) + "\n")
	}
	if c.Replace {
		sb.WriteString("replace_peers=true\n")
	}
	for _, p := range c.Peers {
		sb.WriteString("public_key=" + p.PublicKey + "\n")
		if p.PreSharedKey != "" {
			sb.WriteString("preshared_key=" + p.PreSharedKey + "\n")
		}
		sb.WriteString("protocol_version=1\n")
		if p.Endpoint != "" {
			sb.WriteString("endpoint=" + p.Endpoint + "\n")
		}
		if p.PersistentKeepalive > 0 {
			sb.WriteString("persistent_keepalive_interval=" + strconv.Itoa(p.PersistentKeepalive) + "\n")
		}
		for _, ip := range p.AllowedIPs {
			sb.WriteString("allowed_ip=" + ip + "\n")
		}
	}
	return sb.String()
}

// PeerStatus is a per-peer status snapshot (from device IpcGet).
type PeerStatus struct {
	PublicKey           string
	Endpoint            string
	LastHandshake       time.Time
	TxBytes             uint64
	RxBytes             uint64
	PersistentKeepalive int
	AllowedIPs          []string
}

// Device wraps a wireguard-go device: stock crypto, stock data plane, but
// connected through our Transport abstraction instead of the public internet.
type Device struct {
	dev       *device.Device
	transport Transport
	tun       tun.Device
	bind      *transportBind
	publicKey string
	port      uint16
	log       *slog.Logger

	configMu sync.Mutex
}

// NewDevice constructs the wireguard-go device from opts. The tun must be
// brought up (see FakeTUN.BringUp / <real tunnel link up>) before the data
// plane is active; config can be applied at any time.
func NewDevice(opts DeviceOptions) (*Device, error) {
	lg := opts.Log
	if lg == nil {
		lg = slog.Default()
	}
	devLogger := &device.Logger{
		Verbosef: func(format string, args ...any) { lg.Debug("wg: "+format, args...) },
		Errorf:   func(format string, args ...any) { lg.Error("wg: "+format, args...) },
	}
	bind := newTransportBind(opts.Transport, opts.ListenPort)
	dev := device.NewDevice(opts.Tun, bind, devLogger)
	d := &Device{
		dev:       dev,
		transport: opts.Transport,
		tun:       opts.Tun,
		bind:      bind,
		publicKey: opts.PublicKey,
		port:      opts.ListenPort,
		log:       lg,
	}
	if err := d.Configure(opts.Config); err != nil {
		dev.Close()
		return nil, err
	}
	return d, nil
}

// DeviceOptions configures a new wireguard-go device.
type DeviceOptions struct {
	Transport  Transport
	Tun        tun.Device
	ListenPort uint16
	PublicKey  string // our own public key (for diagnostics)
	Config     Config
	Log        *slog.Logger
}

// Configure applies a full uapi config (idempotent).
func (d *Device) Configure(cfg Config) error {
	d.configMu.Lock()
	defer d.configMu.Unlock()
	if cfg.PrivateKey == "" {
		cfg.PrivateKey = "" // never change the identity via Configure
	}
	return d.dev.IpcSet(cfg.String())
}

// ApplyPeerList rebuilds the peer set (used by the bastion on enroll/delete).
func (d *Device) ApplyPeerList(peers []PeerConfig) error {
	return d.Configure(Config{
		ListenPort: d.port,
		Replace:    true,
		Peers:      peers,
	})
}

// Status returns per-peer status from the device's uapi dump.
func (d *Device) Status() ([]PeerStatus, error) {
	out, err := d.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("ipc get: %w", err)
	}
	return parsePeerStatus(out), nil
}

func parsePeerStatus(uapi string) []PeerStatus {
	var (
		statuses []PeerStatus
		cur      *PeerStatus
		peerSeen bool
	)
	committed := func() {
		if cur != nil && peerSeen {
			statuses = append(statuses, *cur)
		}
		cur = nil
		peerSeen = false
	}
	for _, line := range strings.Split(uapi, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			committed()
			cur = &PeerStatus{PublicKey: v}
			peerSeen = true
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			if cur != nil {
				secs, _ := strconv.ParseInt(v, 10, 64)
				if secs > 0 {
					cur.LastHandshake = time.Unix(secs, 0)
				} else {
					cur.LastHandshake = time.Time{} // never handshaken
				}
			}
		case "last_handshake_time_nsec":
			if cur != nil && !cur.LastHandshake.IsZero() {
				nsecs, _ := strconv.ParseInt(v, 10, 64)
				cur.LastHandshake = cur.LastHandshake.Add(time.Duration(nsecs))
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "persistent_keepalive_interval":
			if cur != nil {
				cur.PersistentKeepalive, _ = strconv.Atoi(v)
			}
		case "allowed_ip":
			if cur != nil {
				cur.AllowedIPs = append(cur.AllowedIPs, v)
			}
		}
	}
	committed()
	return statuses
}

// LookupPeerStatus returns the status of the peer with the given public key.
func (d *Device) LookupPeerStatus(pubKey string) (PeerStatus, bool) {
	st, err := d.Status()
	if err != nil {
		return PeerStatus{}, false
	}
	for _, p := range st {
		if p.PublicKey == pubKey {
			return p, true
		}
	}
	return PeerStatus{}, false
}

// HandshakeComplete reports whether the given peer has completed at least one
// handshake and one has been healthy within the last idle timeout.
func (d *Device) HandshakeComplete(pubKey string, freshWindow time.Duration) bool {
	st, ok := d.LookupPeerStatus(pubKey)
	if !ok {
		return false
	}
	if st.LastHandshake.IsZero() {
		return false
	}
	if freshWindow > 0 && time.Since(st.LastHandshake) > freshWindow {
		return false
	}
	return true
}

// PublicKey returns our own public key hex.
func (d *Device) PublicKey() string { return d.publicKey }

// Transport exposes the attached datagram transport (used by the hub to
// funnel inbound datagrams into the device).
func (d *Device) Transport() Transport { return d.transport }

// InjectFrom feeds an inbound datagram into the device with an explicit
// endpoint token (the hub: per-daemon control-channel routing; single-peer
// transports may pass 0 to use the local anchor).
func (d *Device) InjectFrom(port uint16, data []byte) {
	d.bind.DeliverWithEP(port, data)
}

// TUN exposes the underlying tun device (useful for tests using FakeTUN).
func (d *Device) TUN() tun.Device { return d.tun }

// Close tears down the device (bind + tun) and the transport.
func (d *Device) Close() error {
	d.bind.Terminate()
	d.dev.Close() // closes bind and tun
	_ = d.transport.Close()
	return nil
}
