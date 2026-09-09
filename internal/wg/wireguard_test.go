package wg

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// The rootless crypto vertical slice: a bastion (10.99.0.1) and daemon
// (10.99.0.2) wireguard-go device, connected by an in-memory Transport behind
// our transportBind, with fake TUN actors. The whole WireGuard crypto path —
// Noise_IKpsk2 handshake, ChaChaPoly transport encryption — is exercised
// without root.
//
// The daemon (spoke) initiates — matching the production topology where the
// spoke sends the first keepalive — so the handshake is a clean single-round
// handshake (no simultaneous-initiation path).

// makeTestPacket crafts a minimal valid IPv4 packet (20-byte header + payload)
// from src to dst. wireguard-go's allowed-IP routing and length-parsing paths
// read the IP header.
func makeTestPacket(srcIP, dstIP string, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // IPv4, IHL=5
	h[2] = byte((20 + len(payload)) >> 8)
	h[3] = byte(20 + len(payload))
	h[4], h[5] = 0x12, 0x34
	h[8], h[9] = 64, 6 // TTL=64, proto TCP
	copy(h[12:16], net.ParseIP(srcIP).To4())
	copy(h[16:20], net.ParseIP(dstIP).To4())
	return append(h, payload...)
}

// TestWireguardCryptoOverMemoryTransport runs both directions of the data
// plane and asserts each side observed a completed handshake.
func TestWireguardCryptoOverMemoryTransport(t *testing.T) {
	bastionPriv, bastionPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	daemonPriv, daemonPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	daemonTun, bastionTun := NewMemPair()

	bastionDev := mustNewTestDevice("bastion", bastionPriv, bastionPub, bastionTun, Config{
		ListenPort: 0,
		Peers: []PeerConfig{{
			PublicKey:  daemonPub,
			AllowedIPs: []string{"10.99.0.2/32"},
			Endpoint:   "127.0.0.1:0",
			// bastion does not initiate; it only ever responds
		}},
	})
	defer bastionDev.Close()

	daemonDev := mustNewTestDevice("daemon", daemonPriv, daemonPub, daemonTun, Config{
		ListenPort: 0,
		Peers: []PeerConfig{{
			PublicKey:           bastionPub,
			AllowedIPs:          []string{"10.99.0.1/32"},
			Endpoint:            "127.0.0.1:0",
			PersistentKeepalive: 25, // the daemon (spoke) initiates
		}},
	})
	defer daemonDev.Close()

	// 1. Handshake completion (daemon initiated; both sides observe it).
	waitForHandshake(t, daemonDev, bastionPub)
	waitForHandshake(t, bastionDev, daemonPub)

	// 2. daemon → bastion data path.
	bastionFT := bastionDev.TUN().(*FakeTUN)
	daemonFT := daemonDev.TUN().(*FakeTUN)

	payload := []byte("entrance-hello-over-wireguard")
	daemonFT.SendPacket(makeTestPacket("10.99.0.2", "10.99.0.1", payload))
	got, err := bastionFT.RecvPacket(3 * time.Second)
	if err != nil {
		t.Fatalf("daemon->bastion packet: %v", err)
	}
	if !bytes.Contains(got, payload) {
		t.Fatalf("daemon->bastion payload mismatch: got %x want %q", got, payload)
	}

	// 3. bastion → daemon data path (keypair exists now).
	payload2 := []byte("reply-from-bastion")
	bastionFT.SendPacket(makeTestPacket("10.99.0.1", "10.99.0.2", payload2))
	got2, err := daemonFT.RecvPacket(3 * time.Second)
	if err != nil {
		t.Fatalf("bastion->daemon packet: %v", err)
	}
	if !bytes.Contains(got2, payload2) {
		t.Fatalf("bastion->daemon payload mismatch: got %x want %q", got2, payload2)
	}
}

// mustNewTestDevice builds a device with the given transport and a fake TUN,
// then brings the fake TUN up so the data plane activates.
func mustNewTestDevice(name, priv, pub string, transport *MemTransport, cfg Config) *Device {
	cfg.PrivateKey = priv
	fakeTun := NewFakeTUN()
	dev, err := NewDevice(DeviceOptions{
		Transport: transport,
		Tun:       fakeTun,
		PublicKey: pub,
		Config:    cfg,
	})
	if err != nil {
		panic("create device " + name + ": " + err.Error())
	}
	fakeTun.BringUp()
	return dev
}

func waitForHandshake(t *testing.T, dev *Device, peerPub string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if st, ok := dev.LookupPeerStatus(peerPub); ok && !st.LastHandshake.IsZero() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, _ := dev.LookupPeerStatus(peerPub)
	t.Fatalf("no handshake with %s on device %s after 8s (status: %+v)",
		peerPub[:8], dev.PublicKey()[:8], st)
}
