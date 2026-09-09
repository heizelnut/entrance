package wg

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// ErrTimeout is returned by FakeTUN.RecvPacket when no packet arrived within
// the deadline.
var ErrTimeout = errors.New("timeout waiting for packet")

// FakeTUN is an in-memory tun.Device (wireguard-go style) that lets tests run
// the full WireGuard crypto/data plane without root:
//
//   - SendPacket injects a plaintext IP packet that the device will encrypt
//     and send to the peer.
//   - RecvPacket returns the next decrypted plaintext IP packet the device
//     wrote out.
//
// FakeTUN must be brought up: wireguard-go only enables its data plane after
// it observes tun.EventUp on the Events channel (see FakeTUN.BringUp).
type FakeTUN struct {
	incoming chan []byte // plaintext packets the test injects (device reads these)
	outbound chan []byte // decrypted plaintext packets the device wrote (test reads)
	events   chan tun.Event

	closed  atomic.Bool
	upOnce  sync.Once
	closeCh chan struct{}
}

// NewFakeTUN creates a fake TUN with the default WireGuard MTU.
func NewFakeTUN() *FakeTUN {
	return &FakeTUN{
		incoming: make(chan []byte, 256),
		outbound: make(chan []byte, 256),
		events:   make(chan tun.Event, 4),
		closeCh:  make(chan struct{}),
	}
}

// --- wireguard-go tun.Device interface ---

func (f *FakeTUN) File() *os.File { return nil }

func (f *FakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if f.closed.Load() {
		return 0, net.ErrClosed
	}
	select {
	case data := <-f.incoming:
		if len(bufs) == 0 {
			return 0, nil
		}
		n := copy(bufs[0][offset:], data)
		sizes[0] = n
		return 1, nil
	case <-f.closeCh:
		return 0, net.ErrClosed
	}
}

func (f *FakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		cp := make([]byte, len(b)-offset)
		copy(cp, b[offset:])
		select {
		case f.outbound <- cp:
		default:
			// Drop on overflow: mirrors a real device queue under pressure.
		}
	}
	return len(bufs), nil
}

func (f *FakeTUN) MTU() (int, error)        { return 1420, nil }
func (f *FakeTUN) Name() (string, error)    { return "fakewg0", nil }
func (f *FakeTUN) Events() <-chan tun.Event { return f.events }
func (f *FakeTUN) BatchSize() int           { return 1 }

func (f *FakeTUN) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	close(f.incoming)
	close(f.events)
	close(f.closeCh)
	return nil
}

// --- test helpers ---

// BringUp emits tun.EventUp once so wireguard-go enables its data plane.
func (f *FakeTUN) BringUp() {
	f.upOnce.Do(func() {
		select {
		case f.events <- tun.EventUp:
		case <-f.closeCh:
		}
	})
}

// SendPacket injects a plaintext IP packet to be sent through the tunnel.
func (f *FakeTUN) SendPacket(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case f.incoming <- cp:
	case <-f.closeCh:
	case <-time.After(5 * time.Second):
	}
}

// RecvPacket returns the next plaintext IP packet emitted by the device, or
// ErrTimeout after the deadline.
func (f *FakeTUN) RecvPacket(timeout time.Duration) ([]byte, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case p := <-f.outbound:
		return p, nil
	case <-t.C:
		return nil, ErrTimeout
	case <-f.closeCh:
		return nil, net.ErrClosed
	}
}
