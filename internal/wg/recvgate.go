package wg

import "sync"

// recvGate serializes receive-callback registration for Transports. Datagrams
// delivered before the callback is registered are queued (bounded) instead of
// dropped, mirroring kernel socket receive buffering. This removes the
// start-up race where two devices both come up and immediately send a
// handshake initiation at each other: whichever side registers its receive
// path slightly later still receives the peer's first attempts.
type recvGate struct {
	mu        sync.Mutex
	cb        func([]byte)
	pending   [][]byte
	maxQueued int
}

func newRecvGate(maxQueued int) *recvGate {
	if maxQueued <= 0 {
		maxQueued = 1024
	}
	return &recvGate{maxQueued: maxQueued}
}

// setCB registers the callback and flushes any queued datagrams.
func (g *recvGate) setCB(cb func([]byte)) {
	g.mu.Lock()
	g.cb = cb
	pending := g.pending
	g.pending = nil
	g.mu.Unlock()
	for _, d := range pending {
		cb(d)
	}
}

// deliver hands the datagram to the callback when registered; otherwise it
// queues the datagram (evicting the oldest when the queue is full) and
// returns whether the datagram was accepted.
func (g *recvGate) deliver(data []byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cb != nil {
		cb := g.cb
		cb(data)
		return true
	}
	if len(g.pending) < g.maxQueued {
		g.pending = append(g.pending, data)
	} else {
		copy(g.pending, g.pending[1:])
		g.pending[len(g.pending)-1] = data
		return false
	}
	return true
}
