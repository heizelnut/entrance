package wg

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestUDPTransportLoopback exercises the phase-2 direct UDP transport on
// loopback: datagrams sent by one side arrive at the other.
func TestUDPTransportLoopback(t *testing.T) {
	pa, pb := freeUDPPorts(t)
	a, err := NewUDPTransport("127.0.0.1:"+pa, "127.0.0.1:"+pb)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewUDPTransport("127.0.0.1:"+pb, "127.0.0.1:"+pa)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 8)
	b.SetRecvCB(func(data []byte) { got <- data })
	if err := a.Open(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := b.Open(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	payload := []byte("udp-direct-datagram")
	if err := a.Send(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-got:
		if !bytes.Equal(d, payload) {
			t.Fatalf("got %x want %x", d, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no datagram received")
	}
}

func freeUDPPorts(t *testing.T) (string, string) {
	t.Helper()
	conns := [](*net.UDPConn){}
	ports := [2]int{}
	for i := range ports {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		ports[i] = c.LocalAddr().(*net.UDPAddr).Port
	}
	for _, c := range conns {
		c.Close()
	}
	return itoa(ports[0]), itoa(ports[1])
}

func itoa(n int) string {
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestIPAMAllocation checks the hub addressing scheme.
func TestIPAMAllocation(t *testing.T) {
	a, err := ParseNetwork("10.99.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Network(); got != "10.99.0.0/24" {
		t.Fatalf("network = %s", got)
	}
	if got := a.BastionIP().String(); got != "10.99.0.1" {
		t.Fatalf("bastion = %s", got)
	}
	want := []string{"10.99.0.2", "10.99.0.3", "10.99.0.4"}
	for i, w := range want {
		ip, err := a.AddressForN(uint64(i))
		if err != nil {
			t.Fatalf("AddressForN(%d): %v", i, err)
		}
		if ip.String() != w {
			t.Fatalf("AddressForN(%d) = %s want %s", i, ip, w)
		}
	}
}
