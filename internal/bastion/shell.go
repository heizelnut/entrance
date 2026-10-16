package bastion

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"entrance/internal/proto"
)

// shellBridge relays one browser terminal to one agent PTY.
type shellBridge struct {
	id      string
	browser *websocket.Conn
	log     *slog.Logger

	wmu    sync.Mutex
	closed bool
}

// handleShellWS upgrades a browser terminal and bridges it to an agent shell.
// Path: /ws/shell/<host>?cols=80&rows=24
func (b *Bastion) handleShellWS(w http.ResponseWriter, r *http.Request) {
	if !b.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	host := strings.TrimPrefix(r.URL.Path, "/ws/shell/")
	host = strings.TrimSuffix(host, "/")
	ac := b.agent(host)
	if ac == nil {
		http.Error(w, "host offline", http.StatusNotFound)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer ws.CloseNow()

	id, _ := randomHex(8)
	cols := parseU16(r.URL.Query().Get("cols"))
	rows := parseU16(r.URL.Query().Get("rows"))
	br := &shellBridge{id: id, browser: ws, log: b.log}
	ac.attach(id, br)
	defer func() {
		ac.detach(id)
		_ = ac.send(proto.Msg{T: proto.TShellClose, ID: id})
	}()

	if err := ac.send(proto.Msg{
		T: proto.TShellOpen, ID: id, Shell: b.cfg.Shell,
		Term: "xterm-256color", Cols: cols, Rows: rows,
	}); err != nil {
		return
	}
	b.log.Info("shell session opened", "host", host, "id", id, "cols", cols, "rows", rows)
	defer b.log.Info("shell session closed", "host", host, "id", id)

	for {
		_, data, err := ws.Read(r.Context())
		if err != nil {
			return
		}
		var m proto.Msg
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch m.T {
		case proto.TShellData:
			_ = ac.send(proto.Msg{T: proto.TShellData, ID: id, Data: m.Data})
		case proto.TShellResize:
			_ = ac.send(proto.Msg{T: proto.TShellResize, ID: id, Cols: m.Cols, Rows: m.Rows})
		}
	}
}

// send writes a frame to the browser terminal.
func (br *shellBridge) send(m proto.Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	br.wmu.Lock()
	defer br.wmu.Unlock()
	if br.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return br.browser.Write(ctx, websocket.MessageText, b)
}

// close ends the browser terminal.
func (br *shellBridge) close() {
	br.wmu.Lock()
	defer br.wmu.Unlock()
	if br.closed {
		return
	}
	br.closed = true
	_ = br.browser.Close(websocket.StatusNormalClosure, "shell ended")
}

func parseU16(s string) uint16 {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}
