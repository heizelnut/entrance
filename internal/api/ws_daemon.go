package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/coder/websocket"

	"entrance/internal/db"
	"entrance/internal/wg"
	"entrance/internal/wsproto"
)

// GET /api/v1/daemons/me/ws — the daemon control channel (D7): one WebSocket
// carries WG datagrams (binary frames) and JSON control messages (text).
func (s *Server) handleDaemonWS(w http.ResponseWriter, r *http.Request) {
	dm := daemonFrom(r)

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return // Accept writes its own error
	}
	conn := wsproto.NewConn(ws)
	defer conn.Close(websocket.StatusNormalClosure, "closing")

	hubT := s.hub.dev.Transport().(*wg.HubTransport)
	token := uint16(mustPort(endpointToken(dm.ID)))
	hubT.Register(token, conn)
	defer hubT.Unregister(token, conn) // identity-guarded: don't clobber a reconnect

	s.log.Info("daemon connected",
		"daemon", dm.ID, "hostname", dm.Hostname, "remote", s.clientIP(r))
	defer s.log.Info("daemon disconnected", "daemon", dm.ID)

	for {
		frame, err := conn.Read()
		if err != nil {
			s.log.Debug("daemon control ws read", "daemon", dm.ID, "err", err)
			return
		}
		switch frame.Kind {
		case wsproto.KindBinary:
			s.hub.dev.InjectFrom(token, frame.Data)
		case wsproto.KindText:
			var ctl wsproto.Control
			if err := json.Unmarshal(frame.Data, &ctl); err != nil {
				s.log.Warn("bad control frame from daemon", "err", err)
				continue
			}
			if !s.handleDaemonControl(conn, dm, &ctl) {
				return
			}
		default:
			s.log.Warn("unexpected frame kind from daemon", "kind", frame.Kind)
		}
	}
}

// handleDaemonControl processes one control message; returns false when the
// daemon asked to close or an unrecoverable write error occurred.
func (s *Server) handleDaemonControl(conn *wsproto.Conn, dm *db.Daemon, ctl *wsproto.Control) bool {
	switch ctl.T {
	case wsproto.THello:
		_ = s.db.UpdateDaemonStatus(dm.ID, ctl.Version, ctl.AllowedPorts, ctl.Remap)
		_ = s.db.TouchDaemonHeartbeat(dm.ID)
		if err := conn.WriteControl(wsproto.Control{
			T:      wsproto.THelloAck,
			Config: cfgPtr(s.daemonConfig(dm)),
		}); err != nil {
			return false
		}
	case wsproto.THeartbeat:
		_ = s.db.TouchDaemonHeartbeat(dm.ID)
		if ctl.Error != "" {
			s.log.Warn("daemon heartbeat error", "daemon", dm.ID, "err", ctl.Error)
		}
		if err := conn.WriteControl(wsproto.Control{T: wsproto.THeartbeatAck}); err != nil {
			return false
		}
	case wsproto.THeartbeatAck, wsproto.THelloAck, wsproto.TConfigAck:
		// agent-side acks; nothing to do server-side
	case wsproto.TClose:
		_ = conn.Close(websocket.StatusNormalClosure, ctl.Reason)
		return false
	default:
		s.log.Warn("unknown daemon control message", "type", ctl.T, "daemon", dm.ID)
	}
	return true
}

func cfgPtr(c wsproto.Config) *wsproto.Config { return &c }

func mustPort(s string) int {
	p, err := strconv.Atoi(s)
	if err != nil {
		panic(errors.New("bad port token: " + s))
	}
	return p
}
