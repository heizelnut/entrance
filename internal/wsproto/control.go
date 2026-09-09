package wsproto

// Polar control messages on the daemon <-> bastion control channel.
// Message types (field T):
//
//	daemon -> bastion:
//	  hello          {version, allowed_ports, remap}
//	  heartbeat      {version, err?}
//	  config_ack     {}
//	bastion -> daemon:
//	  hello_ack      {config}
//	  heartbeat_ack  {config}
//	  config         {config}
//	  close          {reason}
//
// Relay WebSocket (user <-> bastion) uses only:
//
//	close          {reason}  — text frame before the socket closes
const (
	THello        = "hello"
	THelloAck     = "hello_ack"
	THeartbeat    = "heartbeat"
	THeartbeatAck = "heartbeat_ack"
	TConfig       = "config"
	TConfigAck    = "config_ack"
	TClose        = "close"
)

// Config is the daemon configuration pushed by the bastion. It carries the
// allocated WG address, the hub's identity, and the current allowed-port
// list.
type Config struct {
	WGIP                 string      `json:"wg_ip,omitempty"`
	BastionWGIP          string      `json:"bastion_wg_ip,omitempty"`
	BastionWGPubKey      string      `json:"bastion_wg_pubkey,omitempty"`
	BastionWGPort        uint16      `json:"bastion_wg_port,omitempty"`
	NetworkCIDR          string      `json:"network_cidr,omitempty"`
	AllowedPorts         []int       `json:"allowed_ports,omitempty"`
	Remap                map[int]int `json:"remap,omitempty"`
	ListenAddr           string      `json:"listen_addr,omitempty"`
	HeartbeatIntervalSec int         `json:"heartbeat_interval_sec,omitempty"`
}

// Control is the JSON envelope for all control-channel messages.
type Control struct {
	T            string      `json:"t"`
	Version      string      `json:"version,omitempty"`
	Error        string      `json:"error,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	AllowedPorts []int       `json:"allowed_ports,omitempty"`
	Remap        map[int]int `json:"remap,omitempty"`
	Config       *Config     `json:"config,omitempty"`
}
