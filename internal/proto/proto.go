// Package proto defines the JSON control protocol spoken over the single
// WebSocket that connects each agent to the bastion.
//
// There is exactly one channel per agent. Every frame is a JSON Msg; shell
// stdin/stdout are carried as base64 Data on shell_data frames. The bastion
// multiplexes several shells over the one channel by ID.
package proto

// Message kinds.
const (
	THello       = "hello"        // agent -> bastion: identify the host
	THelloAck    = "hello_ack"    // bastion -> agent: accepted
	TPing        = "ping"         // bastion -> agent
	TPong        = "pong"         // agent -> bastion
	TShellOpen   = "shell_open"   // bastion -> agent: start a PTY
	TShellData   = "shell_data"   // both: terminal bytes
	TShellResize = "shell_resize" // bastion -> agent
	TShellClose  = "shell_close"  // both
	TShellExit   = "shell_exit"   // agent -> bastion: PTY ended
	TError       = "error"        // both
)

// Msg is the single JSON envelope for every frame on the agent channel.
type Msg struct {
	T        string `json:"t"`
	ID       string `json:"id,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Version  string `json:"version,omitempty"`
	Shell    string `json:"shell,omitempty"`
	Term     string `json:"term,omitempty"`
	Cols     uint16 `json:"cols,omitempty"`
	Rows     uint16 `json:"rows,omitempty"`
	Data     []byte `json:"data,omitempty"` // base64 in JSON
	Code     *int   `json:"code,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Host is a connected agent as exposed by the bastion API.
type Host struct {
	Name    string `json:"name"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
	Remote  string `json:"remote"`
	Online  bool   `json:"online"`
	Since   string `json:"since,omitempty"`
}
