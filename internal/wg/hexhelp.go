package wg

import "fmt"

func hexHead(b []byte) string {
	if len(b) > 4 {
		return fmt.Sprintf("%02x%02x%02x%02x", b[0], b[1], b[2], b[3])
	}
	return fmt.Sprintf("%x", b)
}
