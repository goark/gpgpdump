package parse

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"
)

// Tag13 - User ID Packet
type Tag13 struct {
	*Options
	OpaquePacket *packet.OpaquePacket
}

// Parse parsing User ID Packet
func (t Tag13) Parse(indent Indent) ([]string, error) {
	var content = make([]string, 0)
	content = append(content, indent.Fill(StringPacketInfo(t.OpaquePacket)))
	content = append(content, (indent + 1).Fill(fmt.Sprintf("User ID - %s", string(t.OpaquePacket.Contents))))
	return content, nil
}
