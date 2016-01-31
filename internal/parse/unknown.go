package parse

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"golang.org/x/crypto/openpgp/packet"
)

// Unknown packet
type Unknown struct {
	*options.Options
	OpaquePacket *packet.OpaquePacket
}

// Parse parsing unknown packet.
func (p Unknown) Parse(indent Indent) ([]string, error) {
	var content = make([]string, 0)
	content = append(content, indent.Fill(StringPacketInfo(p.OpaquePacket)))
	return content, nil
}
