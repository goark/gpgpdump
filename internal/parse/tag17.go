package parse

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"golang.org/x/crypto/openpgp/packet"
)

// Tag17 - User Attribute Packet
type Tag17 struct {
	*options.Options
	OpaquePacket *packet.OpaquePacket
}

// Parse parsing User Attribute Packet
func (t Tag17) Parse(indent Indent) ([]string, error) {
	var content = make([]string, 0)
	content = append(content, indent.Fill(StringPacketInfo(t.OpaquePacket)))

	osp, err := packet.OpaqueSubpackets(t.OpaquePacket.Contents)
	if err != nil {
		return content, err
	}
	sp := &Subpackets{Options: t.Options, Title: "Subpacket -", OpaqueSubpackets: osp}
	content = append(content, sp.ParseUA(indent+1)...)
	return content, nil
}
