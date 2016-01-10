package parse

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"
)

// Tag11 packet
type Tag11 struct {
	*Options
	OpaquePacket *packet.OpaquePacket
}

// Parse parsing packet(11).
func (t Tag11) Parse(indent Indent) ([]string, error) {
	var content = make([]string, 0)
	content = append(content, indent.Fill(StringPacketInfo(t.OpaquePacket)))

	p, err := t.OpaquePacket.Parse()
	if err != nil {
		return content, err
	}
	indent++
	switch pkt := p.(type) {
	case *packet.LiteralData:
		content = append(content, indent.Fill(t.tag11Format(pkt)))
		content = append(content, indent.Fill(t.tag11Filename(pkt)))
		content = append(content, indent.Fill(t.tag11Time(pkt)))
	default:
		content = append(content, indent.Fill("Unknown"))
	}

	return content, nil
}

func (t Tag11) tag11Format(ld *packet.LiteralData) string {
	if ld.IsBinary {
		return "Format - binary"
	}
	return "Format - text"
}

func (t Tag11) tag11Filename(ld *packet.LiteralData) string {
	return fmt.Sprintf("Filename - %s", ld.FileName)
}

func (t Tag11) tag11Time(ld *packet.LiteralData) string {
	return fmt.Sprintf("File modified time - %s", StringRFC3339(ld.Time, t.Uflag))
}
