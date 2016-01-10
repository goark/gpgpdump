package parse

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/openpgp/packet"
)

// Tag11 - Literal Data Packet
type Tag11 struct {
	*Options
	OpaquePacket *packet.OpaquePacket
}

// Parse parsing Literal Data Packet
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
		content = append(content, indent.Fill(t.format(pkt)))
		content = append(content, indent.Fill(t.filename(pkt)))
		content = append(content, indent.Fill(t.unixtime(pkt)))
		content = append(content, indent.Fill(t.body(pkt)))
	default:
		content = append(content, indent.Fill("Unknown"))
	}

	return content, nil
}

func (t Tag11) format(ld *packet.LiteralData) string {
	return fmt.Sprintf("Format - %v", LiteralFormat(t.OpaquePacket.Contents[0]))
}

func (t Tag11) filename(ld *packet.LiteralData) string {
	return fmt.Sprintf("Filename - %s", ld.FileName)
}

func (t Tag11) unixtime(ld *packet.LiteralData) string {
	return fmt.Sprintf("File modified time - %s", StringRFC3339UNIX(ld.Time, t.Uflag))
}

func (t Tag11) body(ld *packet.LiteralData) string {
	dump := "..."
	if t.Lflag {
		if data, err := ioutil.ReadAll(ld.Body); err == nil {
			dump = DumpByte(data)
		}
	}
	return fmt.Sprintf("Literal - %s", dump)
}
