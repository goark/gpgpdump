package packets

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"
)

// Tag11 parsing packet(11).
func Tag11(cxt *Context, indent Indent) ([]string, error) {
	var content = make([]string, 0)
	content = append(content, indent.Fill(cxt.PacketName()))

	p, err := cxt.Parse()
	if err != nil {
		return content, err
	}
	indent++
	switch pkt := p.(type) {
	case *packet.LiteralData:
		content = append(content, indent.Fill(tag11Format(cxt, pkt)))
		content = append(content, indent.Fill(tag11Filename(cxt, pkt)))
		content = append(content, indent.Fill(tag11Time(cxt, pkt)))
	default:
		content = append(content, indent.Fill("Unknown"))
	}

	return content, nil
}

func tag11Format(cxt *Context, ld *packet.LiteralData) string {
	if ld.IsBinary {
		return "Format - binary"
	}
	return "Format - text"
}

func tag11Filename(cxt *Context, ld *packet.LiteralData) string {
	return fmt.Sprintf("Filename - %s", ld.FileName)
}

func tag11Time(cxt *Context, ld *packet.LiteralData) string {
	return fmt.Sprintf("File modified time - %s", UnixTime(ld.Time, cxt.Uflag))
}
