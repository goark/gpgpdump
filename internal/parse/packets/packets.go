package packets

import (
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/private"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag01"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag02"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag06"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag09"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag10"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag11"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag13"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag14"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag17"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/unknown"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

//Packet is OpenPGP Packet
type Packet struct {
	Tag     values.Tag
	Content []byte
}

// StringPacketInfo returns string of packet information
func (p Packet) String() string {
	return fmt.Sprintf("%v (%d bytes)", p.Tag, len(p.Content))
}

//Parse parsing OpenPGP packet.
func (p Packet) Parse(opt *options.Options) (values.Content, error) {
	content := values.NewContent()
	indent := values.Indent(0)
	content = append(content, indent.Fill(p.String()))

	c, err := p.getTag(opt).Parse(indent)
	if err != nil {
		return content, err
	}
	content = content.Add(c)
	return content, nil
}

//Tags parsing interface
type Tags interface {
	Parse(values.Indent) (values.Content, error)
}

func (p Packet) getTag(opt *options.Options) Tags {
	switch p.Tag {
	case 1:
		return tag01.New(opt, p.Content)
	case 2:
		return tag02.New(opt, p.Content)
	case 6:
		return tag06.New(opt, p.Content)
	case 9:
		return tag09.New(opt, p.Content)
	case 10:
		return tag10.New(opt, p.Content)
	case 11:
		return tag11.New(opt, p.Content)
	case 13:
		return tag13.New(opt, p.Content)
	case 14:
		return tag14.New(opt, p.Content)
	case 17:
		return tag17.New(opt, p.Content)
	case 60, 61, 62, 63:
		return private.New(opt, p.Content)
	default:
		return unknown.New(opt, p.Content)
	}
}

//Packets is OpenPGP Packets
type Packets struct {
	reader *packet.OpaqueReader
}

//NewPackets returns Packets
func NewPackets(r io.Reader) *Packets {
	return &Packets{reader: packet.NewOpaqueReader(r)}
}

//Next returns next OpenPGP packet
func (p *Packets) Next() (*Packet, error) {
	op, err := p.reader.Next()
	if err != nil {
		if err != io.EOF {
			return nil, err
		}
		return nil, nil
	}
	return &Packet{Tag: values.Tag(op.Tag), Content: op.Contents}, nil
}
