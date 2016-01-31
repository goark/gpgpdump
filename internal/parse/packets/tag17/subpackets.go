package tag17

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag02"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

var subpacketNames = values.Msgs{
	0: "Reserved",        //00
	1: "Image Attribute", //01
}

// Subpackets - Sub-Packets
type Subpackets struct {
	*options.Options
	title            string
	opaqueSubpackets []*packet.OpaqueSubpacket
	sigCreationTime  int64
	keyCreationTime  int64
}

//NewSubpackets returns new Subpackets.
func NewSubpackets(opt *options.Options, title string, body []byte) (*Subpackets, error) {
	osp, err := packet.OpaqueSubpackets(body)
	if err != nil {
		return nil, err
	}
	return &Subpackets{Options: opt, title: title, opaqueSubpackets: osp}, nil
}

// ParseSubpacket is function value of parsing sub-packet
type ParseSubpacket func(*Subpackets, *packet.OpaqueSubpacket) (values.Content, error)

//Functions is type of function list.
type Functions map[int]ParseSubpacket

//Get returns message.
func (fs Functions) Get(i int, def ParseSubpacket) ParseSubpacket {
	if f, ok := fs[i]; ok {
		return f
	}
	return def
}

var parseSubpacketFunctions = Functions{
	1: parseSPType01,
}

//Parse parsing sub-packets
func (sp *Subpackets) Parse(indent values.Indent) values.Content {
	content := values.NewContent()
	for _, pckt := range sp.opaqueSubpackets {
		st := tag02.SubpacketType(pckt.SubType)
		content = append(content, indent.Fill(tag02.SubpacketName(tag02.SubpacketType(pckt.SubType), len(pckt.Contents), sp.title)))
		c, err := parseSubpacketFunctions.Get(int(st), parseSPReserved)(sp, pckt)
		if err != nil {
			return content
		}
		content = content.AddIndent(c, indent+1)
	}
	return content
}

func parseSPReserved(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	return nil, nil
}

//Signature Creation Time
func parseSPType01(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	length := values.Octets2IntLE(op.Contents[0:2])
	version := op.Contents[2]
	if version == 1 {
		content = append(content, fmt.Sprintf("Version of the image header - %d", version))
		enc := op.Contents[3]
		encName := "Unknown"
		if enc == 0x01 {
			encName = "JPEG"
		}
		content = append(content, fmt.Sprintf("Encoding format of the image - %s(enc %d)", encName, enc))
	} else if 100 <= version && version <= 110 {
		content = append(content, fmt.Sprintf("private or experimental use(ver %d)", version))
	} else {
		content = append(content, fmt.Sprintf("Unknown version of the image header(ver %d)", version))
	}
	content = append(content, fmt.Sprintf("Image data(%d bytes)", len(op.Contents)-int(length)))
	return content, nil
}
