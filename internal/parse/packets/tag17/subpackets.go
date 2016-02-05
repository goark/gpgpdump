package tag17

import (
	"fmt"
	"strconv"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag02"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Subpackets - Sub-Packets
type Subpackets struct {
	*options.Options
	title            string
	opaqueSubpackets []*packet.OpaqueSubpacket
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
type ParseSubpacket func(*Subpackets, *packet.OpaqueSubpacket, *items.Item) error

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
func (sp *Subpackets) Parse(pckt *items.Item) error {
	sub := items.NewItem(sp.title, "", "", "")
	for _, p := range sp.opaqueSubpackets {
		if err := parseSubpacketFunctions.Get(int(p.SubType), parseSPReserved)(sp, p, sub); err != nil {
			return err
		}
	}
	pckt.AddSub(sub)
	return nil
}

func parseSPReserved(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := tag02.SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	item.AddSub(st)
	return nil
}

//Image Attribute
func parseSPType01(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := tag02.SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	length := values.Octets2IntLE(op.Contents[0:2])
	version := op.Contents[2]
	if version == 1 {
		st.AddSub(items.NewItem("Version", strconv.Itoa(int(version)), "", ""))
		enc := op.Contents[3]
		encName := "Unknown"
		if enc == 0x01 {
			encName = "JPEG"
		}
		st.AddSub(items.NewItem("Encoding", encName, fmt.Sprintf("(enc %d)", enc), ""))
	} else if 100 <= version && version <= 110 {
		st.AddSub(items.NewItem("Version", strconv.Itoa(int(version)), "private or experimental use", ""))
	} else {
		st.AddSub(items.NewItem("Version", strconv.Itoa(int(version)), "Unknown", ""))
	}
	st.AddSub(items.NewItem("Image data", "", fmt.Sprintf("%d bytes", len(op.Contents)-int(length)), ""))

	item.AddSub(st)
	return nil
}
